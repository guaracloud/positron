//! Exact-object persistence and reopen behavior for the Local Root Key File.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use std::os::unix::fs::MetadataExt;

use rustix::fs::{self as unix_fs, Mode, OFlags};

use super::acl::{verify_directory_acl, verify_file_acl};
use super::bootstrap::verify_key_file;
use super::codec::{EncodedLocalKeyFile, parse_file_v1};
use super::security_directory::open_absolute_directory;
use super::{
    LOCAL_KEY_FILE_NAME, LocalKeyCreationTime, LocalKeyEvidence, LocalKeyFailure,
    LocalKeyFailureCode, LocalKeyFingerprint, LocalKeyId, VerifiedLocalKey,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ExpectedLocalKeyIdentity {
    key_id: LocalKeyId,
    fingerprint: LocalKeyFingerprint,
    creation_time: LocalKeyCreationTime,
}

impl std::fmt::Debug for ExpectedLocalKeyIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExpectedLocalKeyIdentity { <redacted> }")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ExpectedSecurityDirectory {
    owner: u32,
    link_count: u64,
    device: u64,
    inode: u64,
}

impl std::fmt::Debug for ExpectedSecurityDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExpectedSecurityDirectory { <redacted> }")
    }
}

impl ExpectedSecurityDirectory {
    #[cfg(test)]
    pub(super) fn for_test(location: &Path) -> Result<Self, LocalKeyFailure> {
        let metadata = std::fs::symlink_metadata(location)
            .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation))?;
        Ok(Self {
            owner: metadata.uid(),
            link_count: metadata.nlink(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl ExpectedLocalKeyIdentity {
    #[cfg(test)]
    pub(super) const fn from_evidence(evidence: LocalKeyEvidence) -> Self {
        Self {
            key_id: evidence.key_id,
            fingerprint: evidence.fingerprint,
            creation_time: evidence.creation_time,
        }
    }

    #[cfg(test)]
    pub(super) const fn with_test_fingerprint(
        evidence: LocalKeyEvidence,
        fingerprint: LocalKeyFingerprint,
    ) -> Self {
        Self {
            key_id: evidence.key_id,
            fingerprint,
            creation_time: evidence.creation_time,
        }
    }

    fn matches(self, evidence: LocalKeyEvidence) -> bool {
        self.key_id == evidence.key_id
            && self.fingerprint == evidence.fingerprint
            && self.creation_time == evidence.creation_time
    }
}

pub(super) fn open_local_key(
    location: &Path,
    expected_directory: ExpectedSecurityDirectory,
    expected: ExpectedLocalKeyIdentity,
) -> Result<VerifiedLocalKey, LocalKeyFailure> {
    let directory = open_absolute_directory(location)?;
    verify_opened_security_directory(&directory, expected_directory)?;
    verify_directory_acl(&directory)?;
    let mut file = unix_fs::openat(
        &directory,
        LOCAL_KEY_FILE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::OpenKeyFileFailed))?;
    verify_key_file(&directory, &file, expected_directory.owner)?;
    verify_file_acl(&file)?;

    let mut encoded = EncodedLocalKeyFile::zeroed();
    file.read_exact(encoded.bytes.as_mut())
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?;
    let mut trailing = [0_u8; 1];
    let trailing_bytes = file
        .read(&mut trailing)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?;
    trailing.fill(0);
    if trailing_bytes != 0 {
        return Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?;
    verify_key_file(&directory, &file, expected_directory.owner)?;
    verify_file_acl(&file)?;

    let verified = parse_file_v1(encoded)?;
    if expected.matches(verified.evidence()) {
        Ok(verified)
    } else {
        Err(LocalKeyFailure::new(LocalKeyFailureCode::IdentityMismatch))
    }
}

pub(super) fn open_existing_local_key(
    location: &Path,
) -> Result<VerifiedLocalKey, LocalKeyFailure> {
    let directory = open_absolute_directory(location)?;
    open_existing_local_key_in(&directory)
}

pub(super) fn open_existing_local_key_in(
    directory: &File,
) -> Result<VerifiedLocalKey, LocalKeyFailure> {
    let metadata = directory
        .metadata()
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation))?;
    let expected_directory = ExpectedSecurityDirectory {
        owner: metadata.uid(),
        link_count: metadata.nlink(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    verify_opened_security_directory(directory, expected_directory)?;
    verify_directory_acl(directory)?;
    let mut file = unix_fs::openat(
        directory,
        LOCAL_KEY_FILE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::OpenKeyFileFailed))?;
    verify_key_file(directory, &file, expected_directory.owner)?;
    verify_file_acl(&file)?;
    let mut encoded = EncodedLocalKeyFile::zeroed();
    file.read_exact(encoded.bytes.as_mut())
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?;
    let mut trailing = [0_u8; 1];
    let trailing_bytes = file
        .read(&mut trailing)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?;
    trailing.fill(0);
    if trailing_bytes != 0 {
        return Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile));
    }
    verify_key_file(directory, &file, expected_directory.owner)?;
    verify_file_acl(&file)?;
    parse_file_v1(encoded)
}

fn verify_opened_security_directory(
    directory: &File,
    expected: ExpectedSecurityDirectory,
) -> Result<(), LocalKeyFailure> {
    let metadata = directory
        .metadata()
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::UnsafeSecurityDirectory))?;
    let safe = metadata.file_type().is_dir()
        && metadata.uid() == expected.owner
        && metadata.mode() & 0o7777 == 0o700
        && metadata.nlink() == expected.link_count
        && metadata.dev() == expected.device
        && metadata.ino() == expected.inode;
    if safe {
        Ok(())
    } else {
        Err(LocalKeyFailure::new(
            LocalKeyFailureCode::UnsafeSecurityDirectory,
        ))
    }
}
