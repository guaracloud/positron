//! Descriptor-relative storage capability for the instance-bootstrap protocol.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{self as unix_fs, AtFlags, Mode, OFlags, RenameFlags};

use crate::{
    BootstrapKeyCustody, BootstrapKeyFailure, CatalogFailureCode, CatalogSecret, InstanceId,
    MountQualification, OwnedPrimaryDataVolume, PrimaryDataVolume,
};

mod io;
#[cfg(test)]
mod tests;

use io::{
    canonical_root, map_open_error, open_verified_root, path_identity, scan, synchronize,
    write_named_new,
};

const MAX_ARTIFACT_BYTES: u64 = 2_097_152;

/// A durable bootstrap artifact selected without exposing a filesystem name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapArtifact {
    Pending,
    InitializedStaging,
    Initialized,
    Claim,
}

impl BootstrapArtifact {
    const fn name(self) -> &'static str {
        match self {
            Self::Pending => ".positron-bootstrap.pending",
            Self::InitializedStaging => ".positron-bootstrap.initialized.new",
            Self::Initialized => ".positron-bootstrap.initialized",
            Self::Claim => "bootstrap-claim.v1",
        }
    }

    const fn root(self) -> BootstrapRoot {
        match self {
            Self::Claim => BootstrapRoot::Secrets,
            Self::Pending | Self::InitializedStaging | Self::Initialized => BootstrapRoot::Data,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BootstrapRoot {
    Data,
    Secrets,
}

/// One recognized entry in a bootstrap root.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum BootstrapEntry {
    VolumeLock,
    Pending,
    InitializedStaging,
    Initialized,
    Catalog,
    Segments,
    LocalKey,
    LocalKeyStaging,
    Claim,
}

/// A bounded, typed observation of both bootstrap roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapLayout {
    data: Vec<BootstrapEntry>,
    secrets: Vec<BootstrapEntry>,
    unknown_or_unsafe: bool,
}

impl BootstrapLayout {
    /// Returns whether the selected recognized entry exists.
    #[must_use]
    pub fn contains(&self, entry: BootstrapEntry) -> bool {
        self.data.contains(&entry) || self.secrets.contains(&entry)
    }

    /// Returns whether the root contained any unknown or unsafe entry.
    #[must_use]
    pub const fn unknown_or_unsafe(&self) -> bool {
        self.unknown_or_unsafe
    }

    /// Returns whether data contains only its ownership lock and secrets is empty.
    #[must_use]
    pub fn is_empty_instance(&self) -> bool {
        (self.data.is_empty() || self.data.as_slice() == [BootstrapEntry::VolumeLock])
            && self.secrets.is_empty()
    }

    /// Returns whether secrets contains no final key and only an optional staged key.
    #[must_use]
    pub fn has_at_most_staged_key(&self) -> bool {
        self.secrets.is_empty() || self.secrets.as_slice() == [BootstrapEntry::LocalKeyStaging]
    }

    /// Returns whether data contains only the ownership lock and pending intent.
    #[must_use]
    pub fn has_only_raw_pending_data(&self) -> bool {
        self.data.as_slice() == [BootstrapEntry::Pending]
            || self.data.as_slice() == [BootstrapEntry::VolumeLock, BootstrapEntry::Pending]
    }
}

/// Closed failure surface for bootstrap storage operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapStorageFailure {
    InvalidRoots,
    Unavailable,
    UnsafeOrCorrupt,
    AlreadyExists,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootIdentity {
    device: u64,
    inode: u64,
}

/// Opaque authority for locating and acquiring the bootstrap roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceBootstrapStorage {
    data: PathBuf,
    secrets: PathBuf,
    data_identity: RootIdentity,
    secrets_identity: RootIdentity,
    qualification: MountQualification,
}

impl InstanceBootstrapStorage {
    /// Binds distinct existing roots to stable identities.
    pub fn new(
        data: &Path,
        secrets: &Path,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapStorageFailure> {
        let data = canonical_root(data)?;
        let secrets = canonical_root(secrets)?;
        if data == secrets || data.starts_with(&secrets) || secrets.starts_with(&data) {
            return Err(BootstrapStorageFailure::InvalidRoots);
        }
        Ok(Self {
            data_identity: path_identity(&data)?,
            secrets_identity: path_identity(&secrets)?,
            data,
            secrets,
            qualification,
        })
    }

    /// Opens both roots without following symbolic links.
    pub fn inspect(&self) -> Result<BootstrapArtifactAccess, BootstrapStorageFailure> {
        Ok(BootstrapArtifactAccess {
            data: open_verified_root(&self.data, self.data_identity)?,
            secrets: open_verified_root(&self.secrets, self.secrets_identity)?,
        })
    }

    /// Acquires the PDV and returns a descriptor-relative artifact capability.
    pub fn acquire(
        &self,
    ) -> Result<(OwnedPrimaryDataVolume, BootstrapArtifactAccess), BootstrapStorageFailure> {
        let volume = PrimaryDataVolume::acquire(&self.data, self.qualification)
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        let data = volume
            ._root
            .try_clone()
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        let secrets = open_verified_root(&self.secrets, self.secrets_identity)?;
        Ok((volume, BootstrapArtifactAccess { data, secrets }))
    }

    /// Returns the trusted mount provenance attached to this authority.
    #[must_use]
    pub const fn qualification(&self) -> MountQualification {
        self.qualification
    }
}

/// Held descriptor capability for bootstrap artifacts.
pub struct BootstrapArtifactAccess {
    data: File,
    secrets: File,
}

impl BootstrapArtifactAccess {
    /// Opens the local bootstrap key relative to the held secrets root.
    pub fn open_key(&self) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        BootstrapKeyCustody::open_in(&self.secrets)
    }

    /// Initializes the local bootstrap key relative to the held secrets root.
    pub fn initialize_key(&self) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        BootstrapKeyCustody::initialize_in(&self.secrets)
    }

    /// Scans recognized root entries and rejects unsafe entry kinds.
    pub fn layout(&self) -> Result<BootstrapLayout, BootstrapStorageFailure> {
        let (mut data, data_unsafe) = scan(&self.data, BootstrapRoot::Data)?;
        let (mut secrets, secrets_unsafe) = scan(&self.secrets, BootstrapRoot::Secrets)?;
        data.sort_unstable();
        secrets.sort_unstable();
        Ok(BootstrapLayout {
            data,
            secrets,
            unknown_or_unsafe: data_unsafe || secrets_unsafe,
        })
    }

    /// Authenticates the complete visible Catalog chain without recovery mutation.
    pub fn inspect_catalog(
        &self,
        instance: InstanceId,
        secret: CatalogSecret,
    ) -> Result<u64, BootstrapStorageFailure> {
        crate::catalog::inspect_read_only(&self.data, instance, secret).map_err(|failure| {
            if failure.code() == CatalogFailureCode::StorageUnavailable {
                BootstrapStorageFailure::Unavailable
            } else {
                BootstrapStorageFailure::UnsafeOrCorrupt
            }
        })
    }

    /// Reads a bounded regular artifact through its held root descriptor.
    pub fn read(&self, artifact: BootstrapArtifact) -> Result<Vec<u8>, BootstrapStorageFailure> {
        let directory = self.directory(artifact);
        let mut file = unix_fs::openat(
            directory,
            artifact.name(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(map_open_error)?;
        let metadata = file
            .metadata()
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > MAX_ARTIFACT_BYTES
        {
            return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
        }
        let length = usize::try_from(metadata.len())
            .map_err(|_| BootstrapStorageFailure::UnsafeOrCorrupt)?;
        let mut bytes = vec![0_u8; length];
        file.read_exact(&mut bytes)
            .map_err(|_| BootstrapStorageFailure::UnsafeOrCorrupt)?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| BootstrapStorageFailure::Unavailable)?
            != 0
        {
            return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
        }
        Ok(bytes)
    }

    /// Creates and durably synchronizes a new artifact.
    pub fn write_new(
        &self,
        artifact: BootstrapArtifact,
        bytes: &[u8],
    ) -> Result<(), BootstrapStorageFailure> {
        let directory = self.directory(artifact);
        let mut file = unix_fs::openat(
            directory,
            artifact.name(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(map_open_error)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        synchronize(directory)
    }

    /// Replaces the pending intent through a private, exclusive temporary.
    pub fn replace_pending(&self, bytes: &[u8]) -> Result<(), BootstrapStorageFailure> {
        const TEMP: &str = ".positron-bootstrap.pending.replacement";
        write_named_new(&self.data, TEMP, bytes)?;
        unix_fs::renameat(
            &self.data,
            TEMP,
            &self.data,
            BootstrapArtifact::Pending.name(),
        )
        .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        synchronize(&self.data)
    }

    /// Removes an artifact and synchronizes its parent directory.
    pub fn remove(&self, artifact: BootstrapArtifact) -> Result<(), BootstrapStorageFailure> {
        let directory = self.directory(artifact);
        unix_fs::unlinkat(directory, artifact.name(), AtFlags::empty())
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        synchronize(directory)
    }

    /// Publishes the initialized marker without replacing a racing final marker.
    pub fn publish_initialized(&self) -> Result<(), BootstrapStorageFailure> {
        unix_fs::renameat_with(
            &self.data,
            BootstrapArtifact::InitializedStaging.name(),
            &self.data,
            BootstrapArtifact::Initialized.name(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                BootstrapStorageFailure::AlreadyExists
            } else {
                BootstrapStorageFailure::Unavailable
            }
        })?;
        synchronize(&self.data)
    }

    /// Tests the exact entry kind without following symbolic links.
    pub fn exists(&self, artifact: BootstrapArtifact) -> Result<bool, BootstrapStorageFailure> {
        let directory = self.directory(artifact);
        match unix_fs::statat(directory, artifact.name(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => {
                if unix_fs::FileType::from_raw_mode(metadata.st_mode).is_file()
                    && metadata.st_nlink == 1
                {
                    Ok(true)
                } else {
                    Err(BootstrapStorageFailure::UnsafeOrCorrupt)
                }
            },
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(_) => Err(BootstrapStorageFailure::Unavailable),
        }
    }

    fn directory(&self, artifact: BootstrapArtifact) -> &File {
        match artifact.root() {
            BootstrapRoot::Data => &self.data,
            BootstrapRoot::Secrets => &self.secrets,
        }
    }
}
