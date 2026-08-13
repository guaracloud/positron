//! Exact security-directory binding for local Root Key custody.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use rustix::fs::{self as unix_fs, AtFlags, Dir, Mode, OFlags};

use super::{
    LOCAL_KEY_FILE_NAME, LOCAL_KEY_STAGING_FILE_NAME, LocalKeyFailure, LocalKeyFailureCode,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalObjectIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalKeyRootState {
    final_key: Option<LocalObjectIdentity>,
    staging_key: Option<LocalObjectIdentity>,
}

pub(super) struct FreshInitializationRootProof {
    directory: File,
    expected_owner: u32,
    expected_link_count: u64,
    identity: LocalObjectIdentity,
    root_state: LocalKeyRootState,
}

impl FreshInitializationRootProof {
    pub(super) fn new(location: &Path) -> Result<Self, LocalKeyFailure> {
        let canonical = std::fs::canonicalize(location)
            .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation))?;
        Self::from_directory(open_absolute_directory(&canonical)?)
    }

    pub(super) fn from_open_directory(directory: &File) -> Result<Self, LocalKeyFailure> {
        let directory = unix_fs::openat(
            directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation))?;
        Self::from_directory(directory)
    }

    fn from_directory(directory: File) -> Result<Self, LocalKeyFailure> {
        let metadata = directory
            .metadata()
            .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation))?;
        if !metadata.file_type().is_dir() {
            return Err(LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation));
        }
        let root_state = local_key_root_state(&directory, LocalKeyFailureCode::InvalidLocation)?;
        Ok(Self {
            directory,
            expected_owner: metadata.uid(),
            expected_link_count: metadata.nlink(),
            identity: LocalObjectIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            root_state,
        })
    }

    pub(super) const fn directory(&self) -> &File {
        &self.directory
    }

    pub(super) const fn expected_owner(&self) -> u32 {
        self.expected_owner
    }

    pub(super) fn verify(&self) -> Result<(), LocalKeyFailure> {
        let metadata = self
            .directory
            .metadata()
            .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::UnsafeSecurityDirectory))?;
        let safe = metadata.file_type().is_dir()
            && metadata.uid() == self.expected_owner
            && metadata.mode() & 0o7777 == 0o700
            && metadata.nlink() == self.expected_link_count
            && LocalObjectIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            } == self.identity
            && local_key_root_state(
                &self.directory,
                LocalKeyFailureCode::UnsafeSecurityDirectory,
            )? == self.root_state;
        if safe {
            Ok(())
        } else {
            Err(LocalKeyFailure::new(
                LocalKeyFailureCode::UnsafeSecurityDirectory,
            ))
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(location: &Path) -> Result<Self, LocalKeyFailure> {
        Self::new(location)
    }
}

fn local_key_root_state(
    directory: &File,
    failure: LocalKeyFailureCode,
) -> Result<LocalKeyRootState, LocalKeyFailure> {
    let invalid = || LocalKeyFailure::new(failure);
    let mut state = LocalKeyRootState {
        final_key: None,
        staging_key: None,
    };
    let mut entries = Dir::read_from(directory).map_err(|_| invalid())?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|_| invalid())?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        let slot = if name == LOCAL_KEY_FILE_NAME.as_bytes() {
            &mut state.final_key
        } else if name == LOCAL_KEY_STAGING_FILE_NAME.as_bytes() {
            &mut state.staging_key
        } else {
            return Err(invalid());
        };
        let metadata = unix_fs::statat(directory, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| invalid())?;
        *slot = Some(LocalObjectIdentity {
            device: metadata.st_dev as u64,
            inode: metadata.st_ino,
        });
    }
    Ok(state)
}

pub(super) fn open_absolute_directory(location: &Path) -> Result<File, LocalKeyFailure> {
    if !location.is_absolute()
        || !location
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation));
    }
    let mut current =
        File::open("/").map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation))?;
    for component in location.components() {
        match component {
            Component::RootDir => {},
            Component::Normal(name) => {
                current = unix_fs::openat(
                    &current,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation))?;
            },
            _ => return Err(LocalKeyFailure::new(LocalKeyFailureCode::InvalidLocation)),
        }
    }
    Ok(current)
}
