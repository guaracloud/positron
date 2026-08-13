use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{self as unix_fs, AtFlags, Dir, Mode, OFlags};

use super::{BootstrapEntry, BootstrapRoot, BootstrapStorageFailure, RootIdentity};

pub(super) fn canonical_root(path: &Path) -> Result<PathBuf, BootstrapStorageFailure> {
    let canonical =
        std::fs::canonicalize(path).map_err(|_| BootstrapStorageFailure::InvalidRoots)?;
    if !canonical.is_absolute()
        || !canonical
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(BootstrapStorageFailure::InvalidRoots);
    }
    Ok(canonical)
}

pub(super) fn path_identity(path: &Path) -> Result<RootIdentity, BootstrapStorageFailure> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| BootstrapStorageFailure::InvalidRoots)?;
    if !metadata.file_type().is_dir() {
        return Err(BootstrapStorageFailure::InvalidRoots);
    }
    Ok(RootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(super) fn open_verified_root(
    path: &Path,
    expected: RootIdentity,
) -> Result<File, BootstrapStorageFailure> {
    let mut current = File::open("/").map_err(|_| BootstrapStorageFailure::Unavailable)?;
    for component in path.components() {
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
                .map_err(|_| BootstrapStorageFailure::UnsafeOrCorrupt)?;
            },
            _ => return Err(BootstrapStorageFailure::InvalidRoots),
        }
    }
    let metadata = current
        .metadata()
        .map_err(|_| BootstrapStorageFailure::Unavailable)?;
    if (RootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }) != expected
    {
        return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
    }
    Ok(current)
}

pub(super) fn scan(
    directory: &File,
    root: BootstrapRoot,
) -> Result<(Vec<BootstrapEntry>, bool), BootstrapStorageFailure> {
    let mut recognized = Vec::new();
    let mut unsafe_entry = false;
    let mut entries =
        Dir::read_from(directory).map_err(|_| BootstrapStorageFailure::Unavailable)?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|_| BootstrapStorageFailure::Unavailable)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let Some(kind) = recognized_entry(root, name) else {
            unsafe_entry = true;
            continue;
        };
        let metadata = unix_fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        let expected_directory = matches!(kind, BootstrapEntry::Catalog | BootstrapEntry::Segments);
        let file_type = unix_fs::FileType::from_raw_mode(metadata.st_mode);
        if (expected_directory && !file_type.is_dir())
            || (!expected_directory && !file_type.is_file())
        {
            unsafe_entry = true;
        } else {
            recognized.push(kind);
        }
    }
    Ok((recognized, unsafe_entry))
}

fn recognized_entry(root: BootstrapRoot, name: &[u8]) -> Option<BootstrapEntry> {
    match (root, name) {
        (BootstrapRoot::Data, b".positron-volume.lock") => Some(BootstrapEntry::VolumeLock),
        (BootstrapRoot::Data, b".positron-bootstrap.pending") => Some(BootstrapEntry::Pending),
        (BootstrapRoot::Data, b".positron-bootstrap.initialized.new") => {
            Some(BootstrapEntry::InitializedStaging)
        },
        (BootstrapRoot::Data, b".positron-bootstrap.initialized") => {
            Some(BootstrapEntry::Initialized)
        },
        (BootstrapRoot::Data, b"catalog") => Some(BootstrapEntry::Catalog),
        (BootstrapRoot::Data, b"segments") => Some(BootstrapEntry::Segments),
        (BootstrapRoot::Secrets, b"local-root-key.v1") => Some(BootstrapEntry::LocalKey),
        (BootstrapRoot::Secrets, b"local-root-key.v1.new") => Some(BootstrapEntry::LocalKeyStaging),
        (BootstrapRoot::Secrets, b"bootstrap-claim.v1") => Some(BootstrapEntry::Claim),
        _ => None,
    }
}

pub(super) fn write_named_new(
    directory: &File,
    name: &str,
    bytes: &[u8],
) -> Result<(), BootstrapStorageFailure> {
    let mut file = unix_fs::openat(
        directory,
        name,
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

pub(super) fn synchronize(directory: &File) -> Result<(), BootstrapStorageFailure> {
    directory
        .sync_all()
        .map_err(|_| BootstrapStorageFailure::Unavailable)
}

pub(super) fn map_open_error(error: rustix::io::Errno) -> BootstrapStorageFailure {
    if error == rustix::io::Errno::EXIST {
        BootstrapStorageFailure::AlreadyExists
    } else if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOENT) {
        BootstrapStorageFailure::UnsafeOrCorrupt
    } else {
        BootstrapStorageFailure::Unavailable
    }
}
