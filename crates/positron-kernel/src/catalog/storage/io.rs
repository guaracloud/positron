use std::fs::File;
use std::io::{Read, Write};

use rustix::fs::{self as unix_fs, AtFlags, Mode, OFlags};

use super::super::types::{CatalogFailure, CatalogFailureCode};
use super::fault::{CatalogFileEvent, injected_partial_write_length};

pub(super) fn open_or_create_directory(parent: &File, name: &str) -> Result<File, CatalogFailure> {
    match unix_fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {},
        Err(_) => return Err(CatalogFailure::new(CatalogFailureCode::StorageUnavailable)),
    }
    let directory = unix_fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
    let metadata = directory
        .metadata()
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
    let parent_metadata = parent
        .metadata()
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.file_type().is_dir() || metadata.dev() != parent_metadata.dev() {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
    }
    synchronize(parent)?;
    Ok(directory)
}

pub(super) fn write_new_file(
    directory: &File,
    name: &str,
    payload: &[u8],
) -> Result<(), CatalogFailure> {
    let mut file = unix_fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
    file.write_all(payload)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))
}

pub(super) fn write_transaction_file(
    directory: &File,
    name: &str,
    payload: &[u8],
    partial_fault: CatalogFileEvent,
) -> Result<(), CatalogFailure> {
    if entry_exists(directory, name)? {
        unix_fs::unlinkat(directory, name, AtFlags::empty())
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        synchronize(directory)?;
    }
    let mut file = unix_fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
    if let Some(length) = injected_partial_write_length(partial_fault, payload.len()) {
        let prefix = payload
            .get(..length)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        file.write_all(prefix)
            .and_then(|()| file.sync_all())
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        return Err(CatalogFailure::new(CatalogFailureCode::StorageUnavailable));
    }
    file.write_all(payload)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))
}

pub(super) fn synchronize_named_file(directory: &File, name: &str) -> Result<(), CatalogFailure> {
    let file = open_regular_file(directory, name)?;
    synchronize(&file)
}

pub(super) fn synchronize(file: &File) -> Result<(), CatalogFailure> {
    file.sync_all()
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))
}

pub(super) fn read_exact_file<N: rustix::path::Arg>(
    directory: &File,
    name: N,
    maximum: usize,
) -> Result<Vec<u8>, CatalogFailure> {
    let file = open_regular_file(directory, name)?;
    let metadata = file
        .metadata()
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
    let length = usize::try_from(metadata.len())
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    if length == 0 || length > maximum {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    let mut reader = file;
    let mut encoded = vec![0_u8; length];
    reader
        .read_exact(&mut encoded)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?
        != 0
    {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    Ok(encoded)
}

fn open_regular_file<N: rustix::path::Arg>(
    directory: &File,
    name: N,
) -> Result<File, CatalogFailure> {
    let file = unix_fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        if matches!(error, rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) {
            CatalogFailure::new(CatalogFailureCode::IntegrityCorruption)
        } else {
            CatalogFailure::new(CatalogFailureCode::StorageUnavailable)
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
    }
    Ok(file)
}

pub(super) fn entry_exists(directory: &File, name: &str) -> Result<bool, CatalogFailure> {
    match unix_fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(_) => Err(CatalogFailure::new(CatalogFailureCode::StorageUnavailable)),
    }
}
