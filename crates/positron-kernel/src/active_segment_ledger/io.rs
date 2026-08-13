use std::fs::File;

use rustix::fs::{self as unix_fs, Mode, OFlags};

use super::{LedgerFailure, LedgerFailureCode};

pub(super) fn open_or_create_directory(parent: &File, name: &str) -> Result<File, LedgerFailure> {
    match unix_fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {},
        Err(_) => return Err(LedgerFailure::new(LedgerFailureCode::StorageUnavailable)),
    }
    let directory = unix_fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
    synchronize(parent)?;
    Ok(directory)
}

pub(super) fn open_regular(
    directory: &File,
    name: &str,
    write: bool,
) -> Result<File, LedgerFailure> {
    let access = if write { OFlags::RDWR } else { OFlags::RDONLY };
    let file = unix_fs::openat(
        directory,
        name,
        access | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        if matches!(error, rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) {
            LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)
        } else {
            LedgerFailure::new(LedgerFailureCode::StorageUnavailable)
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
    }
    Ok(file)
}

pub(super) fn synchronize(file: &File) -> Result<(), LedgerFailure> {
    file.sync_all()
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))
}

pub(super) fn hex<const N: usize>(bytes: [u8; N]) -> String {
    let mut output = String::with_capacity(N * 2);
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            let ascii = nibble + if nibble < 10 { b'0' } else { b'a' - 10 };
            output.push(char::from(ascii));
        }
    }
    output
}
