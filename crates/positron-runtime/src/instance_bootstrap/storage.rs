use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose};

use super::codec::BootstrapRecord;
use super::{BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState};

pub(super) const PENDING: &str = ".positron-bootstrap.pending";
pub(super) const INITIALIZED_TEMP: &str = ".positron-bootstrap.initialized.new";
pub(super) const INITIALIZED: &str = ".positron-bootstrap.initialized";
pub(super) const CLAIM: &str = "bootstrap-claim.v1";
pub(super) const LOCAL_KEY: &str = "local-root-key.v1";
pub(super) const LOCAL_KEY_STAGING: &str = "local-root-key.v1.new";
pub(super) const INTENT: &[u8] = b"positron-bootstrap-in-progress-v1";
const MAX_ARTIFACT_BYTES: u64 = 2_097_152;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BootstrapFileEvent {
    WritePending,
    WriteClaim,
    WriteInitialized,
    RemovePending,
    PublishInitialized,
    RemoveClaim,
    SynchronizeDirectory,
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Option<BootstrapFileEvent>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn with_fault<T>(event: BootstrapFileEvent, action: impl FnOnce() -> T) -> T {
    FAULT.with(|fault| fault.set(Some(event)));
    let result = action();
    FAULT.with(|fault| fault.set(None));
    result
}

fn event(event: BootstrapFileEvent) -> Result<(), BootstrapFailure> {
    #[cfg(test)]
    if FAULT.with(|fault| {
        let matches = fault.get() == Some(event);
        if matches {
            fault.set(None);
        }
        matches
    }) {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::StorageUnavailable,
        ));
    }
    #[cfg(not(test))]
    let _ = event;
    Ok(())
}

pub(super) fn classify(paths: &BootstrapPaths) -> Result<BootstrapState, BootstrapFailure> {
    let data = entries(&paths.data)?;
    let secrets = entries(&paths.secrets)?;
    if data.iter().all(|name| name == ".positron-volume.lock") && secrets.is_empty() {
        return Ok(BootstrapState::Empty);
    }
    let has_key = secrets.iter().any(|name| name == LOCAL_KEY);
    let has_pending = data
        .iter()
        .any(|name| name == PENDING || name == INITIALIZED_TEMP);
    let has_initialized = data.iter().any(|name| name == INITIALIZED);
    let known_data = data.iter().all(|name| {
        matches!(
            name.as_str(),
            PENDING
                | INITIALIZED_TEMP
                | INITIALIZED
                | ".positron-volume.lock"
                | "catalog"
                | "segments"
        )
    });
    let known_secrets = secrets
        .iter()
        .all(|name| matches!(name.as_str(), LOCAL_KEY | LOCAL_KEY_STAGING | CLAIM));
    if !known_data || !known_secrets {
        return Ok(BootstrapState::Inconsistent);
    }
    if has_initialized && has_pending {
        return Ok(BootstrapState::Inconsistent);
    }
    if has_initialized && has_key {
        let required_storage =
            data.iter().any(|name| name == "catalog") && data.iter().any(|name| name == "segments");
        return Ok(
            if required_storage
                && authenticated_record(paths, INITIALIZED, BootstrapObjectPurpose::Initialized)
            {
                BootstrapState::Initialized
            } else {
                BootstrapState::Inconsistent
            },
        );
    }
    if has_pending {
        if !has_key {
            let staged_key_only =
                secrets.is_empty() || (secrets.len() == 1 && secrets[0] == LOCAL_KEY_STAGING);
            let raw_intent_only = staged_key_only
                && data
                    .iter()
                    .all(|name| matches!(name.as_str(), PENDING | ".positron-volume.lock"))
                && fs::read(paths.data.join(PENDING)).ok().as_deref() == Some(INTENT);
            return Ok(if raw_intent_only {
                BootstrapState::Incomplete
            } else {
                BootstrapState::Inconsistent
            });
        }
        let pending_valid = !data.iter().any(|name| name == PENDING)
            || authenticated_record(paths, PENDING, BootstrapObjectPurpose::Pending);
        let staged_valid = !data.iter().any(|name| name == INITIALIZED_TEMP)
            || authenticated_record(paths, INITIALIZED_TEMP, BootstrapObjectPurpose::Initialized);
        return Ok(if pending_valid && staged_valid {
            BootstrapState::Incomplete
        } else {
            BootstrapState::Inconsistent
        });
    }
    Ok(BootstrapState::Inconsistent)
}

fn authenticated_record(
    paths: &BootstrapPaths,
    name: &str,
    purpose: BootstrapObjectPurpose,
) -> bool {
    let Ok(key) = BootstrapKeyCustody::open(&paths.secrets) else {
        return false;
    };
    let Ok(encoded) = read(&paths.data, name) else {
        return false;
    };
    let Ok(instance) = BootstrapKeyCustody::routed_instance(purpose, &encoded) else {
        return false;
    };
    let Ok(plaintext) = key.open_object(instance, purpose, &encoded) else {
        return false;
    };
    let Ok(record) = BootstrapRecord::decode(&plaintext) else {
        return false;
    };
    record.instance == instance && record.key == key.identity()
}

fn entries(root: &Path) -> Result<Vec<String>, BootstrapFailure> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root).map_err(storage_failure)? {
        let entry = entry.map_err(storage_failure)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(storage_failure)?;
        if metadata.file_type().is_symlink() {
            return Ok(vec!["<unsafe-entry>".to_owned()]);
        }
        names.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::InconsistentRoots))?,
        );
    }
    names.sort();
    Ok(names)
}

pub(super) fn write_new(root: &Path, name: &str, bytes: &[u8]) -> Result<(), BootstrapFailure> {
    event(match name {
        PENDING => BootstrapFileEvent::WritePending,
        CLAIM => BootstrapFileEvent::WriteClaim,
        INITIALIZED_TEMP => BootstrapFileEvent::WriteInitialized,
        _ => BootstrapFileEvent::SynchronizeDirectory,
    })?;
    let path = root.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(storage_failure)?;
    file.write_all(bytes).map_err(storage_failure)?;
    file.sync_all().map_err(storage_failure)?;
    sync_directory(root)
}

pub(super) fn replace(root: &Path, name: &str, bytes: &[u8]) -> Result<(), BootstrapFailure> {
    let temporary = format!("{name}.replacement");
    write_new(root, &temporary, bytes)?;
    fs::rename(root.join(&temporary), root.join(name)).map_err(storage_failure)?;
    sync_directory(root)
}

pub(super) fn read(root: &Path, name: &str) -> Result<Vec<u8>, BootstrapFailure> {
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(storage_failure)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_ARTIFACT_BYTES
    {
        return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
    }
    let mut file = File::open(path).map_err(storage_failure)?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes).map_err(storage_failure)?;
    if bytes.len() != capacity {
        return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
    }
    Ok(bytes)
}

pub(super) fn remove(root: &Path, name: &str) -> Result<(), BootstrapFailure> {
    event(if name == CLAIM {
        BootstrapFileEvent::RemoveClaim
    } else {
        BootstrapFileEvent::RemovePending
    })?;
    fs::remove_file(root.join(name)).map_err(storage_failure)?;
    sync_directory(root)
}

pub(super) fn publish_initialized(root: &Path) -> Result<(), BootstrapFailure> {
    event(BootstrapFileEvent::PublishInitialized)?;
    fs::rename(root.join(INITIALIZED_TEMP), root.join(INITIALIZED)).map_err(storage_failure)?;
    sync_directory(root)
}

pub(super) fn exists(root: &Path, name: &str) -> bool {
    root.join(name).is_file()
}

fn sync_directory(root: &Path) -> Result<(), BootstrapFailure> {
    event(BootstrapFileEvent::SynchronizeDirectory)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(storage_failure)
}

fn storage_failure(_failure: std::io::Error) -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::StorageUnavailable)
}
