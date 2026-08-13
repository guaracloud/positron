use positron_kernel::{
    BootstrapArtifact, BootstrapArtifactAccess, BootstrapEntry, BootstrapKeyCustody,
    BootstrapObjectPurpose, BootstrapStorageFailure,
};

use super::codec::BootstrapRecord;
use super::{BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState};

pub(super) const INTENT: &[u8] = b"positron-bootstrap-in-progress-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BootstrapFileEvent {
    WritePending,
    WriteClaim,
    WriteInitialized,
    RemovePending,
    PublishInitialized,
    RemoveClaim,
    ReplacePendingAfterSync,
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
    let access = paths.storage.inspect().map_err(storage_failure)?;
    classify_with(&access)
}

pub(super) fn classify_with(
    access: &BootstrapArtifactAccess,
) -> Result<BootstrapState, BootstrapFailure> {
    let layout = access.layout().map_err(storage_failure)?;
    if layout.unknown_or_unsafe() {
        return Ok(BootstrapState::Inconsistent);
    }
    if layout.is_empty_instance() {
        return Ok(BootstrapState::Empty);
    }
    let has_key = layout.contains(BootstrapEntry::LocalKey);
    let has_pending = layout.contains(BootstrapEntry::Pending)
        || layout.contains(BootstrapEntry::PendingReplacement)
        || layout.contains(BootstrapEntry::InitializedStaging);
    let has_initialized = layout.contains(BootstrapEntry::Initialized);
    if has_initialized && has_pending {
        return Ok(BootstrapState::Inconsistent);
    }
    if has_initialized && has_key {
        let required_storage =
            layout.contains(BootstrapEntry::Catalog) && layout.contains(BootstrapEntry::Segments);
        return Ok(
            if required_storage
                && authenticated_record(
                    access,
                    BootstrapArtifact::Initialized,
                    BootstrapObjectPurpose::Initialized,
                )
            {
                BootstrapState::Initialized
            } else {
                BootstrapState::Inconsistent
            },
        );
    }
    if has_pending {
        if !has_key {
            let raw_intent_only = layout.has_at_most_staged_key()
                && layout.has_only_raw_pending_data()
                && access.read(BootstrapArtifact::Pending).ok().as_deref() == Some(INTENT);
            return Ok(if raw_intent_only {
                BootstrapState::Incomplete
            } else {
                BootstrapState::Inconsistent
            });
        }
        let has_replacement = layout.contains(BootstrapEntry::PendingReplacement);
        let replacement_valid = !has_replacement
            || (layout.contains(BootstrapEntry::Pending)
                && !layout.contains(BootstrapEntry::InitializedStaging)
                && access.read(BootstrapArtifact::Pending).ok().as_deref() == Some(INTENT)
                && authenticated_record(
                    access,
                    BootstrapArtifact::PendingReplacement,
                    BootstrapObjectPurpose::Pending,
                ));
        let pending_valid = has_replacement
            || !layout.contains(BootstrapEntry::Pending)
            || authenticated_record(
                access,
                BootstrapArtifact::Pending,
                BootstrapObjectPurpose::Pending,
            );
        let staged_valid = !layout.contains(BootstrapEntry::InitializedStaging)
            || authenticated_record(
                access,
                BootstrapArtifact::InitializedStaging,
                BootstrapObjectPurpose::Initialized,
            );
        return Ok(if replacement_valid && pending_valid && staged_valid {
            BootstrapState::Incomplete
        } else {
            BootstrapState::Inconsistent
        });
    }
    Ok(BootstrapState::Inconsistent)
}

fn authenticated_record(
    access: &BootstrapArtifactAccess,
    artifact: BootstrapArtifact,
    purpose: BootstrapObjectPurpose,
) -> bool {
    let Ok(key) = access.open_key() else {
        return false;
    };
    let Ok(encoded) = access.read(artifact) else {
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

pub(super) fn write_new(
    access: &BootstrapArtifactAccess,
    artifact: BootstrapArtifact,
    bytes: &[u8],
) -> Result<(), BootstrapFailure> {
    event(match artifact {
        BootstrapArtifact::Pending => BootstrapFileEvent::WritePending,
        BootstrapArtifact::PendingReplacement => BootstrapFileEvent::SynchronizeDirectory,
        BootstrapArtifact::Claim => BootstrapFileEvent::WriteClaim,
        BootstrapArtifact::InitializedStaging => BootstrapFileEvent::WriteInitialized,
        BootstrapArtifact::Initialized => BootstrapFileEvent::SynchronizeDirectory,
    })?;
    access.write_new(artifact, bytes).map_err(storage_failure)
}

pub(super) fn replace_pending(
    access: &BootstrapArtifactAccess,
    bytes: &[u8],
) -> Result<(), BootstrapFailure> {
    access
        .write_new(BootstrapArtifact::PendingReplacement, bytes)
        .map_err(storage_failure)?;
    event(BootstrapFileEvent::ReplacePendingAfterSync)?;
    access
        .publish_pending_replacement()
        .map_err(storage_failure)
}

pub(super) fn read(
    access: &BootstrapArtifactAccess,
    artifact: BootstrapArtifact,
) -> Result<Vec<u8>, BootstrapFailure> {
    access.read(artifact).map_err(storage_failure)
}

pub(super) fn remove(
    access: &BootstrapArtifactAccess,
    artifact: BootstrapArtifact,
) -> Result<(), BootstrapFailure> {
    event(if artifact == BootstrapArtifact::Claim {
        BootstrapFileEvent::RemoveClaim
    } else {
        BootstrapFileEvent::RemovePending
    })?;
    access.remove(artifact).map_err(storage_failure)
}

pub(super) fn publish_initialized(
    access: &BootstrapArtifactAccess,
) -> Result<(), BootstrapFailure> {
    event(BootstrapFileEvent::PublishInitialized)?;
    access.publish_initialized().map_err(storage_failure)
}

pub(super) fn exists(
    access: &BootstrapArtifactAccess,
    artifact: BootstrapArtifact,
) -> Result<bool, BootstrapFailure> {
    access.exists(artifact).map_err(storage_failure)
}

pub(super) fn storage_failure(failure: BootstrapStorageFailure) -> BootstrapFailure {
    let code = match failure {
        BootstrapStorageFailure::InvalidRoots => BootstrapFailureCode::InvalidRoots,
        BootstrapStorageFailure::BoundIdentityMismatch => BootstrapFailureCode::InconsistentRoots,
        BootstrapStorageFailure::UnsafeOrCorrupt | BootstrapStorageFailure::AlreadyExists => {
            BootstrapFailureCode::CorruptState
        },
        BootstrapStorageFailure::Unavailable => BootstrapFailureCode::StorageUnavailable,
    };
    BootstrapFailure::new(code)
}
