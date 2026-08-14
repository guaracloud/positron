use positron_kernel::{BootstrapArtifact, BootstrapArtifactAccess, BootstrapObjectPurpose};

use super::support::{decode_record, inconsistent, key_failure, require_key_identity};
use crate::instance_bootstrap::{
    BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState, storage,
};

pub(in crate::instance_bootstrap) fn classify(
    paths: &BootstrapPaths,
) -> Result<BootstrapState, BootstrapFailure> {
    let access = paths.storage.inspect().map_err(storage::storage_failure)?;
    let state = storage::classify_with(&access)?;
    if state != BootstrapState::Initialized {
        return Ok(state);
    }
    match validate_initialized(&access) {
        Ok(()) => Ok(BootstrapState::Initialized),
        Err(failure)
            if matches!(
                failure.code(),
                BootstrapFailureCode::CorruptState | BootstrapFailureCode::IdentityMismatch
            ) =>
        {
            Ok(BootstrapState::Inconsistent)
        },
        Err(failure) => Err(failure),
    }
}

fn validate_initialized(access: &BootstrapArtifactAccess) -> Result<(), BootstrapFailure> {
    if storage::classify_with(access)? != BootstrapState::Initialized {
        return Err(inconsistent());
    }
    let key = access.open_key().map_err(key_failure)?;
    let encoded = storage::read(access, BootstrapArtifact::Initialized)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &encoded)?;
    require_key_identity(&record, key.identity())?;
    let generation = access
        .inspect_catalog(
            record.instance,
            key.catalog_secret(record.instance).map_err(key_failure)?,
        )
        .map_err(storage::storage_failure)?;
    if generation == 0 {
        return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
    }
    Ok(())
}
