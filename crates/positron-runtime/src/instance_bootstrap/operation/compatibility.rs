use positron_domain::identity::PrincipalId;
use positron_kernel::{
    BootstrapArtifactAccess, BootstrapKeyCustody, BootstrapObjectPurpose, Catalog,
};
use zeroize::Zeroizing;

use super::super::codec::{BootstrapIngestIdentity, BootstrapQueryIdentity, BootstrapRecord};
use super::super::storage;
use super::super::{BootstrapFailure, BootstrapFailureCode};
use super::support::{entropy_failure, key_failure};

pub(super) fn migrate_pending_v1(
    access: &BootstrapArtifactAccess,
    key: &BootstrapKeyCustody,
    catalog: &Catalog<'_>,
    record: &mut BootstrapRecord,
) -> Result<(), BootstrapFailure> {
    if (record.ingest.is_some() && record.query.is_some())
        || catalog
            .pin()
            .map_err(super::support::catalog_failure)?
            .number()
            != 0
    {
        return Ok(());
    }
    if record.ingest.is_none() {
        let principal = PrincipalId::from_bytes(key.random_identifier().map_err(key_failure)?)
            .map_err(|_| entropy_failure())?;
        let salt = key.random_secret().map_err(key_failure)?;
        let secret = key.random_secret().map_err(key_failure)?;
        let hash = key
            .salted_secret_hash(salt.as_ref(), secret.as_ref())
            .map_err(key_failure)?;
        record.ingest = Some(BootstrapIngestIdentity {
            principal,
            api_key_salt: *salt,
            api_key_hash: hash,
            api_key_secret: Some(Zeroizing::new(*secret)),
        });
    }
    if record.query.is_none() {
        let principal = PrincipalId::from_bytes(key.random_identifier().map_err(key_failure)?)
            .map_err(|_| entropy_failure())?;
        let salt = key.random_secret().map_err(key_failure)?;
        let secret = key.random_secret().map_err(key_failure)?;
        let hash = key
            .salted_secret_hash(salt.as_ref(), secret.as_ref())
            .map_err(key_failure)?;
        record.query = Some(BootstrapQueryIdentity {
            principal,
            api_key_salt: *salt,
            api_key_hash: hash,
            api_key_secret: Some(Zeroizing::new(*secret)),
        });
    }
    let protected = key
        .protect(
            record.instance,
            BootstrapObjectPurpose::Pending,
            &record.encode(),
        )
        .map_err(key_failure)?;
    storage::replace_pending(access, &protected)
}

pub(super) fn require_new_query(
    record: &BootstrapRecord,
) -> Result<&BootstrapQueryIdentity, BootstrapFailure> {
    record
        .query
        .as_ref()
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
}

pub(super) fn require_new_ingest(
    record: &BootstrapRecord,
) -> Result<&BootstrapIngestIdentity, BootstrapFailure> {
    record
        .ingest
        .as_ref()
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
}
