use positron_domain::identity::TenantId;
use positron_kernel::CatalogSnapshot;

use super::support::catalog_failure;
use crate::instance_bootstrap::{BootstrapFailure, BootstrapFailureCode};

pub(in crate::instance_bootstrap) fn activated_policy(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<positron_ingest::IngestPolicy, BootstrapFailure> {
    let mut activated = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(catalog_failure)?
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let Some(policy) = positron_ingest::IngestPolicy::decode_activated_object(tenant, bytes)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?
        else {
            continue;
        };
        if activated.replace(policy).is_some() {
            return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
        }
    }
    activated.map_or_else(
        || {
            positron_ingest::IngestPolicy::preserving(1)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
        },
        Ok,
    )
}
