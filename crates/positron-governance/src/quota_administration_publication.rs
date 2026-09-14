use positron_domain::identity::TenantId;
use positron_kernel::{
    Catalog, CatalogFailure, CatalogFailureCode, CatalogObject, CatalogObjectId, CatalogSnapshot,
    TransactionId,
};

use super::{
    TenantQuotaAdministrationFailure, TenantQuotaAdministrationFailureCode,
    TenantQuotaUpdateRequest, corrupt, map_catalog, map_tenant_quota_record_failure,
};
use crate::tenant_quota_record::{TenantQuotaState, tenant_quota_state};
use crate::{AdministrativeIdempotencyKey, ResourceGeneration};

pub(super) fn default_tenant_successor(
    snapshot: &CatalogSnapshot,
    request: TenantQuotaUpdateRequest,
    generation: ResourceGeneration,
) -> Result<Vec<CatalogObject>, TenantQuotaAdministrationFailure> {
    let (governance_id, governance) = snapshot.governance_object().map_err(map_catalog)?;
    if governance.tenant() != request.tenant {
        return Err(TenantQuotaAdministrationFailure::new(
            TenantQuotaAdministrationFailureCode::Unauthorized,
        ));
    }
    if governance.quota_generation() != request.expected.get() {
        return Err(TenantQuotaAdministrationFailure::stale(
            TenantQuotaState {
                generation: ResourceGeneration::new(governance.quota_generation())
                    .map_err(|_| corrupt())?,
                weight: governance.quota_weight(),
                resources: governance.quota_resources(),
            },
            request,
        ));
    }
    let mut objects = retained_objects(snapshot, governance_id)?;
    let successor = governance
        .with_quota(generation.get(), request.weight, request.resources)
        .map_err(map_catalog)?;
    objects.try_reserve(1).map_err(|_| {
        TenantQuotaAdministrationFailure::new(
            TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
        )
    })?;
    objects.push(CatalogObject::new(successor).map_err(map_catalog)?);
    Ok(objects)
}

pub(super) fn retained_objects(
    snapshot: &CatalogSnapshot,
    governance: CatalogObjectId,
) -> Result<Vec<CatalogObject>, TenantQuotaAdministrationFailure> {
    let mut objects = Vec::new();
    for identity in snapshot.object_identities() {
        if identity == governance {
            continue;
        }
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or_else(corrupt)?;
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
    }
    Ok(objects)
}

pub(super) fn audit_position(
    catalog: &Catalog<'_>,
    key: AdministrativeIdempotencyKey,
) -> Result<u64, TenantQuotaAdministrationFailure> {
    let transaction = TransactionId::new(key.to_bytes()).map_err(map_catalog)?;
    catalog
        .governance_audit_records()
        .map_err(map_catalog)?
        .into_iter()
        .find(|record| record.transaction() == transaction)
        .map(|record| record.position())
        .ok_or_else(corrupt)
}

pub(super) fn map_commit_failure(
    catalog: &Catalog<'_>,
    tenant: TenantId,
    failure: CatalogFailure,
) -> TenantQuotaAdministrationFailure {
    if failure.code() != CatalogFailureCode::StaleGeneration {
        return map_catalog(failure);
    }
    let current =
        catalog.pin().map_err(map_catalog).and_then(|snapshot| {
            match tenant_quota_state(&snapshot, tenant).map_err(map_tenant_quota_record_failure)? {
                Some(state) => Ok(state.generation),
                None => {
                    let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
                    if governance.tenant() != tenant {
                        return Err(TenantQuotaAdministrationFailure::new(
                            TenantQuotaAdministrationFailureCode::Unauthorized,
                        ));
                    }
                    ResourceGeneration::new(governance.quota_generation()).map_err(|_| corrupt())
                },
            }
        });
    match current {
        Ok(generation) => TenantQuotaAdministrationFailure::stale_generation(generation),
        Err(failure) => failure,
    }
}
