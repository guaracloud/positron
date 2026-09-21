use positron_kernel::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, ResourceAmounts,
    StorageKernelResourceAuthority, TransactionId,
};

use super::quota_administration_publication::{
    audit_position, default_tenant_successor, map_commit_failure,
};
use super::quota_administration_receipt::{
    AUDIT_MAGIC, QuotaSemantics, RECEIPT_MAGIC, encode, find_receipt, request_digest,
};
use super::{
    TenantQuotaAdministration, TenantQuotaAdministrationFailure,
    TenantQuotaAdministrationFailureCode, TenantQuotaUpdate, TenantQuotaUpdateRequest, map_catalog,
    map_tenant_quota_record_failure,
};
use crate::tenant_quota_record::{
    TenantQuotaState, replace_tenant_quota_record, tenant_quota_state,
};
use crate::{Identity, ResourceGeneration};

impl TenantQuotaAdministration {
    pub fn update(
        catalog: &Catalog<'_>,
        authority: &StorageKernelResourceAuthority,
        identity: &Identity,
        request: TenantQuotaUpdateRequest,
    ) -> Result<TenantQuotaUpdate, TenantQuotaAdministrationFailure> {
        let principal = identity
            .authorize_quota_update(request.actor, request.tenant)
            .map_err(|_| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::Unauthorized,
                )
            })?;
        if request.weight == 0
            || request.weight > u32::from(u16::MAX)
            || request.resources.contains(&0)
        {
            return Err(TenantQuotaAdministrationFailure::new(
                TenantQuotaAdministrationFailureCode::InvalidInput,
            ));
        }
        let weight = u16::try_from(request.weight).map_err(|_| {
            TenantQuotaAdministrationFailure::new(
                TenantQuotaAdministrationFailureCode::InvalidInput,
            )
        })?;
        authority
            .validate_tenant_quota(weight, ResourceAmounts::new(request.resources))
            .map_err(|_| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::InvalidInput,
                )
            })?;
        let generation =
            ResourceGeneration::new(request.expected.get().checked_add(1).ok_or_else(|| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::InvalidInput,
                )
            })?)
            .map_err(|_| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::InvalidInput,
                )
            })?;
        let request_digest = request_digest(
            request.key,
            principal,
            request.tenant,
            request.expected,
            generation,
            request.weight,
            request.resources,
        );
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(receipt) = find_receipt(&snapshot, request.key)? {
            if receipt.principal != principal
                || receipt.tenant != request.tenant
                || receipt.expected != request.expected
                || receipt.generation != generation
                || receipt.weight != request.weight
                || receipt.resources != request.resources
                || receipt.request_digest != request_digest
            {
                return Err(TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::IdempotencyConflict,
                ));
            }
            let current = tenant_quota_state(&snapshot, request.tenant)
                .map_err(map_tenant_quota_record_failure)?;
            if current.is_some_and(|current| {
                current.generation == receipt.generation
                    && current.weight == receipt.weight
                    && current.resources == receipt.resources
            }) {
                authority
                    .prepare_tenant_quota_update(
                        request.tenant,
                        weight,
                        ResourceAmounts::new(request.resources),
                    )
                    .map_err(|_| {
                        TenantQuotaAdministrationFailure::new(
                            TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
                        )
                    })?
                    .publish();
            }
            return Ok(TenantQuotaUpdate {
                generation,
                audit_position: if receipt.audit_position == 0 {
                    audit_position(catalog, request.key)?
                } else {
                    receipt.audit_position
                },
            });
        }
        let mut objects = match tenant_quota_state(&snapshot, request.tenant)
            .map_err(map_tenant_quota_record_failure)?
        {
            Some(current) => {
                if current.generation != request.expected {
                    return Err(TenantQuotaAdministrationFailure::stale(current, request));
                }
                replace_tenant_quota_record(
                    &snapshot,
                    request.tenant,
                    TenantQuotaState {
                        generation,
                        weight: request.weight,
                        resources: request.resources,
                    },
                )
                .map_err(map_tenant_quota_record_failure)?
            },
            None => default_tenant_successor(&snapshot, request, generation)?,
        };
        objects.try_reserve(1).map_err(|_| {
            TenantQuotaAdministrationFailure::new(
                TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
            )
        })?;
        let semantics = QuotaSemantics {
            key: request.key,
            principal,
            tenant: request.tenant,
            expected: request.expected,
            generation,
            weight: request.weight,
            resources: request.resources,
            request_digest,
            audit_position: snapshot
                .governance_audit_frontier()
                .checked_add(1)
                .ok_or_else(|| {
                    TenantQuotaAdministrationFailure::new(
                        TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
                    )
                })?,
        };
        objects.push(CatalogObject::new(encode(RECEIPT_MAGIC, semantics)).map_err(map_catalog)?);
        let staged = authority
            .prepare_tenant_quota_update(
                request.tenant,
                weight,
                ResourceAmounts::new(request.resources),
            )
            .map_err(|_| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
                )
            })?;
        let commit = catalog
            .commit(
                snapshot.identity(),
                CatalogProposal::new(
                    TransactionId::new(request.key.to_bytes()).map_err(map_catalog)?,
                    snapshot.format_epoch().ok_or_else(|| {
                        TenantQuotaAdministrationFailure::new(
                            TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
                        )
                    })?,
                    objects,
                )
                .map_err(map_catalog)?,
                Some(AuditIntent::new(encode(AUDIT_MAGIC, semantics)).map_err(map_catalog)?),
            )
            .map_err(|failure| map_commit_failure(catalog, request.tenant, failure))?;
        let audit_position = commit
            .governance_audit_record()
            .ok_or_else(|| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
                )
            })?
            .position();
        if audit_position != semantics.audit_position {
            return Err(TenantQuotaAdministrationFailure::new(
                TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
            ));
        }
        staged.publish();
        Ok(TenantQuotaUpdate {
            generation,
            audit_position,
        })
    }
}
