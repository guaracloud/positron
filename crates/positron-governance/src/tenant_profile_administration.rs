use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::TenantId;
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    TransactionId,
};
use sha2::{Digest, Sha256};

use crate::tenant_quota_record::{
    TenantProfileState, replace_tenant_profile_record, tenant_profile_state,
};
use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, GovernanceAuditEntry, Identity,
    ResourceGeneration, TenantAdministrationFailure,
};

pub(crate) const TENANT_DISPLAY_MAGIC: [u8; 8] = *b"POSTDP01";

/// A successful, redacted display-name successor publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantDisplayNameUpdate {
    generation: ResourceGeneration,
    audit_position: u64,
}

impl TenantDisplayNameUpdate {
    #[must_use]
    pub const fn resource_generation(self) -> ResourceGeneration {
        self.generation
    }

    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

/// One authenticated, generation-pinned display-name mutation.
#[derive(Clone)]
pub struct TenantDisplayNameUpdateRequest {
    actor: AuthorizedContext,
    tenant: TenantId,
    expected: ResourceGeneration,
    display_name: String,
    idempotency: AdministrativeIdempotencyKey,
}

impl TenantDisplayNameUpdateRequest {
    #[must_use]
    pub fn new(
        actor: AuthorizedContext,
        tenant: TenantId,
        expected: ResourceGeneration,
        display_name: &str,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            tenant,
            expected,
            display_name: display_name.to_owned(),
            idempotency,
        }
    }
}

/// Redacted current display-generation returned for a stale mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantDisplayGenerationConflict {
    current_generation: ResourceGeneration,
    display_name_changed: bool,
}

impl TenantDisplayGenerationConflict {
    #[must_use]
    pub const fn current_generation(self) -> ResourceGeneration {
        self.current_generation
    }

    /// Renders only the field name; neither current nor requested label is
    /// exposed by an optimistic-concurrency conflict.
    #[must_use]
    pub const fn semantic_diff(self) -> &'static str {
        if self.display_name_changed {
            "display_name"
        } else {
            "display_generation"
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantProfileAdministrationFailureCode {
    InvalidInput,
    Unauthorized,
    UnknownTenant,
    StaleDisplayGeneration,
    IdempotencyConflict,
    PersistenceUnavailable,
}

#[derive(Debug)]
pub struct TenantProfileAdministrationFailure {
    code: TenantProfileAdministrationFailureCode,
    conflict: Option<TenantDisplayGenerationConflict>,
}

impl TenantProfileAdministrationFailure {
    const fn new(code: TenantProfileAdministrationFailureCode) -> Self {
        Self {
            code,
            conflict: None,
        }
    }

    fn stale(
        current_generation: ResourceGeneration,
        current_display_name: &str,
        requested_display_name: &str,
    ) -> Self {
        Self {
            code: TenantProfileAdministrationFailureCode::StaleDisplayGeneration,
            conflict: Some(TenantDisplayGenerationConflict {
                current_generation,
                display_name_changed: current_display_name != requested_display_name,
            }),
        }
    }

    #[must_use]
    pub const fn code(&self) -> TenantProfileAdministrationFailureCode {
        self.code
    }

    #[must_use]
    pub const fn generation_conflict(&self) -> Option<TenantDisplayGenerationConflict> {
        self.conflict
    }
}

impl Display for TenantProfileAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tenant profile administration failed")
    }
}

impl Error for TenantProfileAdministrationFailure {}

/// Administration owns display-name meaning while Catalog publishes one atomic
/// replacement of the tenant's canonical authority and audit evidence.
pub struct TenantProfileAdministration;

impl TenantProfileAdministration {
    pub fn update_display_name(
        catalog: &Catalog<'_>,
        identity: &Identity,
        request: TenantDisplayNameUpdateRequest,
    ) -> Result<TenantDisplayNameUpdate, TenantProfileAdministrationFailure> {
        if request.display_name.is_empty() || request.display_name.len() > 128 {
            return Err(TenantProfileAdministrationFailure::new(
                TenantProfileAdministrationFailureCode::InvalidInput,
            ));
        }
        let principal = identity
            .authorize_policy_activation(request.actor, request.tenant)
            .map_err(|_| {
                TenantProfileAdministrationFailure::new(
                    TenantProfileAdministrationFailureCode::Unauthorized,
                )
            })?;
        let successor = request
            .expected
            .get()
            .checked_add(1)
            .and_then(|generation| ResourceGeneration::new(generation).ok())
            .ok_or_else(|| {
                TenantProfileAdministrationFailure::new(
                    TenantProfileAdministrationFailureCode::InvalidInput,
                )
            })?;
        let digest = request_digest(principal, &request, successor);
        if let Some(replay) = replay(catalog, principal, &request, successor, digest)? {
            return Ok(replay);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (governance_id, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let objects = if governance.tenant() == request.tenant {
            let current =
                ResourceGeneration::new(governance.display_generation()).map_err(|_| {
                    TenantProfileAdministrationFailure::new(
                        TenantProfileAdministrationFailureCode::PersistenceUnavailable,
                    )
                })?;
            if current != request.expected {
                return Err(TenantProfileAdministrationFailure::stale(
                    current,
                    governance.display_name(),
                    &request.display_name,
                ));
            }
            let mut objects = retained_objects(&snapshot, governance_id)?;
            objects.try_reserve(1).map_err(|_| unavailable())?;
            objects.push(
                CatalogObject::new(
                    governance
                        .with_display_name(&request.display_name, successor.get())
                        .map_err(map_catalog)?,
                )
                .map_err(map_catalog)?,
            );
            objects
        } else {
            let current = tenant_profile_state(&snapshot, request.tenant)
                .map_err(map_record)?
                .ok_or_else(|| {
                    TenantProfileAdministrationFailure::new(
                        TenantProfileAdministrationFailureCode::UnknownTenant,
                    )
                })?;
            if current.display_generation != request.expected {
                return Err(TenantProfileAdministrationFailure::stale(
                    current.display_generation,
                    &current.display_name,
                    &request.display_name,
                ));
            }
            replace_tenant_profile_record(
                &snapshot,
                request.tenant,
                &TenantProfileState {
                    display_name: request.display_name.clone(),
                    display_generation: successor,
                    retention_seconds: current.retention_seconds,
                    retention_generation: current.retention_generation,
                },
            )
            .map_err(map_record)?
        };
        let audit = encode_audit(principal, &request, successor, digest);
        let commit = catalog
            .commit(
                snapshot.identity(),
                CatalogProposal::new(
                    TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?,
                    snapshot.format_epoch().ok_or_else(unavailable)?,
                    objects,
                )
                .map_err(map_catalog)?,
                Some(AuditIntent::new(audit).map_err(map_catalog)?),
            )
            .map_err(map_catalog)?;
        Ok(TenantDisplayNameUpdate {
            generation: successor,
            audit_position: commit
                .governance_audit_record()
                .ok_or_else(unavailable)?
                .position(),
        })
    }
}

fn replay(
    catalog: &Catalog<'_>,
    principal: positron_domain::identity::PrincipalId,
    request: &TenantDisplayNameUpdateRequest,
    successor: ResourceGeneration,
    digest: [u8; 32],
) -> Result<Option<TenantDisplayNameUpdate>, TenantProfileAdministrationFailure> {
    for record in catalog.governance_audit_records().map_err(map_catalog)? {
        if record.transaction().to_bytes() != request.idempotency.to_bytes() {
            continue;
        }
        let entry = GovernanceAuditEntry::decode(&record).map_err(|_| {
            TenantProfileAdministrationFailure::new(
                TenantProfileAdministrationFailureCode::IdempotencyConflict,
            )
        })?;
        let display = entry.as_tenant_display_name_update().ok_or_else(|| {
            TenantProfileAdministrationFailure::new(
                TenantProfileAdministrationFailureCode::IdempotencyConflict,
            )
        })?;
        if display.principal_id() != principal
            || display.tenant_id() != request.tenant
            || display.expected_generation() != request.expected
            || display.generation() != successor
            || display.request_digest() != digest
        {
            return Err(TenantProfileAdministrationFailure::new(
                TenantProfileAdministrationFailureCode::IdempotencyConflict,
            ));
        }
        return Ok(Some(TenantDisplayNameUpdate {
            generation: successor,
            audit_position: display.position(),
        }));
    }
    Ok(None)
}

fn retained_objects(
    snapshot: &CatalogSnapshot,
    governance: positron_kernel::CatalogObjectId,
) -> Result<Vec<CatalogObject>, TenantProfileAdministrationFailure> {
    let mut objects = Vec::new();
    for object_id in snapshot.object_identities() {
        if object_id == governance {
            continue;
        }
        let bytes = snapshot
            .object(object_id)
            .map_err(map_catalog)?
            .ok_or_else(unavailable)?;
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
    }
    Ok(objects)
}

fn request_digest(
    principal: positron_domain::identity::PrincipalId,
    request: &TenantDisplayNameUpdateRequest,
    successor: ResourceGeneration,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.tenant-display-name.update.request.v1\0");
    hash.update(request.idempotency.to_bytes());
    hash.update(principal.to_bytes());
    hash.update(request.tenant.to_bytes());
    hash.update(request.expected.get().to_be_bytes());
    hash.update(successor.get().to_be_bytes());
    hash.update(request.display_name.as_bytes());
    hash.finalize().into()
}

fn encode_audit(
    principal: positron_domain::identity::PrincipalId,
    request: &TenantDisplayNameUpdateRequest,
    successor: ResourceGeneration,
    digest: [u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(104);
    bytes.extend_from_slice(&TENANT_DISPLAY_MAGIC);
    bytes.extend_from_slice(&request.idempotency.to_bytes());
    bytes.extend_from_slice(&principal.to_bytes());
    bytes.extend_from_slice(&request.tenant.to_bytes());
    bytes.extend_from_slice(&request.expected.get().to_be_bytes());
    bytes.extend_from_slice(&successor.get().to_be_bytes());
    bytes.extend_from_slice(&digest);
    bytes
}

const fn unavailable() -> TenantProfileAdministrationFailure {
    TenantProfileAdministrationFailure::new(
        TenantProfileAdministrationFailureCode::PersistenceUnavailable,
    )
}

fn map_record(failure: TenantAdministrationFailure) -> TenantProfileAdministrationFailure {
    match failure {
        TenantAdministrationFailure::Unauthorized => TenantProfileAdministrationFailure::new(
            TenantProfileAdministrationFailureCode::UnknownTenant,
        ),
        TenantAdministrationFailure::InvalidInput
        | TenantAdministrationFailure::DuplicateTenant
        | TenantAdministrationFailure::StaleGeneration
        | TenantAdministrationFailure::IdempotencyConflict
        | TenantAdministrationFailure::PersistenceUnavailable => unavailable(),
    }
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> TenantProfileAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::IdempotencyConflict => TenantProfileAdministrationFailure::new(
            TenantProfileAdministrationFailureCode::IdempotencyConflict,
        ),
        _ => unavailable(),
    }
}
