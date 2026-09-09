use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope, TenantId};
use positron_domain::lifecycle::{TenantLifecycle, TenantLifecycleState};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    FormatEpoch, TransactionId,
};

use crate::audit::tenant_lifecycle_audit_intent;
use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, GovernanceAuditEntry, ResourceGeneration,
};

/// The result of one durably published tenant lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantLifecycleTransition {
    tenant: TenantId,
    from: TenantLifecycleState,
    to: TenantLifecycleState,
    generation: ResourceGeneration,
    audit_position: u64,
}

impl TenantLifecycleTransition {
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn from(self) -> TenantLifecycleState {
        self.from
    }
    #[must_use]
    pub const fn to(self) -> TenantLifecycleState {
        self.to
    }
    #[must_use]
    pub const fn resource_generation(self) -> ResourceGeneration {
        self.generation
    }
    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

/// Closed failures from the narrow lifecycle authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantLifecycleAdministrationFailure {
    Unauthorized,
    UnknownTenant,
    InvalidTransition,
    PurgeCompletionUnavailable,
    StaleGeneration,
    IdempotencyConflict,
    CapacityExceeded,
    PersistenceUnavailable,
}

impl Display for TenantLifecycleAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tenant lifecycle administration failed")
    }
}

impl Error for TenantLifecycleAdministrationFailure {}

/// Administration owns lifecycle meaning; Catalog remains the only publisher.
pub struct TenantLifecycleAdministration;

impl TenantLifecycleAdministration {
    pub fn transition(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        actor: AuthorizedContext,
        tenant: TenantId,
        target: TenantLifecycleState,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantLifecycleTransition, TenantLifecycleAdministrationFailure> {
        if actor.principal_id() != administrator
            || actor.scope() != Scope::SystemAdministration
            || actor.tenant_attribution().is_some()
        {
            return Err(TenantLifecycleAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if governance.tenant() != tenant {
            return Err(TenantLifecycleAdministrationFailure::UnknownTenant);
        }
        if let Some(replay) = replay(
            catalog,
            idempotency,
            actor.principal_id(),
            tenant,
            target,
            expected,
        )? {
            return Ok(replay);
        }
        let from = governance.lifecycle();
        if target == TenantLifecycleState::Purged {
            return Err(TenantLifecycleAdministrationFailure::PurgeCompletionUnavailable);
        }
        TenantLifecycle::from_durable_state(from)
            .transition_to(target)
            .map_err(|_| TenantLifecycleAdministrationFailure::InvalidTransition)?;
        let generation = next_generation(governance.lifecycle_generation(), expected)?;
        let replacement = governance
            .with_lifecycle(target, generation.get())
            .map_err(map_catalog)?;
        let audit = tenant_lifecycle_audit_intent(
            idempotency,
            actor.principal_id(),
            tenant,
            from,
            target,
            expected,
            generation,
        );
        let commit = commit(catalog, &snapshot, replacement, idempotency, audit)?;
        let record = commit
            .governance_audit_record()
            .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
        let entry = GovernanceAuditEntry::decode(record)
            .map_err(|_| TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
        let audit = entry
            .as_tenant_lifecycle()
            .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
        Ok(TenantLifecycleTransition {
            tenant,
            from,
            to: target,
            generation,
            audit_position: audit.position(),
        })
    }
}

fn replay(
    catalog: &Catalog<'_>,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    tenant: TenantId,
    target: TenantLifecycleState,
    expected: ResourceGeneration,
) -> Result<Option<TenantLifecycleTransition>, TenantLifecycleAdministrationFailure> {
    for record in catalog.governance_audit_records().map_err(map_catalog)? {
        if record.transaction().to_bytes() != idempotency.to_bytes() {
            continue;
        }
        let entry = GovernanceAuditEntry::decode(&record)
            .map_err(|_| TenantLifecycleAdministrationFailure::IdempotencyConflict)?;
        let lifecycle = entry
            .as_tenant_lifecycle()
            .ok_or(TenantLifecycleAdministrationFailure::IdempotencyConflict)?;
        if lifecycle.actor_id() != actor
            || lifecycle.tenant_id() != tenant
            || lifecycle.to() != target
            || lifecycle.expected_generation() != expected
        {
            return Err(TenantLifecycleAdministrationFailure::IdempotencyConflict);
        }
        return Ok(Some(TenantLifecycleTransition {
            tenant,
            from: lifecycle.from(),
            to: lifecycle.to(),
            generation: lifecycle.generation(),
            audit_position: lifecycle.position(),
        }));
    }
    Ok(None)
}

fn next_generation(
    current: u64,
    expected: ResourceGeneration,
) -> Result<ResourceGeneration, TenantLifecycleAdministrationFailure> {
    if current != expected.get() {
        return Err(TenantLifecycleAdministrationFailure::StaleGeneration);
    }
    expected
        .get()
        .checked_add(1)
        .ok_or(TenantLifecycleAdministrationFailure::CapacityExceeded)
        .and_then(|value| {
            ResourceGeneration::new(value)
                .map_err(|_| TenantLifecycleAdministrationFailure::CapacityExceeded)
        })
}

fn commit(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    replacement: Vec<u8>,
    idempotency: AdministrativeIdempotencyKey,
    audit: Vec<u8>,
) -> Result<positron_kernel::CatalogCommit, TenantLifecycleAdministrationFailure> {
    let mut objects = Vec::new();
    for object_id in snapshot.object_identities() {
        let bytes = snapshot
            .object(object_id)
            .map_err(map_catalog)?
            .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(b"POSGOV") {
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
        }
    }
    objects.push(CatalogObject::new(replacement).map_err(map_catalog)?);
    let proposal = CatalogProposal::new(
        TransactionId::new(idempotency.to_bytes()).map_err(map_catalog)?,
        FormatEpoch::CATALOG_V1,
        objects,
    )
    .map_err(map_catalog)?;
    catalog
        .commit(
            snapshot.identity(),
            proposal,
            Some(AuditIntent::new(audit).map_err(map_catalog)?),
        )
        .map_err(map_catalog)
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> TenantLifecycleAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::StaleGeneration => {
            TenantLifecycleAdministrationFailure::StaleGeneration
        },
        CatalogFailureCode::IdempotencyConflict => {
            TenantLifecycleAdministrationFailure::IdempotencyConflict
        },
        CatalogFailureCode::LimitExceeded | CatalogFailureCode::ResourceAdmissionRefused => {
            TenantLifecycleAdministrationFailure::CapacityExceeded
        },
        CatalogFailureCode::StorageUnavailable
        | CatalogFailureCode::ConcurrentWriter
        | CatalogFailureCode::InvalidInput
        | CatalogFailureCode::IntegrityCorruption
        | CatalogFailureCode::AuthenticationFailed
        | CatalogFailureCode::UnsupportedFormat => {
            TenantLifecycleAdministrationFailure::PersistenceUnavailable
        },
    }
}
