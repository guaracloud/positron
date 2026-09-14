use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope, TenantId};
use positron_domain::lifecycle::{TenantLifecycle, TenantLifecycleState};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogReadView,
    CatalogSnapshot, GovernanceAuditRecord, PreparedTransactionResolution, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::audit::TenantLifecycleAuditIntent;
use crate::tenant_quota_record::{
    TenantLifecycleRecord, replace_tenant_lifecycle_record, tenant_lifecycle_record,
};
use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, GovernanceAuditEntry, ResourceGeneration,
    TenantAdministration,
};

/// The result of one durably published tenant lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantLifecycleTransition {
    tenant: TenantId,
    from: TenantLifecycleState,
    to: TenantLifecycleState,
    generation: ResourceGeneration,
    audit_position: u64,
    audit_ingest_time_unix_seconds: u64,
}

/// One authenticated, generation-checked lifecycle publication request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantLifecycleTransitionRequest {
    actor: AuthorizedContext,
    tenant: TenantId,
    target: TenantLifecycleState,
    expected: ResourceGeneration,
    idempotency: AdministrativeIdempotencyKey,
}

impl TenantLifecycleTransitionRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        tenant: TenantId,
        target: TenantLifecycleState,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            tenant,
            target,
            expected,
            idempotency,
        }
    }
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
    #[must_use]
    pub const fn audit_ingest_time_unix_seconds(self) -> u64 {
        self.audit_ingest_time_unix_seconds
    }
}

/// Redacted state supplied with an optimistic lifecycle-generation conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantLifecycleGenerationConflict {
    current_generation: ResourceGeneration,
    current_state: TenantLifecycleState,
}

impl TenantLifecycleGenerationConflict {
    #[must_use]
    pub const fn current_generation(self) -> ResourceGeneration {
        self.current_generation
    }
    #[must_use]
    pub const fn current_state(self) -> TenantLifecycleState {
        self.current_state
    }
}

/// Closed failures from the narrow lifecycle authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantLifecycleAdministrationFailure {
    Unauthorized,
    UnknownTenant,
    InvalidTransition,
    PurgeCompletionUnavailable,
    StaleGeneration(TenantLifecycleGenerationConflict),
    IdempotencyConflict,
    CapacityExceeded,
    TimeUnavailable,
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
    /// Resolves an exact committed retry before callers acquire fresh work barriers.
    pub fn replay(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        request: TenantLifecycleTransitionRequest,
    ) -> Result<Option<TenantLifecycleTransition>, TenantLifecycleAdministrationFailure> {
        validate_request(catalog, administrator, request)?;
        replay(catalog, request)
    }

    /// Resolves an exact committed retry from one immutable read-only Catalog
    /// view, before a caller acquires any lifecycle drain or writer lease.
    pub fn replay_from_view(
        view: &CatalogReadView,
        administrator: PrincipalId,
        request: TenantLifecycleTransitionRequest,
    ) -> Result<Option<TenantLifecycleTransition>, TenantLifecycleAdministrationFailure> {
        validate_snapshot(view.snapshot().clone(), administrator, request)?;
        replay_records(view.governance_audit_records(), request)
    }

    /// Validates a non-replay transition against one pinned read-only Catalog
    /// view before callers close data-plane admission.
    ///
    /// Callers must resolve an exact committed replay first, then open the
    /// Catalog Writer and call [`Self::transition`] after the required drain.
    /// The writer path repeats this validation against its current snapshot.
    pub fn preflight_from_view(
        view: &CatalogReadView,
        administrator: PrincipalId,
        request: TenantLifecycleTransitionRequest,
    ) -> Result<(), TenantLifecycleAdministrationFailure> {
        let snapshot = validate_snapshot(view.snapshot().clone(), administrator, request)?;
        validate_lifecycle_transition(&snapshot, request)
    }

    pub fn transition<F>(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        request: TenantLifecycleTransitionRequest,
        audit_time: F,
    ) -> Result<TenantLifecycleTransition, TenantLifecycleAdministrationFailure>
    where
        F: FnOnce() -> Result<u64, TenantLifecycleAdministrationFailure>,
    {
        let snapshot = validate_request(catalog, administrator, request)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if let Some(replay) = replay(catalog, request)? {
            return Ok(replay);
        }
        if let Some(resumed) = resume_prepared(catalog, request)? {
            return Ok(resumed);
        }
        if request.tenant != governance.tenant() {
            return transition_secondary(catalog, &snapshot, request, audit_time);
        }
        let audit_ingest_time_unix_seconds = audit_time()?;
        if audit_ingest_time_unix_seconds == 0 {
            return Err(TenantLifecycleAdministrationFailure::PersistenceUnavailable);
        }
        let from = governance.lifecycle();
        if request.target == TenantLifecycleState::Purged {
            return Err(TenantLifecycleAdministrationFailure::PurgeCompletionUnavailable);
        }
        let generation =
            next_generation(governance.lifecycle_generation(), from, request.expected)?;
        TenantLifecycle::from_durable_state(from)
            .transition_to(request.target)
            .map_err(|_| TenantLifecycleAdministrationFailure::InvalidTransition)?;
        let replacement = governance
            .with_lifecycle(request.target, generation.get())
            .map_err(map_catalog)?;
        let audit = TenantLifecycleAuditIntent {
            ingest_time_unix_seconds: audit_ingest_time_unix_seconds,
            idempotency_key: request.idempotency,
            actor: request.actor.principal_id(),
            tenant: request.tenant,
            from,
            to: request.target,
            expected_generation: request.expected,
            generation,
            request_digest: request_digest(request),
        }
        .encode();
        let commit = commit(catalog, &snapshot, replacement, request, audit)?;
        let record = commit
            .governance_audit_record()
            .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
        let entry = GovernanceAuditEntry::decode(record)
            .map_err(|_| TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
        let audit = entry
            .as_tenant_lifecycle()
            .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
        Ok(TenantLifecycleTransition {
            tenant: request.tenant,
            from,
            to: request.target,
            generation,
            audit_position: audit.position(),
            audit_ingest_time_unix_seconds: audit.ingest_time_unix_seconds(),
        })
    }
}

fn transition_secondary<F>(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    request: TenantLifecycleTransitionRequest,
    audit_time: F,
) -> Result<TenantLifecycleTransition, TenantLifecycleAdministrationFailure>
where
    F: FnOnce() -> Result<u64, TenantLifecycleAdministrationFailure>,
{
    let current = tenant_lifecycle_record(snapshot, request.tenant)
        .map_err(map_tenant_record_failure)?
        .ok_or(TenantLifecycleAdministrationFailure::UnknownTenant)?;
    let audit_ingest_time_unix_seconds = audit_time()?;
    if audit_ingest_time_unix_seconds == 0 {
        return Err(TenantLifecycleAdministrationFailure::PersistenceUnavailable);
    }
    if request.target == TenantLifecycleState::Purged {
        return Err(TenantLifecycleAdministrationFailure::PurgeCompletionUnavailable);
    }
    let generation = next_generation(current.generation.get(), current.state, request.expected)?;
    TenantLifecycle::from_durable_state(current.state)
        .transition_to(request.target)
        .map_err(|_| TenantLifecycleAdministrationFailure::InvalidTransition)?;
    let objects = replace_tenant_lifecycle_record(
        snapshot,
        request.tenant,
        TenantLifecycleRecord {
            generation,
            state: request.target,
        },
    )
    .map_err(map_tenant_record_failure)?;
    let audit = TenantLifecycleAuditIntent {
        ingest_time_unix_seconds: audit_ingest_time_unix_seconds,
        idempotency_key: request.idempotency,
        actor: request.actor.principal_id(),
        tenant: request.tenant,
        from: current.state,
        to: request.target,
        expected_generation: request.expected,
        generation,
        request_digest: request_digest(request),
    }
    .encode();
    let commit = commit_objects(catalog, snapshot, objects, request, audit)?;
    transition_from_commit(
        commit,
        request.tenant,
        current.state,
        request.target,
        generation,
    )
}

fn transition_from_commit(
    commit: positron_kernel::CatalogCommit,
    tenant: TenantId,
    from: TenantLifecycleState,
    to: TenantLifecycleState,
    generation: ResourceGeneration,
) -> Result<TenantLifecycleTransition, TenantLifecycleAdministrationFailure> {
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
        to,
        generation,
        audit_position: audit.position(),
        audit_ingest_time_unix_seconds: audit.ingest_time_unix_seconds(),
    })
}

fn validate_request(
    catalog: &Catalog<'_>,
    administrator: PrincipalId,
    request: TenantLifecycleTransitionRequest,
) -> Result<CatalogSnapshot, TenantLifecycleAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    validate_snapshot(snapshot, administrator, request)
}

fn validate_snapshot(
    snapshot: CatalogSnapshot,
    administrator: PrincipalId,
    request: TenantLifecycleTransitionRequest,
) -> Result<CatalogSnapshot, TenantLifecycleAdministrationFailure> {
    if request.actor.principal_id() != administrator
        || request.actor.scope() != Scope::SystemAdministration
        || request.actor.tenant_attribution().is_some()
    {
        return Err(TenantLifecycleAdministrationFailure::Unauthorized);
    }
    let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
    if governance.tenant() != request.tenant
        && !TenantAdministration::registered_tenant_ids(&snapshot)
            .map_err(map_tenant_record_failure)?
            .contains(&request.tenant)
    {
        return Err(TenantLifecycleAdministrationFailure::UnknownTenant);
    }
    Ok(snapshot)
}

fn validate_lifecycle_transition(
    snapshot: &CatalogSnapshot,
    request: TenantLifecycleTransitionRequest,
) -> Result<(), TenantLifecycleAdministrationFailure> {
    let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
    let (generation, state) = if request.tenant == governance.tenant() {
        (governance.lifecycle_generation(), governance.lifecycle())
    } else {
        let current = tenant_lifecycle_record(snapshot, request.tenant)
            .map_err(map_tenant_record_failure)?
            .ok_or(TenantLifecycleAdministrationFailure::UnknownTenant)?;
        (current.generation.get(), current.state)
    };
    if request.target == TenantLifecycleState::Purged {
        return Err(TenantLifecycleAdministrationFailure::PurgeCompletionUnavailable);
    }
    next_generation(generation, state, request.expected)?;
    TenantLifecycle::from_durable_state(state)
        .transition_to(request.target)
        .map_err(|_| TenantLifecycleAdministrationFailure::InvalidTransition)?;
    Ok(())
}

fn replay(
    catalog: &Catalog<'_>,
    request: TenantLifecycleTransitionRequest,
) -> Result<Option<TenantLifecycleTransition>, TenantLifecycleAdministrationFailure> {
    let records = catalog.governance_audit_records().map_err(map_catalog)?;
    replay_records(&records, request)
}

fn replay_records(
    records: &[GovernanceAuditRecord],
    request: TenantLifecycleTransitionRequest,
) -> Result<Option<TenantLifecycleTransition>, TenantLifecycleAdministrationFailure> {
    for record in records {
        if record.transaction().to_bytes() != request.idempotency.to_bytes() {
            continue;
        }
        let entry = GovernanceAuditEntry::decode(record)
            .map_err(|_| TenantLifecycleAdministrationFailure::IdempotencyConflict)?;
        let lifecycle = entry
            .as_tenant_lifecycle()
            .ok_or(TenantLifecycleAdministrationFailure::IdempotencyConflict)?;
        if lifecycle.actor_id() != request.actor.principal_id()
            || lifecycle.tenant_id() != request.tenant
            || lifecycle.to() != request.target
            || lifecycle.expected_generation() != request.expected
            || lifecycle
                .request_digest()
                .is_some_and(|actual| actual != request_digest(request))
        {
            return Err(TenantLifecycleAdministrationFailure::IdempotencyConflict);
        }
        return Ok(Some(TenantLifecycleTransition {
            tenant: request.tenant,
            from: lifecycle.from(),
            to: lifecycle.to(),
            generation: lifecycle.generation(),
            audit_position: lifecycle.position(),
            audit_ingest_time_unix_seconds: lifecycle.ingest_time_unix_seconds(),
        }));
    }
    Ok(None)
}

fn resume_prepared(
    catalog: &Catalog<'_>,
    request: TenantLifecycleTransitionRequest,
) -> Result<Option<TenantLifecycleTransition>, TenantLifecycleAdministrationFailure> {
    let transaction = TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?;
    match catalog
        .resume_prepared(transaction, request_digest(request))
        .map_err(map_catalog)?
    {
        PreparedTransactionResolution::Absent => Ok(None),
        PreparedTransactionResolution::Unavailable => {
            Err(TenantLifecycleAdministrationFailure::PersistenceUnavailable)
        },
        PreparedTransactionResolution::Resumed(commit) => {
            let record = commit
                .governance_audit_record()
                .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
            replay_records(std::slice::from_ref(record), request)?
                .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)
                .map(Some)
        },
    }
}

fn next_generation(
    current: u64,
    current_state: TenantLifecycleState,
    expected: ResourceGeneration,
) -> Result<ResourceGeneration, TenantLifecycleAdministrationFailure> {
    if current != expected.get() {
        return Err(TenantLifecycleAdministrationFailure::StaleGeneration(
            TenantLifecycleGenerationConflict {
                current_generation: ResourceGeneration::new(current)
                    .map_err(|_| TenantLifecycleAdministrationFailure::PersistenceUnavailable)?,
                current_state,
            },
        ));
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
    request: TenantLifecycleTransitionRequest,
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
    commit_objects(catalog, snapshot, objects, request, audit)
}

fn commit_objects(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    objects: Vec<CatalogObject>,
    request: TenantLifecycleTransitionRequest,
    audit: Vec<u8>,
) -> Result<positron_kernel::CatalogCommit, TenantLifecycleAdministrationFailure> {
    let proposal = CatalogProposal::new(
        TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?,
        snapshot
            .format_epoch()
            .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)?,
        objects,
    )
    .map_err(map_catalog)?;
    catalog
        .commit_prepared(
            snapshot.identity(),
            proposal,
            AuditIntent::new(audit).map_err(map_catalog)?,
            request_digest(request),
        )
        .map_err(map_catalog)
}

fn request_digest(request: TenantLifecycleTransitionRequest) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.tenant-lifecycle.transition.request.v1\0");
    hash.update(request.idempotency.to_bytes());
    hash.update(request.actor.principal_id().to_bytes());
    hash.update(request.tenant.to_bytes());
    hash.update([lifecycle_state_code(request.target)]);
    hash.update(request.expected.get().to_be_bytes());
    hash.finalize().into()
}

const fn lifecycle_state_code(state: TenantLifecycleState) -> u8 {
    match state {
        TenantLifecycleState::Active => 1,
        TenantLifecycleState::ReadOnly => 2,
        TenantLifecycleState::Suspended => 3,
        TenantLifecycleState::Purging => 4,
        TenantLifecycleState::Purged => 5,
    }
}

fn map_tenant_record_failure(
    failure: crate::TenantAdministrationFailure,
) -> TenantLifecycleAdministrationFailure {
    match failure {
        crate::TenantAdministrationFailure::Unauthorized => {
            TenantLifecycleAdministrationFailure::UnknownTenant
        },
        crate::TenantAdministrationFailure::InvalidInput
        | crate::TenantAdministrationFailure::DuplicateTenant
        | crate::TenantAdministrationFailure::StaleGeneration
        | crate::TenantAdministrationFailure::IdempotencyConflict
        | crate::TenantAdministrationFailure::PersistenceUnavailable => {
            TenantLifecycleAdministrationFailure::PersistenceUnavailable
        },
    }
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> TenantLifecycleAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::StaleGeneration => {
            TenantLifecycleAdministrationFailure::PersistenceUnavailable
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
