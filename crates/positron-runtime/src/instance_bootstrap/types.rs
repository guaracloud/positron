use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, Scope, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_domain::routing::SignalKind;
use positron_kernel::{
    BootstrapKeyCustody, Catalog, CatalogFailureCode, InstanceBootstrapStorage, InstanceId,
    MountQualification, OwnedPrimaryDataVolume, RetentionTimeAuthority,
    StorageKernelResourceAuthority,
};
use zeroize::Zeroizing;

use positron_governance::{
    AdministrativeIdempotencyKey, ApiKeyAdministrationFailure, ApiKeyCreation, AuthorizedContext,
    ListenerTransportAdministration, ListenerTransportAdministrationFailure, ResourceGeneration,
    TenantLifecycleAdministration, TenantLifecycleAdministrationFailure, TenantLifecycleTransition,
};
use positron_query::QueryCancellation;

/// Coordinates the bounded native-ingest finalization with lifecycle closure.
///
/// A transition first closes entry, then waits for already-entered ingest work
/// to finish its final Catalog-serialized validation and publication. New work
/// observes the closed gate before it can reach the durable append boundary.
pub(super) struct IngestDrainGate {
    state: Mutex<IngestDrainState>,
    changed: Condvar,
    #[cfg(test)]
    transition_observer: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

const LIFECYCLE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

struct IngestDrainState {
    lifecycle_transitioning: bool,
    in_flight: u64,
}

/// Cancels and drains active query executions before restrictive lifecycle publication.
pub(super) struct QueryDrainGate {
    state: Mutex<QueryDrainState>,
    changed: Condvar,
    #[cfg(test)]
    transition_observer: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

struct QueryDrainState {
    closing: bool,
    next_id: u64,
    active: Vec<(u64, QueryCancellation)>,
}

impl QueryDrainGate {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(QueryDrainState {
                closing: false,
                next_id: 0,
                active: Vec::new(),
            }),
            changed: Condvar::new(),
            #[cfg(test)]
            transition_observer: Mutex::new(None),
        }
    }

    fn enter(
        &self,
        cancellation: QueryCancellation,
    ) -> Result<QueryDrainPermit<'_>, BootstrapFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        if state.closing {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::ResourceUnavailable,
            ));
        }
        let id = state.next_id;
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        state
            .active
            .try_reserve(1)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        state.active.push((id, cancellation));
        Ok(QueryDrainPermit { gate: self, id })
    }

    fn cancel_and_drain(&self) -> Result<QueryLifecycleDrainPermit<'_>, BootstrapFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let deadline = Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        while state.closing {
            let (next, timed_out) = wait_for_query_drain(&self.changed, state, deadline)?;
            if timed_out {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            state = next;
        }
        state.closing = true;
        #[cfg(test)]
        if let Some(observer) = self
            .transition_observer
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?
            .clone()
        {
            let _ = observer.send(());
        }
        for (_, cancellation) in &state.active {
            cancellation.cancel();
        }
        while !state.active.is_empty() {
            let (next, timed_out) = wait_for_query_drain(&self.changed, state, deadline)?;
            state = next;
            if timed_out {
                state.closing = false;
                self.changed.notify_all();
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
        }
        Ok(QueryLifecycleDrainPermit { gate: self })
    }

    #[cfg(test)]
    fn install_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        *self
            .transition_observer
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))? =
            Some(observer);
        Ok(())
    }
}

fn wait_for_query_drain<'gate>(
    changed: &'gate Condvar,
    state: std::sync::MutexGuard<'gate, QueryDrainState>,
    deadline: Instant,
) -> Result<(std::sync::MutexGuard<'gate, QueryDrainState>, bool), BootstrapFailure> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    let (state, timed_out) = changed
        .wait_timeout(state, remaining)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    Ok((state, timed_out.timed_out()))
}

pub(crate) struct QueryDrainPermit<'gate> {
    gate: &'gate QueryDrainGate,
    id: u64,
}

impl Drop for QueryDrainPermit<'_> {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(index) = state.active.iter().position(|(id, _)| *id == self.id) {
            state.active.remove(index);
        }
        self.gate.changed.notify_all();
    }
}

struct QueryLifecycleDrainPermit<'gate> {
    gate: &'gate QueryDrainGate,
}

impl Drop for QueryLifecycleDrainPermit<'_> {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.closing = false;
        self.gate.changed.notify_all();
    }
}

impl IngestDrainGate {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(IngestDrainState {
                lifecycle_transitioning: false,
                in_flight: 0,
            }),
            changed: Condvar::new(),
            #[cfg(test)]
            transition_observer: Mutex::new(None),
        }
    }

    fn enter(&self) -> Result<IngestDrainPermit<'_>, BootstrapFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        if state.lifecycle_transitioning {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::ResourceUnavailable,
            ));
        }
        state.in_flight = state
            .in_flight
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        Ok(IngestDrainPermit { gate: self })
    }

    fn close_and_drain(&self) -> Result<LifecycleDrainPermit<'_>, BootstrapFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let deadline = Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        while state.lifecycle_transitioning {
            let (next, timed_out) = wait_for_lifecycle_drain(&self.changed, state, deadline)?;
            if timed_out {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            state = next;
        }
        state.lifecycle_transitioning = true;
        #[cfg(test)]
        if let Some(observer) = self
            .transition_observer
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?
            .clone()
        {
            let _ = observer.send(());
        }
        while state.in_flight != 0 {
            let (next, timed_out) = wait_for_lifecycle_drain(&self.changed, state, deadline)?;
            state = next;
            if timed_out {
                state.lifecycle_transitioning = false;
                self.changed.notify_all();
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
        }
        Ok(LifecycleDrainPermit { gate: self })
    }

    #[cfg(test)]
    fn install_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        *self
            .transition_observer
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))? =
            Some(observer);
        Ok(())
    }
}

fn wait_for_lifecycle_drain<'gate>(
    changed: &'gate Condvar,
    state: std::sync::MutexGuard<'gate, IngestDrainState>,
    deadline: Instant,
) -> Result<(std::sync::MutexGuard<'gate, IngestDrainState>, bool), BootstrapFailure> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    let (state, timed_out) = changed
        .wait_timeout(state, remaining)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    Ok((state, timed_out.timed_out()))
}

pub(crate) struct IngestDrainPermit<'gate> {
    gate: &'gate IngestDrainGate,
}

impl Drop for IngestDrainPermit<'_> {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.in_flight = state.in_flight.saturating_sub(1);
        self.gate.changed.notify_all();
    }
}

struct LifecycleDrainPermit<'gate> {
    gate: &'gate IngestDrainGate,
}

impl Drop for LifecycleDrainPermit<'_> {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.lifecycle_transitioning = false;
        self.gate.changed.notify_all();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapState {
    Empty,
    Incomplete,
    Initialized,
    Inconsistent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapFailureCode {
    InvalidRoots,
    InconsistentRoots,
    AlreadyInitialized,
    StorageUnavailable,
    KeyCustodyUnavailable,
    ResourceUnavailable,
    CatalogUnavailable,
    LedgerUnavailable,
    CorruptState,
    IdentityMismatch,
    ClaimUnavailable,
    ClaimDestructionFailed,
    EntropyUnavailable,
    ApiKeyUnauthorized,
    ApiKeyStaleGeneration,
    ApiKeyIdempotencyConflict,
    ApiKeyUnavailable,
    TenantLifecycleUnauthorized,
    TenantLifecycleUnknownTenant,
    TenantLifecycleInvalidTransition,
    TenantLifecyclePurgeCompletionUnavailable,
    TenantLifecycleStaleGeneration,
    TenantLifecycleIdempotencyConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapFailure {
    code: BootstrapFailureCode,
    lifecycle_generation_conflict: Option<positron_governance::TenantLifecycleGenerationConflict>,
}

impl BootstrapFailure {
    pub(crate) const fn new(code: BootstrapFailureCode) -> Self {
        Self {
            code,
            lifecycle_generation_conflict: None,
        }
    }

    const fn with_lifecycle_generation_conflict(
        conflict: positron_governance::TenantLifecycleGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantLifecycleStaleGeneration,
            lifecycle_generation_conflict: Some(conflict),
        }
    }

    #[must_use]
    pub const fn code(self) -> BootstrapFailureCode {
        self.code
    }

    #[must_use]
    pub const fn lifecycle_generation_conflict(
        self,
    ) -> Option<positron_governance::TenantLifecycleGenerationConflict> {
        self.lifecycle_generation_conflict
    }
}

impl Display for BootstrapFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("instance bootstrap failed")
    }
}

impl Error for BootstrapFailure {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapPaths {
    pub(super) storage: InstanceBootstrapStorage,
    #[cfg(test)]
    data: std::path::PathBuf,
    #[cfg(test)]
    secrets: std::path::PathBuf,
}

impl BootstrapPaths {
    pub fn new(
        data: &Path,
        secrets: &Path,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapFailure> {
        Ok(Self {
            storage: InstanceBootstrapStorage::new(data, secrets, qualification)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::InvalidRoots))?,
            #[cfg(test)]
            data: data.to_owned(),
            #[cfg(test)]
            secrets: secrets.to_owned(),
        })
    }

    /// Binds bootstrap custody to the exact effective local-key reference.
    pub fn with_local_key(
        data: &Path,
        secrets: &Path,
        local_key_file: &Path,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapFailure> {
        if local_key_file != secrets.join("local-root-key.v1") {
            return Err(BootstrapFailure::new(BootstrapFailureCode::InvalidRoots));
        }
        Self::new(data, secrets, qualification)
    }

    #[cfg(test)]
    pub(super) fn data_root(&self) -> &Path {
        &self.data
    }

    #[cfg(test)]
    pub(super) fn secrets_root(&self) -> &Path {
        &self.secrets
    }

    #[must_use]
    pub const fn mount_qualification(&self) -> MountQualification {
        self.storage.qualification()
    }

    pub(crate) fn retain_volume(&self) -> Result<OwnedPrimaryDataVolume, BootstrapFailure> {
        self.storage
            .acquire()
            .map(|(volume, _)| volume)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
    }

    #[doc(hidden)]
    pub fn retain_volume_for_test(&self) -> Result<OwnedPrimaryDataVolume, BootstrapFailure> {
        self.retain_volume()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializationPlan {
    non_interactive: bool,
    external_alias: Option<ExternalTenantAlias>,
}

impl InitializationPlan {
    #[must_use]
    pub const fn non_interactive() -> Self {
        Self {
            non_interactive: true,
            external_alias: None,
        }
    }

    /// Creates a non-interactive plan with an explicitly bound protocol alias.
    pub fn non_interactive_with_external_tenant_alias(
        alias: &str,
    ) -> Result<Self, BootstrapFailure> {
        let external_alias = ExternalTenantAlias::parse(alias)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::InvalidRoots))?;
        Ok(Self {
            non_interactive: true,
            external_alias: Some(external_alias),
        })
    }

    pub(super) const fn creates_claim(&self) -> bool {
        self.non_interactive
    }

    pub(super) fn external_alias(&self) -> Result<ExternalTenantAlias, BootstrapFailure> {
        self.external_alias.clone().map_or_else(
            || {
                ExternalTenantAlias::parse("trace-external")
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
            },
            Ok,
        )
    }
}

pub struct InitializedInstance {
    pub(crate) key: BootstrapKeyCustody,
    // Fixture-only inspection data; product authorization always reads the
    // current durable identity through `durable_identity`.
    #[cfg(any(test, fuzzing))]
    pub(crate) identity: positron_governance::Identity,
    #[cfg(any(test, fuzzing))]
    pub(super) audit: Vec<positron_governance::GovernanceAuditEntry>,
    pub(crate) _authority: StorageKernelResourceAuthority,
    pub(crate) retention_time: RetentionTimeAuthority,
    pub(crate) instance: InstanceId,
    pub(crate) tenant: TenantId,
    pub(crate) logs_shard: positron_domain::routing::VirtualShardId,
    pub(crate) ingest_policy: positron_governance::IngestPolicyAdministration,
    pub(crate) value_limit_profile: positron_domain::value::ValueLimitProfile,
    pub(crate) admission_group_planner: Arc<dyn positron_ingest::AdmissionGroupPlanner>,
    pub(super) ingest_drain: IngestDrainGate,
    pub(super) query_drain: QueryDrainGate,
    pub(super) tenant_slug: TenantSlug,
    pub(super) administrator: PrincipalId,
    pub(super) integrity_key_fingerprint: [u8; 32],
    pub(super) catalog_generation: u64,
    pub(super) governance_audit_frontier: u64,
    pub(super) claim_available: bool,
}

impl std::fmt::Debug for InitializedInstance {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitializedInstance")
            .field("instance", &self.instance)
            .field("tenant", &self.tenant)
            .field("catalog_generation", &self.catalog_generation)
            .field("claim_available", &self.claim_available)
            .finish_non_exhaustive()
    }
}

impl InitializedInstance {
    pub(crate) fn enter_ingest_finalization(
        &self,
    ) -> Result<IngestDrainPermit<'_>, BootstrapFailure> {
        self.ingest_drain.enter()
    }

    pub(crate) fn enter_query_execution(
        &self,
        cancellation: QueryCancellation,
    ) -> Result<QueryDrainPermit<'_>, BootstrapFailure> {
        self.query_drain.enter(cancellation)
    }

    #[cfg(test)]
    pub(crate) fn install_lifecycle_query_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.query_drain.install_transition_observer(observer)
    }

    #[cfg(test)]
    pub(crate) fn install_lifecycle_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.ingest_drain.install_transition_observer(observer)
    }

    pub(crate) fn durable_identity(
        &self,
    ) -> Result<positron_governance::Identity, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let snapshot = Catalog::read_current_snapshot(&self._authority, self.instance, secret)
            .map_err(|failure| {
                let code = match failure.code() {
                    CatalogFailureCode::ResourceAdmissionRefused
                    | CatalogFailureCode::LimitExceeded => {
                        BootstrapFailureCode::ResourceUnavailable
                    },
                    CatalogFailureCode::StorageUnavailable
                    | CatalogFailureCode::ConcurrentWriter
                    | CatalogFailureCode::StaleGeneration
                    | CatalogFailureCode::IdempotencyConflict
                    | CatalogFailureCode::InvalidInput
                    | CatalogFailureCode::IntegrityCorruption
                    | CatalogFailureCode::AuthenticationFailed
                    | CatalogFailureCode::UnsupportedFormat => {
                        BootstrapFailureCode::CatalogUnavailable
                    },
                };
                BootstrapFailure::new(code)
            })?;
        positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
    }

    pub(crate) fn begin_shutdown(&self) -> Result<(), BootstrapFailure> {
        self._authority
            .begin_shutdown()
            .map(|_| ())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
    }

    pub fn attribute(
        &self,
        credential: positron_governance::PresentedCredential,
        intent: positron_governance::RequestedIntent,
        hints: positron_governance::CompatibilityHints,
    ) -> Result<positron_governance::AuthorizedContext, positron_governance::AttributionFailure>
    {
        // Never expose the boot-cached identity as a data-plane authority.
        // Rebuild the immutable view from the current durable Catalog
        // generation for every attribution request.
        let scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        let lifecycle_seconds = self
            .retention_time
            .governance_time_seconds(scope)
            .map_err(|_| positron_governance::AttributionFailure)?;
        self.durable_identity()
            .map_err(|_| positron_governance::AttributionFailure)?
            .attribute_at(
                &self.key,
                credential,
                intent,
                hints,
                Some(lifecycle_seconds),
            )
    }

    /// Records the active explicit plaintext API transport selection through
    /// the Catalog's single joint governance-audit publication path.
    pub(crate) fn activate_public_plaintext_api_transport(&self) -> Result<(), BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        ListenerTransportAdministration::activate_public_plaintext_api(&catalog, self.instance)
            .map(|_| ())
            .map_err(map_listener_transport_failure)
    }

    pub fn create_api_key(
        &self,
        actor: AuthorizedContext,
        scope: Scope,
        expires_at_unix_seconds: Option<u64>,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<ApiKeyCreation, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::create(
            &catalog,
            &self.key,
            self.administrator,
            positron_governance::ApiKeyCreateRequest::new(
                actor,
                scope,
                expires_at_unix_seconds,
                expected,
                idempotency,
            ),
        )
        .map_err(map_api_key_failure)
    }

    /// Publishes one authenticated lifecycle successor for the explicitly named tenant.
    ///
    /// `Purged` is intentionally unavailable here: only the later managed purge
    /// authority may complete the verified destructive operation.
    pub fn transition_tenant_lifecycle(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        target: TenantLifecycleState,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantLifecycleTransition, BootstrapFailure> {
        let _drain = self.ingest_drain.close_and_drain()?;
        let _query_drain = match target {
            TenantLifecycleState::Suspended | TenantLifecycleState::Purging => {
                Some(self.query_drain.cancel_and_drain()?)
            },
            TenantLifecycleState::Active
            | TenantLifecycleState::ReadOnly
            | TenantLifecycleState::Purged => None,
        };
        let audit_scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        let audit_ingest_time_unix_seconds = self
            .retention_time
            .governance_time_seconds(audit_scope)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        TenantLifecycleAdministration::transition(
            &catalog,
            self.administrator,
            actor,
            tenant,
            target,
            expected,
            idempotency,
            audit_ingest_time_unix_seconds,
        )
        .map_err(map_tenant_lifecycle_failure)
    }

    /// Returns decoded audit evidence through the same authenticated Catalog
    /// reader used by lifecycle integration tests.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn governance_audit_for_test(
        &self,
    ) -> Result<Vec<positron_governance::GovernanceAuditEntry>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        catalog
            .governance_audit_records()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
            .into_iter()
            .map(|record| {
                positron_governance::GovernanceAuditEntry::decode(&record)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
            })
            .collect()
    }

    /// Returns redacted key descriptors for the authorized system operator.
    pub fn list_api_keys(
        &self,
        actor: AuthorizedContext,
    ) -> Result<Vec<positron_governance::ApiKeyDescriptor>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::list(&catalog, self.administrator, actor)
            .map_err(map_api_key_failure)
    }

    /// Creates a successor credential without retiring its predecessor.  The
    /// caller must explicitly revoke the old key once dependent clients have
    /// switched, so a failed rollout never loses the only working key.
    pub fn rotate_api_key(
        &self,
        actor: AuthorizedContext,
        predecessor: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<ApiKeyCreation, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::rotate(
            &catalog,
            &self.key,
            self.administrator,
            actor,
            predecessor,
            expected,
            idempotency,
        )
        .map_err(map_api_key_failure)
    }

    /// Immediately disables one tenant credential while retaining its redacted
    /// descriptor as permanent identity history.
    pub fn revoke_api_key(
        &self,
        actor: AuthorizedContext,
        principal: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<(), BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::revoke(
            &catalog,
            self.administrator,
            actor,
            principal,
            expected,
            idempotency,
        )
        .map_err(map_api_key_failure)
    }

    /// Borrows the initialized instance's ordinary resource-admission authority.
    #[must_use]
    pub const fn resource_governor(&self) -> positron_kernel::ResourceGovernor<'_> {
        self._authority.governor()
    }

    #[cfg(any(test, fuzzing))]
    pub fn inspect_governance_for_fixture(
        &self,
        context: positron_governance::AuthorizedContext,
    ) -> Result<
        positron_governance::GovernanceInspection<'_, '_>,
        positron_governance::AttributionFailure,
    > {
        self.identity.inspect(context, &self.audit)
    }

    #[must_use]
    pub const fn instance_id(&self) -> InstanceId {
        self.instance
    }

    #[must_use]
    pub const fn default_tenant_id(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn default_tenant_slug(&self) -> &TenantSlug {
        &self.tenant_slug
    }

    #[must_use]
    pub const fn system_administrator_id(&self) -> PrincipalId {
        self.administrator
    }

    #[must_use]
    pub const fn integrity_key_fingerprint(&self) -> [u8; 32] {
        self.integrity_key_fingerprint
    }

    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    #[must_use]
    pub const fn governance_audit_frontier(&self) -> u64 {
        self.governance_audit_frontier
    }

    #[must_use]
    pub const fn claim_available(&self) -> bool {
        self.claim_available
    }
}

fn map_api_key_failure(failure: ApiKeyAdministrationFailure) -> BootstrapFailure {
    let code = match failure {
        ApiKeyAdministrationFailure::CapacityExceeded => BootstrapFailureCode::ResourceUnavailable,
        ApiKeyAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
        ApiKeyAdministrationFailure::Unauthorized => BootstrapFailureCode::ApiKeyUnauthorized,
        ApiKeyAdministrationFailure::StaleGeneration => BootstrapFailureCode::ApiKeyStaleGeneration,
        ApiKeyAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::ApiKeyIdempotencyConflict
        },
        ApiKeyAdministrationFailure::CredentialUnavailable => {
            BootstrapFailureCode::ApiKeyUnavailable
        },
    };
    BootstrapFailure::new(code)
}

fn map_tenant_lifecycle_failure(failure: TenantLifecycleAdministrationFailure) -> BootstrapFailure {
    let code = match failure {
        TenantLifecycleAdministrationFailure::Unauthorized => {
            BootstrapFailureCode::TenantLifecycleUnauthorized
        },
        TenantLifecycleAdministrationFailure::UnknownTenant => {
            BootstrapFailureCode::TenantLifecycleUnknownTenant
        },
        TenantLifecycleAdministrationFailure::InvalidTransition => {
            BootstrapFailureCode::TenantLifecycleInvalidTransition
        },
        TenantLifecycleAdministrationFailure::PurgeCompletionUnavailable => {
            BootstrapFailureCode::TenantLifecyclePurgeCompletionUnavailable
        },
        TenantLifecycleAdministrationFailure::StaleGeneration(conflict) => {
            return BootstrapFailure::with_lifecycle_generation_conflict(conflict);
        },
        TenantLifecycleAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::TenantLifecycleIdempotencyConflict
        },
        TenantLifecycleAdministrationFailure::CapacityExceeded
        | TenantLifecycleAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

fn map_listener_transport_failure(
    failure: ListenerTransportAdministrationFailure,
) -> BootstrapFailure {
    let code = match failure {
        ListenerTransportAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
        ListenerTransportAdministrationFailure::CorruptState => BootstrapFailureCode::CorruptState,
    };
    BootstrapFailure::new(code)
}

pub struct BootstrapClaim {
    pub(super) principal: PrincipalId,
    pub(super) secret: Zeroizing<String>,
    pub(super) ingest: Option<(PrincipalId, Zeroizing<String>)>,
    pub(super) query: Option<(PrincipalId, Zeroizing<String>)>,
}

impl BootstrapClaim {
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub fn secret(&self) -> &str {
        self.secret.as_str()
    }

    #[must_use]
    pub fn ingest_principal_id(&self) -> Option<PrincipalId> {
        self.ingest.as_ref().map(|(principal, _)| *principal)
    }

    #[must_use]
    pub fn ingest_secret(&self) -> Option<&str> {
        self.ingest.as_ref().map(|(_, secret)| secret.as_str())
    }

    #[must_use]
    pub fn query_principal_id(&self) -> Option<PrincipalId> {
        self.query.as_ref().map(|(principal, _)| *principal)
    }

    #[must_use]
    pub fn query_secret(&self) -> Option<&str> {
        self.query.as_ref().map(|(_, secret)| secret.as_str())
    }
}

impl std::fmt::Debug for BootstrapClaim {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BootstrapClaim { <redacted> }")
    }
}
