use std::error::Error;
use std::fmt::{Display, Formatter};
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, Scope, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_domain::routing::SignalKind;
use positron_kernel::{
    BootstrapKeyCustody, Catalog, CatalogFailureCode, CommittedLedgerReader,
    InstanceBootstrapStorage, InstanceId, MountQualification, OwnedPrimaryDataVolume,
    ResourceAmounts, RetentionImpactPreview, RetentionReclamationEstimate, RetentionTimeAuthority,
    StorageKernelResourceAuthority,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use positron_governance::{
    AdministrativeIdempotencyKey, ApiKeyAdministrationFailure, ApiKeyCreation, AuthorizedContext,
    CatalogFormatMigration, CatalogFormatMigrationAdministration, CatalogFormatMigrationFailure,
    ListenerTransportAdministration, ListenerTransportAdministrationFailure, ResourceGeneration,
    RetentionImpactConfirmation, TenantAliasAdministration, TenantAliasAdministrationFailure,
    TenantAliasBindRequest, TenantAliasBinding, TenantDisplayGenerationConflict,
    TenantDisplayNameUpdate, TenantDisplayNameUpdateRequest, TenantLifecycleAdministration,
    TenantLifecycleAdministrationFailure, TenantLifecycleTransition,
    TenantLifecycleTransitionRequest, TenantProfileAdministration,
    TenantProfileAdministrationFailure, TenantProfileAdministrationFailureCode,
    TenantRetentionAdministration, TenantRetentionAdministrationFailure, TenantRetentionUpdate,
    TenantRetentionUpdateRequest,
};
use positron_query::QueryCancellation;

/// Read-only, generation-bound retention-reduction evidence for one tenant.
pub struct TenantRetentionImpactPreview {
    tenant: TenantId,
    retention_generation: ResourceGeneration,
    proposed_retention_seconds: NonZeroU64,
    catalog_identity: positron_kernel::CatalogGenerationId,
    catalog_generation: u64,
    scopes: Vec<RetentionImpactPreview>,
}

impl TenantRetentionImpactPreview {
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn retention_generation(&self) -> ResourceGeneration {
        self.retention_generation
    }
    #[must_use]
    pub const fn proposed_retention_seconds(&self) -> NonZeroU64 {
        self.proposed_retention_seconds
    }
    #[must_use]
    pub const fn catalog_identity(&self) -> positron_kernel::CatalogGenerationId {
        self.catalog_identity
    }
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub fn scopes(&self) -> &[RetentionImpactPreview] {
        &self.scopes
    }
    #[must_use]
    pub fn confirmation_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron.tenant-retention-impact.v1");
        hash.update(self.tenant.to_bytes());
        hash.update(self.retention_generation.get().to_be_bytes());
        hash.update(self.proposed_retention_seconds.get().to_be_bytes());
        hash.update(self.catalog_identity.to_bytes());
        hash.update(self.catalog_generation.to_be_bytes());
        for scope in &self.scopes {
            hash.update(scope.scope().tenant_id().to_bytes());
            hash.update([match scope.scope().signal_kind() {
                SignalKind::Logs => 1,
                SignalKind::Traces => 2,
            }]);
            hash.update(scope.scope().shard_id().value().to_be_bytes());
            hash.update(scope.catalog_identity().to_bytes());
            hash.update(scope.catalog_generation().to_be_bytes());
            hash.update(scope.evaluated_at().value().to_be_bytes());
            hash.update(scope.approximate_affected_bytes().to_be_bytes());
            hash.update(
                scope
                    .approximate_immediately_reclaimable_bytes()
                    .to_be_bytes(),
            );
            hash.update(scope.deferred_active_segment_bytes().to_be_bytes());
            hash.update(scope.deferred_mixed_sealed_segment_bytes().to_be_bytes());
            match scope.affected_time_range() {
                Some(range) => {
                    hash.update([1]);
                    hash.update(range.earliest().value().to_be_bytes());
                    hash.update(range.latest().value().to_be_bytes());
                },
                None => hash.update([0]),
            }
            match scope.earliest_reclamation() {
                RetentionReclamationEstimate::None => hash.update([0]),
                RetentionReclamationEstimate::At(time) => {
                    hash.update([1]);
                    hash.update(time.value().to_be_bytes());
                },
                RetentionReclamationEstimate::BlockedByDurableLease(time) => {
                    hash.update([2]);
                    hash.update(time.value().to_be_bytes());
                },
                RetentionReclamationEstimate::BlockedByInProcessSnapshot => hash.update([3]),
            }
        }
        hash.finalize().into()
    }
}

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
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueryDrainState {
                closing: false,
                next_id: 0,
                active: Vec::new(),
            }),
            changed: Condvar::new(),
            #[cfg(test)]
            transition_observer: Mutex::new(None),
        })
    }

    fn enter(
        self: &Arc<Self>,
        cancellation: QueryCancellation,
    ) -> Result<QueryDrainPermit, BootstrapFailure> {
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
        Ok(QueryDrainPermit {
            gate: Arc::clone(self),
            id,
        })
    }

    fn cancel_and_drain(self: &Arc<Self>) -> Result<QueryLifecycleDrainPermit, BootstrapFailure> {
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
        Ok(QueryLifecycleDrainPermit {
            gate: Arc::clone(self),
        })
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
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Ok((state, true));
    };
    let (state, timed_out) = changed
        .wait_timeout(state, remaining)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    Ok((state, timed_out.timed_out()))
}

pub(crate) struct QueryDrainPermit {
    gate: Arc<QueryDrainGate>,
    id: u64,
}

impl Drop for QueryDrainPermit {
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

struct QueryLifecycleDrainPermit {
    gate: Arc<QueryDrainGate>,
}

impl Drop for QueryLifecycleDrainPermit {
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
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(IngestDrainState {
                lifecycle_transitioning: false,
                in_flight: 0,
            }),
            changed: Condvar::new(),
            #[cfg(test)]
            transition_observer: Mutex::new(None),
        })
    }

    fn enter(self: &Arc<Self>) -> Result<IngestDrainPermit, BootstrapFailure> {
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
        Ok(IngestDrainPermit {
            gate: Arc::clone(self),
        })
    }

    fn close_and_drain(self: &Arc<Self>) -> Result<LifecycleDrainPermit, BootstrapFailure> {
        let deadline = Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        self.close_and_drain_before(deadline)
    }

    fn close_and_drain_before(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<LifecycleDrainPermit, BootstrapFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
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
        Ok(LifecycleDrainPermit {
            gate: Arc::clone(self),
        })
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
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Ok((state, true));
    };
    let (state, timed_out) = changed
        .wait_timeout(state, remaining)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    Ok((state, timed_out.timed_out()))
}

pub(crate) struct IngestDrainPermit {
    gate: Arc<IngestDrainGate>,
}

impl Drop for IngestDrainPermit {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.in_flight = state.in_flight.saturating_sub(1);
        self.gate.changed.notify_all();
    }
}

struct LifecycleDrainPermit {
    gate: Arc<IngestDrainGate>,
}

impl Drop for LifecycleDrainPermit {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.lifecycle_transitioning = false;
        self.gate.changed.notify_all();
    }
}

/// Serializes a tenant's lifecycle validation, drain, and publication sequence.
struct LifecycleMutationGate {
    active: Mutex<bool>,
    changed: Condvar,
}

impl LifecycleMutationGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(false),
            changed: Condvar::new(),
        })
    }

    fn acquire(self: &Arc<Self>) -> Result<LifecycleMutationPermit, BootstrapFailure> {
        let deadline = Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        while *active {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            };
            let (next, timed_out) = self
                .changed
                .wait_timeout(active, remaining)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
            if timed_out.timed_out() {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            active = next;
        }
        *active = true;
        Ok(LifecycleMutationPermit {
            gate: Arc::clone(self),
        })
    }
}

struct LifecycleMutationPermit {
    gate: Arc<LifecycleMutationGate>,
}

impl Drop for LifecycleMutationPermit {
    fn drop(&mut self) {
        let mut active = match self.gate.active.lock() {
            Ok(active) => active,
            Err(poisoned) => poisoned.into_inner(),
        };
        *active = false;
        self.gate.changed.notify_all();
    }
}

/// Bounded, tenant-keyed lifecycle drain gates for the tenants that are
/// actually registered in the Catalog. The Catalog remains the lifecycle
/// authority; this registry only prevents one tenant's transition from
/// draining another tenant's data-plane work.
pub(super) struct TenantDrainRegistry {
    maximum: usize,
    entries: Mutex<Vec<TenantDrainEntry>>,
}

struct TenantDrainEntry {
    tenant: TenantId,
    ingest: Arc<IngestDrainGate>,
    query: Arc<QueryDrainGate>,
    mutation: Arc<LifecycleMutationGate>,
    active: bool,
}

pub(super) struct TenantDrainEnrollment<'registry> {
    registry: &'registry TenantDrainRegistry,
    tenant: TenantId,
    activated: bool,
}

impl TenantDrainRegistry {
    pub(super) fn establish(
        registered: &[TenantId],
        maximum: u16,
    ) -> Result<Self, BootstrapFailure> {
        let maximum = usize::from(maximum);
        if maximum == 0 || registered.is_empty() || registered.len() > maximum {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::ResourceUnavailable,
            ));
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(registered.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        for tenant in registered {
            if entries
                .iter()
                .any(|entry: &TenantDrainEntry| entry.tenant == *tenant)
            {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            entries.push(TenantDrainEntry {
                tenant: *tenant,
                ingest: IngestDrainGate::new(),
                query: QueryDrainGate::new(),
                mutation: LifecycleMutationGate::new(),
                active: true,
            });
        }
        Ok(Self {
            maximum,
            entries: Mutex::new(entries),
        })
    }

    fn active_entry(
        &self,
        tenant: TenantId,
    ) -> Result<(Arc<IngestDrainGate>, Arc<QueryDrainGate>), BootstrapFailure> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let entry = entries
            .iter()
            .find(|entry| entry.tenant == tenant && entry.active)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        Ok((Arc::clone(&entry.ingest), Arc::clone(&entry.query)))
    }

    pub(super) fn enter_ingest(
        &self,
        tenant: TenantId,
    ) -> Result<IngestDrainPermit, BootstrapFailure> {
        self.active_entry(tenant)?.0.enter()
    }

    pub(super) fn enter_query(
        &self,
        tenant: TenantId,
        cancellation: QueryCancellation,
    ) -> Result<QueryDrainPermit, BootstrapFailure> {
        self.active_entry(tenant)?.1.enter(cancellation)
    }

    fn close_and_drain(&self, tenant: TenantId) -> Result<LifecycleDrainPermit, BootstrapFailure> {
        self.active_entry(tenant)?.0.close_and_drain()
    }

    fn cancel_and_drain(
        &self,
        tenant: TenantId,
    ) -> Result<QueryLifecycleDrainPermit, BootstrapFailure> {
        self.active_entry(tenant)?.1.cancel_and_drain()
    }

    fn begin_lifecycle_mutation(
        &self,
        tenant: TenantId,
    ) -> Result<LifecycleMutationPermit, BootstrapFailure> {
        let mutation = {
            let entries = self
                .entries
                .lock()
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
            let entry = entries
                .iter()
                .find(|entry| entry.tenant == tenant && entry.active)
                .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
            Arc::clone(&entry.mutation)
        };
        mutation.acquire()
    }

    fn close_all_and_drain(&self) -> Result<Vec<LifecycleDrainPermit>, BootstrapFailure> {
        let gates = self.active_gates()?;
        let mut permits = Vec::new();
        permits
            .try_reserve_exact(gates.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        for (ingest, _) in gates {
            permits.push(ingest.close_and_drain()?);
        }
        Ok(permits)
    }

    fn cancel_all_and_drain(&self) -> Result<Vec<QueryLifecycleDrainPermit>, BootstrapFailure> {
        let gates = self.active_gates()?;
        let mut permits = Vec::new();
        permits
            .try_reserve_exact(gates.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        for (_, query) in gates {
            permits.push(query.cancel_and_drain()?);
        }
        Ok(permits)
    }

    fn active_gates(&self) -> Result<Vec<TenantDrainGates>, BootstrapFailure> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let mut gates = Vec::new();
        gates
            .try_reserve_exact(entries.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        for entry in entries.iter().filter(|entry| entry.active) {
            gates.push((Arc::clone(&entry.ingest), Arc::clone(&entry.query)));
        }
        Ok(gates)
    }

    pub(super) fn prepare_tenant(
        &self,
        tenant: TenantId,
    ) -> Result<TenantDrainEnrollment<'_>, BootstrapFailure> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        if entries.len() >= self.maximum || entries.iter().any(|entry| entry.tenant == tenant) {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::ResourceUnavailable,
            ));
        }
        entries
            .try_reserve(1)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        entries.push(TenantDrainEntry {
            tenant,
            ingest: IngestDrainGate::new(),
            query: QueryDrainGate::new(),
            mutation: LifecycleMutationGate::new(),
            active: false,
        });
        Ok(TenantDrainEnrollment {
            registry: self,
            tenant,
            activated: false,
        })
    }

    #[cfg(test)]
    fn install_ingest_transition_observer(
        &self,
        tenant: TenantId,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.active_entry(tenant)?
            .0
            .install_transition_observer(observer)
    }

    #[cfg(test)]
    fn install_query_transition_observer(
        &self,
        tenant: TenantId,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.active_entry(tenant)?
            .1
            .install_transition_observer(observer)
    }
}

type TenantDrainGates = (Arc<IngestDrainGate>, Arc<QueryDrainGate>);

impl TenantDrainEnrollment<'_> {
    fn activate(&mut self) {
        let mut entries = match self.registry.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.tenant == self.tenant && !entry.active)
        {
            entry.active = true;
            self.activated = true;
        }
    }
}

impl Drop for TenantDrainEnrollment<'_> {
    fn drop(&mut self) {
        if self.activated {
            return;
        }
        let mut entries = match self.registry.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(index) = entries
            .iter()
            .position(|entry| entry.tenant == self.tenant && !entry.active)
        {
            entries.remove(index);
        }
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
    TenantQuotaUnauthorized,
    TenantQuotaStaleGeneration,
    TenantQuotaIdempotencyConflict,
    TenantDisplayNameUnauthorized,
    TenantDisplayNameStaleGeneration,
    TenantDisplayNameIdempotencyConflict,
    TenantAliasUnauthorized,
    TenantAliasUnknownTenant,
    TenantAliasAlreadyBound,
    TenantAliasConflict,
    TenantAliasStaleGeneration,
    TenantAliasIdempotencyConflict,
    TenantRetentionUnauthorized,
    TenantRetentionUnknownTenant,
    TenantRetentionInvalidConfirmation,
    TenantRetentionStaleGeneration,
    TenantRetentionIdempotencyConflict,
    TenantCreateConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapFailure {
    code: BootstrapFailureCode,
    lifecycle_generation_conflict: Option<positron_governance::TenantLifecycleGenerationConflict>,
    quota_generation_conflict: Option<positron_governance::TenantQuotaGenerationConflict>,
    display_generation_conflict: Option<TenantDisplayGenerationConflict>,
    retention_generation_conflict: Option<positron_governance::TenantRetentionGenerationConflict>,
}

impl BootstrapFailure {
    pub(crate) const fn new(code: BootstrapFailureCode) -> Self {
        Self {
            code,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: None,
        }
    }

    const fn with_lifecycle_generation_conflict(
        conflict: positron_governance::TenantLifecycleGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantLifecycleStaleGeneration,
            lifecycle_generation_conflict: Some(conflict),
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: None,
        }
    }

    const fn with_quota_generation_conflict(
        conflict: positron_governance::TenantQuotaGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantQuotaStaleGeneration,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: Some(conflict),
            display_generation_conflict: None,
            retention_generation_conflict: None,
        }
    }

    const fn with_display_generation_conflict(conflict: TenantDisplayGenerationConflict) -> Self {
        Self {
            code: BootstrapFailureCode::TenantDisplayNameStaleGeneration,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: Some(conflict),
            retention_generation_conflict: None,
        }
    }

    const fn with_retention_generation_conflict(
        conflict: positron_governance::TenantRetentionGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantRetentionStaleGeneration,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: Some(conflict),
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

    #[must_use]
    pub const fn quota_generation_conflict(&self) -> Option<ResourceGeneration> {
        match self.quota_generation_conflict {
            Some(conflict) => Some(conflict.current_generation()),
            None => None,
        }
    }

    #[must_use]
    pub const fn quota_generation_conflict_detail(
        &self,
    ) -> Option<positron_governance::TenantQuotaGenerationConflict> {
        self.quota_generation_conflict
    }

    #[must_use]
    pub const fn display_generation_conflict(&self) -> Option<TenantDisplayGenerationConflict> {
        self.display_generation_conflict
    }

    #[must_use]
    pub const fn retention_generation_conflict(
        &self,
    ) -> Option<positron_governance::TenantRetentionGenerationConflict> {
        self.retention_generation_conflict
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
    pub(crate) value_limit_profile: positron_domain::value::ValueLimitProfile,
    pub(crate) admission_group_planner: Arc<dyn positron_ingest::AdmissionGroupPlanner>,
    pub(super) tenant_drains: TenantDrainRegistry,
    #[cfg(test)]
    pub(super) lifecycle_preflight_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
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
    pub(crate) fn enter_ingest_finalization_for(
        &self,
        tenant: TenantId,
    ) -> Result<IngestDrainPermit, BootstrapFailure> {
        self.tenant_drains.enter_ingest(tenant)
    }

    pub(crate) fn enter_query_execution_for(
        &self,
        tenant: TenantId,
        cancellation: QueryCancellation,
    ) -> Result<QueryDrainPermit, BootstrapFailure> {
        self.tenant_drains.enter_query(tenant, cancellation)
    }

    #[cfg(test)]
    pub(crate) fn install_lifecycle_preflight_hook(
        &self,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), BootstrapFailure> {
        *self
            .lifecycle_preflight_hook
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))? =
            Some(hook);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn install_lifecycle_query_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.tenant_drains
            .install_query_transition_observer(self.tenant, observer)
    }

    #[cfg(test)]
    pub(crate) fn install_lifecycle_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.tenant_drains
            .install_ingest_transition_observer(self.tenant, observer)
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

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn install_retention_time_for_test(
        &mut self,
        retention_time: RetentionTimeAuthority,
    ) -> Result<(), BootstrapFailure> {
        self.retention_time = retention_time;
        let scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        self.retention_time
            .governance_time_seconds(scope)
            .map(|_| ())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
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

    /// Provisions a scoped API key for an explicitly named tenant without
    /// granting the system actor data-plane attribution for that tenant.
    pub fn create_api_key_for_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
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
        positron_governance::ApiKeyAdministration::create_for_tenant(
            &catalog,
            &self.key,
            self.administrator,
            positron_governance::ApiKeyCreateRequest::new(
                actor,
                scope,
                expires_at_unix_seconds,
                expected,
                idempotency,
            )
            .for_tenant(tenant),
        )
        .map_err(map_api_key_failure)
    }

    /// Durably publishes a tenant quota successor and then applies its limits
    /// to future local admission. Existing reservations are retained by the
    /// Resource Governor's bounded quota-update contract.
    pub fn update_tenant_quota(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
        weight: u32,
        resources: [u64; 11],
    ) -> Result<positron_governance::TenantQuotaUpdate, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(
            &catalog
                .pin()
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let update = positron_governance::TenantQuotaAdministration::update(
            &catalog,
            &self._authority,
            &identity,
            positron_governance::TenantQuotaUpdateRequest::new(
                actor,
                tenant,
                expected,
                idempotency,
                weight,
                resources,
            ),
        )
        .map_err(map_tenant_quota_failure)?;
        Ok(update)
    }

    /// Durably updates one tenant's display label while retaining independent
    /// retention, quota, policy, and lifecycle resources unchanged.
    pub fn update_tenant_display_name(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        expected: ResourceGeneration,
        display_name: &str,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantDisplayNameUpdate, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(
            &catalog
                .pin()
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        TenantProfileAdministration::update_display_name(
            &catalog,
            &identity,
            TenantDisplayNameUpdateRequest::new(actor, tenant, expected, display_name, idempotency),
        )
        .map_err(map_tenant_profile_failure)
    }

    /// Atomically publishes a new tenant registry record, then enrolls that
    /// tenant in the live bounded admission authority.
    pub fn create_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        configuration: positron_governance::TenantCreateConfiguration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<positron_governance::TenantCreation, BootstrapFailure> {
        let resources = configuration.resources();
        let weight = u16::try_from(configuration.weight())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let request = positron_governance::TenantCreateRequest::new(
            actor,
            tenant,
            configuration,
            idempotency,
        );
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let preflight = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(replay) = positron_governance::TenantAdministration::replay_from_view(
            &preflight,
            self.administrator,
            request.clone(),
        )
        .map_err(map_tenant_administration_failure)?
        {
            return Ok(replay);
        }
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        // The Catalog Writer serializes all governance changes that can alter
        // tenant topology. Prepare live enrollment only after acquiring it, so
        // a quota successor cannot be derived from stale membership.
        let mut drain_enrollment = self.tenant_drains.prepare_tenant(tenant)?;
        let mut enrollment = self
            ._authority
            .prepare_tenant_enrollment(tenant, weight, ResourceAmounts::new(resources))
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let created = positron_governance::TenantAdministration::create(
            &catalog,
            &self.key,
            self.instance,
            self.administrator,
            request,
        )
        .map_err(map_tenant_administration_failure)?;
        enrollment.activate();
        drain_enrollment.activate();
        Ok(created)
    }

    /// Enumerates tenant state only for the authenticated system administrator.
    pub fn list_tenants(
        &self,
        actor: AuthorizedContext,
    ) -> Result<Vec<positron_governance::TenantInspection>, BootstrapFailure> {
        self.authorize_tenant_inspection(actor)?;
        let snapshot = self.current_catalog_snapshot()?;
        positron_governance::TenantAdministration::list(&snapshot)
            .map_err(map_tenant_administration_failure)
    }

    /// Returns one redacted tenant-administration view without exposing keys.
    pub fn inspect_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<positron_governance::TenantInspection, BootstrapFailure> {
        self.authorize_tenant_inspection(actor)?;
        let snapshot = self.current_catalog_snapshot()?;
        positron_governance::TenantAdministration::inspect(&snapshot, tenant)
            .map_err(map_tenant_administration_failure)
    }

    /// Reads bounded canonical segment evidence without publishing a retention change.
    pub fn inspect_tenant_retention_impact(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        proposed_retention_seconds: NonZeroU64,
    ) -> Result<TenantRetentionImpactPreview, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let snapshot = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let inspection = positron_governance::TenantAdministration::inspect(&snapshot, tenant)
            .map_err(map_tenant_administration_failure)?;
        let identity = positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .authorize_tenant_retention(actor, tenant)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))?;
        let mut scopes = Vec::new();
        for signal in [SignalKind::Logs, SignalKind::Traces] {
            for scope in snapshot
                .reachable_ledger_scopes(tenant, signal)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
            {
                let protection = self
                    .key
                    .segment_key_from_tenant_envelope(
                        self.instance,
                        scope,
                        identity.tenant_key_envelope(tenant).map_err(|_| {
                            BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable)
                        })?,
                    )
                    .map_err(|_| {
                        BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable)
                    })?;
                let seconds = self
                    .retention_time
                    .governance_time_seconds(scope)
                    .map_err(|_| {
                        BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable)
                    })?;
                let nanos = seconds
                    .checked_mul(1_000_000_000)
                    .and_then(|value| i64::try_from(value).ok())
                    .ok_or_else(|| {
                        BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable)
                    })?;
                let reader =
                    CommittedLedgerReader::open(&self._authority, &catalog, scope, protection)
                        .map_err(|_| {
                            BootstrapFailure::new(BootstrapFailureCode::LedgerUnavailable)
                        })?;
                scopes.push(
                    reader
                        .inspect_retention_impact_at(
                            proposed_retention_seconds,
                            positron_domain::time::UnixNanoseconds::new(nanos),
                        )
                        .map_err(|_| {
                            BootstrapFailure::new(BootstrapFailureCode::LedgerUnavailable)
                        })?,
                );
            }
        }
        Ok(TenantRetentionImpactPreview {
            tenant,
            retention_generation: ResourceGeneration::new(inspection.retention_generation().get())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
            proposed_retention_seconds,
            catalog_identity: snapshot.identity(),
            catalog_generation: snapshot.number(),
            scopes,
        })
    }

    /// Publishes a retention successor. A reduction must carry a preview that
    /// is recomputed here from the current committed ledgers before its opaque
    /// confirmation binding can reach governance.
    pub fn update_tenant_retention(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        proposed_retention_seconds: NonZeroU64,
        expected: ResourceGeneration,
        confirmation: Option<&TenantRetentionImpactPreview>,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantRetentionUpdate, BootstrapFailure> {
        if confirmation.is_some_and(|candidate| {
            candidate.tenant() != tenant
                || candidate.retention_generation() != expected
                || candidate.proposed_retention_seconds() != proposed_retention_seconds
        }) {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::TenantRetentionInvalidConfirmation,
            ));
        }
        self.update_tenant_retention_with_confirmation_digest(
            actor,
            tenant,
            proposed_retention_seconds,
            expected,
            confirmation.map(TenantRetentionImpactPreview::confirmation_digest),
            idempotency,
        )
    }

    /// Publishes a retention successor using only an opaque confirmation that
    /// was returned by a prior preview. Exact retries resolve before a current
    /// preview is rebuilt; fresh reductions still bind the digest to current
    /// canonical retention evidence below.
    pub(crate) fn update_tenant_retention_with_confirmation_digest(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        proposed_retention_seconds: NonZeroU64,
        expected: ResourceGeneration,
        confirmation_digest: Option<[u8; 32]>,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantRetentionUpdate, BootstrapFailure> {
        let requested_confirmation = confirmation_digest
            .map(RetentionImpactConfirmation::from_runtime_digest)
            .transpose()
            .map_err(map_tenant_retention_failure)?;
        let prepared_replay = {
            let secret = self
                .key
                .catalog_secret(self.instance)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
            let catalog = Catalog::open(&self._authority, self.instance, secret)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            TenantRetentionAdministration::resume_prepared_existing(
                &catalog,
                self.instance.to_bytes(),
                TenantRetentionUpdateRequest::new(
                    actor,
                    tenant,
                    proposed_retention_seconds,
                    expected,
                    requested_confirmation,
                    idempotency,
                ),
            )
            .map_err(map_tenant_retention_failure)?
        };
        if let Some(replay) = prepared_replay {
            return Ok(replay);
        }
        let (binding, preview_catalog) = if let Some(digest) = confirmation_digest {
            let current =
                self.inspect_tenant_retention_impact(actor, tenant, proposed_retention_seconds)?;
            if digest != current.confirmation_digest() {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::TenantRetentionInvalidConfirmation,
                ));
            }
            (
                Some(
                    RetentionImpactConfirmation::from_runtime_digest(current.confirmation_digest())
                        .map_err(map_tenant_retention_failure)?,
                ),
                Some((current.catalog_identity(), current.catalog_generation())),
            )
        } else {
            (None, None)
        };
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let snapshot = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if preview_catalog.is_some_and(|(identity, generation)| {
            snapshot.identity() != identity || snapshot.number() != generation
        }) {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::TenantRetentionInvalidConfirmation,
            ));
        }
        let identity = positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        TenantRetentionAdministration::update(
            &catalog,
            &identity,
            TenantRetentionUpdateRequest::new(
                actor,
                tenant,
                proposed_retention_seconds,
                expected,
                binding,
                idempotency,
            ),
            || {
                self.retention_time
                    .governance_time_seconds(positron_kernel::SegmentScope::new(
                        tenant,
                        SignalKind::Logs,
                        self.logs_shard,
                    ))
                    .map_err(|_| TenantRetentionAdministrationFailure::TimeUnavailable)
            },
        )
        .map_err(map_tenant_retention_failure)
    }

    /// Publishes the concrete V1-to-V2 Catalog transformation while both
    /// native data admission gates are closed. Broader upgrade orchestration
    /// remains outside this narrowly scoped format transition.
    pub fn migrate_catalog_to_epoch_two(
        &self,
        actor: AuthorizedContext,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<CatalogFormatMigration, BootstrapFailure> {
        let _ingest_drain = self.tenant_drains.close_all_and_drain()?;
        let _query_drain = self.tenant_drains.cancel_all_and_drain()?;
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        CatalogFormatMigrationAdministration::migrate_to_epoch_two(
            &catalog,
            self.administrator,
            actor,
            idempotency,
        )
        .map_err(map_catalog_format_migration_failure)
    }

    /// Reads the currently authenticated Catalog format without acquiring the
    /// writer or exposing any Catalog object content.
    pub fn catalog_format_epoch(
        &self,
    ) -> Result<Option<positron_kernel::FormatEpoch>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        Catalog::read_current_snapshot(&self._authority, self.instance, secret)
            .map(|snapshot| snapshot.format_epoch())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
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
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let request =
            TenantLifecycleTransitionRequest::new(actor, tenant, target, expected, idempotency);
        let preflight = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(replay) =
            TenantLifecycleAdministration::replay_from_view(&preflight, self.administrator, request)
                .map_err(map_tenant_lifecycle_failure)?
        {
            return Ok(replay);
        }
        TenantLifecycleAdministration::preflight_from_view(&preflight, self.administrator, request)
            .map_err(map_tenant_lifecycle_failure)?;
        #[cfg(test)]
        let lifecycle_preflight_hook = self
            .lifecycle_preflight_hook
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?
            .clone();
        #[cfg(test)]
        if let Some(hook) = lifecycle_preflight_hook {
            hook();
        }
        let _mutation = self.tenant_drains.begin_lifecycle_mutation(tenant)?;
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let preflight = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(replay) =
            TenantLifecycleAdministration::replay_from_view(&preflight, self.administrator, request)
                .map_err(map_tenant_lifecycle_failure)?
        {
            return Ok(replay);
        }
        TenantLifecycleAdministration::preflight_from_view(&preflight, self.administrator, request)
            .map_err(map_tenant_lifecycle_failure)?;
        let _drain = self.tenant_drains.close_and_drain(tenant)?;
        let _query_drain = match target {
            TenantLifecycleState::Suspended | TenantLifecycleState::Purging => {
                Some(self.tenant_drains.cancel_and_drain(tenant)?)
            },
            TenantLifecycleState::Active
            | TenantLifecycleState::ReadOnly
            | TenantLifecycleState::Purged => None,
        };
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let audit_scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        TenantLifecycleAdministration::transition(&catalog, self.administrator, request, || {
            self.retention_time
                .governance_time_seconds(audit_scope)
                .map_err(|_| TenantLifecycleAdministrationFailure::TimeUnavailable)
        })
        .map_err(map_tenant_lifecycle_failure)
    }

    /// Binds one external compatibility assertion to a tenant. The alias is
    /// never an authority selector: authentication still attributes requests
    /// to the credential's immutable tenant before this value is consulted.
    pub fn bind_tenant_alias(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        alias: ExternalTenantAlias,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantAliasBinding, BootstrapFailure> {
        let request = TenantAliasBindRequest::new(actor, tenant, alias, expected, idempotency);
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let preflight = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(replay) = TenantAliasAdministration::replay_from_view(
            &preflight,
            self.administrator,
            request.clone(),
        )
        .map_err(map_tenant_alias_failure)?
        {
            return Ok(replay);
        }
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let audit_scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        TenantAliasAdministration::bind(&catalog, self.administrator, request, || {
            self.retention_time
                .governance_time_seconds(audit_scope)
                .map_err(|_| TenantAliasAdministrationFailure::TimeUnavailable)
        })
        .map_err(map_tenant_alias_failure)
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

    /// Returns redacted descriptors for one explicitly targeted tenant.
    pub fn list_api_keys_for_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<Vec<positron_governance::ApiKeyDescriptor>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::list_for_tenant(
            &catalog,
            self.administrator,
            actor,
            tenant,
        )
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
            positron_governance::ApiKeyRotationRequest::new(
                actor,
                predecessor,
                expected,
                idempotency,
            ),
        )
        .map_err(map_api_key_failure)
    }

    /// Rotates a credential in one explicitly named tenant keyring.
    pub fn rotate_api_key_for_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
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
        positron_governance::ApiKeyAdministration::rotate_for_tenant(
            &catalog,
            &self.key,
            self.administrator,
            positron_governance::ApiKeyRotationRequest::new(
                actor,
                predecessor,
                expected,
                idempotency,
            )
            .for_tenant(tenant),
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

    /// Revokes a credential in one explicitly named tenant keyring.
    pub fn revoke_api_key_for_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
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
        positron_governance::ApiKeyAdministration::revoke_for_tenant(
            &catalog,
            self.administrator,
            actor,
            tenant,
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

    fn current_catalog_snapshot(
        &self,
    ) -> Result<positron_kernel::CatalogSnapshot, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        Catalog::read_current_snapshot(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }

    fn authorize_tenant_inspection(
        &self,
        actor: AuthorizedContext,
    ) -> Result<(), BootstrapFailure> {
        let snapshot = self.current_catalog_snapshot()?;
        let identity = positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .inspect(actor, &[])
            .map(|_| ())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))
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
        | TenantLifecycleAdministrationFailure::TimeUnavailable
        | TenantLifecycleAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

fn map_tenant_alias_failure(failure: TenantAliasAdministrationFailure) -> BootstrapFailure {
    let code = match failure {
        TenantAliasAdministrationFailure::Unauthorized => {
            BootstrapFailureCode::TenantAliasUnauthorized
        },
        TenantAliasAdministrationFailure::UnknownTenant => {
            BootstrapFailureCode::TenantAliasUnknownTenant
        },
        TenantAliasAdministrationFailure::AliasAlreadyBound => {
            BootstrapFailureCode::TenantAliasAlreadyBound
        },
        TenantAliasAdministrationFailure::AliasConflict => {
            BootstrapFailureCode::TenantAliasConflict
        },
        TenantAliasAdministrationFailure::StaleGeneration(_) => {
            BootstrapFailureCode::TenantAliasStaleGeneration
        },
        TenantAliasAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::TenantAliasIdempotencyConflict
        },
        TenantAliasAdministrationFailure::CapacityExceeded
        | TenantAliasAdministrationFailure::TimeUnavailable
        | TenantAliasAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

fn map_tenant_retention_failure(failure: TenantRetentionAdministrationFailure) -> BootstrapFailure {
    if let TenantRetentionAdministrationFailure::StaleGeneration(conflict) = failure {
        return BootstrapFailure::with_retention_generation_conflict(conflict);
    }
    let code = match failure {
        TenantRetentionAdministrationFailure::Unauthorized => {
            BootstrapFailureCode::TenantRetentionUnauthorized
        },
        TenantRetentionAdministrationFailure::UnknownTenant => {
            BootstrapFailureCode::TenantRetentionUnknownTenant
        },
        TenantRetentionAdministrationFailure::InvalidConfirmation => {
            BootstrapFailureCode::TenantRetentionInvalidConfirmation
        },
        TenantRetentionAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::TenantRetentionIdempotencyConflict
        },
        TenantRetentionAdministrationFailure::InvalidInput
        | TenantRetentionAdministrationFailure::CapacityExceeded
        | TenantRetentionAdministrationFailure::TimeUnavailable
        | TenantRetentionAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
        TenantRetentionAdministrationFailure::StaleGeneration(_) => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

fn map_tenant_quota_failure(
    failure: positron_governance::TenantQuotaAdministrationFailure,
) -> BootstrapFailure {
    if let Some(conflict) = failure.generation_conflict() {
        return BootstrapFailure::with_quota_generation_conflict(conflict);
    }
    let code = match failure.code() {
        positron_governance::TenantQuotaAdministrationFailureCode::Unauthorized => {
            BootstrapFailureCode::TenantQuotaUnauthorized
        },
        positron_governance::TenantQuotaAdministrationFailureCode::StaleResourceGeneration => {
            BootstrapFailureCode::TenantQuotaStaleGeneration
        },
        positron_governance::TenantQuotaAdministrationFailureCode::IdempotencyConflict => {
            BootstrapFailureCode::TenantQuotaIdempotencyConflict
        },
        positron_governance::TenantQuotaAdministrationFailureCode::InvalidInput
        | positron_governance::TenantQuotaAdministrationFailureCode::PersistenceUnavailable
        | positron_governance::TenantQuotaAdministrationFailureCode::CorruptState => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

fn map_tenant_profile_failure(failure: TenantProfileAdministrationFailure) -> BootstrapFailure {
    if let Some(conflict) = failure.generation_conflict() {
        return BootstrapFailure::with_display_generation_conflict(conflict);
    }
    let code = match failure.code() {
        TenantProfileAdministrationFailureCode::Unauthorized => {
            BootstrapFailureCode::TenantDisplayNameUnauthorized
        },
        TenantProfileAdministrationFailureCode::IdempotencyConflict => {
            BootstrapFailureCode::TenantDisplayNameIdempotencyConflict
        },
        TenantProfileAdministrationFailureCode::InvalidInput
        | TenantProfileAdministrationFailureCode::UnknownTenant
        | TenantProfileAdministrationFailureCode::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
        TenantProfileAdministrationFailureCode::StaleDisplayGeneration => {
            BootstrapFailureCode::TenantDisplayNameStaleGeneration
        },
    };
    BootstrapFailure::new(code)
}

fn map_tenant_administration_failure(
    failure: positron_governance::TenantAdministrationFailure,
) -> BootstrapFailure {
    let code = match failure {
        positron_governance::TenantAdministrationFailure::Unauthorized => {
            BootstrapFailureCode::ApiKeyUnauthorized
        },
        positron_governance::TenantAdministrationFailure::StaleGeneration => {
            BootstrapFailureCode::ApiKeyStaleGeneration
        },
        positron_governance::TenantAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::ApiKeyIdempotencyConflict
        },
        positron_governance::TenantAdministrationFailure::DuplicateTenant => {
            BootstrapFailureCode::TenantCreateConflict
        },
        positron_governance::TenantAdministrationFailure::InvalidInput
        | positron_governance::TenantAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

fn map_catalog_format_migration_failure(
    failure: CatalogFormatMigrationFailure,
) -> BootstrapFailure {
    let code = match failure {
        CatalogFormatMigrationFailure::Unauthorized => BootstrapFailureCode::ApiKeyUnauthorized,
        CatalogFormatMigrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::ApiKeyIdempotencyConflict
        },
        CatalogFormatMigrationFailure::InvalidState
        | CatalogFormatMigrationFailure::PersistenceUnavailable => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_lifecycle_drain_deadline_restores_admission() {
        let gate = IngestDrainGate::new();
        let held = gate.enter().expect("initial admission");

        let failure = match gate.close_and_drain_before(Instant::now()) {
            Ok(_) => panic!("an already elapsed deadline cannot publish a lifecycle closure"),
            Err(failure) => failure,
        };
        assert_eq!(failure.code(), BootstrapFailureCode::ResourceUnavailable);

        let later = gate.enter().expect("failed drain reopens admission");
        drop(later);
        drop(held);
    }
}
