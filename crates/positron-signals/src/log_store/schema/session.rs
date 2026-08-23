use positron_domain::identity::TenantId;
use positron_kernel::{
    CommittedBlock, LedgerSnapshot, ResourceGovernor, ResourceReservation, StoreBlockIdentity,
    TransferredResourceReservation,
};

use super::{SchemaBudget, SchemaCatalog, SchemaDelta, SchemaFailure};
use crate::log_store::{LogRecord, LogStore, LogStoreFailure, ScanCancellation, ScanObserver};

/// Opaque tenant-bound schema store owned by the governed ingest session.
///
/// Construction consumes the live governor grant, so mutable authority cannot
/// outlive or be copied independently from its capacity.
#[doc(hidden)]
pub struct SchemaSessionStore {
    pub(super) catalog: SchemaCatalog,
    _capacity: TransferredResourceReservation,
    capacity_bytes: u64,
}

/// Fallibly constructed, unpublished catalog replacement.
#[doc(hidden)]
pub struct SchemaQueryUpdate {
    catalog: SchemaCatalog,
}

/// Unpublished replay state whose lifetime is tied to the temporary replay
/// reservation. It cannot be published after that reservation is dropped.
#[doc(hidden)]
pub struct SchemaReplayCandidate<'reservation> {
    pub(super) catalog: SchemaCatalog,
    pub(super) reservation: ResourceReservation<'reservation>,
}

impl SchemaSessionStore {
    pub fn new(
        reservation: ResourceReservation<'_>,
        tenant: TenantId,
        budget: SchemaBudget,
    ) -> Result<Self, SchemaFailure> {
        let memory_bytes = u64::try_from(SchemaCatalog::base_memory_bound(budget)?)
            .map_err(|_| SchemaFailure::LimitExceeded)?;
        if !reservation.authorizes_tenant_schema_session(tenant, memory_bytes) {
            return Err(SchemaFailure::AllocationUnavailable);
        }
        let capacity_bytes = reservation
            .granted()
            .get(positron_kernel::ResourceDimension::MemoryBytes);
        let catalog = SchemaCatalog::new(tenant, budget)?;
        Ok(Self {
            catalog,
            _capacity: reservation.transfer(),
            capacity_bytes,
        })
    }

    pub fn from_checkpoint(
        reservation: ResourceReservation<'_>,
        tenant: TenantId,
        checkpoint: &[u8],
    ) -> Result<Option<(Self, Vec<super::SchemaCheckpointFrontier>)>, SchemaFailure> {
        let total_memory = SchemaCatalog::catalog_memory_bound(checkpoint)?;
        let sidecar_memory = SchemaCatalog::catalog_sidecar_memory_bound(checkpoint)?;
        let base_memory = total_memory
            .checked_sub(sidecar_memory)
            .ok_or(SchemaFailure::MalformedCatalog)?;
        let base_memory = u64::try_from(base_memory).map_err(|_| SchemaFailure::LimitExceeded)?;
        if !reservation.authorizes_tenant_schema_session(tenant, base_memory) {
            return Err(SchemaFailure::AllocationUnavailable);
        }
        let capacity_bytes = reservation
            .granted()
            .get(positron_kernel::ResourceDimension::MemoryBytes);
        let (catalog, frontiers) = SchemaCatalog::decode_checkpoint_object(checkpoint)?;
        if catalog.tenant() != tenant {
            return Ok(None);
        }
        Ok(Some((
            Self {
                catalog,
                _capacity: reservation.transfer(),
                capacity_bytes,
            },
            frontiers,
        )))
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.catalog.tenant()
    }

    #[must_use]
    pub const fn catalog(&self) -> &SchemaCatalog {
        &self.catalog
    }

    #[must_use]
    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    #[must_use]
    pub fn governed_by(&self, governor: ResourceGovernor<'_>) -> bool {
        self._capacity.can_reclaim_with(governor)
    }

    /// Builds an unpublished catalog copy under the caller's already-admitted
    /// replay reservation. The candidate owns that temporary capacity and
    /// therefore cannot transfer the live session's base grant at publication
    /// time.
    pub fn try_clone_for_replay<'reservation>(
        &self,
        reservation: ResourceReservation<'reservation>,
    ) -> Result<SchemaReplayCandidate<'reservation>, SchemaFailure> {
        self.try_clone_for_replay_inner(reservation, None)
    }

    pub fn try_clone_for_replay_observed<'reservation>(
        &self,
        reservation: ResourceReservation<'reservation>,
        observer: &dyn ScanObserver,
    ) -> Result<SchemaReplayCandidate<'reservation>, SchemaFailure> {
        self.try_clone_for_replay_inner(reservation, Some(observer))
    }

    fn try_clone_for_replay_inner<'reservation>(
        &self,
        reservation: ResourceReservation<'reservation>,
        observer: Option<&dyn ScanObserver>,
    ) -> Result<SchemaReplayCandidate<'reservation>, SchemaFailure> {
        let required =
            u64::try_from(self.catalog.memory_bytes()).map_err(|_| SchemaFailure::LimitExceeded)?;
        if !reservation.authorizes_tenant_schema_session(self.tenant(), required) {
            return Err(SchemaFailure::AllocationUnavailable);
        }
        Ok(SchemaReplayCandidate {
            catalog: match observer {
                Some(observer) => self.catalog.try_clone_observed(observer)?,
                None => self.catalog.try_clone()?,
            },
            reservation,
        })
    }

    pub fn stage_group(&self, records: &mut [LogRecord]) -> Result<SchemaDelta, LogStoreFailure> {
        LogStore::new().stage_schema_group(records, &self.catalog)
    }

    pub fn stage_group_observed(
        &self,
        records: &mut [LogRecord],
        observer: &dyn ScanObserver,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        LogStore::new().stage_schema_group_observed(records, &self.catalog, observer)
    }

    pub fn commit(
        &mut self,
        delta: SchemaDelta,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), LogStoreFailure> {
        LogStore::new().apply_schema_delta(&mut self.catalog, delta, identity, digest)
    }

    pub fn commit_observed(
        &mut self,
        delta: SchemaDelta,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
        observer: &dyn ScanObserver,
    ) -> Result<(), LogStoreFailure> {
        LogStore::new().apply_schema_delta_replay_observed(
            &mut self.catalog,
            delta,
            identity,
            digest,
            observer,
        )
    }

    pub fn replay(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        LogStore::new().replay_schema_block(tenant, snapshot, block, &self.catalog)
    }

    pub fn replay_observed(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        observer: &dyn ScanObserver,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        self.replay_observed_cancellable(
            tenant,
            snapshot,
            block,
            &super::super::scan::NeverCancelled,
            observer,
        )
    }

    pub fn replay_observed_cancellable(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        LogStore::new().replay_schema_block_observed_cancellable(
            tenant,
            snapshot,
            block,
            &self.catalog,
            cancellation,
            observer,
        )
    }

    pub fn replay_observed_cancellable_with_text_observer(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
        text_observer: Option<&dyn ScanObserver>,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        LogStore::new().replay_schema_block_observed_cancellable_with_text_observer(
            tenant,
            snapshot,
            block,
            &self.catalog,
            cancellation,
            observer,
            text_observer,
        )
    }

    pub fn stage_query_update(&self) -> Result<SchemaQueryUpdate, SchemaFailure> {
        Ok(SchemaQueryUpdate {
            catalog: self.catalog.try_clone()?,
        })
    }

    pub fn commit_query_update(&mut self, update: SchemaQueryUpdate) -> Result<(), SchemaFailure> {
        if self.catalog.tenant() != update.catalog.tenant() {
            return Err(SchemaFailure::InvalidValue);
        }
        self.catalog = update.catalog;
        Ok(())
    }

    pub fn commit_replay_candidate<'reservation>(
        &mut self,
        candidate: SchemaReplayCandidate<'reservation>,
    ) -> Result<(), SchemaFailure> {
        if self.catalog.tenant() != candidate.catalog.tenant() {
            return Err(SchemaFailure::InvalidValue);
        }
        self.catalog = candidate.catalog;
        Ok(())
    }

    pub fn retain_reachable_indexes(
        &mut self,
        reachable: &[(StoreBlockIdentity, [u8; 32])],
    ) -> Result<(), SchemaFailure> {
        self.catalog.retain_reachable_indexes(reachable)
    }
}

impl SchemaQueryUpdate {
    pub fn record_query_use(&mut self, path: &super::SchemaPath) -> Result<(), SchemaFailure> {
        self.catalog.record_query_use(path)
    }

    pub fn index_replayed_query_path(
        &mut self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        path: &super::SchemaPath,
    ) -> Result<(), LogStoreFailure> {
        let delta = LogStore::new().replay_schema_block(tenant, snapshot, block, &self.catalog)?;
        let digest = block.content_digest().map_err(LogStoreFailure::kernel)?;
        if let Some(index) = delta
            .into_query_index(path, block.identity(), digest)
            .map_err(crate::log_store::map_schema_failure)?
        {
            self.catalog
                .install_query_index(index)
                .map_err(crate::log_store::map_schema_failure)?;
        }
        Ok(())
    }

    pub fn remove_query_evidence(&mut self, path: &super::SchemaPath) -> Result<(), SchemaFailure> {
        self.catalog.remove_query_evidence(path)
    }

    #[must_use]
    pub const fn memory_bytes(&self) -> usize {
        self.catalog.memory_bytes()
    }
}

impl<'reservation> SchemaReplayCandidate<'reservation> {
    pub fn prepare_replay_mutation_observed(
        &mut self,
        observer: &dyn ScanObserver,
    ) -> Result<(), SchemaFailure> {
        self.catalog.prepare_replay_mutation_observed(observer)
    }

    pub fn commit(
        &mut self,
        delta: SchemaDelta,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), LogStoreFailure> {
        LogStore::new().apply_schema_delta(&mut self.catalog, delta, identity, digest)
    }

    pub fn commit_observed(
        &mut self,
        delta: SchemaDelta,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
        observer: &dyn ScanObserver,
    ) -> Result<(), LogStoreFailure> {
        LogStore::new().apply_schema_delta_replay_observed(
            &mut self.catalog,
            delta,
            identity,
            digest,
            observer,
        )
    }

    pub fn replay_observed_cancellable_with_text_observer(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
        text_observer: Option<&dyn ScanObserver>,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        LogStore::new().replay_schema_block_observed_cancellable_with_text_observer(
            tenant,
            snapshot,
            block,
            &self.catalog,
            cancellation,
            observer,
            text_observer,
        )
    }

    pub fn reconcile_block_identity(
        &mut self,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), SchemaFailure> {
        self.catalog.reconcile_block_identity(identity, digest)
    }
}

impl SchemaSessionStore {
    pub fn has_verified_block(&self, identity: StoreBlockIdentity, digest: [u8; 32]) -> bool {
        self.catalog.has_verified_block(identity, digest)
    }

    pub fn reconcile_block_identity(
        &mut self,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), SchemaFailure> {
        self.catalog.reconcile_block_identity(identity, digest)
    }
}
