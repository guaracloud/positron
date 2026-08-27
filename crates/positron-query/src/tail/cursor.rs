use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{CommitPosition, RecordOrdinal, VirtualShardId};
use positron_kernel::SnapshotLeaseId;
#[path = "cursor_progress.rs"]
mod progress;
#[path = "cursor_wire.rs"]
mod wire;
pub(super) use super::history::HistoricalMarker;
pub use wire::TailCursor;
pub(crate) use wire::budget_digest;
#[cfg(feature = "test-support")]
pub use wire::fail_next_encode;

use crate::{QueryFailure, QueryFailureCode};

const MAX_SHARDS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TailPosition {
    shard: VirtualShardId,
    position: CommitPosition,
    ordinal: RecordOrdinal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TailSourceBinding {
    shard: VirtualShardId,
    lease: SnapshotLeaseId,
    frontier: CommitPosition,
}

impl TailSourceBinding {
    pub(super) const fn new(
        shard: VirtualShardId,
        lease: SnapshotLeaseId,
        frontier: CommitPosition,
    ) -> Self {
        Self {
            shard,
            lease,
            frontier,
        }
    }

    pub(super) const fn shard(self) -> VirtualShardId {
        self.shard
    }

    pub(super) const fn lease(self) -> SnapshotLeaseId {
        self.lease
    }

    pub(super) const fn frontier(self) -> CommitPosition {
        self.frontier
    }
}

impl TailPosition {
    pub const fn new(shard: VirtualShardId, position: CommitPosition) -> Self {
        Self {
            shard,
            position,
            ordinal: RecordOrdinal::first(),
        }
    }
    pub const fn with_ordinal(
        shard: VirtualShardId,
        position: CommitPosition,
        ordinal: RecordOrdinal,
    ) -> Self {
        Self {
            shard,
            position,
            ordinal,
        }
    }
    #[must_use]
    pub const fn shard(self) -> VirtualShardId {
        self.shard
    }
    #[must_use]
    pub const fn position(self) -> CommitPosition {
        self.position
    }
    #[must_use]
    pub const fn ordinal(self) -> RecordOrdinal {
        self.ordinal
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TailCursorState {
    principal: PrincipalId,
    tenant: TenantId,
    authorization_generation: u64,
    plan_digest: [u8; 32],
    signal_digest: [u8; 32],
    positions: Vec<TailPosition>,
    record_bound: bool,
    expiry: u64,
    sequence: u64,
    prior_digest: [u8; 32],
    scanned_bytes: u64,
    decoded_records: u64,
    output_rows: u64,
    output_bytes: u64,
    cpu_work_units: u64,
    resume_count: u64,
    repeated_batch_count: u64,
    budget_digest: [u8; 32],
    pub(super) historical_markers: Option<Vec<HistoricalMarker>>,
    pub(super) snapshot_identity: [u8; 32],
    pub(super) snapshot_generation: u64,
    pub(super) source_bindings: Option<Vec<TailSourceBinding>>,
    memory_peak_bytes: u64,
    elapsed_seconds: u64,
    reduced_pruning: bool,
    limiting_budget: Option<crate::QueryBudgetDimension>,
}

impl TailCursorState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: PrincipalId,
        tenant: TenantId,
        authorization_generation: u64,
        plan_digest: [u8; 32],
        signal_digest: [u8; 32],
        mut positions: Vec<TailPosition>,
        expiry: u64,
        sequence: u64,
        prior_digest: [u8; 32],
    ) -> Result<Self, QueryFailure> {
        if expiry == 0 || positions.is_empty() || positions.len() > MAX_SHARDS {
            return Err(invalid());
        }
        positions.sort_unstable();
        if positions.windows(2).any(|w| w[0].shard == w[1].shard) {
            return Err(invalid());
        }
        Ok(Self {
            principal,
            tenant,
            authorization_generation,
            plan_digest,
            signal_digest,
            positions,
            record_bound: false,
            expiry,
            sequence,
            prior_digest,
            scanned_bytes: 0,
            decoded_records: 0,
            output_rows: 0,
            output_bytes: 0,
            cpu_work_units: 0,
            resume_count: 0,
            repeated_batch_count: 0,
            budget_digest: [0; 32],
            historical_markers: None,
            snapshot_identity: [0; 32],
            snapshot_generation: 0,
            source_bindings: None,
            memory_peak_bytes: 0,
            elapsed_seconds: 0,
            reduced_pruning: false,
            limiting_budget: None,
        })
    }
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub const fn authorization_generation(&self) -> u64 {
        self.authorization_generation
    }
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
    pub const fn signal_digest(&self) -> [u8; 32] {
        self.signal_digest
    }
    pub fn positions(&self) -> &[TailPosition] {
        &self.positions
    }
    pub const fn record_bound(&self) -> bool {
        self.record_bound
    }
    pub const fn expiry(&self) -> u64 {
        self.expiry
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn prior_digest(&self) -> [u8; 32] {
        self.prior_digest
    }
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }
    pub const fn decoded_records(&self) -> u64 {
        self.decoded_records
    }
    pub const fn output_rows(&self) -> u64 {
        self.output_rows
    }
    pub const fn output_bytes(&self) -> u64 {
        self.output_bytes
    }
    pub const fn cpu_work_units(&self) -> u64 {
        self.cpu_work_units
    }
    pub const fn resume_count(&self) -> u64 {
        self.resume_count
    }
    pub const fn repeated_batch_count(&self) -> u64 {
        self.repeated_batch_count
    }
    pub const fn budget_digest(&self) -> [u8; 32] {
        self.budget_digest
    }

    pub(crate) const fn memory_peak_bytes(&self) -> u64 {
        self.memory_peak_bytes
    }

    pub(crate) const fn elapsed_seconds(&self) -> u64 {
        self.elapsed_seconds
    }

    pub(crate) const fn reduced_pruning(&self) -> bool {
        self.reduced_pruning
    }

    pub(crate) const fn limiting_budget(&self) -> Option<crate::QueryBudgetDimension> {
        self.limiting_budget
    }

    pub(crate) fn set_runtime_stats(
        &mut self,
        memory_peak_bytes: u64,
        elapsed_seconds: u64,
        reduced_pruning: bool,
        limiting_budget: Option<crate::QueryBudgetDimension>,
    ) {
        self.memory_peak_bytes = memory_peak_bytes;
        self.elapsed_seconds = elapsed_seconds;
        self.reduced_pruning = reduced_pruning;
        self.limiting_budget = limiting_budget;
    }

    pub(crate) fn set_budget_digest(&mut self, digest: [u8; 32]) {
        self.budget_digest = digest;
    }

    pub(super) fn set_source_bindings(
        &mut self,
        snapshot_identity: [u8; 32],
        snapshot_generation: u64,
        mut bindings: Vec<TailSourceBinding>,
    ) -> Result<(), QueryFailure> {
        if bindings.is_empty() || bindings.len() > MAX_SHARDS {
            return Err(invalid());
        }
        bindings.sort_unstable_by_key(|binding| binding.shard);
        if bindings
            .windows(2)
            .any(|pair| pair[0].shard == pair[1].shard)
        {
            return Err(invalid());
        }
        self.snapshot_identity = snapshot_identity;
        self.snapshot_generation = snapshot_generation;
        self.source_bindings = Some(bindings);
        Ok(())
    }

    pub(super) fn source_bindings(&self) -> Option<&[TailSourceBinding]> {
        self.source_bindings.as_deref()
    }

    pub(crate) const fn snapshot_identity(&self) -> [u8; 32] {
        self.snapshot_identity
    }

    pub(crate) const fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }

    /// Returns the durable source frontier covered by this cursor binding.
    #[must_use]
    pub fn source_frontier(&self, shard: VirtualShardId) -> Option<CommitPosition> {
        self.source_binding(shard).map(TailSourceBinding::frontier)
    }

    pub(super) fn source_binding(&self, shard: VirtualShardId) -> Option<TailSourceBinding> {
        self.source_bindings
            .as_ref()?
            .iter()
            .find(|binding| binding.shard == shard)
            .copied()
    }

    pub(crate) fn validate_budget(&self, expected: [u8; 32]) -> Result<(), QueryFailure> {
        if self.budget_digest != expected {
            return Err(QueryFailure::new(QueryFailureCode::AuthorizationChanged));
        }
        Ok(())
    }

    pub(crate) fn set_progress(
        &mut self,
        scanned_bytes: u64,
        decoded_records: u64,
        output_rows: u64,
        output_bytes: u64,
        cpu_work_units: u64,
    ) {
        self.scanned_bytes = scanned_bytes;
        self.decoded_records = decoded_records;
        self.output_rows = output_rows;
        self.output_bytes = output_bytes;
        self.cpu_work_units = cpu_work_units;
    }

    pub(crate) fn set_resume_stats(&mut self, resume_count: u64, repeated_batch_count: u64) {
        self.resume_count = resume_count;
        self.repeated_batch_count = repeated_batch_count;
    }

    pub fn validate_for_resume(
        &self,
        principal: PrincipalId,
        tenant: TenantId,
        generation: u64,
        plan_digest: [u8; 32],
        signal_digest: [u8; 32],
        now: u64,
    ) -> Result<(), QueryFailure> {
        if now >= self.expiry {
            return Err(QueryFailure::new(QueryFailureCode::SnapshotExpired));
        }
        if self.principal != principal
            || self.tenant != tenant
            || self.authorization_generation != generation
            || self.plan_digest != plan_digest
            || self.signal_digest != signal_digest
        {
            return Err(QueryFailure::new(QueryFailureCode::AuthorizationChanged));
        }
        Ok(())
    }
}

fn invalid() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::InvalidCursor)
}
fn resource() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::ResourceExhausted)
}

#[cfg(test)]
#[path = "cursor_state_tests.rs"]
mod tests;
