use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{CommitPosition, RecordOrdinal, VirtualShardId};
#[path = "cursor_wire.rs"]
mod wire;
pub use wire::TailCursor;
pub(crate) use wire::budget_digest;

use crate::{QueryFailure, QueryFailureCode};

const MAX_SHARDS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TailPosition {
    shard: VirtualShardId,
    position: CommitPosition,
    ordinal: RecordOrdinal,
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
    budget_digest: [u8; 32],
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
            budget_digest: [0; 32],
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
    pub const fn budget_digest(&self) -> [u8; 32] {
        self.budget_digest
    }

    pub(crate) fn set_budget_digest(&mut self, digest: [u8; 32]) {
        self.budget_digest = digest;
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

    pub(crate) fn advance_batch(
        &self,
        updates: &[TailPosition],
        digest: [u8; 32],
    ) -> Result<Self, QueryFailure> {
        if updates.is_empty() {
            return Err(invalid());
        }
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(self.positions.len())
            .map_err(|_| resource())?;
        positions.extend_from_slice(&self.positions);
        for update in updates {
            let entry = positions
                .iter_mut()
                .find(|entry| entry.shard == update.shard)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
            if (update.position, update.ordinal) < (entry.position, entry.ordinal) {
                return Err(invalid());
            }
            entry.position = update.position;
            entry.ordinal = update.ordinal;
        }
        let sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
        let mut state = Self::new(
            self.principal,
            self.tenant,
            self.authorization_generation,
            self.plan_digest,
            self.signal_digest,
            positions,
            self.expiry,
            sequence,
            digest,
        )?;
        state.record_bound = true;
        state.set_progress(
            self.scanned_bytes,
            self.decoded_records,
            self.output_rows,
            self.output_bytes,
            self.cpu_work_units,
        );
        state.budget_digest = self.budget_digest;
        Ok(state)
    }

    pub(crate) fn advance_positions(&self, updates: &[TailPosition]) -> Result<Self, QueryFailure> {
        if updates.is_empty() {
            return Err(invalid());
        }
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(self.positions.len())
            .map_err(|_| resource())?;
        positions.extend_from_slice(&self.positions);
        for update in updates {
            let entry = positions
                .iter_mut()
                .find(|entry| entry.shard == update.shard)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
            if (update.position, update.ordinal) < (entry.position, entry.ordinal) {
                return Err(invalid());
            }
            entry.position = update.position;
            entry.ordinal = update.ordinal;
        }
        let mut state = Self::new(
            self.principal,
            self.tenant,
            self.authorization_generation,
            self.plan_digest,
            self.signal_digest,
            positions,
            self.expiry,
            self.sequence,
            self.prior_digest,
        )?;
        state.record_bound = true;
        state.set_progress(
            self.scanned_bytes,
            self.decoded_records,
            self.output_rows,
            self.output_bytes,
            self.cpu_work_units,
        );
        state.budget_digest = self.budget_digest;
        Ok(state)
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
