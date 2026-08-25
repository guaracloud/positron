use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{CommitPosition, RecordOrdinal, VirtualShardId};
use positron_kernel::{ControlTokenAuthentication, ControlTokenProtector};

use crate::{QueryFailure, QueryFailureCode};

const MAGIC: [u8; 8] = *b"POSTCUR3";
const PURPOSE: &[u8] = b"tail-cursor-v3";
const VERSION: u16 = 2;
const MAX_SHARDS: usize = 64;
const MAX_BYTES: usize = 2_048;
const AUTH_BYTES: usize = 32;
const PREFIX_BYTES: usize = 8 + 2 + 8 + 16 + 16 + 8 + 32 + 32 + 8 + 8 + 32 + 40 + 32 + 2;

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

#[derive(Clone, Eq, PartialEq)]
pub struct TailCursor(Vec<u8>);

impl TailCursor {
    pub fn encode(
        protector: &ControlTokenProtector<'_>,
        state: &TailCursorState,
    ) -> Result<Self, QueryFailure> {
        let payload = PREFIX_BYTES
            .checked_add(state.positions.len().checked_mul(16).ok_or_else(resource)?)
            .ok_or_else(resource)?;
        let total = payload.checked_add(AUTH_BYTES).ok_or_else(resource)?;
        if total > MAX_BYTES {
            return Err(resource());
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(total).map_err(|_| resource())?;
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes.extend_from_slice(&state.principal.to_bytes());
        bytes.extend_from_slice(&state.tenant.to_bytes());
        bytes.extend_from_slice(&state.authorization_generation.to_be_bytes());
        bytes.extend_from_slice(&state.plan_digest);
        bytes.extend_from_slice(&state.signal_digest);
        bytes.extend_from_slice(&state.expiry.to_be_bytes());
        bytes.extend_from_slice(&state.sequence.to_be_bytes());
        bytes.extend_from_slice(&state.prior_digest);
        bytes.extend_from_slice(&state.scanned_bytes.to_be_bytes());
        bytes.extend_from_slice(&state.decoded_records.to_be_bytes());
        bytes.extend_from_slice(&state.output_rows.to_be_bytes());
        bytes.extend_from_slice(&state.output_bytes.to_be_bytes());
        bytes.extend_from_slice(&state.cpu_work_units.to_be_bytes());
        bytes.extend_from_slice(&state.budget_digest);
        bytes.extend_from_slice(
            &(u16::try_from(state.positions.len()).map_err(|_| invalid())?).to_be_bytes(),
        );
        for position in &state.positions {
            bytes.extend_from_slice(&position.shard.value().to_be_bytes());
            bytes.extend_from_slice(&position.position.value().to_be_bytes());
            bytes.extend_from_slice(&position.ordinal.value().to_be_bytes());
            bytes.extend_from_slice(&[u8::from(state.record_bound), 0]);
        }
        let auth = protector
            .authenticate_query_cursor(PURPOSE, &bytes)
            .map_err(|_| invalid())?;
        bytes
            .get_mut(10..18)
            .ok_or_else(invalid)?
            .copy_from_slice(&auth.epoch().to_be_bytes());
        let auth = protector
            .authenticate_query_cursor(PURPOSE, &bytes)
            .map_err(|_| invalid())?;
        bytes.extend_from_slice(&auth.tag());
        Ok(Self(bytes))
    }

    pub fn decode(
        protector: &ControlTokenProtector<'_>,
        cursor: &Self,
    ) -> Result<TailCursorState, QueryFailure> {
        let bytes = cursor.0.as_slice();
        if bytes.len() < PREFIX_BYTES + 16 + AUTH_BYTES || bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let payload_len = bytes.len().checked_sub(AUTH_BYTES).ok_or_else(invalid)?;
        let (payload, tag) = bytes.split_at(payload_len);
        if payload.get(..8) != Some(MAGIC.as_slice()) || u16_at(payload, 8)? != VERSION {
            return Err(invalid());
        }
        let epoch = u64_at(payload, 10)?;
        let auth = ControlTokenAuthentication::new(epoch, tag.try_into().map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        // The authentication epoch is intentionally encoded by the protector's
        // verifier; a zero epoch is the only stable wire value in this format.
        protector
            .verify_query_cursor(PURPOSE, payload, auth)
            .map_err(|_| invalid())?;
        let principal = PrincipalId::from_bytes(array_at(payload, 18)?).map_err(|_| invalid())?;
        let tenant = TenantId::from_bytes(array_at(payload, 34)?).map_err(|_| invalid())?;
        let generation = u64_at(payload, 50)?;
        let plan = array_at_at::<32>(payload, 58)?;
        let signal = array_at_at::<32>(payload, 90)?;
        let expiry = u64_at(payload, 122)?;
        let sequence = u64_at(payload, 130)?;
        let prior = array_at_at::<32>(payload, 138)?;
        let scanned_bytes = u64_at(payload, 170)?;
        let decoded_records = u64_at(payload, 178)?;
        let output_rows = u64_at(payload, 186)?;
        let output_bytes = u64_at(payload, 194)?;
        let cpu_work_units = u64_at(payload, 202)?;
        let budget_digest = array_at_at::<32>(payload, 210)?;
        let count = usize::from(u16_at(payload, 242)?);
        if count == 0 || count > MAX_SHARDS {
            return Err(invalid());
        }
        let expected = PREFIX_BYTES
            .checked_add(count.checked_mul(16).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if payload.len() != expected {
            return Err(invalid());
        }
        let mut positions = Vec::new();
        positions.try_reserve_exact(count).map_err(|_| resource())?;
        let mut record_bound = None;
        for index in 0..count {
            let offset = PREFIX_BYTES
                .checked_add(index.checked_mul(16).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
            let shard = VirtualShardId::new(u32_at(payload, offset)?).map_err(|_| invalid())?;
            let position = match std::num::NonZeroU64::new(u64_at(payload, offset + 4)?) {
                Some(value) => CommitPosition::origin()
                    .advance_by(value)
                    .map_err(|_| invalid())?,
                None => CommitPosition::origin(),
            };
            let ordinal = RecordOrdinal::new(u16::from_be_bytes(array_at(payload, offset + 12)?))
                .map_err(|_| invalid())?;
            let position_record_bound = match payload.get(offset + 14) {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(invalid()),
            };
            if record_bound.is_some_and(|value| value != position_record_bound) {
                return Err(invalid());
            }
            record_bound = Some(position_record_bound);
            positions.push(TailPosition::with_ordinal(shard, position, ordinal));
        }
        let mut state = TailCursorState::new(
            principal, tenant, generation, plan, signal, positions, expiry, sequence, prior,
        )?;
        state.record_bound = record_bound.ok_or_else(invalid)?;
        state.set_progress(
            scanned_bytes,
            decoded_records,
            output_rows,
            output_bytes,
            cpu_work_units,
        );
        state.budget_digest = budget_digest;
        Ok(state)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, QueryFailure> {
        if bytes.len() < PREFIX_BYTES + 16 + AUTH_BYTES || bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| resource())?;
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for TailCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TailCursor { <opaque> }")
    }
}
fn array_at<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], QueryFailure> {
    array_at_at(bytes, start)
}
fn array_at_at<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], QueryFailure> {
    bytes
        .get(start..start.checked_add(N).ok_or_else(invalid)?)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())
}
fn u16_at(bytes: &[u8], start: usize) -> Result<u16, QueryFailure> {
    Ok(u16::from_be_bytes(array_at(bytes, start)?))
}
fn u32_at(bytes: &[u8], start: usize) -> Result<u32, QueryFailure> {
    Ok(u32::from_be_bytes(array_at(bytes, start)?))
}
fn u64_at(bytes: &[u8], start: usize) -> Result<u64, QueryFailure> {
    Ok(u64::from_be_bytes(array_at(bytes, start)?))
}
fn invalid() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::InvalidCursor)
}
fn resource() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::ResourceExhausted)
}

pub(crate) fn budget_digest(
    protector: &ControlTokenProtector<'_>,
    budget: crate::QueryBudget,
) -> Result<[u8; 32], QueryFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(8 * std::mem::size_of::<u64>())
        .map_err(|_| resource())?;
    for value in [
        budget.scanned_bytes(),
        budget.decoded_records(),
        budget.output_rows(),
        budget.output_bytes(),
        budget.memory_bytes(),
        budget.cpu_work_units(),
        budget.wall_seconds(),
        budget.maximum_time_range_nanoseconds(),
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    protector
        .digest(b"tail-budget-v1", &bytes)
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use positron_domain::identity::{PrincipalId, TenantId};
    use positron_domain::routing::{CommitPosition, VirtualShardId};

    use super::{TailCursorState, TailPosition};
    use crate::QueryFailureCode;

    fn state() -> TailCursorState {
        TailCursorState::new(
            PrincipalId::from_bytes([1; 16]).expect("principal"),
            TenantId::from_bytes([2; 16]).expect("tenant"),
            1,
            [3; 32],
            [4; 32],
            vec![TailPosition::new(
                VirtualShardId::new(1).expect("shard"),
                CommitPosition::origin()
                    .advance_by(NonZeroU64::new(2).expect("non-zero"))
                    .expect("position"),
            )],
            100,
            0,
            [0; 32],
        )
        .expect("valid cursor state")
    }

    #[test]
    fn state_advancement_rejects_empty_unknown_and_rewound_updates() {
        let state = state();
        assert_eq!(
            state
                .advance_batch(&[], [5; 32])
                .expect_err("empty batch")
                .code(),
            QueryFailureCode::InvalidCursor
        );
        assert_eq!(
            state
                .advance_positions(&[])
                .expect_err("empty position update")
                .code(),
            QueryFailureCode::InvalidCursor
        );

        let unknown = TailPosition::new(
            VirtualShardId::new(2).expect("shard"),
            CommitPosition::origin(),
        );
        assert_eq!(
            state
                .advance_batch(&[unknown], [5; 32])
                .expect_err("unknown shard")
                .code(),
            QueryFailureCode::InvalidCursor
        );
        assert_eq!(
            state
                .advance_positions(&[unknown])
                .expect_err("unknown shard")
                .code(),
            QueryFailureCode::InvalidCursor
        );

        let rewound = TailPosition::new(
            VirtualShardId::new(1).expect("shard"),
            CommitPosition::origin(),
        );
        assert_eq!(
            state
                .advance_batch(&[rewound], [5; 32])
                .expect_err("rewound batch")
                .code(),
            QueryFailureCode::InvalidCursor
        );
        assert_eq!(
            state
                .advance_positions(&[rewound])
                .expect_err("rewound position")
                .code(),
            QueryFailureCode::InvalidCursor
        );

        let mut malformed = state;
        malformed.positions.push(malformed.positions[0]);
        let update = malformed.positions[0];
        assert_eq!(
            malformed
                .advance_batch(&[update], [5; 32])
                .expect_err("duplicate state")
                .code(),
            QueryFailureCode::InvalidCursor
        );
        assert_eq!(
            malformed
                .advance_positions(&[update])
                .expect_err("duplicate state")
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }
}
