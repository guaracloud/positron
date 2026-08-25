use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{CommitPosition, RecordOrdinal, VirtualShardId};
use positron_kernel::{ControlTokenAuthentication, ControlTokenProtector};

use crate::{QueryFailure, QueryFailureCode};

const MAGIC: [u8; 8] = *b"POSTCUR2";
const PURPOSE: &[u8] = b"tail-cursor-v2";
const MAX_SHARDS: usize = 64;
const MAX_BYTES: usize = 2_048;
const AUTH_BYTES: usize = 32;
const PREFIX_BYTES: usize = 8 + 2 + 8 + 16 + 16 + 8 + 32 + 32 + 8 + 8 + 32 + 2;

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
    expiry: u64,
    sequence: u64,
    prior_digest: [u8; 32],
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
            expiry,
            sequence,
            prior_digest,
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
    pub const fn expiry(&self) -> u64 {
        self.expiry
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn prior_digest(&self) -> [u8; 32] {
        self.prior_digest
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

    pub(crate) fn advance(
        &self,
        shard: VirtualShardId,
        position: CommitPosition,
        ordinal: RecordOrdinal,
        digest: [u8; 32],
    ) -> Result<Self, QueryFailure> {
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(self.positions.len())
            .map_err(|_| resource())?;
        positions.extend_from_slice(&self.positions);
        let entry = positions
            .iter_mut()
            .find(|entry| entry.shard == shard)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        if (position, ordinal) < (entry.position, entry.ordinal) {
            return Err(invalid());
        }
        entry.position = position;
        entry.ordinal = ordinal;
        let sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
        Self::new(
            self.principal,
            self.tenant,
            self.authorization_generation,
            self.plan_digest,
            self.signal_digest,
            positions,
            self.expiry,
            sequence,
            digest,
        )
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
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes.extend_from_slice(&state.principal.to_bytes());
        bytes.extend_from_slice(&state.tenant.to_bytes());
        bytes.extend_from_slice(&state.authorization_generation.to_be_bytes());
        bytes.extend_from_slice(&state.plan_digest);
        bytes.extend_from_slice(&state.signal_digest);
        bytes.extend_from_slice(&state.expiry.to_be_bytes());
        bytes.extend_from_slice(&state.sequence.to_be_bytes());
        bytes.extend_from_slice(&state.prior_digest);
        bytes.extend_from_slice(
            &(u16::try_from(state.positions.len()).map_err(|_| invalid())?).to_be_bytes(),
        );
        for position in &state.positions {
            bytes.extend_from_slice(&position.shard.value().to_be_bytes());
            bytes.extend_from_slice(&position.position.value().to_be_bytes());
            bytes.extend_from_slice(&position.ordinal.value().to_be_bytes());
            bytes.extend_from_slice(&[0; 2]);
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
        if payload.get(..8) != Some(MAGIC.as_slice()) || u16_at(payload, 8)? != 1 {
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
        let count = usize::from(u16_at(payload, 170)?);
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
            positions.push(TailPosition::with_ordinal(shard, position, ordinal));
        }
        TailCursorState::new(
            principal, tenant, generation, plan, signal, positions, expiry, sequence, prior,
        )
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
