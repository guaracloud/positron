use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{CommitPosition, RecordOrdinal, VirtualShardId};
use positron_kernel::{ControlTokenAuthentication, ControlTokenProtector};

use super::{TailCursorState, TailPosition, invalid, resource};
use crate::{QueryFailure, QueryFailureCode};

const MAGIC: [u8; 8] = *b"POSTCUR3";
const PURPOSE: &[u8] = b"tail-cursor-v3";
const VERSION: u16 = 2;
const MAX_BYTES: usize = 2_048;
const AUTH_BYTES: usize = 32;
const PREFIX_BYTES: usize = 8 + 2 + 8 + 16 + 16 + 8 + 32 + 32 + 8 + 8 + 32 + 40 + 32 + 2;

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
        if count == 0 || count > super::MAX_SHARDS {
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
