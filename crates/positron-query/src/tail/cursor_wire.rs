use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{CommitPosition, RecordOrdinal, VirtualShardId};
use positron_kernel::{ControlTokenAuthentication, ControlTokenProtector};
#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicBool, Ordering};

use super::{HistoricalMarker, TailCursorState, TailPosition, invalid, resource};
use crate::{QueryFailure, QueryFailureCode};

const MAGIC: [u8; 8] = *b"POSTCUR3";
const PURPOSE: &[u8] = b"tail-cursor-v3";
const VERSION: u16 = 2;
const MAX_BYTES: usize = 4_096;
const AUTH_BYTES: usize = 32;
const EXT_MAGIC: [u8; 4] = *b"TX01";
const PREFIX_BYTES: usize = 8 + 2 + 8 + 16 + 16 + 8 + 32 + 32 + 8 + 8 + 32 + 40 + 16 + 32 + 2;

#[cfg(feature = "test-support")]
static FAIL_NEXT_ENCODE: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "test-support")]
pub fn fail_next_encode() {
    FAIL_NEXT_ENCODE.store(true, Ordering::Release);
}

#[derive(Clone, Eq, PartialEq)]
pub struct TailCursor(Vec<u8>);

impl TailCursor {
    pub fn encode(
        protector: &ControlTokenProtector<'_>,
        state: &TailCursorState,
    ) -> Result<Self, QueryFailure> {
        #[cfg(feature = "test-support")]
        if FAIL_NEXT_ENCODE.swap(false, Ordering::AcqRel) {
            return Err(invalid());
        }
        let extension = extension_bytes(state)?;
        let payload = PREFIX_BYTES
            .checked_add(state.positions.len().checked_mul(16).ok_or_else(resource)?)
            .and_then(|value| value.checked_add(extension))
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
        bytes.extend_from_slice(&state.resume_count.to_be_bytes());
        bytes.extend_from_slice(&state.repeated_batch_count.to_be_bytes());
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
        if extension > 0 {
            bytes.extend_from_slice(&EXT_MAGIC);
            let markers = state.historical_markers().unwrap_or(&[]);
            bytes.extend_from_slice(
                &u16::try_from(markers.len())
                    .map_err(|_| invalid())?
                    .to_be_bytes(),
            );
            for marker in markers {
                bytes.extend_from_slice(&marker.lower_bound().value().to_be_bytes());
                bytes.extend_from_slice(&marker.handoff_frontier().value().to_be_bytes());
            }
            bytes.extend_from_slice(&state.memory_peak_bytes().to_be_bytes());
            bytes.extend_from_slice(&state.elapsed_seconds().to_be_bytes());
            bytes.push(u8::from(state.reduced_pruning()));
            bytes.push(limiting_budget_code(state.limiting_budget()));
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
        let resume_count = u64_at(payload, 210)?;
        let repeated_batch_count = u64_at(payload, 218)?;
        let budget_digest = array_at_at::<32>(payload, 226)?;
        let count = usize::from(u16_at(payload, 258)?);
        if count == 0 || count > super::MAX_SHARDS {
            return Err(invalid());
        }
        let positions_end = PREFIX_BYTES
            .checked_add(count.checked_mul(16).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if payload.len() < positions_end {
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
        state.set_resume_stats(resume_count, repeated_batch_count);
        if payload.len() != positions_end {
            let extension_start = positions_end;
            if payload.get(extension_start..extension_start + EXT_MAGIC.len())
                != Some(EXT_MAGIC.as_slice())
            {
                return Err(invalid());
            }
            let marker_count = usize::from(u16_at(payload, extension_start + 4)?);
            if marker_count != 0 && marker_count != count {
                return Err(invalid());
            }
            let markers_end = extension_start
                .checked_add(4)
                .and_then(|value| value.checked_add(2))
                .and_then(|value| value.checked_add(marker_count.checked_mul(16)?))
                .ok_or_else(invalid)?;
            let stats_end = markers_end.checked_add(18).ok_or_else(invalid)?;
            if payload.len() != stats_end {
                return Err(invalid());
            }
            if marker_count > 0 {
                let mut markers = Vec::new();
                markers
                    .try_reserve_exact(marker_count)
                    .map_err(|_| resource())?;
                for index in 0..marker_count {
                    let offset = extension_start
                        .checked_add(6)
                        .and_then(|value| value.checked_add(index.checked_mul(16)?))
                        .ok_or_else(invalid)?;
                    let lower_bound = commit_position(u64_at(payload, offset)?)?;
                    let handoff_frontier = commit_position(u64_at(payload, offset + 8)?)?;
                    markers.push(HistoricalMarker::new(lower_bound, handoff_frontier)?);
                }
                state.set_historical_markers(markers)?;
            }
            let memory_peak = u64_at(payload, markers_end)?;
            let elapsed = u64_at(payload, markers_end + 8)?;
            let reduced = match payload.get(markers_end + 16) {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(invalid()),
            };
            state.set_runtime_stats(
                memory_peak,
                elapsed,
                reduced,
                limiting_budget_from_code(*payload.get(markers_end + 17).ok_or_else(invalid)?)?,
            );
        }
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

fn commit_position(value: u64) -> Result<CommitPosition, QueryFailure> {
    match std::num::NonZeroU64::new(value) {
        Some(value) => CommitPosition::origin()
            .advance_by(value)
            .map_err(|_| invalid()),
        None => Ok(CommitPosition::origin()),
    }
}

fn extension_bytes(state: &TailCursorState) -> Result<usize, QueryFailure> {
    let has_extension = state.historical_markers().is_some()
        || state.memory_peak_bytes() != 0
        || state.elapsed_seconds() != 0
        || state.reduced_pruning()
        || state.limiting_budget().is_some();
    if !has_extension {
        return Ok(0);
    }
    let markers = state.historical_markers().map_or(0, <[_]>::len);
    4_usize
        .checked_add(2)
        .and_then(|value| value.checked_add(markers.checked_mul(16)?))
        .and_then(|value| value.checked_add(18))
        .ok_or_else(resource)
}

fn limiting_budget_code(dimension: Option<crate::QueryBudgetDimension>) -> u8 {
    match dimension {
        None => 0,
        Some(crate::QueryBudgetDimension::ScannedBytes) => 1,
        Some(crate::QueryBudgetDimension::DecodedRecords) => 2,
        Some(crate::QueryBudgetDimension::OutputRows) => 3,
        Some(crate::QueryBudgetDimension::OutputBytes) => 4,
        Some(crate::QueryBudgetDimension::MemoryBytes) => 5,
        Some(crate::QueryBudgetDimension::CpuWorkUnits) => 6,
        Some(crate::QueryBudgetDimension::WallSeconds) => 7,
        Some(crate::QueryBudgetDimension::MaximumTimeRangeNanoseconds) => 8,
    }
}

fn limiting_budget_from_code(
    code: u8,
) -> Result<Option<crate::QueryBudgetDimension>, QueryFailure> {
    Ok(match code {
        0 => None,
        1 => Some(crate::QueryBudgetDimension::ScannedBytes),
        2 => Some(crate::QueryBudgetDimension::DecodedRecords),
        3 => Some(crate::QueryBudgetDimension::OutputRows),
        4 => Some(crate::QueryBudgetDimension::OutputBytes),
        5 => Some(crate::QueryBudgetDimension::MemoryBytes),
        6 => Some(crate::QueryBudgetDimension::CpuWorkUnits),
        7 => Some(crate::QueryBudgetDimension::WallSeconds),
        8 => Some(crate::QueryBudgetDimension::MaximumTimeRangeNanoseconds),
        _ => return Err(invalid()),
    })
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
#[path = "cursor_wire_tests.rs"]
mod tests;
