use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{CommitPosition, RecordOrdinal, VirtualShardId};
use positron_kernel::{ControlTokenAuthentication, ControlTokenProtector};

use super::{
    HistoricalMarker, TailCursorState, TailPosition, TailSourceBinding, invalid, resource,
};
use crate::QueryFailure;
use crate::result_key::{HISTORICAL_TOTAL_KEY_BYTES, HistoricalTotalKey};
#[path = "cursor_wire_helpers.rs"]
mod helpers;
pub(crate) use helpers::budget_digest;
use helpers::{
    array_at, array_at_at, commit_position, extension_bytes, limiting_budget_code,
    limiting_budget_from_code, u16_at, u32_at, u64_at,
};

const MAGIC: [u8; 8] = *b"POSTCUR3";
const PURPOSE: &[u8] = b"tail-cursor-v3";
const VERSION: u16 = 2;
const MAX_BYTES: usize = 4_096;
const AUTH_BYTES: usize = 32;
const EXT_MAGIC: [u8; 4] = *b"TX01";
const BIND_MAGIC: [u8; 4] = *b"TB01";
const DELIVERY_MAGIC: [u8; 4] = *b"DLV1";
const PREFIX_BYTES: usize = 8 + 2 + 8 + 16 + 16 + 8 + 32 + 32 + 8 + 8 + 32 + 40 + 16 + 32 + 2;

#[derive(Clone, Eq, PartialEq)]
pub struct TailCursor(Vec<u8>);

impl TailCursor {
    pub fn encode(
        protector: &ControlTokenProtector<'_>,
        state: &TailCursorState,
    ) -> Result<Self, QueryFailure> {
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
            if state.historical_markers().is_some() {
                if let Some(key) = state.historical_key() {
                    bytes.push(1);
                    bytes.extend_from_slice(&key.encode());
                } else {
                    bytes.push(0);
                    bytes.extend_from_slice(&[0; HISTORICAL_TOTAL_KEY_BYTES]);
                }
            }
            if let Some(bindings) = state.source_bindings() {
                bytes.extend_from_slice(&BIND_MAGIC);
                bytes.extend_from_slice(
                    &u16::try_from(bindings.len())
                        .map_err(|_| invalid())?
                        .to_be_bytes(),
                );
                bytes.extend_from_slice(&state.snapshot_identity());
                bytes.extend_from_slice(&state.snapshot_generation().to_be_bytes());
                for binding in bindings {
                    bytes.extend_from_slice(&binding.lease().to_bytes());
                    bytes.extend_from_slice(&binding.frontier().value().to_be_bytes());
                }
            }
            if let Some((sequence, digest)) = state.unacknowledged_delivery() {
                bytes.extend_from_slice(&DELIVERY_MAGIC);
                bytes.extend_from_slice(&sequence.to_be_bytes());
                bytes.extend_from_slice(&digest);
            }
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
        let mut position_shards = Vec::new();
        position_shards
            .try_reserve_exact(positions.len())
            .map_err(|_| resource())?;
        position_shards.extend(positions.iter().map(|position| position.shard()));
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
            if payload.len() < stats_end {
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
            let history_key_end = if marker_count > 0 {
                let flag = *payload.get(stats_end).ok_or_else(invalid)?;
                let key_start = stats_end.checked_add(1).ok_or_else(invalid)?;
                let key_end = key_start
                    .checked_add(HISTORICAL_TOTAL_KEY_BYTES)
                    .ok_or_else(invalid)?;
                let key_bytes = payload.get(key_start..key_end).ok_or_else(invalid)?;
                match flag {
                    0 if key_bytes.iter().all(|byte| *byte == 0) => {},
                    1 => {
                        let key = HistoricalTotalKey::decode(key_bytes)?.ok_or_else(invalid)?;
                        state.set_historical_key(Some(key));
                    },
                    _ => return Err(invalid()),
                }
                key_end
            } else {
                stats_end
            };
            let bindings_start = history_key_end;
            let mut trailing_start = bindings_start;
            let binding_magic_end = bindings_start
                .checked_add(BIND_MAGIC.len())
                .ok_or_else(invalid)?;
            if payload.get(bindings_start..binding_magic_end) == Some(BIND_MAGIC.as_slice()) {
                let binding_count = usize::from(u16_at(payload, bindings_start + 4)?);
                if binding_count != count {
                    return Err(invalid());
                }
                let identity_start = bindings_start.checked_add(6).ok_or_else(invalid)?;
                let generation_start = identity_start.checked_add(32).ok_or_else(invalid)?;
                let bindings_start_data = generation_start.checked_add(8).ok_or_else(invalid)?;
                let bindings_end = bindings_start_data
                    .checked_add(binding_count.checked_mul(24).ok_or_else(invalid)?)
                    .ok_or_else(invalid)?;
                if payload.len() < bindings_end {
                    return Err(invalid());
                }
                let snapshot_identity = array_at_at::<32>(payload, identity_start)?;
                let snapshot_generation = u64_at(payload, generation_start)?;
                let mut bindings = Vec::new();
                bindings
                    .try_reserve_exact(binding_count)
                    .map_err(|_| resource())?;
                for index in 0..binding_count {
                    let offset = bindings_start_data
                        .checked_add(index.checked_mul(24).ok_or_else(invalid)?)
                        .ok_or_else(invalid)?;
                    let lease =
                        positron_kernel::SnapshotLeaseId::new(array_at_at::<16>(payload, offset)?)
                            .map_err(|_| invalid())?;
                    let frontier = commit_position(u64_at(payload, offset + 16)?)?;
                    let shard = *position_shards.get(index).ok_or_else(invalid)?;
                    bindings.push(TailSourceBinding::new(shard, lease, frontier));
                }
                state.set_source_bindings(snapshot_identity, snapshot_generation, bindings)?;
                trailing_start = bindings_end;
            }
            if payload.len() > trailing_start {
                let delivery_end = trailing_start
                    .checked_add(DELIVERY_MAGIC.len() + 8 + 32)
                    .ok_or_else(invalid)?;
                if payload.len() != delivery_end
                    || payload.get(trailing_start..trailing_start + DELIVERY_MAGIC.len())
                        != Some(DELIVERY_MAGIC.as_slice())
                {
                    return Err(invalid());
                }
                let sequence = u64_at(payload, trailing_start + DELIVERY_MAGIC.len())?;
                let digest = array_at_at::<32>(payload, trailing_start + DELIVERY_MAGIC.len() + 8)?;
                state.set_unacknowledged_delivery((sequence, digest));
                trailing_start = delivery_end;
            }
            if payload.len() != trailing_start {
                return Err(invalid());
            }
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

#[cfg(test)]
#[path = "cursor_wire_tests.rs"]
mod tests;
