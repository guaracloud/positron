use positron_domain::identity::TenantId;
use positron_domain::time::SourceTimeQuality;

use super::super::failure::TraceStoreFailure;
use super::super::types::{TraceLimits, release_1_limits};
use super::decode::Input;
use super::format::{
    MAGIC, MAX_RECORDS, VERSION, decode_kind, decode_namespace, decode_quality, decode_sampling,
    namespace_index,
};
use crate::ScanCancellation;

/// Computes a conservative peak heap bound without constructing a decoded
/// value. The scan reserves this amount before its first allocating decode.
pub(crate) fn decoded_memory_bound(
    expected_tenant: TenantId,
    bytes: &[u8],
    cancellation: &dyn ScanCancellation,
) -> Result<u64, TraceStoreFailure> {
    let limits = release_1_limits()?;
    let mut input = Input::cancelable(bytes, cancellation);
    if input.take(MAGIC.len())? != MAGIC || input.u16()? != VERSION {
        return Err(TraceStoreFailure::malformed_block());
    }
    if input.array::<16>()? != expected_tenant.to_bytes() {
        return Err(TraceStoreFailure::physical_scope_mismatch());
    }
    let count = input.count(MAX_RECORDS)?;
    if count == 0 {
        return Err(TraceStoreFailure::malformed_block());
    }
    let mut bound = 0_u64;
    for _ in 0..count {
        bound = checked_bound_add(bound, preflight_observation(&mut input, &limits)?)?;
    }
    if !input.is_empty() {
        return Err(TraceStoreFailure::malformed_block());
    }
    Ok(bound)
}

struct ValueBound {
    decoded_bytes: usize,
    dynamic_bytes: u64,
}

fn preflight_observation(
    input: &mut Input<'_>,
    limits: &TraceLimits,
) -> Result<u64, TraceStoreFailure> {
    let _ = input.array::<16>()?;
    let _ = input.array::<8>()?;
    match input.u8()? {
        0 => {},
        1 => {
            let _ = input.array::<8>()?;
        },
        _ => return Err(TraceStoreFailure::malformed_block()),
    }
    let _ = decode_kind(input.u8()?)?;
    let _ = decode_sampling(input.u8()?)?;
    preflight_time(input)?;
    preflight_time(input)?;
    let name = input.raw_string(limits.key_path_bytes)?;
    let mut decoded_bytes = name.len();
    let attributes_count = input.count(limits.attribute_sets)?;
    let mut bound = checked_slot_bound(
        super::DECODED_RECORD_SLOT_BYTES,
        attributes_count,
        super::DECODED_VECTOR_SLOT_BYTES,
    )?;
    let mut occurrences_by_namespace = [0_usize; 4];
    bound = checked_bound_add(bound, checked_u64(name.len())?)?;
    for _ in 0..attributes_count {
        let namespace = decode_namespace(input.u8()?)?;
        let key = input.raw_string(limits.key_path_bytes)?;
        decoded_bytes = decoded_bytes
            .checked_add(key.len())
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        bound = checked_bound_add(bound, checked_u64(key.len())?)?;
        let count = input.count(limits.occurrences_per_namespace)?;
        if count == 0 {
            return Err(TraceStoreFailure::malformed_block());
        }
        let index = namespace_index(namespace);
        occurrences_by_namespace[index] = occurrences_by_namespace[index]
            .checked_add(count)
            .filter(|total| *total <= limits.occurrences_per_namespace)
            .ok_or_else(TraceStoreFailure::malformed_block)?;
        bound = checked_slot_bound(bound, count, super::DECODED_VECTOR_SLOT_BYTES)?;
        for _ in 0..count {
            let value = preflight_value(input, limits.nesting_depth, limits)?;
            decoded_bytes = decoded_bytes
                .checked_add(value.decoded_bytes)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            bound = checked_bound_add(bound, value.dynamic_bytes)?;
        }
    }
    if decoded_bytes > limits.decoded_bytes {
        return Err(TraceStoreFailure::malformed_block());
    }
    preflight_policy(input, &mut bound)?;
    let _ = input.i64()?;
    let dynamic = bound
        .checked_sub(super::DECODED_RECORD_SLOT_BYTES)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    checked_bound_add(
        super::DECODED_RECORD_SLOT_BYTES,
        dynamic
            .checked_mul(2)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?,
    )
}

fn preflight_value(
    input: &mut Input<'_>,
    depth: u8,
    limits: &TraceLimits,
) -> Result<ValueBound, TraceStoreFailure> {
    match input.u8()? {
        0 => Ok(ValueBound {
            decoded_bytes: 0,
            dynamic_bytes: 0,
        }),
        1 => {
            let value = input.u8()?;
            if value > 1 {
                return Err(TraceStoreFailure::malformed_block());
            }
            Ok(ValueBound {
                decoded_bytes: 1,
                dynamic_bytes: 0,
            })
        },
        2 | 3 => {
            let _ = input.u64()?;
            Ok(ValueBound {
                decoded_bytes: 8,
                dynamic_bytes: 0,
            })
        },
        4 => {
            let value = input.raw_string(limits.value_bytes)?;
            Ok(ValueBound {
                decoded_bytes: value.len(),
                dynamic_bytes: u64::try_from(value.len())
                    .map_err(|_| TraceStoreFailure::limit_exceeded())?,
            })
        },
        5 => {
            let value = input.raw_bytes(limits.value_bytes)?;
            Ok(ValueBound {
                decoded_bytes: value.len(),
                dynamic_bytes: u64::try_from(value.len())
                    .map_err(|_| TraceStoreFailure::limit_exceeded())?,
            })
        },
        6 => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::malformed_block)?;
            let count = input.count(limits.array_entries)?;
            let mut result = ValueBound {
                decoded_bytes: 0,
                dynamic_bytes: checked_slot_bound(0, count, super::DECODED_VECTOR_SLOT_BYTES)?,
            };
            for _ in 0..count {
                let child = preflight_value(input, next, limits)?;
                result.decoded_bytes = result
                    .decoded_bytes
                    .checked_add(child.decoded_bytes)
                    .filter(|bytes| *bytes <= limits.value_bytes)
                    .ok_or_else(TraceStoreFailure::malformed_block)?;
                result.dynamic_bytes =
                    checked_bound_add(result.dynamic_bytes, child.dynamic_bytes)?;
            }
            Ok(result)
        },
        7 => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::malformed_block)?;
            let count = input.count(limits.key_value_list_entries)?;
            let mut result = ValueBound {
                decoded_bytes: 0,
                dynamic_bytes: checked_slot_bound(0, count, super::DECODED_KEY_VALUE_SLOT_BYTES)?,
            };
            for _ in 0..count {
                let key = input.raw_string(limits.key_path_bytes)?;
                result.decoded_bytes = result
                    .decoded_bytes
                    .checked_add(key.len())
                    .filter(|bytes| *bytes <= limits.value_bytes)
                    .ok_or_else(TraceStoreFailure::malformed_block)?;
                result.dynamic_bytes =
                    checked_bound_add(result.dynamic_bytes, checked_u64(key.len())?)?;
                let child = preflight_value(input, next, limits)?;
                result.decoded_bytes = result
                    .decoded_bytes
                    .checked_add(child.decoded_bytes)
                    .filter(|bytes| *bytes <= limits.value_bytes)
                    .ok_or_else(TraceStoreFailure::malformed_block)?;
                result.dynamic_bytes =
                    checked_bound_add(result.dynamic_bytes, child.dynamic_bytes)?;
            }
            Ok(result)
        },
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}

fn preflight_time(input: &mut Input<'_>) -> Result<(), TraceStoreFailure> {
    let quality = decode_quality(input.u8()?)?;
    if quality != SourceTimeQuality::Missing {
        let _ = input.i64()?;
    }
    Ok(())
}

pub(crate) fn preflight_policy(
    input: &mut Input<'_>,
    bound: &mut u64,
) -> Result<(), TraceStoreFailure> {
    let generation = input.u64()?;
    let digest = input.array::<32>()?;
    let count = input.count(positron_policy::PolicyProvenance::MAX_APPLIED_RULES)?;
    positron_policy::PolicyProvenance::validate_parts(generation, digest, std::iter::empty())
        .map_err(|_| TraceStoreFailure::malformed_block())?;
    *bound = checked_bound_add(
        *bound,
        checked_bound_mul(
            checked_u64(count)?,
            checked_u64(std::mem::size_of::<String>())?,
        )?,
    )?;
    for _ in 0..count {
        let rule = input.raw_string(positron_policy::PolicyProvenance::MAX_RULE_ID_BYTES)?;
        if rule.is_empty() {
            return Err(TraceStoreFailure::malformed_block());
        }
        *bound = checked_bound_add(*bound, checked_u64(rule.len())?)?;
    }
    Ok(())
}

fn checked_bound_add(left: u64, right: u64) -> Result<u64, TraceStoreFailure> {
    left.checked_add(right)
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}

fn checked_u64(value: usize) -> Result<u64, TraceStoreFailure> {
    u64::try_from(value).map_err(|_| TraceStoreFailure::limit_exceeded())
}

fn checked_bound_mul(left: u64, right: u64) -> Result<u64, TraceStoreFailure> {
    left.checked_mul(right)
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}

fn checked_slot_bound(total: u64, count: usize, slot_bytes: u64) -> Result<u64, TraceStoreFailure> {
    let count = checked_u64(count)?;
    checked_bound_add(total, checked_bound_mul(count, slot_bytes)?)
}
