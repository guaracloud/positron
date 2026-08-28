use positron_domain::routing::CommitPosition;
use positron_kernel::ControlTokenProtector;

use super::{TailCursorState, invalid, resource};
use crate::{QueryFailure, QueryFailureCode};

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

pub(super) fn array_at<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], QueryFailure> {
    array_at_at(bytes, start)
}

pub(super) fn array_at_at<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], QueryFailure> {
    bytes
        .get(start..start.checked_add(N).ok_or_else(invalid)?)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())
}

pub(super) fn u16_at(bytes: &[u8], start: usize) -> Result<u16, QueryFailure> {
    Ok(u16::from_be_bytes(array_at(bytes, start)?))
}

pub(super) fn u32_at(bytes: &[u8], start: usize) -> Result<u32, QueryFailure> {
    Ok(u32::from_be_bytes(array_at(bytes, start)?))
}

pub(super) fn u64_at(bytes: &[u8], start: usize) -> Result<u64, QueryFailure> {
    Ok(u64::from_be_bytes(array_at(bytes, start)?))
}

pub(super) fn commit_position(value: u64) -> Result<CommitPosition, QueryFailure> {
    match std::num::NonZeroU64::new(value) {
        Some(value) => CommitPosition::origin()
            .advance_by(value)
            .map_err(|_| invalid()),
        None => Ok(CommitPosition::origin()),
    }
}

pub(super) fn extension_bytes(state: &TailCursorState) -> Result<usize, QueryFailure> {
    let has_extension = state.historical_markers().is_some()
        || state.memory_peak_bytes() != 0
        || state.elapsed_seconds() != 0
        || state.reduced_pruning()
        || state.limiting_budget().is_some()
        || state.source_bindings().is_some()
        || state.unacknowledged_delivery().is_some();
    if !has_extension {
        return Ok(0);
    }
    let markers = state.historical_markers().map_or(0, <[_]>::len);
    let historical_key = if state.historical_markers().is_some() {
        crate::result_key::HISTORICAL_TOTAL_KEY_BYTES + 1
    } else {
        0
    };
    let bindings = state.source_bindings().map_or(Ok(0), |bindings| {
        bindings
            .len()
            .checked_mul(24)
            .and_then(|bytes| {
                4_usize
                    .checked_add(2)?
                    .checked_add(32)?
                    .checked_add(8)?
                    .checked_add(bytes)
            })
            .ok_or_else(resource)
    })?;
    let delivery = state.unacknowledged_delivery().map_or(0, |_| 4 + 8 + 32);
    4_usize
        .checked_add(2)
        .and_then(|value| value.checked_add(markers.checked_mul(16)?))
        .and_then(|value| value.checked_add(18))
        .and_then(|value| value.checked_add(historical_key))
        .and_then(|value| value.checked_add(bindings))
        .and_then(|value| value.checked_add(delivery))
        .ok_or_else(resource)
}

pub(super) fn limiting_budget_code(dimension: Option<crate::QueryBudgetDimension>) -> u8 {
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

pub(super) fn limiting_budget_from_code(
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
