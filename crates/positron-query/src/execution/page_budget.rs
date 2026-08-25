use super::memory::plan_memory;
use crate::cursor::CursorState;
use crate::memory::QueryMemory;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};
use positron_signals::ScanLimit;

pub(super) fn prepare_page_budget(
    state: &mut CursorState,
) -> Result<(u64, ScanLimit, QueryMemory), QueryFailure> {
    let decoded_remaining = state
        .budget
        .decoded_records()
        .checked_sub(state.physical_decoded_records)
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::DecodedRecords))?;
    if decoded_remaining == 0 {
        return Err(QueryFailure::budget_exhausted(
            QueryBudgetDimension::DecodedRecords,
        ));
    }
    let scanned_remaining = state
        .budget
        .scanned_bytes()
        .checked_sub(state.physical_scanned_bytes)
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::ScannedBytes))?;
    let scan_limit = usize::try_from(decoded_remaining)
        .ok()
        .map(|limit| limit.min(super::scan::MAX_SCAN_RECORDS))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
    let scan_limit =
        ScanLimit::new(scan_limit).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let plan_memory = plan_memory(state)?;
    let execution_memory = state
        .budget
        .memory_bytes()
        .checked_sub(plan_memory)
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes))?;
    state.physical_memory_peak_bytes = state.physical_memory_peak_bytes.max(plan_memory);
    let mut memory = QueryMemory::new(execution_memory);
    memory.acquire(state.plan.search_memory_bytes())?;
    state.physical_memory_peak_bytes = state.physical_memory_peak_bytes.max(memory.peak());
    Ok((scanned_remaining, scan_limit, memory))
}
