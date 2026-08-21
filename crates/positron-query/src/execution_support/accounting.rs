use crate::cursor::CursorState;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord};

pub(crate) fn charge_scan(
    state: &mut CursorState,
    result: &positron_signals::LogScanResult<'_>,
) -> Result<(), QueryFailure> {
    state.scanned_bytes = state
        .scanned_bytes
        .checked_add(result.scanned_bytes())
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::ScannedBytes))?;
    state.decoded_records =
        state
            .decoded_records
            .checked_add(u64::try_from(result.records().len()).map_err(|_| {
                QueryFailure::budget_exhausted(QueryBudgetDimension::DecodedRecords)
            })?)
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::DecodedRecords))?;
    Ok(())
}

pub(crate) fn charge_work(
    state: &mut CursorState,
    cpu_work_units: u64,
) -> Result<(), QueryFailure> {
    state.cpu_work_units = state
        .cpu_work_units
        .checked_add(cpu_work_units)
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::CpuWorkUnits))?;
    Ok(())
}

pub(crate) fn charge_output(
    state: &mut CursorState,
    page: &[QueryRecord],
    cancellation: &crate::QueryCancellation,
) -> Result<(), QueryFailure> {
    state.output_rows = state
        .output_rows
        .checked_add(
            u64::try_from(page.len())
                .map_err(|_| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputRows))?,
        )
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputRows))?;
    let mut page_bytes = 0_u64;
    for record in page {
        if cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        page_bytes = page_bytes
            .checked_add(record.emitted_size_bytes()?)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    }
    state.output_bytes = state
        .output_bytes
        .checked_add(page_bytes)
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputBytes))?;
    Ok(())
}

pub(crate) fn limiting_budget(state: &CursorState) -> Option<QueryBudgetDimension> {
    if state.scanned_bytes > state.budget.scanned_bytes() {
        Some(QueryBudgetDimension::ScannedBytes)
    } else if state.decoded_records > state.budget.decoded_records() {
        Some(QueryBudgetDimension::DecodedRecords)
    } else if state.output_rows > state.budget.output_rows() {
        Some(QueryBudgetDimension::OutputRows)
    } else if state.output_bytes > state.budget.output_bytes() {
        Some(QueryBudgetDimension::OutputBytes)
    } else if state.cpu_work_units > state.budget.cpu_work_units() {
        Some(QueryBudgetDimension::CpuWorkUnits)
    } else if state.elapsed_wall_seconds >= state.budget.wall_seconds() {
        Some(QueryBudgetDimension::WallSeconds)
    } else {
        None
    }
}

pub(crate) fn exhausted(state: &CursorState) -> bool {
    limiting_budget(state).is_some()
}
