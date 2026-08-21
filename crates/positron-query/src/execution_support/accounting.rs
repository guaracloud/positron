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
    charge_work_counter(&mut state.cpu_work_units, cpu_work_units)
}

pub(crate) fn charge_work_counter(
    consumed: &mut u64,
    cpu_work_units: u64,
) -> Result<(), QueryFailure> {
    *consumed = consumed
        .checked_add(cpu_work_units)
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::CpuWorkUnits))?;
    Ok(())
}

pub(crate) const fn cpu_work_exhausted(consumed: u64, limit: u64) -> bool {
    consumed > limit
}

pub(crate) fn charge_output(
    service: &crate::QueryService<'_, '_, '_>,
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
        let mut observer = super::QueryValueObserver::new(
            service,
            &mut state.cpu_work_units,
            state.budget.cpu_work_units(),
            cancellation.clone(),
            crate::QueryWorkStage::Output,
        );
        page_bytes = page_bytes
            .checked_add(record_emitted_size_bytes(record, &mut observer)?)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    }
    state.output_bytes = state
        .output_bytes
        .checked_add(page_bytes)
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputBytes))?;
    Ok(())
}

fn record_emitted_size_bytes(
    record: &QueryRecord,
    observer: &mut impl positron_domain::value::NativeValueObserver<Error = QueryFailure>,
) -> Result<u64, QueryFailure> {
    let body_bytes = if record.body_selected() {
        let encoded = record
            .body_value()
            .map_or(Ok(0), |body| {
                body.canonical_encoded_size_bytes_observed(observer)
            })
            .map_err(super::map_observed_failure)?;
        checked_u64(encoded)?.checked_add(1).ok_or(INTERNAL)?
    } else {
        0
    };
    let query_time_bytes = if record.query_time_selected() {
        record.query_time_value().ok_or(INTERNAL)?;
        9
    } else {
        0
    };
    let event_time_bytes = if record.event_time_selected() {
        let value = record.event_time_value().ok_or(INTERNAL)?;
        2 + u64::from(value.instant().is_some()) * 8
    } else {
        0
    };
    let ingest_time_bytes = if record.ingest_time_selected() {
        record.ingest_time_value().ok_or(INTERNAL)?;
        8
    } else {
        0
    };
    let mut attribute_bytes = 0_u64;
    for projected in record.attribute_projections() {
        let crate::stream::AttributeProjection::Attribute(value) = projected else {
            continue;
        };
        let encoded = value
            .as_ref()
            .map_or(Ok(0), |set| {
                set.canonical_encoded_size_bytes_observed(observer)
            })
            .map_err(super::map_observed_failure)?;
        attribute_bytes = attribute_bytes
            .checked_add(1)
            .and_then(|value| value.checked_add(checked_u64(encoded).ok()?))
            .ok_or(INTERNAL)?;
    }
    body_bytes
        .checked_add(query_time_bytes)
        .and_then(|value| value.checked_add(event_time_bytes))
        .and_then(|value| value.checked_add(ingest_time_bytes))
        .and_then(|value| value.checked_add(u64::from(record.commit_position_selected()) * 8))
        .and_then(|value| value.checked_add(u64::from(record.count().is_some()) * 8))
        .and_then(|value| value.checked_add(attribute_bytes))
        .ok_or(INTERNAL)
}

const INTERNAL: QueryFailure = QueryFailure::new(QueryFailureCode::Internal);

fn checked_u64(value: usize) -> Result<u64, QueryFailure> {
    u64::try_from(value).map_err(|_| INTERNAL)
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
