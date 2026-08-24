use crate::cursor::CursorState;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord};

pub(crate) fn charge_scan(
    state: &mut CursorState,
    result: &positron_signals::LogScanResult<'_>,
) -> Result<(), QueryFailure> {
    state.physical_scanned_bytes = state
        .physical_scanned_bytes
        .checked_add(result.scanned_bytes())
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::ScannedBytes))?;
    state.physical_decoded_records = state
        .physical_decoded_records
        .checked_add(result.decoded_records())
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::DecodedRecords))?;
    Ok(())
}

pub(crate) fn charge_work(
    state: &mut CursorState,
    cpu_work_units: u64,
) -> Result<(), QueryFailure> {
    charge_work_counter(&mut state.physical_cpu_work_units, cpu_work_units)
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
    logical_delivery: bool,
) -> Result<(), QueryFailure> {
    let rows = u64::try_from(page.len())
        .map_err(|_| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputRows))?;
    state.physical_output_rows = state
        .physical_output_rows
        .checked_add(rows)
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputRows))?;
    if logical_delivery {
        state.output_rows = state
            .output_rows
            .checked_add(rows)
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputRows))?;
    }
    let mut page_bytes = 0_u64;
    for record in page {
        let mut observer = super::QueryValueObserver::new(
            service,
            &mut state.physical_cpu_work_units,
            state.budget.cpu_work_units(),
            cancellation.clone(),
            crate::QueryWorkStage::Output,
        );
        page_bytes = page_bytes
            .checked_add(record_emitted_size_bytes(record, &mut observer)?)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    }
    state.physical_output_bytes = state
        .physical_output_bytes
        .checked_add(page_bytes)
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputBytes))?;
    if logical_delivery {
        state.output_bytes = state
            .output_bytes
            .checked_add(page_bytes)
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputBytes))?;
    }
    Ok(())
}

pub(crate) fn preserve_output_attempt(state: &mut CursorState, output_state: &CursorState) {
    state.physical_output_rows = output_state.physical_output_rows;
    state.physical_output_bytes = output_state.physical_output_bytes;
    state.physical_cpu_work_units = output_state.physical_cpu_work_units;
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
    if state.physical_scanned_bytes > state.budget.scanned_bytes() {
        Some(QueryBudgetDimension::ScannedBytes)
    } else if state.physical_decoded_records > state.budget.decoded_records() {
        Some(QueryBudgetDimension::DecodedRecords)
    } else if state.physical_output_rows > state.budget.output_rows() {
        Some(QueryBudgetDimension::OutputRows)
    } else if state.physical_output_bytes > state.budget.output_bytes() {
        Some(QueryBudgetDimension::OutputBytes)
    } else if state.physical_cpu_work_units > state.budget.cpu_work_units() {
        Some(QueryBudgetDimension::CpuWorkUnits)
    } else if state.physical_elapsed_wall_seconds >= state.budget.wall_seconds() {
        Some(QueryBudgetDimension::WallSeconds)
    } else {
        None
    }
}

pub(crate) fn exhausted(state: &CursorState) -> bool {
    limiting_budget(state).is_some()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use positron_domain::identity::{PrincipalId, TenantId};

    use super::limiting_budget;
    use crate::cursor::CursorState;
    use crate::{
        LogicalPlan, QueryBudget, QueryBudgetDimension, QueryCancellation, TemporalAxis,
        TemporalRange,
    };

    fn state() -> CursorState {
        CursorState {
            principal: PrincipalId::from_bytes([1; 16]).expect("test principal"),
            tenant: TenantId::from_bytes([2; 16]).expect("test tenant"),
            authorization_generation: 1,
            catalog_identity: [3; 32],
            catalog_generation: 1,
            frontier: 1,
            plan: Arc::new(LogicalPlan::logs(
                TemporalAxis::QueryTime,
                TemporalRange::new(-1, 1).expect("test range"),
                1,
            )),
            source: None,
            language: None,
            plan_digest: [4; 32],
            resume_key: None,
            sequence: 0,
            prior_digest: [0; 32],
            lease_identity: [5; 16],
            expiry: 10,
            budget: QueryBudget::new(10, 10, 10, 10, 10, 10).expect("test budget"),
            scanned_bytes: 0,
            decoded_records: 0,
            physical_scanned_bytes: 0,
            physical_decoded_records: 0,
            output_rows: 0,
            output_bytes: 0,
            physical_output_rows: 0,
            physical_output_bytes: 0,
            memory_peak_bytes: 0,
            physical_memory_peak_bytes: 0,
            started_at: 0,
            last_observed_at: 0,
            cpu_work_units: 0,
            elapsed_wall_seconds: 0,
            physical_cpu_work_units: 0,
            physical_elapsed_wall_seconds: 0,
            reduced_pruning: false,
            resume_count: 0,
            repeated_batch_count: 0,
            cancellation: QueryCancellation::new(),
        }
    }

    #[test]
    fn limiting_budget_reports_scan_before_decode_overrun() {
        let mut scan = state();
        scan.physical_scanned_bytes = scan.budget.scanned_bytes() + 1;
        assert_eq!(
            limiting_budget(&scan),
            Some(QueryBudgetDimension::ScannedBytes)
        );

        let mut decode = state();
        decode.physical_decoded_records = decode.budget.decoded_records() + 1;
        assert_eq!(
            limiting_budget(&decode),
            Some(QueryBudgetDimension::DecodedRecords)
        );
    }
}
