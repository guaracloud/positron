use crate::cursor::CursorState;
use crate::execution_support::{
    aggregate_records, charge_work, compare_records, exhausted, query_record,
};
use crate::{
    QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord, QueryService, QueryWorkStage,
};
use std::cmp::Ordering;

pub(crate) fn execute<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    scanned: positron_signals::LogScanResult<'kernel>,
    predicate_applied: bool,
    correlation_spans: Option<&[positron_signals::LogicalSpan]>,
    memory: &mut crate::memory::QueryMemory,
) -> Result<crate::memory::RecordBuffer, QueryFailure> {
    let operator_count = state.plan.operator_count();
    let mut records = crate::memory::RecordBuffer::allocate(
        scanned.records().len(),
        state.plan.is_log_to_trace_correlation(),
        memory,
    )?;
    let scanned_retained_bytes = scanned.retained_size_bytes();
    let mut transferred_body_bytes = 0_u64;
    for mut record in scanned.into_records() {
        check_cancellation(state)?;
        if operator_count > 0 {
            let operator_units = service
                .work_units(QueryWorkStage::Operators)?
                .checked_mul(operator_count)
                .ok_or_else(|| {
                    QueryFailure::budget_exhausted(QueryBudgetDimension::CpuWorkUnits)
                })?;
            check_cancellation(state)?;
            charge_work(state, operator_units)?;
            if exhausted(state) {
                return Err(QueryFailure::budget_exhausted(
                    QueryBudgetDimension::CpuWorkUnits,
                ));
            }
        }
        if let Some(materialized) =
            query_record(service, state, &mut record, predicate_applied, memory)?
        {
            let (record, correlation) = materialized.into_parts();
            let correlation = if state.plan.is_log_to_trace_correlation() {
                let spans = correlation_spans
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
                Some(correlation_outcome(
                    service,
                    state,
                    correlation.trace_id(),
                    correlation.span_id(),
                    spans,
                )?)
            } else {
                None
            };
            let dynamic_bytes = record.retained_dynamic_bytes()?;
            transferred_body_bytes = transferred_body_bytes
                .checked_add(record.body_retained_bytes())
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            records.push_acquired(record, dynamic_bytes, correlation)?;
        }
    }
    let released_scan_bytes = if state.plan.transform().is_some() {
        // A transform allocates a fresh query value. Its retained bytes are
        // already charged by `query_record`, so no source body bytes can be
        // transferred out of the scan buffer.
        scanned_retained_bytes
    } else {
        scanned_retained_bytes
            .checked_sub(transferred_body_bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?
    };
    memory.release(released_scan_bytes)?;

    if let Some(aggregate) = state.plan.aggregate().cloned() {
        return aggregate_records(service, state, records, &aggregate, memory);
    }
    check_cancellation(state)?;
    sort_records(service, state, &mut records)?;
    check_cancellation(state)?;
    Ok(records)
}

fn correlation_outcome<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    log_trace_id: Option<[u8; 16]>,
    log_span_id: Option<[u8; 8]>,
    spans: &[positron_signals::LogicalSpan],
) -> Result<crate::CorrelationOutcome, QueryFailure> {
    let Some(trace_id) = log_trace_id else {
        return Ok(crate::CorrelationOutcome::MissingLogTraceId);
    };
    let mut matched = false;
    for span in spans {
        charge_correlation_target_work(service, state)?;
        if span.trace_id() == trace_id
            && log_span_id.is_none_or(|span_id| span.span_id() == span_id)
        {
            if span.conflicted() {
                return Ok(crate::CorrelationOutcome::Ambiguous {
                    trace_id,
                    span_id: log_span_id,
                });
            }
            matched = true;
        }
    }
    if matched {
        Ok(crate::CorrelationOutcome::Matched {
            trace_id,
            span_id: log_span_id,
        })
    } else {
        Ok(crate::CorrelationOutcome::MissingTraceTarget {
            trace_id,
            span_id: log_span_id,
        })
    }
}

fn charge_correlation_target_work<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
) -> Result<(), QueryFailure> {
    check_cancellation(state)?;
    let units = service.work_units(QueryWorkStage::Operators)?;
    check_cancellation(state)?;
    charge_work(state, units)?;
    if exhausted(state) {
        return Err(QueryFailure::budget_exhausted(
            QueryBudgetDimension::CpuWorkUnits,
        ));
    }
    check_cancellation(state)
}

fn sort_records<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    records: &mut crate::memory::RecordBuffer,
) -> Result<(), QueryFailure> {
    let length = records.len();
    if length < 2 {
        return Ok(());
    }
    for root in (0..(length / 2)).rev() {
        sift_down(service, state, records, root, length)?;
    }
    for end in (1..length).rev() {
        records.swap(0, end)?;
        sift_down(service, state, records, 0, end)?;
    }
    Ok(())
}

fn sift_down<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    records: &mut crate::memory::RecordBuffer,
    mut root: usize,
    end: usize,
) -> Result<(), QueryFailure> {
    loop {
        let Some(left_child) = root.checked_mul(2).and_then(|value| value.checked_add(1)) else {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        };
        if left_child >= end {
            return Ok(());
        }
        let right_child = left_child
            .checked_add(1)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let left_record = records
            .as_slice()
            .get(left_child)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let greater_child = if right_child < end
            && compare_with_work(
                service,
                state,
                left_record,
                records
                    .as_slice()
                    .get(right_child)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            )? == Ordering::Less
        {
            right_child
        } else {
            left_child
        };
        if compare_with_work(
            service,
            state,
            records
                .as_slice()
                .get(root)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            records
                .as_slice()
                .get(greater_child)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
        )? != Ordering::Less
        {
            return Ok(());
        }
        records.swap(root, greater_child)?;
        root = greater_child;
    }
}

fn compare_with_work<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    left: &QueryRecord,
    right: &QueryRecord,
) -> Result<Ordering, QueryFailure> {
    check_cancellation(state)?;
    let work = service.work_units(QueryWorkStage::Operators)?;
    check_cancellation(state)?;
    charge_work(state, work)?;
    if exhausted(state) {
        return Err(QueryFailure::budget_exhausted(
            QueryBudgetDimension::CpuWorkUnits,
        ));
    }
    check_cancellation(state)?;
    Ok(compare_records(left, right, state.plan.ordering()))
}

fn check_cancellation(state: &CursorState) -> Result<(), QueryFailure> {
    if state.cancellation.is_cancelled() {
        Err(QueryFailure::new(QueryFailureCode::Cancelled))
    } else {
        Ok(())
    }
}
