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
    memory: &mut crate::memory::QueryMemory,
) -> Result<crate::memory::RecordBuffer, QueryFailure> {
    let operator_count = state
        .plan
        .operator_count()
        .saturating_sub(u64::from(predicate_applied));
    let mut records = crate::memory::RecordBuffer::allocate(scanned.records().len(), memory)?;
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
        if let Some(record) = query_record(service, state, &mut record, predicate_applied, memory)?
        {
            let dynamic_bytes = record.retained_dynamic_bytes()?;
            transferred_body_bytes = transferred_body_bytes
                .checked_add(record.body_retained_bytes())
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            records.push_acquired(record, dynamic_bytes)?;
        }
    }
    let released_scan_bytes = scanned_retained_bytes
        .checked_sub(transferred_body_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    memory.release(released_scan_bytes)?;

    if let Some(aggregate) = state.plan.aggregate().cloned() {
        return aggregate_records(service, state, records, &aggregate, memory);
    }
    check_cancellation(state)?;
    sort_records(service, state, records.as_mut_slice())?;
    check_cancellation(state)?;
    Ok(records)
}

fn sort_records<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    records: &mut [QueryRecord],
) -> Result<(), QueryFailure> {
    let length = records.len();
    if length < 2 {
        return Ok(());
    }
    for root in (0..(length / 2)).rev() {
        sift_down(service, state, records, root, length)?;
    }
    for end in (1..length).rev() {
        checked_swap(records, 0, end)?;
        sift_down(service, state, records, 0, end)?;
    }
    Ok(())
}

fn sift_down<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    records: &mut [QueryRecord],
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
            .get(left_child)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let greater_child = if right_child < end
            && compare_with_work(
                service,
                state,
                left_record,
                records
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
                .get(root)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            records
                .get(greater_child)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
        )? != Ordering::Less
        {
            return Ok(());
        }
        checked_swap(records, root, greater_child)?;
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

fn checked_swap(
    records: &mut [QueryRecord],
    left: usize,
    right: usize,
) -> Result<(), QueryFailure> {
    if left >= records.len() || right >= records.len() {
        return Err(QueryFailure::new(QueryFailureCode::Internal));
    }
    records.swap(left, right);
    Ok(())
}

fn check_cancellation(state: &CursorState) -> Result<(), QueryFailure> {
    if state.cancellation.is_cancelled() {
        Err(QueryFailure::new(QueryFailureCode::Cancelled))
    } else {
        Ok(())
    }
}
