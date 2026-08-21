use crate::cursor::CursorState;
use crate::execution_support::{
    aggregate_records, charge_work, compare_records, exhausted, query_record,
};
use crate::{QueryFailure, QueryFailureCode, QueryRecord, QueryService, QueryWorkStage};

pub(crate) fn execute<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    state: &mut CursorState,
    scanned: &[positron_signals::ScannedLogRecord],
) -> Result<Vec<QueryRecord>, QueryFailure> {
    let operator_count = state.plan.operator_count();
    let mut records = Vec::with_capacity(scanned.len());
    for record in scanned {
        check_cancellation(state)?;
        if operator_count > 0 {
            let operator_units = service
                .work_units(QueryWorkStage::Operators)?
                .checked_mul(operator_count)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
            check_cancellation(state)?;
            charge_work(state, operator_units)?;
            if exhausted(state) {
                return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
            }
        }
        if let Some(record) = query_record(record, &state.plan) {
            records.push(record);
        }
    }

    if let Some(aggregate) = state.plan.aggregate().cloned() {
        return aggregate_records(
            records,
            &aggregate,
            state.budget.memory_bytes(),
            &state.cancellation,
        );
    }
    check_cancellation(state)?;
    records.sort_by(|left, right| compare_records(left, right, state.plan.ordering()));
    check_cancellation(state)?;
    Ok(records)
}

fn check_cancellation(state: &CursorState) -> Result<(), QueryFailure> {
    if state.cancellation.is_cancelled() {
        Err(QueryFailure::new(QueryFailureCode::Cancelled))
    } else {
        Ok(())
    }
}
