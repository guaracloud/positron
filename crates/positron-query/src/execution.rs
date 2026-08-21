use positron_kernel::LedgerSnapshot;
use positron_signals::{LogScan, LogStore, ScanLimit};

use crate::cursor::{self, CursorState};
use crate::execution_state::{commit_position, stats_before_current, stats_with_current};
use crate::execution_support::{
    QueryScanObserver, batch_digest, charge_output, charge_scan, charge_work, exhausted,
    map_store_failure,
};
use crate::{
    QueryBatch, QueryEvent, QueryFailure, QueryFailureCode, QueryHeader, QueryService, QueryStream,
    QueryTerminal, ResultLease, ResultSnapshot,
};

const MAX_SCAN_RECORDS: usize = 1_024;

mod entry;
mod lifecycle;
mod resources;

use resources::ExecutionResources;

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub(super) fn run_page(
        &self,
        mut state: CursorState,
        snapshot: &LedgerSnapshot<'kernel>,
        batch_limit: u16,
        pagination: bool,
        resources: ExecutionResources,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let delivered_before = stats_before_current(&state);
        let initially_exhausted = match self.observe_state(&mut state) {
            Ok(exhausted) => exhausted,
            Err(failure) => {
                return Err(resources.fail_before_stream(self.ledger, failure));
            },
        };
        if initially_exhausted {
            return self.stopped_page(
                None,
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
                resources,
            );
        }
        let frontier = commit_position(state.frontier)?;
        let initial_cursor = pagination
            .then(|| cursor::encode(&self.ledger.control_tokens(), state.clone()))
            .transpose()?;
        let header = QueryEvent::Header(QueryHeader::new(
            state.plan.clone(),
            state.budget,
            ResultSnapshot::new(
                state.catalog_identity,
                state.catalog_generation,
                state.frontier,
            ),
            ResultLease::new(state.lease_identity, state.expiry),
            initial_cursor,
        )?);
        macro_rules! framed {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(failure) => {
                        return self.failed_page(
                            Some(header),
                            failure,
                            &state,
                            delivered_before,
                            resources,
                        );
                    },
                }
            };
        }
        let scan_limit = framed!(
            usize::try_from(state.budget.decoded_records())
                .ok()
                .map(|limit| limit.min(MAX_SCAN_RECORDS))
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))
        );
        let scan_limit = framed!(
            ScanLimit::new(scan_limit).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
        );
        let observer = QueryScanObserver::new(
            self.work_meter.as_ref(),
            state.cancellation.clone(),
            state.cpu_work_units,
            state.budget.cpu_work_units(),
        );
        let scan_result = LogStore::new().scan_observed(
            self.governor,
            state.tenant,
            snapshot,
            LogScan::through(scan_limit, frontier),
            &state.cancellation,
            &observer,
        );
        state.cpu_work_units = observer.consumed();
        let result = framed!(scan_result.map_err(map_store_failure));
        let scan_work = framed!(self.work_units(crate::QueryWorkStage::ScanDecode));
        framed!(charge_scan(&mut state, &result, scan_work));
        let mut memory = crate::memory::QueryMemory::new(state.budget.memory_bytes());
        framed!(memory.acquire(result.retained_size_bytes()));
        if state.cancellation.is_cancelled() {
            return self.stopped_page(
                Some(header),
                QueryFailureCode::Cancelled,
                &state,
                delivered_before,
                resources,
            );
        }
        let wall_exhausted = framed!(self.observe_state(&mut state));
        if wall_exhausted || exhausted(&state) || !result.complete() {
            return self.stopped_page(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
                resources,
            );
        }

        let operator_count = state.plan.operator_count();
        let records = framed!(crate::operators::execute(
            self,
            &mut state,
            result,
            &mut memory,
        ));
        let operator_wall_exhausted = if operator_count > 0 {
            framed!(self.observe_state(&mut state))
        } else {
            false
        };
        if operator_wall_exhausted {
            return self.stopped_page(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
                resources,
            );
        }

        let wanted = usize::from(state.plan.limit()).min(records.len());
        let start = usize::from(state.offset);
        let end = framed!(
            start
                .checked_add(usize::from(batch_limit))
                .map(|end| end.min(wanted))
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))
        );
        let page = framed!(materialize_page(records, start, end, &mut memory));
        let before_batch = stats_before_current(&state);
        let output_work = framed!(self.work_units(crate::QueryWorkStage::Output));
        framed!(charge_work(&mut state, output_work));
        if state.cancellation.is_cancelled() {
            return self.stopped_page_with_stats(
                Some(header),
                QueryFailureCode::Cancelled,
                &state,
                delivered_before,
                before_batch,
                resources,
            );
        }
        let output_wall_exhausted = framed!(self.observe_state(&mut state));
        if output_wall_exhausted || exhausted(&state) {
            return self.stopped_page(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
                resources,
            );
        }
        let mut output_state = state.clone();
        framed!(charge_output(&mut output_state, &page, &state.cancellation,));
        if exhausted(&output_state) {
            return self.stopped_page_with_stats(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
                before_batch,
                resources,
            );
        }
        if page.is_empty() {
            state = output_state;
            let stats = stats_before_current(&state);
            return self.stream(
                vec![header, QueryEvent::Terminal(QueryTerminal::Complete(stats))],
                &state,
                pagination,
                delivered_before,
                stats,
                resources,
            );
        }
        let digest = framed!(batch_digest(
            &self.ledger.control_tokens(),
            state.prior_digest,
            state.sequence,
            &state.plan,
            &page,
            &state.cancellation,
            &mut memory,
        ));
        let post_digest_expired = framed!(self.observe_state(&mut state));
        if post_digest_expired {
            return self.stopped_page(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
                resources,
            );
        }
        output_state.last_observed_at = state.last_observed_at;
        output_state.elapsed_wall_seconds = state.elapsed_wall_seconds;
        state = output_state;
        let batch = QueryEvent::Batch(QueryBatch::new(
            state.sequence,
            page,
            state.prior_digest,
            digest,
        ));
        let mut delivered_state = state.clone();
        delivered_state.prior_digest = digest;
        let batch_stats = stats_with_current(&delivered_state);
        macro_rules! framed_batch {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(failure) => {
                        return self.incomplete_events(
                            vec![header, batch],
                            failure,
                            &state,
                            delivered_before,
                            batch_stats,
                            resources,
                        );
                    },
                }
            };
        }
        let terminal = if pagination && end < wanted {
            state.offset = framed_batch!(
                u16::try_from(end).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
            );
            state.sequence = framed_batch!(
                state
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))
            );
            state.prior_digest = digest;
            let cursor =
                framed_batch!(cursor::encode(&self.ledger.control_tokens(), state.clone(),));
            QueryTerminal::Continued(cursor)
        } else {
            state.prior_digest = digest;
            QueryTerminal::Complete(stats_with_current(&state))
        };
        self.stream(
            vec![header, batch, QueryEvent::Terminal(terminal)],
            &state,
            pagination,
            delivered_before,
            batch_stats,
            resources,
        )
    }

    fn observe_state(&self, state: &mut CursorState) -> Result<bool, QueryFailure> {
        let now = self.now()?;
        if now < state.last_observed_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        state.last_observed_at = now;
        state.elapsed_wall_seconds = now.saturating_sub(state.started_at);
        Ok(now >= state.expiry)
    }
}

fn materialize_page(
    records: crate::memory::RecordBuffer,
    start: usize,
    end: usize,
    memory: &mut crate::memory::QueryMemory,
) -> Result<Vec<crate::QueryRecord>, QueryFailure> {
    if start > end || end > records.len() {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    let mut page = crate::memory::RecordBuffer::allocate(end - start, memory)?;
    let (records, input_slots, _) = records.into_parts();
    for (index, record) in records.into_iter().enumerate() {
        let dynamic_bytes = record.retained_dynamic_bytes()?;
        if (start..end).contains(&index) {
            page.push_acquired(record, dynamic_bytes)?;
        } else {
            memory.release(dynamic_bytes)?;
        }
    }
    memory.release(input_slots)?;
    Ok(page.into_parts().0)
}
