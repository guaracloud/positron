use positron_kernel::LedgerSnapshot;
use positron_signals::{LogScan, LogStore, ScanLimit};

use crate::cursor::{self, CursorState};
use crate::execution_state::{commit_position, stats_before_current, stats_with_current};
use crate::execution_support::{
    BatchDigestInput, QueryScanObserver, batch_digest, charge_output, charge_scan, limiting_budget,
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
        schema: Option<&positron_signals::SchemaCatalog>,
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
            return self.failed_page(
                None,
                QueryFailure::budget_exhausted(crate::QueryBudgetDimension::WallSeconds),
                &state,
                delivered_before,
                resources,
            );
        }
        let frontier = match commit_position(state.frontier) {
            Ok(frontier) => frontier,
            Err(failure) => return Err(resources.fail_before_stream(self.ledger, failure)),
        };
        let initial_cursor = match pagination
            .then(|| cursor::encode(&self.ledger.control_tokens(), state.clone()))
            .transpose()
        {
            Ok(cursor) => cursor,
            Err(failure) => return Err(resources.fail_before_stream(self.ledger, failure)),
        };
        let header = match QueryHeader::new(
            state.plan.clone(),
            state.budget,
            ResultSnapshot::new(
                state.catalog_identity,
                state.catalog_generation,
                state.frontier,
            ),
            ResultLease::new(state.lease_identity, state.expiry),
            initial_cursor,
        ) {
            Ok(header) => QueryEvent::Header(header),
            Err(failure) => return Err(resources.fail_before_stream(self.ledger, failure)),
        };
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
        let mut observer = QueryScanObserver::new(
            self.work_meter.as_ref(),
            state.cancellation.clone(),
            state.cpu_work_units,
            state.budget.cpu_work_units(),
        );
        let schema_query = state.plan.schema_query();
        let schema_filter_used = schema.zip(schema_query).is_some();
        let text_candidate = framed!(state.plan.text_search_candidate());
        let text_filter_used = schema.zip(text_candidate.as_ref()).is_some();
        let scan_result = match (schema, schema_query, text_candidate.as_ref()) {
            (Some(schema), None, Some(candidate)) => LogStore::new().scan_text_observed(
                self.governor,
                state.tenant,
                snapshot,
                LogScan::through(scan_limit, frontier),
                schema,
                candidate,
                &state.cancellation,
                &observer,
            ),
            (Some(schema), Some(query), _) => LogStore::new().scan_schema_observed(
                self.governor,
                state.tenant,
                snapshot,
                LogScan::through(scan_limit, frontier),
                schema,
                query,
                &state.cancellation,
                &mut observer,
            ),
            _ => LogStore::new().scan_observed(
                self.governor,
                state.tenant,
                snapshot,
                LogScan::through(scan_limit, frontier),
                &state.cancellation,
                &observer,
            ),
        };
        state.cpu_work_units = observer.consumed();
        let result = framed!(scan_result.map_err(map_store_failure));
        state.reduced_pruning |= result.reduced_pruning();
        framed!(charge_scan(&mut state, &result));
        let mut memory = crate::memory::QueryMemory::new(state.budget.memory_bytes());
        framed!(memory.acquire(result.retained_size_bytes()));
        if state.cancellation.is_cancelled() {
            return self.failed_page(
                Some(header),
                QueryFailure::new(QueryFailureCode::Cancelled),
                &state,
                delivered_before,
                resources,
            );
        }
        let wall_exhausted = framed!(self.observe_state(&mut state));
        if wall_exhausted || limiting_budget(&state).is_some() || !result.complete() {
            let dimension =
                limiting_budget(&state).unwrap_or(crate::QueryBudgetDimension::DecodedRecords);
            return self.failed_page(
                Some(header),
                QueryFailure::budget_exhausted(dimension),
                &state,
                delivered_before,
                resources,
            );
        }

        let has_operator_work = state.plan.has_advanced_operators();
        state.reduced_pruning |= state.plan.requires_post_decode_predicate_fallback()
            && !schema_filter_used
            && !text_filter_used;
        let records = framed!(crate::operators::execute(
            self,
            &mut state,
            result,
            schema_filter_used,
            &mut memory,
        ));
        let operator_wall_exhausted = if has_operator_work {
            framed!(self.observe_state(&mut state))
        } else {
            false
        };
        if operator_wall_exhausted {
            return self.failed_page(
                Some(header),
                QueryFailure::budget_exhausted(crate::QueryBudgetDimension::WallSeconds),
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
        if state.cancellation.is_cancelled() {
            return self.failed_page_with_stats(
                Some(header),
                QueryFailure::new(QueryFailureCode::Cancelled),
                &state,
                delivered_before,
                before_batch,
                resources,
            );
        }
        let output_wall_exhausted = framed!(self.observe_state(&mut state));
        if output_wall_exhausted || limiting_budget(&state).is_some() {
            let dimension =
                limiting_budget(&state).unwrap_or(crate::QueryBudgetDimension::WallSeconds);
            return self.failed_page(
                Some(header),
                QueryFailure::budget_exhausted(dimension),
                &state,
                delivered_before,
                resources,
            );
        }
        let mut output_state = state.clone();
        if let Err(failure) = charge_output(self, &mut output_state, &page, &state.cancellation) {
            state.cpu_work_units = output_state.cpu_work_units;
            return self.failed_page(Some(header), failure, &state, delivered_before, resources);
        }
        if let Some(dimension) = limiting_budget(&output_state) {
            return self.failed_page_with_stats(
                Some(header),
                QueryFailure::budget_exhausted(dimension),
                &state,
                delivered_before,
                before_batch,
                resources,
            );
        }
        state.cpu_work_units = output_state.cpu_work_units;
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
        let digest_cancellation = state.cancellation.clone();
        let digest_limit = state.budget.cpu_work_units();
        let mut digest_observer = crate::execution_support::QueryValueObserver::new(
            self,
            &mut state.cpu_work_units,
            digest_limit,
            digest_cancellation.clone(),
            crate::QueryWorkStage::Output,
        );
        let digest = framed!(batch_digest(
            &self.ledger.control_tokens(),
            BatchDigestInput {
                prior: state.prior_digest,
                sequence: state.sequence,
                plan: &state.plan,
                records: &page,
                cancellation: &digest_cancellation,
                observer: &mut digest_observer,
            },
            &mut memory,
        ));
        let post_digest_expired = framed!(self.observe_state(&mut state));
        if post_digest_expired {
            return self.failed_page(
                Some(header),
                QueryFailure::budget_exhausted(crate::QueryBudgetDimension::WallSeconds),
                &state,
                delivered_before,
                resources,
            );
        }
        output_state.last_observed_at = state.last_observed_at;
        output_state.elapsed_wall_seconds = state.elapsed_wall_seconds;
        output_state.cpu_work_units = state.cpu_work_units;
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
