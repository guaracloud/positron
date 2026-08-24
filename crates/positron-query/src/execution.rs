use positron_kernel::LedgerSnapshot;
use positron_signals::ScanLimit;

use crate::cursor::{self, CursorState};
use crate::execution_state::{commit_position, stats_before_current, stats_with_current};
use crate::execution_support::{
    BatchDigestInput, QueryScanObserver, batch_digest, charge_output, charge_scan, limiting_budget,
};
use crate::{
    QueryBatch, QueryEvent, QueryFailure, QueryFailureCode, QueryService, QueryStream,
    QueryTerminal,
};

mod clock;
mod contract;
mod entry;
mod lifecycle;
mod memory;
mod predicates;
mod resources;
mod results;
mod scan;

use contract::initial_header;
use memory::plan_memory;
use predicates::scan_predicates;
use resources::ExecutionResources;
use results::{find_resume_index, materialize_page, resume_key_for_page};

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
        let header = match initial_header(&self.ledger.control_tokens(), &state, pagination) {
            Ok(header) => header,
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
        let decoded_remaining = state
            .budget
            .decoded_records()
            .checked_sub(state.decoded_records)
            .ok_or_else(|| {
                QueryFailure::budget_exhausted(crate::QueryBudgetDimension::DecodedRecords)
            });
        let decoded_remaining = framed!(decoded_remaining);
        if decoded_remaining == 0 {
            return self.failed_page(
                Some(header),
                QueryFailure::budget_exhausted(crate::QueryBudgetDimension::DecodedRecords),
                &state,
                delivered_before,
                resources,
            );
        }
        let scanned_remaining = framed!(
            state
                .budget
                .scanned_bytes()
                .checked_sub(state.scanned_bytes)
                .ok_or_else(|| {
                    QueryFailure::budget_exhausted(crate::QueryBudgetDimension::ScannedBytes)
                })
        );
        let scan_limit = framed!(
            usize::try_from(decoded_remaining)
                .ok()
                .map(|limit| limit.min(scan::MAX_SCAN_RECORDS))
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))
        );
        let scan_limit = framed!(
            ScanLimit::new(scan_limit).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
        );
        let plan_memory = framed!(plan_memory(&state));
        let execution_memory = framed!(
            state
                .budget
                .memory_bytes()
                .checked_sub(plan_memory)
                .ok_or_else(|| QueryFailure::budget_exhausted(
                    crate::QueryBudgetDimension::MemoryBytes
                ))
        );
        state.memory_peak_bytes = state.memory_peak_bytes.max(plan_memory);
        let mut memory = crate::memory::QueryMemory::new(execution_memory);
        framed!(memory.acquire(state.plan.search_memory_bytes()));
        state.memory_peak_bytes = state.memory_peak_bytes.max(memory.peak());
        let mut observer = QueryScanObserver::new(
            self.work_meter.as_ref(),
            state.cancellation.clone(),
            state.cpu_work_units,
            state.budget.cpu_work_units(),
        );
        let (schema_query, schema_filter_used, text_candidate, text_filter_used) =
            framed!(scan_predicates(&state.plan, schema));
        let scan_result = framed!(scan::execute_scan(
            self.governor,
            state.tenant,
            snapshot,
            frontier,
            scan_limit,
            scanned_remaining,
            schema,
            schema_query,
            text_candidate.as_ref(),
            &state.cancellation,
            &mut observer,
        ));
        state.cpu_work_units = observer.consumed();
        let result = scan_result;
        state.reduced_pruning |= result.reduced_pruning();
        framed!(charge_scan(&mut state, &result));
        framed!(memory.acquire(result.retained_size_bytes()));
        state.memory_peak_bytes = state.memory_peak_bytes.max(memory.peak());
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
            let dimension = limiting_budget(&state).unwrap_or_else(|| {
                if result.scanned_bytes_limited() {
                    crate::QueryBudgetDimension::ScannedBytes
                } else {
                    crate::QueryBudgetDimension::DecodedRecords
                }
            });
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
        state.memory_peak_bytes = state.memory_peak_bytes.max(memory.peak());
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

        let output_rows_remaining = state
            .budget
            .output_rows()
            .checked_sub(state.output_rows)
            .ok_or_else(|| QueryFailure::budget_exhausted(crate::QueryBudgetDimension::OutputRows));
        let output_rows_remaining = framed!(output_rows_remaining);
        let wanted = usize::from(state.plan.limit()).min(records.len());
        let start = match state.resume_key {
            Some(key) => framed!(find_resume_index(
                self,
                &mut state,
                records.as_slice(),
                key,
                &mut memory,
            )),
            None => 0,
        };
        if start > wanted {
            return self.failed_page(
                Some(header),
                QueryFailure::new(QueryFailureCode::InvalidCursor),
                &state,
                delivered_before,
                resources,
            );
        }
        let page_capacity = usize::try_from(output_rows_remaining)
            .unwrap_or(usize::MAX)
            .min(usize::from(batch_limit));
        let end = framed!(
            start
                .checked_add(page_capacity)
                .map(|end| end.min(wanted))
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))
        );
        let page = framed!(materialize_page(records, start, end, &mut memory));
        state.memory_peak_bytes = state.memory_peak_bytes.max(memory.peak());
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
        state.memory_peak_bytes = state.memory_peak_bytes.max(memory.peak());
        let needs_resume = pagination && end < wanted;
        let resume_key = framed!(resume_key_for_page(
            self,
            &mut state,
            &page,
            digest,
            needs_resume,
            &mut memory,
        ));
        state.memory_peak_bytes = state.memory_peak_bytes.max(memory.peak());
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
        output_state.memory_peak_bytes =
            output_state.memory_peak_bytes.max(state.memory_peak_bytes);
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
        let terminal = if needs_resume {
            state.resume_key = resume_key;
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
            state.resume_key = resume_key;
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
}
