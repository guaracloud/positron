use positron_governance::AuthorizedContext;
use positron_kernel::{LedgerSnapshot, SnapshotLeaseId};
use positron_signals::{LogScan, LogStore, ScanLimit};

use crate::cursor::{self, CursorState};
use crate::execution_state::{
    commit_position, initial_state, query_tenant, stats_before_current, stats_with_current,
    validate_authorization,
};
use crate::execution_support::{
    batch_digest, charge_output, charge_scan, charge_work, exhausted, map_ledger_failure,
    map_store_failure,
};
use crate::{
    PlannedQuery, QueryBatch, QueryCursor, QueryEvent, QueryFailure, QueryFailureCode, QueryHeader,
    QueryIncomplete, QueryService, QueryStats, QueryStream, QueryTerminal, ResultLease,
    ResultSnapshot,
};

const MAX_SCAN_RECORDS: usize = 1_024;

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub fn execute(
        &self,
        query: PlannedQuery<'kernel>,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        if query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let now = self.observe_planned(&query)?;
        let expiry = query
            .started_at
            .checked_add(query.budget.wall_seconds())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
        if now >= expiry {
            return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
        }
        let lease = self
            .ledger
            .create_snapshot_lease(now, expiry)
            .map_err(map_ledger_failure)?;
        let tenant = query_tenant(query.context)?;
        let state = initial_state(&query, lease.snapshot(), tenant, expiry, lease.identity());
        self.run_page(state, lease.snapshot(), query.plan.limit(), false)
    }

    pub fn execute_page(
        &self,
        query: PlannedQuery<'kernel>,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        if query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        if self.batch_limit == 0 {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        if query.plan.has_advanced_operators() {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
        let now_seconds = self.observe_planned(&query)?;
        let expiry = query
            .started_at
            .checked_add(query.budget.wall_seconds())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
        let lease = self
            .ledger
            .create_snapshot_lease(now_seconds, expiry)
            .map_err(map_ledger_failure)?;
        let tenant = query_tenant(query.context)?;
        let state = initial_state(&query, lease.snapshot(), tenant, expiry, lease.identity());
        self.run_page(state, lease.snapshot(), self.batch_limit, true)
    }

    pub fn resume(
        &self,
        context: AuthorizedContext,
        cursor: &QueryCursor,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let tenant = query_tenant(context)?;
        let state = cursor::decode(&self.ledger.control_tokens(), cursor)?;
        validate_authorization(
            state.principal,
            state.tenant,
            state.authorization_generation,
            context.principal_id(),
            tenant,
            context.authorization_generation(),
        )?;
        let now_seconds = self.now()?;
        if now_seconds < state.last_observed_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        if now_seconds >= state.expiry {
            return Err(QueryFailure::new(QueryFailureCode::SnapshotExpired));
        }
        let _reservation = self.reserve_query(tenant, state.budget)?;
        let lease_id = SnapshotLeaseId::new(state.lease_identity)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        let lease = self
            .ledger
            .resume_snapshot_lease(lease_id, now_seconds)
            .map_err(map_ledger_failure)?;
        if lease.snapshot().catalog_identity().to_bytes() != state.catalog_identity
            || lease.snapshot().catalog_generation() != state.catalog_generation
            || lease.snapshot().frontier().value() != state.frontier
            || lease.expiry() != state.expiry
        {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        let mut state = state;
        state.last_observed_at = now_seconds;
        state.elapsed_wall_seconds = now_seconds.saturating_sub(state.started_at);
        self.run_page(state, lease.snapshot(), self.batch_limit, true)
    }

    fn run_page(
        &self,
        mut state: CursorState,
        snapshot: &LedgerSnapshot<'kernel>,
        batch_limit: u16,
        pagination: bool,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let delivered_before = stats_before_current(&state);
        if self.observe_state(&mut state)? {
            return self.stopped_page(
                None,
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
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
        ));
        let result = match LogStore::new().scan(
            self.governor,
            state.tenant,
            snapshot,
            LogScan::through(
                ScanLimit::new(MAX_SCAN_RECORDS)
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
                frontier,
            ),
        ) {
            Ok(result) => result,
            Err(failure) => {
                return self.failed_page(
                    Some(header),
                    map_store_failure(failure),
                    &state,
                    delivered_before,
                );
            },
        };
        charge_scan(
            &mut state,
            &result,
            self.work_units(crate::QueryWorkStage::ScanDecode)?,
        )?;
        if state.cancellation.is_cancelled() {
            return self.stopped_page(
                Some(header),
                QueryFailureCode::Cancelled,
                &state,
                delivered_before,
            );
        }
        if self.observe_state(&mut state)? || exhausted(&state) || !result.complete() {
            return self.stopped_page(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
            );
        }

        let operator_count = state.plan.operator_count();
        let records = match crate::operators::execute(self, &mut state, result.records()) {
            Ok(records) => records,
            Err(failure)
                if matches!(
                    failure.code(),
                    QueryFailureCode::BudgetExhausted | QueryFailureCode::Cancelled
                ) =>
            {
                return self.failed_page(Some(header), failure, &state, delivered_before);
            },
            Err(failure) => return Err(failure),
        };
        if operator_count > 0 && self.observe_state(&mut state)? {
            return self.stopped_page(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
            );
        }

        let wanted = usize::from(state.plan.limit()).min(records.len());
        let start = usize::from(state.offset);
        let end = start
            .checked_add(usize::from(batch_limit))
            .map(|end| end.min(wanted))
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        let page = records
            .get(start..end)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?
            .to_vec();
        let before_batch = stats_before_current(&state);
        charge_work(&mut state, self.work_units(crate::QueryWorkStage::Output)?)?;
        if state.cancellation.is_cancelled() {
            return self.stopped_page_with_stats(
                Some(header),
                QueryFailureCode::Cancelled,
                &state,
                delivered_before,
                before_batch,
            );
        }
        if self.observe_state(&mut state)? || exhausted(&state) {
            return self.stopped_page(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
            );
        }
        let mut output_state = state.clone();
        match charge_output(&mut output_state, &page, &state.cancellation) {
            Ok(()) => {},
            Err(failure) if failure.code() == QueryFailureCode::Cancelled => {
                return self.failed_page(Some(header), failure, &state, delivered_before);
            },
            Err(failure) => return Err(failure),
        }
        if exhausted(&output_state) {
            return self.stopped_page_with_stats(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
                before_batch,
            );
        }
        if page.is_empty() {
            state = output_state;
            let stats = stats_before_current(&state);
            if state.cancellation.is_cancelled() {
                return self.stopped_page_with_stats(
                    Some(header),
                    QueryFailureCode::Cancelled,
                    &state,
                    delivered_before,
                    stats,
                );
            }
            return self.stream(
                vec![header, QueryEvent::Terminal(QueryTerminal::Complete(stats))],
                &state,
                pagination,
                delivered_before,
                stats,
            );
        }
        let digest = match batch_digest(
            &self.ledger.control_tokens(),
            state.prior_digest,
            state.sequence,
            &page,
            &state.cancellation,
        ) {
            Ok(digest) => digest,
            Err(failure) if failure.code() == QueryFailureCode::Cancelled => {
                return self.failed_page(Some(header), failure, &state, delivered_before);
            },
            Err(failure) => return Err(failure),
        };
        if self.observe_state(&mut state)? {
            output_state.last_observed_at = state.last_observed_at;
            output_state.elapsed_wall_seconds = state.elapsed_wall_seconds;
            state = output_state;
            return self.stopped_page(
                Some(header),
                QueryFailureCode::BudgetExhausted,
                &state,
                delivered_before,
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
        let terminal = if pagination && end < wanted {
            state.offset =
                u16::try_from(end).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
            state.sequence = state
                .sequence
                .checked_add(1)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            state.prior_digest = digest;
            QueryTerminal::Continued(cursor::encode(
                &self.ledger.control_tokens(),
                state.clone(),
            )?)
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
        )
    }

    fn stopped_page(
        &self,
        header: Option<QueryEvent>,
        code: QueryFailureCode,
        state: &CursorState,
        delivered_before: QueryStats,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        self.failed_page(header, QueryFailure::new(code), state, delivered_before)
    }

    fn failed_page(
        &self,
        header: Option<QueryEvent>,
        failure: QueryFailure,
        state: &CursorState,
        delivered_before: QueryStats,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        self.incomplete_page(
            header,
            failure,
            state,
            delivered_before,
            stats_before_current(state),
        )
    }

    fn stopped_page_with_stats(
        &self,
        header: Option<QueryEvent>,
        code: QueryFailureCode,
        state: &CursorState,
        delivered_before: QueryStats,
        terminal_stats: QueryStats,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        self.incomplete_page(
            header,
            QueryFailure::new(code),
            state,
            delivered_before,
            terminal_stats,
        )
    }

    fn incomplete_page(
        &self,
        header: Option<QueryEvent>,
        failure: QueryFailure,
        state: &CursorState,
        delivered_before: QueryStats,
        terminal_stats: QueryStats,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let mut events = Vec::with_capacity(2);
        events.extend(header);
        events.push(QueryEvent::Terminal(QueryTerminal::Incomplete(
            QueryIncomplete::new(failure, terminal_stats),
        )));
        self.stream(events, state, false, delivered_before, terminal_stats)
    }

    fn stream(
        &self,
        events: Vec<QueryEvent>,
        state: &CursorState,
        retain_for_resume: bool,
        observed_stats: QueryStats,
        batch_stats: QueryStats,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let ledger = self.ledger;
        let identity = state.lease_identity;
        let cancellation = state.cancellation.clone();
        let release = Box::new(move || {
            let identity = SnapshotLeaseId::new(identity)
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
            ledger
                .release_snapshot_lease(identity)
                .map_err(map_ledger_failure)
        });
        if retain_for_resume {
            Ok(QueryStream::new(
                events,
                Some(release),
                true,
                observed_stats,
                batch_stats,
                cancellation,
            ))
        } else {
            release()?;
            Ok(QueryStream::new(
                events,
                None,
                false,
                observed_stats,
                batch_stats,
                cancellation,
            ))
        }
    }

    fn observe_planned(&self, query: &PlannedQuery<'_>) -> Result<u64, QueryFailure> {
        let now = self.now()?;
        if now < query.last_observed_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        Ok(now)
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
