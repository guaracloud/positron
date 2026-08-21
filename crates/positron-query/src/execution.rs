use positron_governance::AuthorizedContext;
use positron_kernel::{LedgerSnapshot, SnapshotLeaseId};
use positron_signals::{LogScan, LogStore, ScanLimit};

use crate::cursor::{self, CursorState};
use crate::execution_state::{
    commit_position, incomplete, initial_state, query_tenant, stats_before_current,
    stats_with_current, validate_authorization,
};
use crate::execution_support::{
    batch_digest, charge_output, charge_scan, charge_work, exhausted, map_ledger_failure,
    map_store_failure, query_record,
};
use crate::{
    PlannedQuery, QueryBatch, QueryCursor, QueryEvent, QueryFailure, QueryFailureCode, QueryHeader,
    QueryIncomplete, QueryRecord, QueryService, QueryStats, QueryStream, QueryTerminal,
    ResultLease, ResultSnapshot,
};

const MAX_SCAN_RECORDS: usize = 1_024;

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub fn execute(
        &self,
        query: PlannedQuery<'kernel>,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
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
            let stats = stats_before_current(&state);
            return self.stream(
                vec![QueryEvent::Terminal(QueryTerminal::Incomplete(
                    QueryIncomplete::new(
                        QueryFailure::new(QueryFailureCode::BudgetExhausted),
                        stats,
                    ),
                ))],
                state.lease_identity,
                false,
                delivered_before,
                stats,
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
                let stats = stats_before_current(&state);
                return self.stream(
                    vec![
                        header,
                        QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete(
                            map_store_failure(failure),
                            &state,
                        ))),
                    ],
                    state.lease_identity,
                    false,
                    delivered_before,
                    stats,
                );
            },
        };
        let mut records = result
            .records()
            .iter()
            .filter_map(|record| query_record(record, &state.plan))
            .collect::<Vec<_>>();
        records.sort_by_key(QueryRecord::order_key);
        if state.plan.aggregate().is_some() {
            records = vec![QueryRecord::count_record(
                u64::try_from(records.len())
                    .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?,
            )];
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
        charge_scan(
            &mut state,
            &result,
            self.work_units(crate::QueryWorkStage::ScanDecode)?,
        )?;
        if self.observe_state(&mut state)? || exhausted(&state) || !result.complete() {
            let stats = stats_before_current(&state);
            return self.stream(
                vec![
                    header,
                    QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete(
                        QueryFailure::new(QueryFailureCode::BudgetExhausted),
                        &state,
                    ))),
                ],
                state.lease_identity,
                false,
                delivered_before,
                stats,
            );
        }
        let before_batch = stats_before_current(&state);
        charge_work(&mut state, self.work_units(crate::QueryWorkStage::Output)?)?;
        if self.observe_state(&mut state)? || exhausted(&state) {
            let stats = stats_before_current(&state);
            return self.stream(
                vec![
                    header,
                    QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete(
                        QueryFailure::new(QueryFailureCode::BudgetExhausted),
                        &state,
                    ))),
                ],
                state.lease_identity,
                false,
                delivered_before,
                stats,
            );
        }
        let mut output_state = state.clone();
        charge_output(&mut output_state, &page)?;
        if exhausted(&output_state) {
            return self.stream(
                vec![
                    header,
                    QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete(
                        QueryFailure::new(QueryFailureCode::BudgetExhausted),
                        &state,
                    ))),
                ],
                state.lease_identity,
                false,
                delivered_before,
                before_batch,
            );
        }
        state = output_state;
        if page.is_empty() {
            let stats = stats_before_current(&state);
            return self.stream(
                vec![header, QueryEvent::Terminal(QueryTerminal::Complete(stats))],
                state.lease_identity,
                pagination,
                delivered_before,
                stats,
            );
        }
        let digest = batch_digest(
            &self.ledger.control_tokens(),
            state.prior_digest,
            state.sequence,
            &page,
        )?;
        if self.observe_state(&mut state)? {
            return self.stream(
                vec![
                    header,
                    QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete(
                        QueryFailure::new(QueryFailureCode::BudgetExhausted),
                        &state,
                    ))),
                ],
                state.lease_identity,
                false,
                delivered_before,
                before_batch,
            );
        }
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
            QueryTerminal::Continued(cursor::encode(&self.ledger.control_tokens(), state.clone())?)
        } else {
            state.prior_digest = digest;
            QueryTerminal::Complete(stats_with_current(&state))
        };
        self.stream(
            vec![header, batch, QueryEvent::Terminal(terminal)],
            state.lease_identity,
            pagination,
            delivered_before,
            batch_stats,
        )
    }

    fn stream(
        &self,
        events: Vec<QueryEvent>,
        identity: [u8; 16],
        retain_for_resume: bool,
        observed_stats: QueryStats,
        batch_stats: QueryStats,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let ledger = self.ledger;
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
            ))
        } else {
            release()?;
            Ok(QueryStream::new(
                events,
                None,
                false,
                observed_stats,
                batch_stats,
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
