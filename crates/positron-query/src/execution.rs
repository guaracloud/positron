use std::num::NonZeroU64;

use positron_domain::identity::{Scope, TenantId};
use positron_domain::routing::CommitPosition;
use positron_governance::AuthorizedContext;
use positron_kernel::{LedgerSnapshot, SnapshotLeaseId};
use positron_signals::{LogScan, LogStore, ScanLimit};

use crate::cursor::{self, CursorState};
use crate::execution_support::{
    batch_digest, charge, exhausted, map_ledger_failure, map_store_failure, query_record,
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
        let expiry = query.budget.wall_seconds();
        let lease = self
            .ledger
            .create_snapshot_lease(expiry)
            .map_err(map_ledger_failure)?;
        let tenant = query_tenant(query.context)?;
        let state = initial_state(&query, lease.snapshot(), tenant, expiry, lease.identity());
        self.run_page(state, lease.snapshot(), query.plan.limit(), false)
    }

    pub fn execute_page(
        &self,
        query: PlannedQuery<'kernel>,
        now_seconds: u64,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        if self.batch_limit == 0 {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        let expiry = now_seconds
            .checked_add(query.budget.wall_seconds())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
        let lease = self
            .ledger
            .create_snapshot_lease(expiry)
            .map_err(map_ledger_failure)?;
        let tenant = query_tenant(query.context)?;
        let state = initial_state(&query, lease.snapshot(), tenant, expiry, lease.identity());
        self.run_page(state, lease.snapshot(), self.batch_limit, true)
    }

    pub fn resume(
        &self,
        context: AuthorizedContext,
        cursor: &QueryCursor,
        now_seconds: u64,
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
        self.run_page(state, lease.snapshot(), self.batch_limit, true)
    }

    fn run_page(
        &self,
        mut state: CursorState,
        snapshot: &LedgerSnapshot<'kernel>,
        batch_limit: u16,
        pagination: bool,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let frontier = commit_position(state.frontier)?;
        let initial_cursor = (state.expiry != 0)
            .then(|| cursor::encode(&self.ledger.control_tokens(), state))
            .transpose()?;
        let header = QueryEvent::Header(QueryHeader::new(
            state.plan,
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
                return Ok(self.stream(
                    vec![
                        header,
                        QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete(
                            map_store_failure(failure),
                            &state,
                        ))),
                    ],
                    state.lease_identity,
                ));
            },
        };
        let mut records = result
            .records()
            .iter()
            .filter_map(|record| query_record(record, state.plan))
            .collect::<Vec<_>>();
        records.sort_by_key(QueryRecord::order_key);
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
        charge(&mut state, &result, &page)?;
        if exhausted(&state) || !result.complete() {
            return Ok(self.stream(
                vec![
                    header,
                    QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete(
                        QueryFailure::new(QueryFailureCode::BudgetExhausted),
                        &state,
                    ))),
                ],
                state.lease_identity,
            ));
        }
        if page.is_empty() {
            return Ok(self.stream(
                vec![
                    header,
                    QueryEvent::Terminal(QueryTerminal::Complete(stats_before_current(&state))),
                ],
                state.lease_identity,
            ));
        }
        let digest = batch_digest(
            &self.ledger.control_tokens(),
            state.prior_digest,
            state.sequence,
            &page,
        )?;
        let batch = QueryEvent::Batch(QueryBatch::new(
            state.sequence,
            page,
            state.prior_digest,
            digest,
        ));
        let terminal = if pagination && end < wanted {
            state.offset =
                u16::try_from(end).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
            state.sequence = state
                .sequence
                .checked_add(1)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            state.prior_digest = digest;
            QueryTerminal::Continued(cursor::encode(&self.ledger.control_tokens(), state)?)
        } else {
            state.prior_digest = digest;
            QueryTerminal::Complete(stats_with_current(&state))
        };
        Ok(self.stream(
            vec![header, batch, QueryEvent::Terminal(terminal)],
            state.lease_identity,
        ))
    }

    fn stream(&self, events: Vec<QueryEvent>, identity: [u8; 16]) -> QueryStream<'ledger> {
        let ledger = self.ledger;
        QueryStream::new(
            events,
            Box::new(move || {
                let identity = SnapshotLeaseId::new(identity)
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
                ledger
                    .release_snapshot_lease(identity)
                    .map_err(map_ledger_failure)
            }),
        )
    }
}

fn stats_before_current(state: &CursorState) -> QueryStats {
    QueryStats::new(
        state.output_rows,
        state.scanned_bytes,
        (state.prior_digest != [0; 32])
            .then(|| state.sequence.checked_sub(1))
            .flatten(),
        state.prior_digest,
    )
}

fn stats_with_current(state: &CursorState) -> QueryStats {
    QueryStats::new(
        state.output_rows,
        state.scanned_bytes,
        Some(state.sequence),
        state.prior_digest,
    )
}

fn incomplete(failure: QueryFailure, state: &CursorState) -> QueryIncomplete {
    QueryIncomplete::new(failure, stats_before_current(state))
}

fn initial_state(
    query: &PlannedQuery<'_>,
    snapshot: &LedgerSnapshot<'_>,
    tenant: TenantId,
    expiry: u64,
    lease_identity: SnapshotLeaseId,
) -> CursorState {
    CursorState {
        principal: query.context.principal_id(),
        tenant,
        authorization_generation: query.context.authorization_generation(),
        catalog_identity: snapshot.catalog_identity().to_bytes(),
        catalog_generation: snapshot.catalog_generation(),
        frontier: snapshot.frontier().value(),
        plan: query.plan,
        offset: 0,
        sequence: 0,
        prior_digest: [0; 32],
        lease_identity: lease_identity.to_bytes(),
        expiry,
        budget: query.budget,
        scanned_bytes: 0,
        decoded_records: 0,
        output_rows: 0,
        output_bytes: 0,
    }
}

fn query_tenant(context: AuthorizedContext) -> Result<TenantId, QueryFailure> {
    context
        .tenant_attribution()
        .filter(|attribution| attribution.scope() == Scope::Query)
        .map(|attribution| attribution.tenant_id())
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))
}

fn commit_position(value: u64) -> Result<CommitPosition, QueryFailure> {
    match NonZeroU64::new(value) {
        Some(value) => CommitPosition::origin()
            .advance_by(value)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor)),
        None => Ok(CommitPosition::origin()),
    }
}

fn validate_authorization(
    expected_principal: positron_domain::identity::PrincipalId,
    expected_tenant: TenantId,
    expected_generation: u64,
    actual_principal: positron_domain::identity::PrincipalId,
    actual_tenant: TenantId,
    actual_generation: u64,
) -> Result<(), QueryFailure> {
    if actual_principal != expected_principal || actual_tenant != expected_tenant {
        return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
    }
    if actual_generation != expected_generation {
        return Err(QueryFailure::new(QueryFailureCode::AuthorizationChanged));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use positron_domain::identity::{PrincipalId, TenantId};

    use super::validate_authorization;
    use crate::QueryFailureCode;

    #[test]
    fn authorization_generation_change_invalidates_resume_binding() {
        let principal = PrincipalId::from_bytes([1; 16]).expect("principal");
        let tenant = TenantId::from_bytes([2; 16]).expect("tenant");
        assert!(validate_authorization(principal, tenant, 4, principal, tenant, 4).is_ok());
        assert_eq!(
            validate_authorization(principal, tenant, 4, principal, tenant, 5)
                .expect_err("new generation invalidates cursor")
                .code(),
            QueryFailureCode::AuthorizationChanged
        );
        let other = PrincipalId::from_bytes([3; 16]).expect("other principal");
        assert_eq!(
            validate_authorization(principal, tenant, 4, other, tenant, 4)
                .expect_err("principal mismatch")
                .code(),
            QueryFailureCode::Unauthorized
        );
        assert!(super::commit_position(0).is_ok());
    }
}
