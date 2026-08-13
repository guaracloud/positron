use std::num::NonZeroU64;

use positron_domain::identity::{Scope, TenantId};
use positron_domain::routing::CommitPosition;
use positron_domain::time::{IngestTimeCandidate, QueryTime};
use positron_governance::AuthorizedContext;
use positron_kernel::LedgerSnapshot;
use positron_signals::{LogScan, LogStore, ScanLimit};
use sha2::{Digest, Sha256};

use crate::cursor::{self, CursorState};
use crate::{
    PlannedQuery, QueryBatch, QueryCursor, QueryEvent, QueryFailure, QueryFailureCode, QueryHeader,
    QueryRecord, QueryService, QueryStats, QueryStream, QueryTerminal,
};

const MAX_SCAN_RECORDS: usize = 1_024;

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub fn execute(&self, query: PlannedQuery<'kernel>) -> Result<QueryStream, QueryFailure> {
        let snapshot = self.snapshot()?;
        let tenant = query_tenant(query.context)?;
        let state = initial_state(&query, &snapshot, tenant, 0, [0; 16]);
        self.run_page(state, &snapshot, query.plan.limit(), false)
    }

    pub fn execute_page(
        &self,
        query: PlannedQuery<'kernel>,
        now_seconds: u64,
    ) -> Result<QueryStream, QueryFailure> {
        if self.batch_limit == 0 {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        let expiry = now_seconds
            .checked_add(query.budget.wall_seconds())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
        let snapshot = self.snapshot()?;
        let tenant = query_tenant(query.context)?;
        let lease = cursor::lease_identity(
            &self.cursor_key.key,
            query.context.principal_id(),
            tenant,
            snapshot.catalog_identity().to_bytes(),
            snapshot.frontier().value(),
            expiry,
        )?;
        let state = initial_state(&query, &snapshot, tenant, expiry, lease);
        self.run_page(state, &snapshot, self.batch_limit, true)
    }

    pub fn resume(
        &self,
        context: AuthorizedContext,
        cursor: &QueryCursor,
        now_seconds: u64,
    ) -> Result<QueryStream, QueryFailure> {
        let tenant = query_tenant(context)?;
        let state = cursor::decode(&self.cursor_key.key, self.cursor_key.epoch, cursor)?;
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
        let snapshot = self.snapshot()?;
        if snapshot.frontier().value() < state.frontier {
            return Err(QueryFailure::new(QueryFailureCode::SnapshotExpired));
        }
        self.run_page(state, &snapshot, self.batch_limit, true)
    }

    fn snapshot(&self) -> Result<LedgerSnapshot<'kernel>, QueryFailure> {
        self.ledger
            .snapshot()
            .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))
    }

    fn run_page(
        &self,
        mut state: CursorState,
        snapshot: &LedgerSnapshot<'kernel>,
        batch_limit: u16,
        pagination: bool,
    ) -> Result<QueryStream, QueryFailure> {
        let frontier = commit_position(state.frontier)?;
        let header = QueryEvent::Header(QueryHeader::new(state.plan, state.budget));
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
                return Ok(QueryStream::new(vec![
                    header,
                    QueryEvent::Terminal(QueryTerminal::Incomplete(map_store_failure(failure))),
                ]));
            },
        };
        let mut records = result
            .records()
            .iter()
            .map(query_record)
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
            return Ok(QueryStream::new(vec![
                header,
                QueryEvent::Terminal(QueryTerminal::Incomplete(QueryFailure::new(
                    QueryFailureCode::BudgetExhausted,
                ))),
            ]));
        }
        if page.is_empty() {
            return Ok(QueryStream::new(vec![
                header,
                QueryEvent::Terminal(QueryTerminal::Complete(QueryStats::new(
                    state.output_rows,
                    state.scanned_bytes,
                ))),
            ]));
        }
        let digest = batch_digest(state.sequence, &page)?;
        let batch = QueryEvent::Batch(QueryBatch::new(state.sequence, page, digest));
        let terminal = if pagination && end < wanted {
            state.offset =
                u16::try_from(end).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
            state.sequence = state
                .sequence
                .checked_add(1)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            state.prior_digest = digest;
            QueryTerminal::Continued(cursor::encode(
                &self.cursor_key.key,
                self.cursor_key.epoch,
                state,
            )?)
        } else {
            QueryTerminal::Complete(QueryStats::new(state.output_rows, state.scanned_bytes))
        };
        Ok(QueryStream::new(vec![
            header,
            batch,
            QueryEvent::Terminal(terminal),
        ]))
    }
}

fn initial_state(
    query: &PlannedQuery<'_>,
    snapshot: &LedgerSnapshot<'_>,
    tenant: TenantId,
    expiry: u64,
    lease_identity: [u8; 16],
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
        lease_identity,
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

fn query_record(record: &positron_signals::ScannedLogRecord) -> QueryRecord {
    let observed = record.observed_time();
    let query_time = QueryTime::for_log(
        &record.event_time(),
        observed.as_ref(),
        IngestTimeCandidate::new(record.ingest_time().instant()),
    )
    .instant();
    QueryRecord::new(
        record
            .body()
            .and_then(|body| body.as_str())
            .map(str::to_owned),
        query_time,
        record.commit_position(),
    )
}

fn charge(
    state: &mut CursorState,
    result: &positron_signals::LogScanResult<'_>,
    page: &[QueryRecord],
) -> Result<(), QueryFailure> {
    state.scanned_bytes = state
        .scanned_bytes
        .checked_add(result.scanned_bytes())
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    state.decoded_records = state
        .decoded_records
        .checked_add(
            u64::try_from(result.records().len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?,
        )
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    state.output_rows = state
        .output_rows
        .checked_add(
            u64::try_from(page.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::BudgetExhausted))?,
        )
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    let page_bytes = page.iter().try_fold(0_u64, |total, record| {
        total.checked_add(u64::try_from(record.body_text().map_or(0, str::len)).ok()?)
    });
    state.output_bytes = state
        .output_bytes
        .checked_add(page_bytes.ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
    Ok(())
}

fn exhausted(state: &CursorState) -> bool {
    state.scanned_bytes > state.budget.scanned_bytes()
        || state.decoded_records > state.budget.decoded_records()
        || state.output_rows > state.budget.output_rows()
        || state.output_bytes > state.budget.output_bytes()
}

fn batch_digest(sequence: u64, records: &[QueryRecord]) -> Result<[u8; 32], QueryFailure> {
    let mut digest = Sha256::new();
    digest.update(b"positron-query-batch-v1\0");
    digest.update(sequence.to_be_bytes());
    digest.update(
        u64::try_from(records.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
            .to_be_bytes(),
    );
    for record in records {
        let (query_time, position) = record.order_key();
        digest.update(query_time.value().to_be_bytes());
        digest.update(position.value().to_be_bytes());
        let body = record.body_text().unwrap_or_default().as_bytes();
        digest.update(
            u64::try_from(body.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
                .to_be_bytes(),
        );
        digest.update(body);
    }
    Ok(digest.finalize().into())
}

fn map_store_failure(failure: positron_signals::LogStoreFailure) -> QueryFailure {
    match failure.code() {
        positron_signals::LogStoreFailureCode::MalformedBlock => {
            QueryFailure::new(QueryFailureCode::MalformedPersistentData)
        },
        positron_signals::LogStoreFailureCode::ResourceAdmissionRefused => {
            QueryFailure::new(QueryFailureCode::ResourceAdmissionRefused)
        },
        positron_signals::LogStoreFailureCode::LimitExceeded
        | positron_signals::LogStoreFailureCode::ResourceExhausted => {
            QueryFailure::new(QueryFailureCode::BudgetExhausted)
        },
        _ => QueryFailure::new(QueryFailureCode::StoreUnavailable),
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
