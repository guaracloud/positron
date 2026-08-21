use std::num::NonZeroU64;

use positron_domain::identity::{PrincipalId, Scope, TenantId};
use positron_domain::routing::CommitPosition;
use positron_governance::AuthorizedContext;
use positron_kernel::{LedgerSnapshot, SnapshotLeaseId};

use crate::cursor::CursorState;
use crate::stream::QueryCounters;
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryStats};

pub(crate) fn stats_before_current(state: &CursorState) -> QueryStats {
    QueryStats::new(
        QueryCounters {
            records: state.output_rows,
            scanned_bytes: state.scanned_bytes,
            decoded_records: state.decoded_records,
            output_bytes: state.output_bytes,
            cpu_work_units: state.cpu_work_units,
            wall_seconds: state.elapsed_wall_seconds,
        },
        (state.prior_digest != [0; 32])
            .then(|| state.sequence.checked_sub(1))
            .flatten(),
        state.prior_digest,
    )
}

pub(crate) fn stats_with_current(state: &CursorState) -> QueryStats {
    QueryStats::new(
        QueryCounters {
            records: state.output_rows,
            scanned_bytes: state.scanned_bytes,
            decoded_records: state.decoded_records,
            output_bytes: state.output_bytes,
            cpu_work_units: state.cpu_work_units,
            wall_seconds: state.elapsed_wall_seconds,
        },
        Some(state.sequence),
        state.prior_digest,
    )
}

pub(crate) fn initial_state(
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
        plan: query.plan.clone(),
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
        started_at: query.started_at,
        last_observed_at: query.last_observed_at,
        cpu_work_units: query.cpu_work_units,
        elapsed_wall_seconds: query.last_observed_at.saturating_sub(query.started_at),
        cancellation: query.cancellation.clone(),
    }
}

pub(crate) fn query_tenant(context: AuthorizedContext) -> Result<TenantId, QueryFailure> {
    context
        .tenant_attribution()
        .filter(|attribution| attribution.scope() == Scope::Query)
        .map(|attribution| attribution.tenant_id())
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))
}

pub(crate) fn commit_position(value: u64) -> Result<CommitPosition, QueryFailure> {
    match NonZeroU64::new(value) {
        Some(value) => CommitPosition::origin()
            .advance_by(value)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor)),
        None => Ok(CommitPosition::origin()),
    }
}

pub(crate) fn validate_authorization(
    expected_principal: PrincipalId,
    expected_tenant: TenantId,
    expected_generation: u64,
    actual_principal: PrincipalId,
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
    use super::*;

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
        assert!(commit_position(0).is_ok());
    }
}
