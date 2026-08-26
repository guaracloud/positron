use std::num::NonZeroU64;

use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{CommitPosition, VirtualShardId};

use super::{TailCursorState, TailPosition};
use crate::QueryFailureCode;

fn state() -> TailCursorState {
    TailCursorState::new(
        PrincipalId::from_bytes([1; 16]).expect("principal"),
        TenantId::from_bytes([2; 16]).expect("tenant"),
        1,
        [3; 32],
        [4; 32],
        vec![TailPosition::new(
            VirtualShardId::new(1).expect("shard"),
            CommitPosition::origin()
                .advance_by(NonZeroU64::new(2).expect("non-zero"))
                .expect("position"),
        )],
        100,
        0,
        [0; 32],
    )
    .expect("valid cursor state")
}

#[test]
fn state_advancement_rejects_empty_unknown_and_rewound_updates() {
    let state = state();
    assert_eq!(
        state
            .advance_batch(&[], [5; 32])
            .expect_err("empty batch")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert_eq!(
        state
            .advance_positions(&[])
            .expect_err("empty position update")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let unknown = TailPosition::new(
        VirtualShardId::new(2).expect("shard"),
        CommitPosition::origin(),
    );
    assert_eq!(
        state
            .advance_batch(&[unknown], [5; 32])
            .expect_err("unknown shard")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert_eq!(
        state
            .advance_positions(&[unknown])
            .expect_err("unknown shard")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let rewound = TailPosition::new(
        VirtualShardId::new(1).expect("shard"),
        CommitPosition::origin(),
    );
    assert_eq!(
        state
            .advance_batch(&[rewound], [5; 32])
            .expect_err("rewound batch")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert_eq!(
        state
            .advance_positions(&[rewound])
            .expect_err("rewound position")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let mut malformed = state;
    malformed.positions.push(malformed.positions[0]);
    let update = malformed.positions[0];
    assert_eq!(
        malformed
            .advance_batch(&[update], [5; 32])
            .expect_err("duplicate state")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert_eq!(
        malformed
            .advance_positions(&[update])
            .expect_err("duplicate state")
            .code(),
        QueryFailureCode::InvalidCursor
    );
}

#[test]
fn state_validation_rejects_expired_mismatched_and_budget_changed_resumes() {
    let state = state();

    assert_eq!(state.budget_digest(), [0; 32]);
    assert_eq!(super::invalid().code(), QueryFailureCode::InvalidCursor);
    assert_eq!(
        super::resource().code(),
        QueryFailureCode::ResourceExhausted
    );

    assert_eq!(
        state
            .validate_budget([9; 32])
            .expect_err("changed budget")
            .code(),
        QueryFailureCode::AuthorizationChanged
    );
    assert_eq!(
        state
            .validate_for_resume(
                state.principal(),
                state.tenant(),
                state.authorization_generation(),
                state.plan_digest(),
                state.signal_digest(),
                state.expiry(),
            )
            .expect_err("expired cursor")
            .code(),
        QueryFailureCode::SnapshotExpired
    );
    assert_eq!(
        state
            .validate_for_resume(
                PrincipalId::from_bytes([8; 16]).expect("principal"),
                state.tenant(),
                state.authorization_generation(),
                state.plan_digest(),
                state.signal_digest(),
                1,
            )
            .expect_err("mismatched principal")
            .code(),
        QueryFailureCode::AuthorizationChanged
    );
}

#[test]
fn historical_markers_validate_bounds_and_source_count() {
    let origin = positron_domain::routing::CommitPosition::origin();
    let later = origin
        .advance_by(NonZeroU64::new(2).expect("non-zero position"))
        .expect("position");
    assert_eq!(
        super::HistoricalMarker::new(later, origin)
            .expect_err("a marker cannot hand off before its lower bound")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let mut state = state();
    assert_eq!(
        state
            .set_historical_markers(Vec::new())
            .expect_err("marker count must match source count")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    state
        .set_historical_markers(vec![
            super::HistoricalMarker::new(origin, later).expect("valid marker"),
        ])
        .expect("marker count matches source count");
    assert!(state.historical_markers().is_some());
    state.clear_historical_markers();
    assert!(state.historical_markers().is_none());
}
