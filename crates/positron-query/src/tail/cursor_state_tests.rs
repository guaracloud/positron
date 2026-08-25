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
