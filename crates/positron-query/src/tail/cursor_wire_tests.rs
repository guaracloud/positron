use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{CommitPosition, RecordOrdinal, VirtualShardId};
use positron_kernel::ControlTokenProtector;

use super::{
    PREFIX_BYTES, PURPOSE, TailCursor, TailCursorState, TailPosition, invalid,
    limiting_budget_from_code,
};
use crate::{QueryBudgetDimension, QueryFailureCode};

fn position(shard: u32, value: u64) -> TailPosition {
    TailPosition::with_ordinal(
        VirtualShardId::new(shard).expect("valid shard"),
        CommitPosition::origin()
            .advance_by(std::num::NonZeroU64::new(value).expect("non-zero position"))
            .expect("valid position"),
        RecordOrdinal::first(),
    )
}

fn state() -> TailCursorState {
    TailCursorState::new(
        PrincipalId::from_bytes([1; 16]).expect("valid principal"),
        TenantId::from_bytes([2; 16]).expect("valid tenant"),
        7,
        [3; 32],
        [4; 32],
        vec![position(1, 2)],
        100,
        3,
        [5; 32],
    )
    .expect("valid cursor state")
}

fn reauthenticate(protector: &ControlTokenProtector<'_>, bytes: &mut [u8]) {
    let payload_len = bytes.len().checked_sub(32).expect("cursor tag");
    let authentication = protector
        .authenticate_query_cursor(PURPOSE, &bytes[..payload_len])
        .expect("cursor payload authenticates");
    bytes[payload_len..].copy_from_slice(&authentication.tag());
}

fn extension_start() -> usize {
    PREFIX_BYTES + 16
}

fn marker_stats_end() -> usize {
    extension_start() + 6 + 16
}

#[test]
fn extended_cursor_round_trips_markers_runtime_stats_and_each_budget_dimension() {
    let protector = positron_kernel::fuzz_control_token_protector();
    let mut state = state();
    state
        .set_historical_markers(vec![
            super::HistoricalMarker::new(
                CommitPosition::origin(),
                CommitPosition::origin()
                    .advance_by(std::num::NonZeroU64::new(9).expect("frontier"))
                    .expect("frontier"),
            )
            .expect("valid historical marker"),
        ])
        .expect("marker count matches positions");
    let dimensions = [
        None,
        Some(QueryBudgetDimension::ScannedBytes),
        Some(QueryBudgetDimension::DecodedRecords),
        Some(QueryBudgetDimension::OutputRows),
        Some(QueryBudgetDimension::OutputBytes),
        Some(QueryBudgetDimension::MemoryBytes),
        Some(QueryBudgetDimension::CpuWorkUnits),
        Some(QueryBudgetDimension::WallSeconds),
        Some(QueryBudgetDimension::MaximumTimeRangeNanoseconds),
    ];
    for dimension in dimensions {
        state.set_runtime_stats(512, 9, true, dimension);
        let encoded = TailCursor::encode(&protector, &state).expect("extended cursor encodes");
        let decoded = TailCursor::decode(&protector, &encoded).expect("extended cursor decodes");
        assert_eq!(decoded.positions(), state.positions());
        assert_eq!(decoded.historical_markers(), state.historical_markers());
        assert_eq!(decoded.memory_peak_bytes(), 512);
        assert_eq!(decoded.elapsed_seconds(), 9);
        assert!(decoded.reduced_pruning());
        assert_eq!(decoded.limiting_budget(), dimension);
    }
}

#[test]
fn extended_cursor_authenticates_and_round_trips_historical_total_key() {
    let protector = positron_kernel::fuzz_control_token_protector();
    let mut state = state();
    state
        .set_historical_markers(vec![
            super::HistoricalMarker::new(CommitPosition::origin(), CommitPosition::origin())
                .expect("valid marker"),
        ])
        .expect("marker count matches positions");
    let key = crate::result_key::HistoricalTotalKey::from_record(
        &crate::QueryRecord::count_record(1),
        VirtualShardId::new(1).expect("source"),
    );
    state.set_historical_key(Some(key));
    let encoded = TailCursor::encode(&protector, &state).expect("key cursor encodes");
    let decoded = TailCursor::decode(&protector, &encoded).expect("key cursor decodes");
    assert_eq!(decoded.historical_key(), Some(key));
}

#[test]
fn extended_cursor_rejects_bad_magic_marker_count_reduced_flag_and_budget_code() {
    let protector = positron_kernel::fuzz_control_token_protector();
    let mut state = state();
    state
        .set_historical_markers(vec![
            super::HistoricalMarker::new(CommitPosition::origin(), CommitPosition::origin())
                .expect("valid historical marker"),
        ])
        .expect("marker count matches positions");
    state.set_runtime_stats(1, 1, false, None);
    let encoded = TailCursor::encode(&protector, &state).expect("extended cursor encodes");
    let start = extension_start();
    let stats_end = marker_stats_end();

    let mut bad_magic = encoded.as_bytes().to_vec();
    bad_magic[start] ^= 1;
    reauthenticate(&protector, &mut bad_magic);
    assert_eq!(
        TailCursor::decode(
            &protector,
            &TailCursor::from_bytes(&bad_magic).expect("bounded")
        )
        .expect_err("bad extension magic")
        .code(),
        QueryFailureCode::InvalidCursor
    );

    let mut bad_count = encoded.as_bytes().to_vec();
    bad_count[start + 4..start + 6].copy_from_slice(&2_u16.to_be_bytes());
    reauthenticate(&protector, &mut bad_count);
    assert_eq!(
        TailCursor::decode(
            &protector,
            &TailCursor::from_bytes(&bad_count).expect("bounded")
        )
        .expect_err("mismatched marker count")
        .code(),
        QueryFailureCode::InvalidCursor
    );

    let mut bad_reduced = encoded.as_bytes().to_vec();
    bad_reduced[stats_end + 16] = 2;
    reauthenticate(&protector, &mut bad_reduced);
    assert_eq!(
        TailCursor::decode(
            &protector,
            &TailCursor::from_bytes(&bad_reduced).expect("bounded")
        )
        .expect_err("invalid reduced flag")
        .code(),
        QueryFailureCode::InvalidCursor
    );

    let mut bad_budget = encoded.as_bytes().to_vec();
    bad_budget[stats_end + 17] = u8::MAX;
    reauthenticate(&protector, &mut bad_budget);
    assert_eq!(
        TailCursor::decode(
            &protector,
            &TailCursor::from_bytes(&bad_budget).expect("bounded")
        )
        .expect_err("invalid budget code")
        .code(),
        QueryFailureCode::InvalidCursor
    );
}

#[test]
fn extended_cursor_rejects_invalid_marker_order_and_marker_count_assignment() {
    let protector = positron_kernel::fuzz_control_token_protector();
    let mut state = state();
    assert_eq!(
        state
            .set_historical_markers(Vec::new())
            .expect_err("marker vector must cover every source")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    state
        .set_historical_markers(vec![
            super::HistoricalMarker::new(CommitPosition::origin(), CommitPosition::origin())
                .expect("valid historical marker"),
        ])
        .expect("marker count matches positions");
    let encoded = TailCursor::encode(&protector, &state).expect("extended cursor encodes");
    let start = extension_start();
    let mut invalid_marker = encoded.as_bytes().to_vec();
    invalid_marker[start + 6..start + 14].copy_from_slice(&2_u64.to_be_bytes());
    reauthenticate(&protector, &mut invalid_marker);
    assert_eq!(
        TailCursor::decode(
            &protector,
            &TailCursor::from_bytes(&invalid_marker).expect("bounded"),
        )
        .expect_err("lower bound after handoff")
        .code(),
        QueryFailureCode::InvalidCursor
    );

    assert_eq!(
        limiting_budget_from_code(u8::MAX)
            .expect_err("unknown limit code")
            .code(),
        QueryFailureCode::InvalidCursor
    );
    assert_eq!(invalid().code(), QueryFailureCode::InvalidCursor);
}

#[test]
fn wire_decoder_rejects_truncated_state_zero_expiry_and_wrong_extension_length() {
    let protector = positron_kernel::fuzz_control_token_protector();
    assert_eq!(
        TailCursor::decode(&protector, &TailCursor(Vec::new()))
            .expect_err("truncated private wire value")
            .code(),
        QueryFailureCode::InvalidCursor
    );

    let base_state = state();
    let encoded = TailCursor::encode(&protector, &base_state).expect("cursor encodes");
    let mut zero_expiry = encoded.as_bytes().to_vec();
    zero_expiry[122..130].copy_from_slice(&0_u64.to_be_bytes());
    reauthenticate(&protector, &mut zero_expiry);
    assert_eq!(
        TailCursor::decode(
            &protector,
            &TailCursor::from_bytes(&zero_expiry).expect("bounded")
        )
        .expect_err("zero expiry")
        .code(),
        QueryFailureCode::InvalidCursor
    );

    let mut extended_state = state();
    extended_state.set_runtime_stats(1, 0, false, None);
    let extended = TailCursor::encode(&protector, &extended_state).expect("cursor extends");
    let mut wrong_length = extended.as_bytes().to_vec();
    let payload_len = wrong_length.len().checked_sub(32).expect("cursor tag");
    wrong_length.insert(payload_len, 0);
    reauthenticate(&protector, &mut wrong_length);
    assert_eq!(
        TailCursor::decode(
            &protector,
            &TailCursor::from_bytes(&wrong_length).expect("bounded")
        )
        .expect_err("wrong extension length")
        .code(),
        QueryFailureCode::InvalidCursor
    );
}
