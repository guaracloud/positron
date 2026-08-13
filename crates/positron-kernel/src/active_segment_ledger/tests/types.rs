use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use crate::active_segment_ledger::{
    AppendCancellation, CommitReceipt, CommittedBlock, LedgerFailure, LedgerFailureCode,
    PreparedStoreBlock, SealedSegment, SegmentId, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};
use crate::catalog::{CatalogFailure, CatalogFailureCode};
use crate::data_protection::{FrameFailure, FrameFailureCode};

#[test]
fn public_values_enforce_bounds_and_expose_only_bounded_outcomes() {
    assert_eq!(
        SegmentId::new([0; 16]).expect_err("zero identity").code(),
        LedgerFailureCode::InvalidInput
    );
    assert_eq!(
        PreparedStoreBlock::new(
            StoreBlockIdentity::new([1; 16]).expect("identity"),
            Vec::new()
        )
        .err()
        .expect("empty block")
        .code(),
        LedgerFailureCode::LimitExceeded
    );
    assert_eq!(
        PreparedStoreBlock::new(
            StoreBlockIdentity::new([1; 16]).expect("identity"),
            vec![0; 1_048_577],
        )
        .err()
        .expect("oversized block")
        .code(),
        LedgerFailureCode::LimitExceeded
    );
    assert_eq!(
        format!("{:?}", SegmentProtectionKey::from_owned(Box::new([1; 32]))),
        "SegmentProtectionKey { <redacted> }"
    );
    for (reference, epoch) in [([0; 16], 1), ([1; 16], 0)] {
        assert_eq!(
            SegmentProtectionKey::from_owned_with_route(Box::new([1; 32]), reference, epoch)
                .expect_err("invalid route")
                .code(),
            LedgerFailureCode::InvalidInput
        );
    }
    assert_eq!(
        StoreBlockIdentity::new([0; 16])
            .expect_err("zero block identity")
            .code(),
        LedgerFailureCode::InvalidInput
    );

    let cancellation = AppendCancellation::default();
    assert!(!cancellation.is_cancelled());
    cancellation.cancel();
    assert!(cancellation.is_cancelled());

    let segment = SegmentId::new([2; 16]).expect("fixed segment");
    let receipt = CommitReceipt {
        segment,
        position: CommitPosition::origin(),
        frontier_authenticator: [3; 32],
    };
    assert_eq!(receipt.segment_id(), segment);
    assert_eq!(receipt.frontier_authenticator(), [3; 32]);
    let block = CommittedBlock {
        identity: StoreBlockIdentity::new([1; 16]).expect("identity"),
        position: receipt.position(),
        payload: b"block".to_vec(),
        segment,
        frontier_authenticator: [3; 32],
    };
    assert_eq!(block.position(), receipt.position());
    assert_eq!(block.payload(), b"block");
    let sealed = SealedSegment {
        segment,
        frontier: receipt.position(),
    };
    assert_eq!(sealed.segment_id(), segment);
    assert_eq!(sealed.frontier(), receipt.position());
    let scope = SegmentScope::new(
        TenantId::from_bytes([4; 16]).expect("fixed tenant"),
        SignalKind::Traces,
        VirtualShardId::new(8).expect("fixed shard"),
    );
    assert_eq!(scope.signal, SignalKind::Traces);
    assert_eq!(scope.lease_key()[16], 2);

    let failure = LedgerFailure::new(LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        failure.to_string(),
        "active segment ledger operation failed"
    );
}

#[test]
fn internal_failures_map_to_the_closed_ledger_outcomes() {
    use crate::active_segment_ledger::map_frame_failure;

    for (source, expected) in [
        (
            FrameFailureCode::InvalidContext,
            LedgerFailureCode::InvalidInput,
        ),
        (
            FrameFailureCode::InvalidLimit,
            LedgerFailureCode::InvalidInput,
        ),
        (
            FrameFailureCode::LimitExceeded,
            LedgerFailureCode::LimitExceeded,
        ),
        (
            FrameFailureCode::SealFailed,
            LedgerFailureCode::StorageUnavailable,
        ),
        (
            FrameFailureCode::HashFailed,
            LedgerFailureCode::StorageUnavailable,
        ),
        (
            FrameFailureCode::EntropyUnavailable,
            LedgerFailureCode::StorageUnavailable,
        ),
        (
            FrameFailureCode::OpenFailed,
            LedgerFailureCode::AuthenticationFailed,
        ),
        (
            FrameFailureCode::AuthenticationFailed,
            LedgerFailureCode::AuthenticationFailed,
        ),
        (
            FrameFailureCode::MalformedFrame,
            LedgerFailureCode::IntegrityCorruption,
        ),
        (
            FrameFailureCode::ChecksumMismatch,
            LedgerFailureCode::IntegrityCorruption,
        ),
        (
            FrameFailureCode::UnsupportedVersion,
            LedgerFailureCode::UnsupportedFormat,
        ),
        (
            FrameFailureCode::UnsupportedAlgorithm,
            LedgerFailureCode::UnsupportedFormat,
        ),
    ] {
        assert_eq!(
            map_frame_failure(FrameFailure::new(source)).code(),
            expected
        );
    }

    for (source, expected) in [
        (
            CatalogFailureCode::InvalidInput,
            LedgerFailureCode::InvalidInput,
        ),
        (
            CatalogFailureCode::IdempotencyConflict,
            LedgerFailureCode::IdempotencyConflict,
        ),
        (
            CatalogFailureCode::StaleGeneration,
            LedgerFailureCode::StaleGeneration,
        ),
        (
            CatalogFailureCode::LimitExceeded,
            LedgerFailureCode::LimitExceeded,
        ),
        (
            CatalogFailureCode::StorageUnavailable,
            LedgerFailureCode::StorageUnavailable,
        ),
        (
            CatalogFailureCode::IntegrityCorruption,
            LedgerFailureCode::IntegrityCorruption,
        ),
        (
            CatalogFailureCode::AuthenticationFailed,
            LedgerFailureCode::AuthenticationFailed,
        ),
        (
            CatalogFailureCode::ConcurrentWriter,
            LedgerFailureCode::ConcurrentWriter,
        ),
        (
            CatalogFailureCode::ResourceAdmissionRefused,
            LedgerFailureCode::ResourceAdmissionRefused,
        ),
        (
            CatalogFailureCode::UnsupportedFormat,
            LedgerFailureCode::UnsupportedFormat,
        ),
    ] {
        assert_eq!(
            LedgerFailure::from(CatalogFailure::new(source)).code(),
            expected
        );
    }
}
