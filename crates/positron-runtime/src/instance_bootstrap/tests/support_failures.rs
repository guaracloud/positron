use super::super::BootstrapFailureCode;
use super::super::operation::support::{entropy_failure, format_secret, inconsistent, key_failure};
use positron_kernel::{
    BootstrapArtifact, BootstrapKeyFailure, BootstrapKeyIdentity, BootstrapStorageFailure,
};

#[test]
fn operation_support_maps_every_closed_key_failure() {
    for (failure, expected) in [
        (
            BootstrapKeyFailure::Custody,
            BootstrapFailureCode::KeyCustodyUnavailable,
        ),
        (
            BootstrapKeyFailure::Entropy,
            BootstrapFailureCode::EntropyUnavailable,
        ),
        (
            BootstrapKeyFailure::Authentication,
            BootstrapFailureCode::CorruptState,
        ),
        (
            BootstrapKeyFailure::InvalidInput,
            BootstrapFailureCode::CorruptState,
        ),
        (
            BootstrapKeyFailure::LimitExceeded,
            BootstrapFailureCode::CorruptState,
        ),
    ] {
        assert_eq!(key_failure(failure).code(), expected);
    }
    assert_eq!(
        inconsistent().code(),
        BootstrapFailureCode::InconsistentRoots
    );
    assert_eq!(
        entropy_failure().code(),
        BootstrapFailureCode::EntropyUnavailable
    );
    assert_eq!(
        super::super::storage::storage_failure(BootstrapStorageFailure::InvalidRoots).code(),
        BootstrapFailureCode::InvalidRoots
    );
}

#[test]
fn initialized_artifact_write_fault_maps_before_storage() {
    let roots = super::support::Roots::new().expect("roots");
    let paths = roots.paths();
    let access = paths.storage.inspect().expect("inspect");
    let failure = super::super::storage::with_fault(
        super::super::storage::BootstrapFileEvent::SynchronizeDirectory,
        || super::super::storage::write_new(&access, BootstrapArtifact::Initialized, b"marker"),
    )
    .expect_err("injected write fault");
    assert_eq!(failure.code(), BootstrapFailureCode::StorageUnavailable);
}

#[test]
fn bootstrap_secret_format_is_exact_and_lowercase() {
    assert_eq!(
        format_secret(&[0xab; 32]),
        format!("pos_{}", "ab".repeat(32))
    );
}

#[test]
fn record_key_identity_mismatch_is_closed() {
    use positron_domain::identity::{PrincipalId, TenantId};
    use positron_kernel::{InstanceId, TransactionId};
    use zeroize::Zeroizing;

    let record = super::super::codec::BootstrapRecord {
        instance: InstanceId::new([1; 16]).expect("instance"),
        key: BootstrapKeyIdentity::from_parts([2; 16], [3; 32], 4).expect("key"),
        tenant: TenantId::from_bytes([5; 16]).expect("tenant"),
        administrator: PrincipalId::from_bytes([6; 16]).expect("principal"),
        transaction: TransactionId::new([7; 16]).expect("transaction"),
        api_key_salt: [8; 32],
        api_key_hash: [9; 32],
        ingest: Some(super::super::codec::BootstrapIngestIdentity {
            principal: PrincipalId::from_bytes([16; 16]).expect("ingest principal"),
            api_key_salt: [17; 32],
            api_key_hash: [18; 32],
            api_key_secret: Some(Zeroizing::new([19; 32])),
        }),
        integrity_fingerprint: [10; 32],
        api_key_secret: Some(Zeroizing::new([11; 32])),
        integrity_key_secret: Some(Zeroizing::new([12; 32])),
    };
    let wrong = BootstrapKeyIdentity::from_parts([13; 16], [14; 32], 15).expect("wrong key");
    assert_eq!(
        super::super::operation::support::require_key_identity(&record, wrong)
            .expect_err("identity mismatch")
            .code(),
        BootstrapFailureCode::IdentityMismatch
    );
}
