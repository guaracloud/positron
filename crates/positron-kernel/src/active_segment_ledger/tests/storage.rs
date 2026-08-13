use std::error::Error;
use std::fs::{self, File};

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use super::support::TemporaryRoot;
use crate::active_segment_ledger::format::{SegmentMetadata, SegmentState};
use crate::active_segment_ledger::recovery::{frontier_name, segment_name};
use crate::active_segment_ledger::storage::{LedgerStorage, entry_exists, recognized_ledger_name};
use crate::active_segment_ledger::{
    LedgerFailureCode, SegmentId, SegmentProtectionKey, SegmentScope,
};
use crate::catalog::InstanceId;
use crate::{MountQualification, PrimaryDataVolume};

#[test]
fn creation_rejects_sealed_metadata_and_wrapped_context_mismatch() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let mut storage = LedgerStorage::open(&fixture.volume)?;
    let mut sealed = metadata(CommitPosition::origin());
    sealed.state = SegmentState::Sealed;
    let failure = storage
        .create_active(sealed, &wrapping_key(), instance()?)
        .expect_err("only active metadata can create an active file");
    assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);

    let original = metadata(CommitPosition::origin());
    storage.create_active(original, &wrapping_key(), instance()?)?;
    let mismatched = SegmentMetadata {
        base_position: CommitPosition::origin().next()?,
        ..original
    };
    let failure = storage
        .recover_segment(mismatched, &wrapping_key(), instance()?)
        .err()
        .expect("catalog context must authenticate the wrapped key");
    assert_eq!(failure.code(), LedgerFailureCode::AuthenticationFailed);
    Ok(())
}

#[test]
fn sealing_rejects_duplicate_segment_and_frontier_artifacts() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let active = fixture.root.path().join("segments/active");
    let sealed = fixture.root.path().join("segments/sealed");
    let current = metadata(CommitPosition::origin());

    let mut storage = LedgerStorage::open(&fixture.volume)?;
    storage.create_active(current, &wrapping_key(), instance()?)?;
    fs::copy(
        active.join(segment_name(current.id)),
        sealed.join(segment_name(current.id)),
    )?;
    let failure = storage
        .seal(current)
        .expect_err("the same segment cannot exist in both namespaces");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);

    let second_fixture = Fixture::new()?;
    let second_active = second_fixture.root.path().join("segments/active");
    let second_sealed = second_fixture.root.path().join("segments/sealed");
    let mut second_storage = LedgerStorage::open(&second_fixture.volume)?;
    second_storage.create_active(current, &wrapping_key(), instance()?)?;
    fs::write(second_active.join(frontier_name(current.id)), b"active")?;
    fs::write(second_sealed.join(frontier_name(current.id)), b"sealed")?;
    let failure = second_storage
        .seal(current)
        .expect_err("the same frontier cannot exist in both namespaces");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn descriptor_relative_existence_checks_report_invalid_components() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let directory = File::open(root.path())?;
    assert!(!entry_exists(&directory, "missing")?);
    fs::write(root.path().join("present"), b"present")?;
    assert!(entry_exists(&directory, "present")?);
    let failure = entry_exists(&directory, &"x".repeat(1_025))
        .expect_err("an invalid component cannot be classified as absent");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    Ok(())
}

#[test]
fn only_canonical_ledger_artifact_names_are_recovery_owned() {
    let identity = "0123456789abcdef0123456789abcdef";
    for suffix in [".segment", ".frontier", ".frontier.tmp"] {
        assert!(recognized_ledger_name(
            format!("{identity}{suffix}").as_bytes()
        ));
    }
    for name in [
        "not-a-ledger-file",
        "0123456789abcdef0123456789abcdeg.segment",
        "0123456789abcdef.segment",
    ] {
        assert!(!recognized_ledger_name(name.as_bytes()));
    }
}

struct Fixture {
    root: TemporaryRoot,
    volume: crate::OwnedPrimaryDataVolume,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        Ok(Self { root, volume })
    }
}

fn metadata(base_position: CommitPosition) -> SegmentMetadata {
    SegmentMetadata {
        scope: SegmentScope::new(
            TenantId::from_bytes([0x64; 16]).expect("fixed tenant"),
            SignalKind::Logs,
            VirtualShardId::new(1).expect("fixed shard"),
        ),
        id: SegmentId::new([0x91; 16]).expect("fixed segment"),
        state: SegmentState::Active,
        base_position,
    }
}

fn wrapping_key() -> SegmentProtectionKey {
    SegmentProtectionKey::from_owned(Box::new([0x92; 32]))
}

fn instance() -> Result<InstanceId, Box<dyn Error>> {
    Ok(InstanceId::new([0x93; 16])?)
}
