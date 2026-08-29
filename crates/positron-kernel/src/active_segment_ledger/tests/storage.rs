use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Write};

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use super::support::TemporaryRoot;
use crate::active_segment_ledger::format::{SegmentMetadata, SegmentState};
use crate::active_segment_ledger::recovery::{frontier_name, segment_name};
use crate::active_segment_ledger::storage::{
    AppendFailure, LedgerStorage, SegmentMutation, entry_exists, recognized_ledger_name,
    write_segment_bytes,
};
use crate::active_segment_ledger::{
    LedgerCompletionState, LedgerFailureCode, SegmentId, SegmentProtectionKey, SegmentScope,
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

#[test]
fn segment_write_tracks_the_exact_first_successful_byte_boundary() {
    let mut zero = ZeroWriter;
    let zero_failure = match write_segment_bytes(&mut zero, b"frame", SegmentMutation::NotStarted) {
        Err(AppendFailure::RejectedBeforeMutation(failure)) => failure,
        _ => panic!("zero progress must be rejected before mutation"),
    };
    assert_eq!(zero_failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        zero_failure.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );

    let mut partial = PartialThenExhausted(false);
    let partial_failure =
        match write_segment_bytes(&mut partial, b"frame", SegmentMutation::NotStarted) {
            Err(AppendFailure::SegmentMutated(failure)) => failure,
            _ => panic!("an error after one byte must require recovery"),
        };
    assert_eq!(partial_failure.code(), LedgerFailureCode::StorageExhausted);
    assert_eq!(
        partial_failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );

    let mut interrupted = InterruptedThenComplete(false);
    assert!(matches!(
        write_segment_bytes(&mut interrupted, b"frame", SegmentMutation::NotStarted),
        Ok(SegmentMutation::BytesWritten)
    ));

    let mut overflowing = PartialThenOverflow(false);
    let overflow_failure =
        match write_segment_bytes(&mut overflowing, b"frame", SegmentMutation::NotStarted) {
            Err(AppendFailure::SegmentMutated(failure)) => failure,
            _ => panic!("invalid writer progress must fail closed after mutation"),
        };
    assert_eq!(overflow_failure.code(), LedgerFailureCode::LimitExceeded);
}

#[test]
fn segment_write_fails_closed_when_writer_overreports_progress() {
    let failure = match write_segment_bytes(
        &mut OverreportingWriter,
        b"frame",
        SegmentMutation::NotStarted,
    ) {
        Err(AppendFailure::SegmentMutated(failure)) => failure,
        _ => panic!("impossible writer progress must require recovery"),
    };
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
}

struct ZeroWriter;

impl Write for ZeroWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Ok(0)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PartialThenExhausted(bool);

impl Write for PartialThenExhausted {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        if std::mem::replace(&mut self.0, true) {
            Err(io::Error::from_raw_os_error(
                rustix::io::Errno::NOSPC.raw_os_error(),
            ))
        } else {
            Ok(1)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct InterruptedThenComplete(bool);

impl Write for InterruptedThenComplete {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if std::mem::replace(&mut self.0, true) {
            Ok(buffer.len())
        } else {
            Err(io::Error::from(io::ErrorKind::Interrupted))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PartialThenOverflow(bool);

impl Write for PartialThenOverflow {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        if std::mem::replace(&mut self.0, true) {
            Ok(usize::MAX)
        } else {
            Ok(1)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct OverreportingWriter;

impl Write for OverreportingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len().saturating_add(1))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
