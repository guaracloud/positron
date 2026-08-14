use positron_domain::routing::VirtualShardId;

use crate::{AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome};

fn group(attempted_records: usize, outcome: IngestOutcome) -> AdmissionGroupOutcome {
    AdmissionGroupOutcome::new(
        VirtualShardId::new(7).expect("fixed shard"),
        attempted_records,
        outcome,
    )
}

#[test]
fn group_accessors_and_permanent_only_request_preserve_exact_truth() {
    let permanent = group(
        3,
        IngestOutcome::Permanent(IngestFailureCode::PolicyRejected),
    );
    assert_eq!(permanent.shard().value(), 7);
    assert_eq!(permanent.attempted_records(), 3);
    assert_eq!(
        permanent.outcome(),
        IngestOutcome::Permanent(IngestFailureCode::PolicyRejected)
    );
    let request = IngestRequestOutcome::new(vec![permanent]);
    assert_eq!(request.groups(), [permanent]);
    assert_eq!(request.accepted_records(), 0);
    assert_eq!(request.permanently_rejected_records(), 3);
    assert_eq!(request.terminal_failure(), Some(permanent.outcome()));
    assert!(!request.capacity_only_retry());
}

#[test]
fn ambiguity_precedes_retry_and_capacity_retry_remains_explicit() {
    let retry = group(
        2,
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable),
    );
    let ambiguous = group(
        1,
        IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable),
    );
    let request = IngestRequestOutcome::new(vec![retry, ambiguous]);
    assert_eq!(request.terminal_failure(), Some(ambiguous.outcome()));
    assert!(request.capacity_only_retry());
    assert_eq!(request.permanently_rejected_records(), 0);
}

#[test]
fn retry_precedes_permanent_and_empty_request_has_no_terminal_failure() {
    let permanent = group(
        1,
        IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
    );
    let retry = group(
        1,
        IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
    );
    let mixed = IngestRequestOutcome::new(vec![permanent, retry]);
    assert_eq!(mixed.terminal_failure(), Some(retry.outcome()));
    assert!(!mixed.capacity_only_retry());

    let empty = IngestRequestOutcome::new(vec![]);
    assert!(empty.groups().is_empty());
    assert_eq!(empty.terminal_failure(), None);
}
