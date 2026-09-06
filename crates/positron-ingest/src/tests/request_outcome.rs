use positron_domain::routing::VirtualShardId;

use crate::{
    AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome, TraceLimitClass,
    TraceLimitRejectionSummary, TraceLimitViolation,
};

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

#[test]
fn trace_limit_summary_merges_in_fixed_order_and_keeps_maximum_representatives() {
    let classes = [
        TraceLimitClass::ContainerCount,
        TraceLimitClass::RecordCount,
        TraceLimitClass::AggregateAttributeCount,
        TraceLimitClass::AttributesPerNamespace,
        TraceLimitClass::NestingDepth,
        TraceLimitClass::ArrayEntries,
        TraceLimitClass::KeyValueListEntries,
        TraceLimitClass::DecodedBatchBytes,
        TraceLimitClass::IndividualValueBytes,
        TraceLimitClass::KeyPathBytes,
    ];
    let mut summary = TraceLimitRejectionSummary::new();
    for (index, class) in classes.into_iter().enumerate() {
        let actual = u64::try_from(index + 1).expect("fixed class index");
        summary.record(TraceLimitViolation::new(class, actual, actual - 1));
    }
    summary.record(TraceLimitViolation::new(
        TraceLimitClass::IndividualValueBytes,
        7,
        4,
    ));
    summary.record(TraceLimitViolation::new(
        TraceLimitClass::IndividualValueBytes,
        5,
        9,
    ));

    let mut merged = TraceLimitRejectionSummary::default();
    merged.record(TraceLimitViolation::new(
        TraceLimitClass::IndividualValueBytes,
        9,
        4,
    ));
    summary.merge(merged);
    summary.record(TraceLimitViolation::new(
        TraceLimitClass::IndividualValueBytes,
        9,
        8,
    ));

    let violations = summary.iter().collect::<Vec<_>>();
    assert_eq!(
        violations
            .iter()
            .map(|violation| violation.class())
            .collect::<Vec<_>>(),
        classes
    );
    assert_eq!(
        violations
            .iter()
            .map(|violation| violation.class().label())
            .collect::<Vec<_>>(),
        [
            "container count",
            "record count",
            "aggregate attribute count",
            "attributes per namespace",
            "nesting depth",
            "array entries",
            "key/value-list entries",
            "decoded batch bytes",
            "individual value bytes",
            "key/path bytes",
        ]
    );
    let individual = violations
        .iter()
        .find(|violation| violation.class() == TraceLimitClass::IndividualValueBytes)
        .expect("individual-value representative");
    assert_eq!((individual.actual(), individual.allowed()), (9, 8));
}
