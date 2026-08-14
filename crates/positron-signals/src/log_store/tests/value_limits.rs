use super::*;

#[test]
fn domain_allocation_failure_remains_retryable_through_log_store_classification() {
    assert_eq!(
        crate::log_store::failure::classify_domain_failure_code(
            positron_domain::outcome::DomainFailureCode::AllocationUnavailable,
        ),
        LogStoreFailureCode::ResourceExhausted
    );
    assert_eq!(
        crate::log_store::failure::classify_domain_failure_code(
            positron_domain::outcome::DomainFailureCode::ValueLimitExceeded,
        ),
        LogStoreFailureCode::LimitExceeded
    );
}

#[test]
fn record_validation_counts_all_occurrences_in_each_namespace() -> Result<(), Box<dyn Error>> {
    let request = RequestLimits::new(
        ByteLimit::new(1_024)?,
        ByteLimit::new(1_024)?,
        CollectionLimit::new(8)?,
        CollectionLimit::new(8)?,
    );
    let record = RecordLimits::new(
        ByteLimit::new(1_024)?,
        ByteLimit::new(1_024)?,
        ByteLimit::new(128)?,
    );
    let dynamic = DynamicValueLimits::new(
        ByteLimit::new(64)?,
        CollectionLimit::new(2)?,
        ByteLimit::new(64)?,
        NestingLimit::new(4)?,
        CollectionLimit::new(8)?,
        CollectionLimit::new(8)?,
    );
    let profile =
        ValueLimitProfileCandidate::new(ValueLimitSet::new(request, record, dynamic), None)
            .validate()?;
    let attributes = vec![
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "first".to_owned(),
            vec![
                CandidateAttributeValue::signed_integer(1),
                CandidateAttributeValue::signed_integer(2),
            ],
        ),
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "second".to_owned(),
            vec![CandidateAttributeValue::signed_integer(3)],
        ),
    ];

    let failure = LogRecord::checked_receiver_candidate(
        profile,
        None,
        None,
        None,
        attributes,
        PolicyProvenance::new(1, [0x71; 32], vec![])?,
    )
    .expect_err("three record occurrences exceed the per-namespace limit of two");
    assert_eq!(failure.code(), LogStoreFailureCode::LimitExceeded);
    Ok(())
}

#[test]
fn decoded_record_limit_is_checked_after_value_validation() -> Result<(), Box<dyn Error>> {
    let request = RequestLimits::new(
        ByteLimit::new(1_024)?,
        ByteLimit::new(1_024)?,
        CollectionLimit::new(8)?,
        CollectionLimit::new(8)?,
    );
    let record = RecordLimits::new(
        ByteLimit::new(1_024)?,
        ByteLimit::new(4)?,
        ByteLimit::new(8)?,
    );
    let dynamic = DynamicValueLimits::new(
        ByteLimit::new(8)?,
        CollectionLimit::new(8)?,
        ByteLimit::new(64)?,
        NestingLimit::new(4)?,
        CollectionLimit::new(8)?,
        CollectionLimit::new(8)?,
    );
    let profile =
        ValueLimitProfileCandidate::new(ValueLimitSet::new(request, record, dynamic), None)
            .validate()?;

    let failure = LogRecord::checked_receiver_candidate(
        profile,
        None,
        None,
        Some(CandidateAttributeValue::string("12345".to_owned())),
        vec![],
        PolicyProvenance::new(1, [0x72; 32], vec![])?,
    )
    .expect_err("five decoded body bytes exceed the four-byte record ceiling");
    assert_eq!(failure.code(), LogStoreFailureCode::LimitExceeded);
    Ok(())
}
