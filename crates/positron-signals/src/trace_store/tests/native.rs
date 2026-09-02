use super::*;

#[test]
fn a_native_span_observation_preserves_its_identity_and_sampling_state() {
    let policy = positron_policy::PolicyProvenance::new(1, [0x70; 32], Vec::new()).unwrap();
    let observation = SpanObservation::checked_native(
        [0x11; 16],
        [0x22; 8],
        None,
        "checkout".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable).unwrap(),
        EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable).unwrap(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        policy.clone(),
    )
    .expect("valid native span");

    assert_eq!(observation.trace_id(), [0x11; 16]);
    assert_eq!(observation.span_id(), [0x22; 8]);
    assert_eq!(observation.parent_span_id(), None);
    assert_eq!(observation.name(), "checkout");
    assert_eq!(observation.kind(), SpanKind::Server);
    assert_eq!(observation.sampling(), SamplingDecision::Sampled);
    assert_eq!(
        observation
            .start_time()
            .instant()
            .map(|value| value.value()),
        Some(10)
    );
    assert_eq!(
        observation.end_time().instant().map(|value| value.value()),
        Some(20)
    );
    let zero_time = SpanObservation::checked_native(
        [0x12; 16],
        [0x23; 8],
        None,
        "zero-time".to_owned(),
        EventTime::received(UnixNanoseconds::new(0), SourceTimeQuality::Zero).unwrap(),
        EventTime::received(UnixNanoseconds::new(0), SourceTimeQuality::Zero).unwrap(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        policy,
    )
    .expect("zero source timestamps remain explicitly non-usable");
    assert_eq!(
        zero_time.start_time().quality(),
        positron_domain::time::SourceTimeQuality::Zero
    );
}

#[test]
fn native_span_identity_and_name_bounds_fail_closed() {
    let policy = positron_policy::PolicyProvenance::new(1, [0x70; 32], Vec::new()).unwrap();
    let zero_trace = SpanObservation::checked_native(
        [0; 16],
        [0x22; 8],
        None,
        "span".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        policy.clone(),
    )
    .expect_err("zero trace IDs are not native identities");
    assert_eq!(zero_trace.code(), TraceStoreFailureCode::InvalidInput);

    let empty_name = SpanObservation::checked_native(
        [0x11; 16],
        [0x22; 8],
        Some([0; 8]),
        String::new(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        policy,
    )
    .expect_err("empty names and zero parents are not native observations");
    assert_eq!(empty_name.code(), TraceStoreFailureCode::InvalidInput);
}

#[test]
fn native_span_counts_occurrences_across_attribute_sets_by_namespace() {
    let profile = ValueLimitProfile::release_1_system_maximum();
    let make_sets = |namespace, count: usize| {
        (0..count)
            .map(|index| {
                AttributeOccurrenceSetCandidate::new(
                    namespace,
                    format!("fixture-{index}"),
                    vec![CandidateAttributeValue::null()],
                )
                .validate(profile)
                .expect("fixture attribute is valid")
            })
            .collect::<Vec<_>>()
    };
    for namespace in [
        AttributeNamespace::Resource,
        AttributeNamespace::InstrumentationScope,
        AttributeNamespace::Record,
    ] {
        let exact = SpanObservation::checked_native(
            [0x41; 16],
            [0x42; 8],
            None,
            "exact".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            make_sets(namespace, 1_024),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x70; 32], Vec::new()).unwrap(),
        );
        assert!(exact.is_ok(), "exact namespace occurrence bound is valid");
        let over = SpanObservation::checked_native(
            [0x43; 16],
            [0x44; 8],
            None,
            "over".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            make_sets(namespace, 1_025),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x71; 32], Vec::new()).unwrap(),
        )
        .expect_err("namespace occurrence bound is aggregate across sets");
        assert_eq!(over.code(), TraceStoreFailureCode::LimitExceeded);
    }
    assert!(
        SpanObservation::checked_native(
            [0x4b; 16],
            [0x4c; 8],
            None,
            "stream".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            make_sets(AttributeNamespace::Stream, 1),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x72; 32], Vec::new()).unwrap(),
        )
        .is_ok()
    );
    let mut mixed = make_sets(AttributeNamespace::Resource, 1_024);
    mixed.extend(make_sets(AttributeNamespace::InstrumentationScope, 1));
    mixed.extend(make_sets(AttributeNamespace::Resource, 1));
    let mixed_over = SpanObservation::checked_native(
        [0x45; 16],
        [0x46; 8],
        None,
        "mixed".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        mixed,
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x73; 32], Vec::new()).unwrap(),
    )
    .expect_err("mixed sets still count all Resource occurrences");
    assert_eq!(mixed_over.code(), TraceStoreFailureCode::LimitExceeded);

    let mut too_many_sets = make_sets(AttributeNamespace::Resource, 1_024);
    too_many_sets.extend(make_sets(AttributeNamespace::InstrumentationScope, 1_024));
    too_many_sets.extend(make_sets(AttributeNamespace::Record, 1_024));
    too_many_sets.extend(make_sets(AttributeNamespace::Stream, 1));
    let too_many_sets = SpanObservation::checked_native(
        [0x47; 16],
        [0x48; 8],
        None,
        "too-many-sets".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        too_many_sets,
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x74; 32], Vec::new()).unwrap(),
    )
    .expect_err("the aggregate attribute-set bound must be enforced");
    assert_eq!(too_many_sets.code(), TraceStoreFailureCode::LimitExceeded);

    let oversized_values = (0..17)
        .map(|_| CandidateAttributeValue::string("x".repeat(65_536)))
        .collect();
    let oversized_values = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Resource,
        "oversized".to_owned(),
        oversized_values,
    )
    .validate(profile)
    .expect("each individual value remains within the profile");
    let decoded_overflow = SpanObservation::checked_native(
        [0x49; 16],
        [0x4a; 8],
        None,
        "decoded-overflow".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        vec![oversized_values],
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x75; 32], Vec::new()).unwrap(),
    )
    .expect_err("the aggregate decoded-byte bound must be enforced");
    assert_eq!(
        decoded_overflow.code(),
        TraceStoreFailureCode::LimitExceeded
    );
}
