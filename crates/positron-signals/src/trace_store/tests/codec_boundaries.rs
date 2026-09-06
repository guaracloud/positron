use super::*;
use crate::{
    SpanEvent, SpanObservationDetails, SpanObservationDetailsInput, SpanResourceMetadata,
    SpanScopeMetadata, SpanStatus, SpanStatusCode,
};

mod markers;

#[test]
fn trace_blocks_round_trip_native_typed_values_and_source_time_fallback()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(8)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    let profile = TraceStore::value_limit_profile();
    let attributes = vec![
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Resource,
            "http.status_code".to_owned(),
            vec![CandidateAttributeValue::signed_integer(200)],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "sampled".to_owned(),
            vec![CandidateAttributeValue::boolean(true)],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "nothing".to_owned(),
            vec![CandidateAttributeValue::null()],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "ratio".to_owned(),
            vec![CandidateAttributeValue::floating_point_bits(
                0x3ff0_0000_0000_0000,
            )],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "payload".to_owned(),
            vec![CandidateAttributeValue::bytes(vec![1, 2, 3])],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "array".to_owned(),
            vec![CandidateAttributeValue::array(vec![
                CandidateAttributeValue::signed_integer(7),
                CandidateAttributeValue::string("nested".to_owned()),
            ])],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "map".to_owned(),
            vec![CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new(
                    "nested".to_owned(),
                    CandidateAttributeValue::boolean(false),
                ),
            ])],
        )
        .validate(profile)?,
    ];
    let details = SpanObservationDetails::checked(SpanObservationDetailsInput {
        trace_state: String::new(),
        flags: 0,
        status: SpanStatus::checked(SpanStatusCode::Unset, String::new())?,
        events: vec![SpanEvent::checked(
            positron_domain::time::EventTime::out_of_range(u64::MAX)?,
            "event".to_owned(),
            Vec::new(),
            0,
        )?],
        links: Vec::new(),
        dropped_attributes_count: 0,
        dropped_events_count: 0,
        dropped_links_count: 0,
        resource: SpanResourceMetadata::checked(0, String::new())?,
        scope: SpanScopeMetadata::checked(String::new(), String::new(), 0, String::new())?,
    })?;
    let observation = SpanObservation::checked_native_with_details(
        [0x61; 16],
        [0x62; 8],
        None,
        "typed".to_owned(),
        positron_domain::time::EventTime::out_of_range(u64::MAX)?,
        positron_domain::time::EventTime::received(
            UnixNanoseconds::new(0),
            positron_domain::time::SourceTimeQuality::Zero,
        )?,
        attributes,
        SpanKind::Server,
        SamplingDecision::NotSampled,
        positron_policy::PolicyProvenance::new(2, [0x71; 32], vec!["rule".to_owned()])?,
        details,
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x69; 16])?,
                vec![observation.clone()],
            )?
            .into_store_block(),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    let span = result.spans().first().ok_or("missing typed span")?;
    let scanned = span
        .structural_representative()
        .ok_or("missing typed structural representative")?;
    let actual = scanned.observation();
    assert_eq!(actual, &observation);
    assert_eq!(actual.start_time().source_value(), Some(u64::MAX));
    assert_eq!(
        actual.start_time().quality(),
        positron_domain::time::SourceTimeQuality::Outlier
    );
    assert_eq!(
        actual.details().events()[0].timestamp().source_value(),
        Some(u64::MAX)
    );
    let query = positron_domain::time::QueryTime::for_span(
        &actual.start_time(),
        positron_domain::time::IngestTimeCandidate::new(scanned.stored().ingest_time().instant()),
    );
    assert_eq!(query.instant(), UnixNanoseconds::new(100));
    assert_eq!(
        query.provenance(),
        positron_domain::time::QueryTimeProvenance::Ingest
    );
    assert_eq!(
        actual.end_time().quality(),
        positron_domain::time::SourceTimeQuality::Zero
    );
    assert_eq!(
        actual
            .attributes()
            .first()
            .ok_or("missing resource attribute")?
            .occurrence(0)
            .ok_or("missing resource occurrence")?
            .as_signed_integer(),
        Some(200)
    );

    // A compact null-heavy block can retain a large nested Vec graph. Its
    // conservative recursive bound must refuse before decode rather than
    // allowing the query governor to be overrun by decoded capacity.
    let nested_values = (0..900)
        .map(|_| {
            CandidateAttributeValue::array(
                (0..900).map(|_| CandidateAttributeValue::null()).collect(),
            )
        })
        .collect();
    let adversarial = SpanObservation::checked_native(
        [0x63; 16],
        [0x64; 8],
        None,
        "nested".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        vec![
            AttributeOccurrenceSetCandidate::new(
                AttributeNamespace::Resource,
                "nested".to_owned(),
                nested_values,
            )
            .validate(profile)?,
        ],
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x85; 32], Vec::new()).unwrap(),
    )?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x6a; 16])?,
                vec![adversarial],
            )?
            .into_store_block(),
    )?;
    let before_refusal = authority.governor().inspect()?.outstanding_total();
    let refusal = store
        .scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(2)?),
        )
        .expect_err("nested decoded peak must be refused before allocation");
    assert_eq!(
        refusal.code(),
        TraceStoreFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_refusal
    );
    Ok(())
}
