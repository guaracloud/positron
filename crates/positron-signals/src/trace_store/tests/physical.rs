use super::*;

#[test]
fn physical_observations_are_not_deduplicated_at_the_storage_seam() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x16; 16])?,
        CatalogSecret::from_owned(Box::new([0x26; 32]), Box::new([0x36; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(6)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x56; 32])),
    )?;
    let observation = SpanObservation::checked_native(
        [0x31; 16],
        [0x32; 8],
        None,
        "retry".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable).unwrap(),
        EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable).unwrap(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x80; 32], Vec::new()).unwrap(),
    )?;
    let conflict = SpanObservation::checked_native(
        [0x31; 16],
        [0x32; 8],
        None,
        "conflicting-retry".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable).unwrap(),
        EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable).unwrap(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x81; 32], Vec::new()).unwrap(),
    )?;
    let store = TraceStore::new();
    let receipt = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x67; 16])?,
                vec![observation.clone(), observation.clone(), conflict.clone()],
            )?
            .into_store_block(),
    )?;
    let result = store.scan_physical(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    assert_eq!(result.observations().len(), 3);
    assert_eq!(
        result.observations()[0].observation(),
        result.observations()[1].observation()
    );
    assert_eq!(
        result.observations()[0].record_ordinal(),
        positron_domain::routing::RecordOrdinal::new(0)?
    );
    assert_eq!(
        result.observations()[1].record_ordinal(),
        positron_domain::routing::RecordOrdinal::new(1)?
    );
    assert_eq!(result.observations()[2].observation(), &conflict);
    drop(result);
    let logical = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    assert!(logical.complete());
    assert_eq!(logical.incompleteness(), TraceIncompleteness::None);
    assert_eq!(logical.decoded_observations(), 3);
    assert_eq!(logical.spans().len(), 1);
    let span = logical.spans().first().ok_or("missing logical span")?;
    assert_eq!(span.trace_id(), [0x31; 16]);
    assert_eq!(span.span_id(), [0x32; 8]);
    assert_eq!(span.observation_count(), 3);
    assert!(span.conflicted());
    assert!(span.structurally_incomplete());
    assert_eq!(span.variants().len(), 2);
    assert_eq!(span.variants()[0].observation_count(), 2);
    assert_eq!(span.variants()[0].observation().observation(), &observation);
    assert_eq!(span.variants()[1].observation_count(), 1);
    assert_eq!(span.variants()[1].observation().observation(), &conflict);
    assert_eq!(
        span.structural_representative()
            .ok_or("missing structural representative")?
            .observation(),
        &observation
    );
    drop(logical);
    let byte_limited = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?).with_scanned_bytes(0),
    )?;
    assert!(byte_limited.spans().is_empty());
    assert!(!byte_limited.complete());
    assert_eq!(
        byte_limited.incompleteness(),
        TraceIncompleteness::ScannedBytesLimit
    );
    drop(byte_limited);
    let observed = store.scan_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
        &NeverCancelled,
        &NeverObserved,
    )?;
    assert_eq!(observed.spans().len(), 1);
    assert_eq!(observed.decoded_observations(), 3);
    drop(observed);
    let resumed = store.scan_physical(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::between_record(
            ScanLimit::new(2)?,
            receipt.position(),
            positron_domain::routing::RecordOrdinal::new(0)?,
            receipt.position(),
        ),
    )?;
    assert!(resumed.complete());
    assert_eq!(resumed.observations().len(), 2);
    assert_eq!(resumed.observations()[0].record_ordinal().value(), 1);
    assert_eq!(resumed.observations()[1].record_ordinal().value(), 2);
    assert_eq!(resumed.observations()[1].observation(), &conflict);
    drop(resumed);
    ledger.seal()?;
    let reopened = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x56; 32])),
    )?;
    let restarted = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    let restarted_span = restarted
        .spans()
        .first()
        .ok_or("missing restarted logical span")?;
    assert_eq!(restarted_span.observation_count(), 3);
    assert_eq!(restarted_span.variants().len(), 2);
    assert!(restarted_span.conflicted());
    assert_eq!(restarted_span.variants()[0].observation_count(), 2);
    assert_eq!(restarted_span.variants()[1].observation_count(), 1);
    Ok(())
}

#[test]
fn logical_scan_keeps_distinct_native_value_bits_as_conflicting_variants()
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
    let attribute = |bits| {
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "duration".to_owned(),
            vec![CandidateAttributeValue::floating_point_bits(bits)],
        )
        .validate(ValueLimitProfile::release_1_system_maximum())
    };
    let observation = |attributes| {
        SpanObservation::checked_native(
            [0x61; 16],
            [0x62; 8],
            None,
            "native-value".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            attributes,
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x90; 32], Vec::new())?,
        )
    };
    let positive_zero = observation(vec![attribute(0.0_f64.to_bits())?])?;
    let negative_zero = observation(vec![attribute((-0.0_f64).to_bits())?])?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x69; 16])?,
                vec![positive_zero.clone(), positive_zero, negative_zero],
            )?
            .into_store_block(),
    )?;
    let logical = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    let span = logical.spans().first().ok_or("missing logical span")?;
    assert_eq!(span.observation_count(), 3);
    assert_eq!(span.variants().len(), 2);
    assert_eq!(span.variants()[0].observation_count(), 2);
    assert_eq!(span.variants()[1].observation_count(), 1);
    assert!(span.conflicted());
    Ok(())
}

#[test]
fn logical_scan_preserves_native_attribute_type_and_namespace_variants()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x28; 16])?,
        CatalogSecret::from_owned(Box::new([0x38; 32]), Box::new([0x48; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(18)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x68; 32])),
    )?;
    let attribute = |namespace, value| {
        AttributeOccurrenceSetCandidate::new(namespace, "enabled".to_owned(), vec![value])
            .validate(ValueLimitProfile::release_1_system_maximum())
    };
    let observation = |attributes| {
        SpanObservation::checked_native(
            [0x71; 16],
            [0x72; 8],
            None,
            "semantic-identity".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            attributes,
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0xa0; 32], Vec::new())?,
        )
    };
    let record_boolean = observation(vec![attribute(
        AttributeNamespace::Record,
        CandidateAttributeValue::boolean(true),
    )?])?;
    let resource_boolean = observation(vec![attribute(
        AttributeNamespace::Resource,
        CandidateAttributeValue::boolean(true),
    )?])?;
    let record_string = observation(vec![attribute(
        AttributeNamespace::Record,
        CandidateAttributeValue::string("true".to_owned()),
    )?])?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x79; 16])?,
                vec![
                    record_boolean.clone(),
                    record_boolean.clone(),
                    resource_boolean.clone(),
                    record_string.clone(),
                ],
            )?
            .into_store_block(),
    )?;
    let logical = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(4)?),
    )?;
    let span = logical.spans().first().ok_or("missing logical span")?;
    assert_eq!(logical.spans().len(), 1);
    assert_eq!(span.observation_count(), 4);
    assert_eq!(span.variants().len(), 3);
    let variant = |expected: &SpanObservation| {
        span.variants()
            .iter()
            .find(|variant| variant.observation().observation() == expected)
            .ok_or("missing semantic variant")
    };
    assert_eq!(variant(&record_boolean)?.observation_count(), 2);
    assert_eq!(variant(&resource_boolean)?.observation_count(), 1);
    assert_eq!(variant(&record_string)?.observation_count(), 1);
    assert!(span.conflicted());
    assert!(span.structurally_incomplete());
    Ok(())
}

#[test]
fn bounded_trace_scan_reports_explicit_result_incompleteness() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x17; 16])?,
        CatalogSecret::from_owned(Box::new([0x27; 32]), Box::new([0x37; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(7)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x57; 32])),
    )?;
    let store = TraceStore::new();
    let observations = (0_u8..3)
        .map(|id| {
            SpanObservation::checked_native(
                [0x41; 16],
                [id.saturating_add(1); 8],
                None,
                format!("span-{id}"),
                EventTime::missing(),
                EventTime::missing(),
                Vec::new(),
                SpanKind::Internal,
                SamplingDecision::Unknown,
                positron_policy::PolicyProvenance::new(1, [0x82; 32], Vec::new()).unwrap(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let first_receipt = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x68; 16])?,
                observations,
            )?
            .into_store_block(),
    )?;
    let third_observation = SpanObservation::checked_native(
        [0x43; 16],
        [0x52; 8],
        None,
        "third-block".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x83; 32], Vec::new()).unwrap(),
    )?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(102))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x6c; 16])?,
                vec![third_observation],
            )?
            .into_store_block(),
    )?;
    let second_observation = SpanObservation::checked_native(
        [0x42; 16],
        [0x51; 8],
        None,
        "second-block".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x84; 32], Vec::new()).unwrap(),
    )?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x6b; 16])?,
                vec![second_observation],
            )?
            .into_store_block(),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.spans().len(), 1);
    assert_eq!(result.decoded_observations(), 1);
    assert!(!result.complete());
    assert_eq!(
        result.incompleteness(),
        super::TraceIncompleteness::ResultLimit
    );
    let next_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::after(ScanLimit::new(1)?, first_receipt.position()),
    )?;
    assert_eq!(next_result.spans().len(), 1);
    assert_eq!(next_result.decoded_observations(), 1);
    assert!(!next_result.complete());
    let roomy_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(roomy_result.spans().len(), 5);
    assert_eq!(roomy_result.decoded_observations(), 5);
    assert!(roomy_result.complete());
    assert!(roomy_result.scanned_bytes() > 0);
    assert!(roomy_result.retained_size_bytes() > 0);
    Ok(())
}
