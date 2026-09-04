use super::super::*;

#[test]
fn sealed_and_successor_active_segments_have_equivalent_trace_scan_visibility()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x15; 16])?,
        CatalogSecret::from_owned(Box::new([0x25; 32]), Box::new([0x35; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(5)?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0x55; 32]));
    let profile = ValueLimitProfile::release_1_system_maximum();
    let boundary_key = "k".repeat(SpanObservation::MAX_NAME_BYTES);
    let boundary_attributes = || {
        vec![
            AttributeOccurrenceSetCandidate::new(
                AttributeNamespace::Resource,
                boundary_key.clone(),
                vec![CandidateAttributeValue::boolean(true)],
            )
            .validate(profile)
            .expect("the exact Release 1 key boundary is valid"),
        ]
    };
    assert!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Resource,
            "k".repeat(SpanObservation::MAX_NAME_BYTES + 1),
            vec![CandidateAttributeValue::boolean(true)],
        )
        .validate(profile)
        .is_err()
    );
    let first = SpanObservation::checked_native(
        [0x11; 16],
        [0x22; 8],
        None,
        "sealed".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable).unwrap(),
        EventTime::missing(),
        boundary_attributes(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x78; 32], Vec::new()).unwrap(),
    )?;
    let second = SpanObservation::checked_native(
        [0x11; 16],
        [0x23; 8],
        Some([0x22; 8]),
        "active".to_owned(),
        EventTime::received(UnixNanoseconds::new(11), SourceTimeQuality::Usable).unwrap(),
        EventTime::received(UnixNanoseconds::new(12), SourceTimeQuality::Usable).unwrap(),
        boundary_attributes(),
        SpanKind::Client,
        SamplingDecision::NotSampled,
        positron_policy::PolicyProvenance::new(1, [0x79; 32], Vec::new()).unwrap(),
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        key(),
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x65; 16])?,
                vec![first.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    let successor = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        key(),
    )?;
    successor.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x66; 16])?,
                vec![second.clone()],
            )?
            .into_store_block(),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &successor.snapshot()?,
        TraceScan::all(ScanLimit::new(2)?),
    )?;
    assert!(result.complete());
    assert_eq!(
        result
            .observations()
            .iter()
            .map(|observation| observation.observation().name())
            .collect::<Vec<_>>(),
        vec!["sealed", "active"]
    );
    assert!(result.observations().iter().all(|observation| {
        observation
            .observation()
            .attributes()
            .first()
            .is_some_and(|attribute| attribute.key().len() == SpanObservation::MAX_NAME_BYTES)
    }));
    Ok(())
}
