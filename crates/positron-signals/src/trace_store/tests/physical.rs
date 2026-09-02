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
    let result = store.scan(
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
    let resumed = store.scan(
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
    assert_eq!(result.observations().len(), 1);
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
    assert_eq!(next_result.observations().len(), 1);
    assert!(!next_result.complete());
    let roomy_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(roomy_result.observations().len(), 5);
    assert!(roomy_result.retained_size_bytes() >= 8 * 512);
    Ok(())
}
