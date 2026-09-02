use super::*;

#[test]
fn committed_span_is_visible_immediately_from_the_active_segment() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x13; 16])?,
        CatalogSecret::from_owned(Box::new([0x23; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(3)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x53; 32])),
    )?;
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
        positron_policy::PolicyProvenance::new(1, [0x76; 32], Vec::new()).unwrap(),
    )?;
    let store = TraceStore::new();
    let block = store.prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        positron_kernel::StoreBlockIdentity::new([0x63; 16])?,
        vec![observation.clone()],
    )?;
    let receipt = ledger.append(block.into_store_block())?;
    let marker = receipt.position();
    let ordinal = positron_domain::routing::RecordOrdinal::new(0)?;
    let through = TraceScan::through(ScanLimit::new(1)?, marker);
    assert_eq!(through.limit().value(), 1);
    assert_eq!(through.frontier(), Some(marker));
    assert_eq!(through.after_position(), None);
    let after = TraceScan::after(ScanLimit::new(1)?, marker);
    assert_eq!(after.after_position(), Some(marker));
    assert_eq!(after.frontier(), None);
    let between = TraceScan::between(ScanLimit::new(1)?, marker, marker);
    assert_eq!(between.after_position(), Some(marker));
    assert_eq!(between.frontier(), Some(marker));
    let between_record = TraceScan::between_record(ScanLimit::new(1)?, marker, ordinal, marker)
        .with_scanned_bytes(1);
    assert_eq!(between_record.after_record(), Some((marker, ordinal)));
    assert_eq!(between_record.scanned_bytes_limit(), Some(1));
    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.observations().len(), 1);
    assert!(result.complete());
    assert_eq!(result.incompleteness(), super::TraceIncompleteness::None);
    assert_eq!(result.observations()[0].observation(), &observation);
    assert_eq!(
        result.observations()[0].commit_position(),
        receipt.position()
    );
    assert_eq!(result.decoded_observations(), 1);
    assert!(result.scanned_bytes() > 0);
    assert!(!result.scanned_bytes_limited());
    assert!(result.retained_size_bytes() >= 512);
    assert_eq!(
        result.observations()[0].stored().observation(),
        &observation
    );
    assert_eq!(result.observations()[0].trace_id(), observation.trace_id());
    assert_eq!(result.observations()[0].span_id(), observation.span_id());
    assert_eq!(
        result.observations()[0].ingest_time().instant().value(),
        100
    );
    let owned = result.into_observations();
    assert_eq!(owned.len(), 1);
    let observed_result = store.scan_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
        &NeverCancelled,
        &NeverObserved,
    )?;
    assert_eq!(observed_result.observations().len(), 1);
    assert!(observed_result.complete());
    drop(ledger);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x53; 32])),
    )?;
    let restarted = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert!(restarted.complete());
    assert_eq!(restarted.observations()[0].observation(), &observation);

    let limited = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?).with_scanned_bytes(0),
    )?;
    assert!(limited.observations().is_empty());
    assert!(!limited.complete());
    assert_eq!(
        limited.incompleteness(),
        super::TraceIncompleteness::ScannedBytesLimit
    );
    drop(limited);

    let after_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::after(ScanLimit::new(1)?, marker),
    )?;
    assert!(after_result.observations().is_empty());
    assert!(after_result.complete());
    let through_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::through(ScanLimit::new(1)?, marker),
    )?;
    assert_eq!(through_result.observations().len(), 1);
    let between_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::between(ScanLimit::new(1)?, marker, marker),
    )?;
    assert!(between_result.observations().is_empty());

    for (observer, expected) in [
        (
            &WorkBudgetExhausted as &dyn ScanObserver,
            TraceStoreFailureCode::BudgetExhausted,
        ),
        (
            &BytesBudgetExhausted as &dyn ScanObserver,
            TraceStoreFailureCode::BudgetExhausted,
        ),
        (
            &RecordsBudgetExhausted as &dyn ScanObserver,
            TraceStoreFailureCode::BudgetExhausted,
        ),
    ] {
        let failure = store
            .scan_observed(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                TraceScan::all(ScanLimit::new(1)?),
                &NeverCancelled,
                observer,
            )
            .expect_err("observer budget failures must remain typed");
        assert_eq!(failure.code(), expected);
    }

    let before_cancel = authority.governor().inspect()?.outstanding_total();
    let cancellation = AlwaysCancelled;
    let failure = store
        .scan_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
            &cancellation,
            &NeverObserved,
        )
        .expect_err("cancelled trace scan must stop before resource admission");
    assert_eq!(failure.code(), TraceStoreFailureCode::Cancelled);
    let after_cancel = authority.governor().inspect()?;
    assert_eq!(after_cancel.outstanding_total(), before_cancel);

    let small_amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?;
    let refused_capacity = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        small_amounts,
    )?)?;
    let admission_failure = store
        .prepare_unretained_for_test(
            refused_capacity,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
            tenant,
            shard,
            positron_kernel::StoreBlockIdentity::new([0x72; 16])?,
            vec![observation.clone()],
        )
        .err()
        .ok_or("insufficient preparation capacity was unexpectedly accepted")?;
    assert_eq!(
        admission_failure.code(),
        TraceStoreFailureCode::ResourceAdmissionRefused
    );

    let too_many = match store.prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
        tenant,
        shard,
        positron_kernel::StoreBlockIdentity::new([0x73; 16])?,
        vec![observation; 1_025],
    ) {
        Ok(_) => return Err("Trace Store accepted too many observations".into()),
        Err(failure) => failure,
    };
    assert_eq!(too_many.code(), TraceStoreFailureCode::LimitExceeded);
    Ok(())
}

#[test]
fn trace_scan_enforces_physical_tenant_and_signal_boundaries() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x14; 16])?,
        CatalogSecret::from_owned(Box::new([0x24; 32]), Box::new([0x34; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(4)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )?;
    let block = TraceStore::new().prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        positron_kernel::StoreBlockIdentity::new([0x64; 16])?,
        vec![SpanObservation::checked_native(
            [0x11; 16],
            [0x22; 8],
            None,
            "server".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x77; 32], Vec::new()).unwrap(),
        )?],
    )?;
    ledger.append(block.into_store_block())?;
    let snapshot = ledger.snapshot()?;
    let wrong_tenant = TraceStore::new()
        .scan(
            authority.governor(),
            TenantId::from_bytes([0x42; 16])?,
            &snapshot,
            TraceScan::all(ScanLimit::new(1)?),
        )
        .expect_err("cross-tenant trace scan must fail closed");
    assert_eq!(
        wrong_tenant.code(),
        TraceStoreFailureCode::PhysicalScopeMismatch
    );
    let logs_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(10)?);
    let logs_ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        logs_scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let wrong_signal = TraceStore::new()
        .scan(
            authority.governor(),
            tenant,
            &logs_ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
        )
        .expect_err("cross-signal trace scan must fail closed");
    assert_eq!(
        wrong_signal.code(),
        TraceStoreFailureCode::PhysicalScopeMismatch
    );
    Ok(())
}

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
