use super::super::*;

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
    assert_eq!(
        result.incompleteness(),
        super::super::TraceIncompleteness::None
    );
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
        super::super::TraceIncompleteness::ScannedBytesLimit
    );
    drop(limited);

    let bounded_snapshot = ledger.snapshot()?;
    let block_bytes = u64::try_from(
        bounded_snapshot
            .blocks()
            .first()
            .ok_or("missing committed trace block")?
            .payload()
            .len(),
    )?;
    let exact_bytes = store.scan(
        authority.governor(),
        tenant,
        &bounded_snapshot,
        TraceScan::all(ScanLimit::new(1)?).with_scanned_bytes(block_bytes),
    )?;
    assert!(exact_bytes.complete());
    assert_eq!(exact_bytes.scanned_bytes(), block_bytes);
    let one_over_bytes = store.scan(
        authority.governor(),
        tenant,
        &bounded_snapshot,
        TraceScan::all(ScanLimit::new(1)?).with_scanned_bytes(block_bytes + 1),
    )?;
    assert!(one_over_bytes.complete());
    assert_eq!(one_over_bytes.scanned_bytes(), block_bytes);

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
