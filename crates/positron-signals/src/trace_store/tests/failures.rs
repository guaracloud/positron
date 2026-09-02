use super::*;

#[test]
fn malformed_trace_block_fails_closed_without_a_partial_result() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x19; 16])?,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(9)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let (retention, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    let store = TraceStore::new();
    let observation = SpanObservation::checked_native(
        [0x71; 16],
        [0x72; 8],
        None,
        "valid-prefix".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x86; 32], Vec::new()).unwrap(),
    )?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)));
    let stored = StoredSpanObservation::new(observation, clock.assign_ingest_time()?);
    let mut malformed = codec::encode_block(tenant, std::slice::from_ref(&stored))?;
    malformed.push(0xff);
    let preparation = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        positron_kernel::StoreBlockIdentity::new([0x73; 16])?,
    )?;
    ledger.append(preparation.finish(malformed)?)?;
    let snapshot = ledger.snapshot()?;
    let block = snapshot.blocks().first().ok_or("missing malformed block")?;
    let cancellation = NeverCancelled;
    let observer = NeverObserved;
    let failure =
        match codec::BlockDecode::observed(tenant, block.payload(), &cancellation, &observer)?
            .decode_after(block, 0, 1, &cancellation)
        {
            Ok(_) => return Err("the decoder accepted trailing bytes".into()),
            Err(failure) => failure,
        };
    assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
    let failure = store
        .scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
        )
        .expect_err("malformed native block must not yield a partial observation");
    assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
    Ok(())
}

#[test]
fn malformed_trace_record_shapes_fail_closed_at_their_boundaries() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x20; 16])?,
        CatalogSecret::from_owned(Box::new([0x30; 32]), Box::new([0x40; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let profile = ValueLimitProfile::release_1_system_maximum();
    let attributes = vec![
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "key".to_owned(),
            vec![CandidateAttributeValue::boolean(true)],
        )
        .validate(profile)?,
    ];
    let observation = SpanObservation::checked_native(
        [0x71; 16],
        [0x72; 8],
        None,
        "valid".to_owned(),
        positron_domain::time::EventTime::missing(),
        positron_domain::time::EventTime::missing(),
        attributes,
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [1; 32], Vec::new())?,
    )?;
    let stored = StoredSpanObservation::new(
        observation,
        LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)))
            .assign_ingest_time()?,
    );
    let valid = codec::encode_block(tenant, std::slice::from_ref(&stored))?;
    let wrong_tenant = codec::encode_block(
        TenantId::from_bytes([0x42; 16])?,
        std::slice::from_ref(&stored),
    )?;
    let mut trailing = valid.clone();
    trailing.push(0xff);
    let truncated = valid
        .get(..valid.len().saturating_sub(3))
        .ok_or("trace fixture was unexpectedly short")?
        .to_vec();
    let mut aggregate_occurrences = valid.clone();
    aggregate_occurrences
        .get_mut(66..68)
        .ok_or("trace fixture attribute count offset")?
        .copy_from_slice(&2_u16.to_be_bytes());
    aggregate_occurrences
        .get_mut(76..78)
        .ok_or("trace fixture occurrence count offset")?
        .copy_from_slice(&1_024_u16.to_be_bytes());
    aggregate_occurrences.splice(80..80, std::iter::repeat_n(0_u8, 1_023));
    let second_set = [3_u8, 0, 0, 0, 1, b'x', 0, 1, 0];
    aggregate_occurrences.splice(1_103..1_103, second_set);
    let cases = vec![
        (
            "wrong magic",
            replaced_byte(&valid, 0, 0xff)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "wrong version",
            replaced_bytes(&valid, 8, [0, 2])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "wrong tenant",
            wrong_tenant,
            TraceStoreFailureCode::PhysicalScopeMismatch,
        ),
        (
            "zero records",
            replaced_bytes(&valid, 26, [0, 0])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "too many records",
            replaced_bytes(&valid, 26, [4, 1])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown parent marker",
            replaced_byte(&valid, 52, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown span kind",
            replaced_byte(&valid, 53, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown sampling decision",
            replaced_byte(&valid, 54, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown source time quality",
            replaced_byte(&valid, 55, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "invalid span name",
            replaced_byte(&valid, 61, 0xff)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown attribute namespace",
            replaced_byte(&valid, 68, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "empty occurrence set",
            replaced_bytes(&valid, 76, [0, 0])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown native value",
            replaced_byte(&valid, 78, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "invalid native boolean",
            replaced_byte(&valid, 79, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "invalid policy provenance",
            replaced_bytes(&valid, 88, [0; 32])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "truncated block",
            truncated,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "trailing bytes",
            trailing,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "aggregate namespace occurrences",
            aggregate_occurrences,
            TraceStoreFailureCode::MalformedBlock,
        ),
    ];

    for (index, (description, bytes, expected)) in cases.into_iter().enumerate() {
        let shard = VirtualShardId::new(u32::try_from(index + 20)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(index + 0x61)?; 32])),
        )?;
        ledger.append(positron_kernel::PreparedStoreBlock::new(
            scope,
            positron_kernel::StoreBlockIdentity::new([u8::try_from(index + 0x71)?; 16])?,
            bytes,
        )?)?;
        let failure = TraceStore::new()
            .scan(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                TraceScan::all(ScanLimit::new(1)?),
            )
            .expect_err(description);
        assert_eq!(failure.code(), expected, "{description}");
    }
    Ok(())
}
