use super::*;

#[test]
fn body_string_bounds_round_trip_above_attribute_limit_through_exact_maximum()
-> Result<(), Box<dyn Error>> {
    for (size, marker) in [(65_537, 0x71), (262_144, 0x72)] {
        let body = "b".repeat(size);
        let actual = round_trip_body(Some(body.clone()), marker)?;
        assert_eq!(
            actual.body().and_then(ValidatedAttributeValue::as_str),
            Some(body.as_str())
        );
    }
    Ok(())
}

#[test]
fn body_bytes_bounds_round_trip_above_attribute_limit_through_exact_maximum()
-> Result<(), Box<dyn Error>> {
    for (size, marker) in [(65_537, 0x73), (262_144, 0x74)] {
        let body = vec![0xa5; size];
        let checked = value(
            super::super::types::body_value_profile()?,
            CandidateAttributeValue::bytes(body.clone()),
        )?;
        let record = LogRecord::checked_native(
            EventTime::missing(),
            None,
            Some(checked),
            vec![],
            PolicyProvenance::new(1, [0x70; 32], vec![])?,
        )?;
        let actual = round_trip_record(record, marker)?;
        assert_eq!(
            actual.body().and_then(ValidatedAttributeValue::as_bytes),
            Some(body.as_slice())
        );
    }
    Ok(())
}

#[test]
fn body_rejects_first_byte_above_maximum_before_preparation() -> Result<(), Box<dyn Error>> {
    let failure = LogRecord::checked_minimal(
        None,
        Some("b".repeat(262_145)),
        vec![],
        PolicyProvenance::new(1, [0x70; 32], vec![])?,
    )
    .expect_err("body maximum must be enforced before a Store Block exists");
    assert_eq!(failure.code(), LogStoreFailureCode::LimitExceeded);
    Ok(())
}

fn round_trip_body(body: Option<String>, marker: u8) -> Result<StoredLogRecord, Box<dyn Error>> {
    let record = LogRecord::checked_minimal(
        None,
        body,
        vec![],
        PolicyProvenance::new(1, [0x70; 32], vec![])?,
    )?;
    round_trip_record(record, marker)
}

fn round_trip_record(record: LogRecord, marker: u8) -> Result<StoredLogRecord, Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([marker; 16])?,
        CatalogSecret::from_owned(Box::new([marker + 1; 32]), Box::new([marker + 2; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(u32::from(marker))?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x51; 32])),
    )?;
    ledger.append(
        LogStore::new()
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1))),
                tenant,
                shard,
                StoreBlockIdentity::new([marker; 16])?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    let result = LogStore::new().scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    result
        .records()
        .first()
        .map(|record| record.stored().clone())
        .ok_or_else(|| "committed body missing".into())
}
