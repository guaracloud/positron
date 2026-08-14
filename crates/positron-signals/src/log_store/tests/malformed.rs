use super::*;

#[test]
fn authenticated_malformed_block_is_rejected_without_observation() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x15; 16])?,
        CatalogSecret::from_owned(Box::new([0x25; 32]), Box::new([0x35; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(6)?),
        SegmentProtectionKey::from_owned(Box::new([0x56; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new(
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(6)?),
        StoreBlockIdentity::new([0x67; 16])?,
        b"not-a-log-store-block".to_vec(),
    )?)?;
    let failure = LogStore::new()
        .scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("authenticated but malformed store bytes cannot become telemetry");
    assert_eq!(failure.code(), LogStoreFailureCode::MalformedBlock);
    Ok(())
}

#[test]
fn authenticated_malformed_record_shapes_fail_closed_at_their_exact_boundaries()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x16; 16])?,
        CatalogSecret::from_owned(Box::new([0x26; 32]), Box::new([0x36; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let valid = encoded_log_fixture(tenant);
    let mut trailing = valid.clone();
    trailing.push(0);
    let cases = vec![
        (
            "wrong tenant",
            encoded_log_fixture(TenantId::from_bytes([0x42; 16])?),
            LogStoreFailureCode::PhysicalScopeMismatch,
        ),
        (
            "zero records",
            replaced_byte(&valid, 27, 0)?,
            LogStoreFailureCode::MalformedBlock,
        ),
        (
            "too many records",
            replaced_bytes(&valid, 26, [4, 1])?,
            LogStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown event quality",
            replaced_byte(&valid, 28, 9)?,
            LogStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown observed-time tag",
            replaced_byte(&valid, 29, 9)?,
            LogStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown body tag",
            replaced_byte(&valid, 38, 9)?,
            LogStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown attribute representation",
            replaced_byte(&valid, 41, 9)?,
            LogStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown attribute namespace",
            replaced_byte(&valid, 42, 9)?,
            LogStoreFailureCode::MalformedBlock,
        ),
        (
            "version one stream namespace",
            replaced_byte(&valid, 42, 4)?,
            LogStoreFailureCode::MalformedBlock,
        ),
        (
            "empty occurrence set",
            replaced_bytes(&valid, 48, [0, 0])?,
            LogStoreFailureCode::MalformedBlock,
        ),
        (
            "trailing bytes",
            trailing,
            LogStoreFailureCode::MalformedBlock,
        ),
    ];

    for (index, (description, bytes, expected)) in cases.into_iter().enumerate() {
        let shard = VirtualShardId::new(u32::try_from(index + 20)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(index + 0x60)?; 32])),
        )?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([u8::try_from(index + 0x70)?; 16])?,
            bytes,
        )?)?;
        let failure = LogStore::new()
            .scan(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                LogScan::all(ScanLimit::new(1)?),
            )
            .expect_err(description);
        assert_eq!(failure.code(), expected);
    }
    Ok(())
}

#[test]
fn result_limit_does_not_hide_a_malformed_declared_record() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x17; 16])?,
        CatalogSecret::from_owned(Box::new([0x27; 32]), Box::new([0x37; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(81)?);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x57; 32])),
    )?;
    let declared_two_with_one_record = replaced_bytes(&encoded_log_fixture(tenant), 26, [0, 2])?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0x77; 16])?,
        declared_two_with_one_record,
    )?)?;

    let failure = LogStore::new()
        .scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("the complete authenticated block must validate before observation");
    assert_eq!(failure.code(), LogStoreFailureCode::MalformedBlock);
    Ok(())
}

#[test]
fn version_two_metadata_tags_and_truncation_fail_closed() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let record = minimal_record("metadata", 1)?;
    let encoded_bytes =
        crate::log_store::codec::encoded_block_length(std::slice::from_ref(&record))?;
    let stored = StoredLogRecord::new(record, clock(1).assign_ingest_time()?);
    let valid = crate::log_store::codec::encode_block(tenant, &[stored], encoded_bytes)?;
    let cases = [
        (
            "oversized event name",
            replaced_bytes(&valid, 38, u32::MAX.to_be_bytes())?,
        ),
        ("unknown trace ID tag", replaced_byte(&valid, 42, 9)?),
        (
            "truncated metadata",
            valid
                .get(..43)
                .ok_or("v2 metadata fixture was shorter than expected")?
                .to_vec(),
        ),
    ];
    for (index, (description, bytes)) in cases.into_iter().enumerate() {
        let shard = VirtualShardId::new(u32::try_from(index + 83)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(index + 0x58)?; 32])),
        )?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([u8::try_from(index + 0x78)?; 16])?,
            bytes,
        )?)?;
        let failure = LogStore::new()
            .scan(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                LogScan::all(ScanLimit::new(1)?),
            )
            .expect_err(description);
        assert_eq!(failure.code(), LogStoreFailureCode::MalformedBlock);
    }
    Ok(())
}
