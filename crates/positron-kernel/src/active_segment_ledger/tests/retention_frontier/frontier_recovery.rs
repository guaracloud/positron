use super::*;

#[cfg(feature = "test-support")]
#[test]
fn deterministic_test_ingest_time_cannot_authorize_retention() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let test_time = RetentionTimeAuthority::for_test_ingest_time(UnixNanoseconds::new(50));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &test_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(10)?),
        SegmentProtectionKey::from_owned(Box::new([0xa5; 32])),
    )?;

    let failure = match ledger.begin_retention() {
        Ok(_) => return Err("test-only Ingest Time authorized deletion".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn authenticated_malformed_and_duplicate_retention_frontiers_fail_closed_on_open()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(11)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
    )?;
    let preparation = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xb5; 16])?,
    )?;
    drop((preparation, ledger));
    let original = catalog
        .pin()?
        .plaintext_objects()
        .find(|bytes| bytes.starts_with(b"PRETFR01"))
        .ok_or("retention frontier missing")?
        .to_vec();

    let mut cases = Vec::new();
    cases.push((
        original.get(..38).ok_or("frontier length")?.to_vec(),
        LedgerFailureCode::UnsupportedFormat,
    ));
    let mut unknown_version = original.clone();
    unknown_version
        .get_mut(8..10)
        .ok_or("version field")?
        .copy_from_slice(&2_u16.to_be_bytes());
    cases.push((unknown_version, LedgerFailureCode::UnsupportedFormat));
    let mut invalid_tenant = original.clone();
    invalid_tenant
        .get_mut(10..26)
        .ok_or("tenant field")?
        .fill(0);
    cases.push((invalid_tenant, LedgerFailureCode::IntegrityCorruption));
    let mut invalid_signal = original.clone();
    *invalid_signal.get_mut(26).ok_or("signal field")? = 0;
    cases.push((invalid_signal, LedgerFailureCode::IntegrityCorruption));
    let mut invalid_shard = original.clone();
    invalid_shard.get_mut(27..31).ok_or("shard field")?.fill(0);
    cases.push((invalid_shard, LedgerFailureCode::IntegrityCorruption));

    for (index, (malformed, expected)) in cases.into_iter().enumerate() {
        replace_retention_frontier(
            &catalog,
            malformed,
            u8::try_from(index)
                .map_err(|_| "transaction index")?
                .saturating_add(0xc0),
        )?;
        let failure = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
        )
        .expect_err("authenticated malformed frontier must fence recovery");
        assert_eq!(failure.code(), expected);
    }

    let basis = catalog.pin()?;
    let mut objects = copied_non_frontier_objects(&basis)?;
    objects.push(CatalogObject::new(original.clone())?);
    let mut second = original;
    let instant = second.last_mut().ok_or("frontier instant")?;
    *instant ^= 1;
    objects.push(CatalogObject::new(second)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xcf; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let failure = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
    )
    .expect_err("duplicate authenticated frontiers must fence recovery");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}
