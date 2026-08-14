use super::*;
use positron_kernel::{FixedLifecycleClockSource, LifecycleClock};

#[test]
fn receiver_zero_observed_time_preserves_its_non_usable_quality() -> Result<(), Box<dyn Error>> {
    let record = LogRecord::checked_receiver_candidate(
        value_profile()?,
        None,
        Some(0),
        None,
        vec![],
        PolicyProvenance::new(1, [0x71; 32], vec![])?,
    )?;

    let observed = record.observed_time().ok_or("observed time missing")?;
    assert_eq!(observed.instant(), Some(UnixNanoseconds::new(0)));
    assert_eq!(observed.quality(), SourceTimeQuality::Zero);
    Ok(())
}

#[test]
fn kernel_clock_assigns_ingest_and_retention_time_while_event_time_remains_untrusted()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x75; 16])?,
        CatalogSecret::from_owned(Box::new([0x76; 32]), Box::new([0x77; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(75)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(123)));
    let record = LogRecord::checked_minimal(
        Some(i64::MAX),
        Some("event cannot choose retention".to_owned()),
        vec![],
        PolicyProvenance::new(1, [0x70; 32], vec![])?,
    )?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0x51; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    ledger.append(
        LogStore::new()
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock,
                tenant,
                shard,
                StoreBlockIdentity::new([0x78; 16])?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let result = LogStore::new().scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let stored = result.records().first().ok_or("stored log missing")?;
    assert_eq!(
        stored.event_time().instant(),
        Some(UnixNanoseconds::new(i64::MAX))
    );
    assert_eq!(stored.ingest_time().instant(), UnixNanoseconds::new(123));
    assert_eq!(stored.retention_time(), UnixNanoseconds::new(123));
    Ok(())
}
