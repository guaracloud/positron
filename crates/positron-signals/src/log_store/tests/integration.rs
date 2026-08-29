use std::error::Error;
use std::sync::Mutex;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, ValueLimitProfile};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, PrimaryDataVolume, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};
use positron_signals::{LogRecord, LogRetentionPolicy, LogScan, LogStore, ScanLimit};

#[path = "support.rs"]
mod support;

use support::{TemporaryRoot, establish_kernel_authority, preparation_capacity};

#[test]
fn retention_policy_requires_a_positive_duration() {
    let failure = LogRetentionPolicy::new(0).expect_err("zero retention is not meaningful");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::InvalidInput
    );
    assert_eq!(
        LogRetentionPolicy::new(7)
            .expect("positive retention")
            .retention_seconds(),
        7
    );
    assert_eq!(
        LogRetentionPolicy::new(u64::MAX)
            .expect_err("retention duration must fit the representable timestamp range")
            .code(),
        positron_signals::LogStoreFailureCode::InvalidInput
    );
}

#[test]
fn public_log_store_commits_and_scans_through_the_storage_kernel() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(8)?);
    let store = LogStore::new();
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("public outcome".to_owned())),
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            "duplicate".to_owned(),
            vec![
                CandidateAttributeValue::string("first".to_owned()),
                CandidateAttributeValue::string("second".to_owned()),
            ],
        )],
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving policy rejected the public fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                VirtualShardId::new(8)?,
                StoreBlockIdentity::new([0x68; 16])?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;

    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records()[0].record(), &record);
    assert!(result.complete());
    Ok(())
}

#[test]
fn expired_sealed_logs_are_removed_by_kernel_ingest_time_only() -> Result<(), Box<dyn Error>> {
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
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(
            Some(i64::MAX),
            None,
            Some(positron_domain::value::CandidateAttributeValue::string(
                "producer time cannot retain this record".to_owned(),
            )),
            vec![],
            LogMetadata::empty(),
        ),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the retention fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ingest_clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        10_000_000_000,
    )));
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &ingest_clock,
                tenant,
                shard,
                StoreBlockIdentity::new([0x69; 16])?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;

    let active = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
    )?;
    let outcome = store.enforce_retention(
        &active,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
        tenant,
        LogRetentionPolicy::new(1)?,
    )?;
    assert_eq!(outcome.evaluated_at(), UnixNanoseconds::new(12_000_000_000));
    assert_eq!(outcome.expired_segments(), 1);
    assert_eq!(outcome.reclaimed_segments(), 1);
    assert_eq!(
        outcome.clock_provenance(),
        positron_signals::RetentionClockProvenance::LifecycleClock
    );
    let result = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert!(result.records().is_empty());
    drop(active);
    let reopened = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert!(result.records().is_empty());
    drop(reopened);
    let reopened_again = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &reopened_again.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert!(result.records().is_empty());
    Ok(())
}

#[test]
fn retention_keeps_an_existing_snapshot_readable_while_new_snapshots_exclude_it()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1a; 16])?,
        CatalogSecret::from_owned(Box::new([0x2a; 32]), Box::new([0x3a; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(10)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(
            None,
            None,
            Some(positron_domain::value::CandidateAttributeValue::string(
                "snapshot remains valid".to_owned(),
            )),
            vec![],
            LogMetadata::empty(),
        ),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the snapshot fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ingest_clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        10_000_000_000,
    )));
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &ingest_clock,
                tenant,
                shard,
                StoreBlockIdentity::new([0x6a; 16])?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    let active = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
    )?;
    let previous = active.snapshot()?;
    assert_eq!(previous.blocks().len(), 1);
    let uncertain_clock = LifecycleClock::new(SequenceLifecycleClock(Mutex::new(vec![
        UnixNanoseconds::new(12_000_000_000),
        UnixNanoseconds::new(1_000_000_000_000),
    ])));
    uncertain_clock.assign_ingest_time()?;
    let failure = store
        .enforce_retention(
            &active,
            &uncertain_clock,
            tenant,
            LogRetentionPolicy::new(1)?,
        )
        .expect_err("retention must pause during an unreconciled clock jump");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::ClockUncertain
    );
    let lease = active.create_snapshot_lease(12, 100)?;
    let lease_identity = lease.identity();
    let outcome = store.enforce_retention(
        &active,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
        tenant,
        LogRetentionPolicy::new(1)?,
    )?;
    assert_eq!(outcome.expired_segments(), 1);
    assert_eq!(outcome.reclaimed_segments(), 0);
    let old_result = store.scan(
        authority.governor(),
        tenant,
        &previous,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(old_result.records().len(), 1);
    let current_result = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert!(current_result.records().is_empty());
    let resumed = active.resume_snapshot_lease(lease_identity, 12)?;
    let resumed_result = store.scan(
        authority.governor(),
        tenant,
        resumed.snapshot(),
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(resumed_result.records().len(), 1);
    drop(resumed);
    let sealed_entries =
        std::fs::read_dir(root.path().join("segments/sealed"))?.collect::<Result<Vec<_>, _>>()?;
    assert!(!sealed_entries.is_empty());
    drop(lease);
    drop(previous);
    active.release_snapshot_lease(lease_identity)?;
    let outcome = store.enforce_retention(
        &active,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
        tenant,
        LogRetentionPolicy::new(1)?,
    )?;
    assert_eq!(outcome.expired_segments(), 0);
    assert_eq!(outcome.reclaimed_segments(), 1);
    let sealed_entries =
        std::fs::read_dir(root.path().join("segments/sealed"))?.collect::<Result<Vec<_>, _>>()?;
    assert!(sealed_entries.is_empty());
    Ok(())
}

struct SequenceLifecycleClock(Mutex<Vec<UnixNanoseconds>>);

impl positron_kernel::LifecycleClockSource for SequenceLifecycleClock {
    fn read(&self) -> Result<UnixNanoseconds, positron_kernel::LifecycleClockFailure> {
        self.0
            .lock()
            .map_err(|_| positron_kernel::LifecycleClockFailure::Unavailable)?
            .pop()
            .ok_or(positron_kernel::LifecycleClockFailure::Unavailable)
    }
}
