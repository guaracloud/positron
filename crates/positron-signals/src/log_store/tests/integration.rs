use std::error::Error;
use std::num::NonZeroU64;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, ValueLimitProfile};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, LifecycleClockFailure, LifecycleClockSource, MountQualification,
    PrimaryDataVolume, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, SegmentProtectionKey,
    SegmentScope, StoreBlockIdentity, WorkClass,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};
use positron_signals::{
    LogRecord, LogRetentionPolicy, LogScan, LogStore, ScanCancellation, ScanLimit,
    ScanObservationFailureCode, ScanObserver,
};

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
fn retention_buckets_are_fixed_by_tenant_store_and_kernel_ingest_time() -> Result<(), Box<dyn Error>>
{
    let policy = LogRetentionPolicy::new(10)?;
    let first_tenant = TenantId::from_bytes([0x41; 16])?;
    let second_tenant = TenantId::from_bytes([0x42; 16])?;
    let first_time = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        12_000_000_000,
    )))
    .assign_ingest_time()?;
    let same_bucket_time = LifecycleClock::new(FixedLifecycleClockSource::new(
        UnixNanoseconds::new(19_999_999_999),
    ))
    .assign_ingest_time()?;
    let next_bucket_time = LifecycleClock::new(FixedLifecycleClockSource::new(
        UnixNanoseconds::new(20_000_000_000),
    ))
    .assign_ingest_time()?;

    let first = policy.bucket(first_tenant, first_time)?;
    assert_eq!(first, policy.bucket(first_tenant, same_bucket_time)?);
    assert_ne!(first, policy.bucket(first_tenant, next_bucket_time)?);
    assert_ne!(first, policy.bucket(second_tenant, first_time)?);
    assert_eq!(first.tenant(), first_tenant);
    assert_eq!(first.signal_kind(), SignalKind::Logs);
    assert_eq!(first.start(), UnixNanoseconds::new(10_000_000_000));
    assert_eq!(first.end_exclusive(), UnixNanoseconds::new(20_000_000_000));
    let maximum_time = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        i64::MAX,
    )))
    .assign_ingest_time()?;
    assert_eq!(
        LogRetentionPolicy::new(1)?
            .bucket(first_tenant, maximum_time)
            .expect_err("a bucket ending beyond the timestamp domain must fail")
            .code(),
        positron_signals::LogStoreFailureCode::LimitExceeded
    );
    Ok(())
}

#[test]
fn retention_refuses_wrong_scope_and_unusable_clock_before_mutation() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1b; 16])?,
        CatalogSecret::from_owned(Box::new([0x2b; 32]), Box::new([0x3b; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let other_tenant = TenantId::from_bytes([0x42; 16])?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(11)?),
        SegmentProtectionKey::from_owned(Box::new([0x5b; 32])),
    )?;
    let store = LogStore::new();
    let policy = LogRetentionPolicy::new(1)?;

    let wrong_scope = store
        .enforce_retention(
            &ledger,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(0))),
            other_tenant,
            policy,
        )
        .expect_err("a tenant cannot execute retention for another tenant's ledger");
    assert_eq!(
        wrong_scope.code(),
        positron_signals::LogStoreFailureCode::PhysicalScopeMismatch
    );

    let unavailable = store
        .enforce_retention(
            &ledger,
            &LifecycleClock::new(UnavailableLifecycleClock),
            tenant,
            policy,
        )
        .expect_err("an unavailable lifecycle clock must fail closed");
    assert_eq!(
        unavailable.code(),
        positron_signals::LogStoreFailureCode::ClockUnavailable
    );

    let out_of_range = store
        .enforce_retention(
            &ledger,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
                i64::MIN,
            ))),
            tenant,
            policy,
        )
        .expect_err("an unrepresentable retention cutoff must fail closed");
    assert_eq!(
        out_of_range.code(),
        positron_signals::LogStoreFailureCode::LimitExceeded
    );
    assert!(ledger.snapshot()?.blocks().is_empty());
    ledger.seal()?;
    let reopened = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(11)?),
        SegmentProtectionKey::from_owned(Box::new([0x5b; 32])),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            2_000_000_000,
        ))),
    )?;
    let empty_segment = store.enforce_retention(
        &reopened,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            2_000_000_000,
        ))),
        tenant,
        policy,
    )?;
    assert_eq!(empty_segment.expired_segments(), 1);
    assert_eq!(empty_segment.reclaimed_segments(), 1);
    Ok(())
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
                vec![record.clone(), record.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &ingest_clock,
                tenant,
                shard,
                StoreBlockIdentity::new([0x79; 16])?,
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
    let retained = store.enforce_retention(
        &active,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            10_500_000_000,
        ))),
        tenant,
        LogRetentionPolicy::new(1)?,
    )?;
    assert_eq!(retained.expired_segments(), 0);
    assert_eq!(retained.reclaimed_segments(), 0);
    assert_eq!(active.snapshot()?.blocks().len(), 2);

    let observation_failure = store
        .enforce_retention_observed(
            &active,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
                12_000_000_000,
            ))),
            tenant,
            LogRetentionPolicy::new(1)?,
            &NeverCancelledRetention,
            &RejectScannedBytes,
        )
        .expect_err("observer refusal must precede retention publication");
    assert_eq!(
        observation_failure.code(),
        positron_signals::LogStoreFailureCode::BudgetExhausted
    );
    assert_eq!(active.snapshot()?.blocks().len(), 2);

    let evidence_snapshot = active.snapshot()?;
    let evidence_block = evidence_snapshot
        .blocks()
        .first()
        .ok_or("sealed retention fixture is missing its committed block")?;
    let authenticated_ingest_time = LifecycleClock::new(FixedLifecycleClockSource::new(
        UnixNanoseconds::new(10_000_000_000),
    ))
    .assign_ingest_time()?;
    let evidence = evidence_snapshot.retention_evidence(
        evidence_block,
        authenticated_ingest_time,
        NonZeroU64::new(1).ok_or("positive retention duration")?,
    )?;
    let cutoff = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        12_000_000_000,
    )))
    .retention_cutoff(NonZeroU64::new(1).ok_or("positive retention duration")?)?;
    let recovery_baseline = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::DurabilityRecovery);
    let recovery_claim = RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Retention,
        ResourceAmounts::new([1; 11]),
    )?;
    let mut held_recovery = Vec::new();
    while let Ok(reservation) = authority.recovery().reserve(recovery_claim) {
        held_recovery.push(reservation);
    }
    assert!(!held_recovery.is_empty());
    let refused = active
        .retire_expired_sealed_segments(cutoff, &[evidence])
        .expect_err("saturated retention recovery capacity must fail before publication");
    assert_eq!(
        refused.code(),
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(evidence_snapshot.blocks().len(), 2);
    drop(held_recovery);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::DurabilityRecovery),
        recovery_baseline
    );
    let incomplete = active.retire_expired_sealed_segments(cutoff, &[])?;
    assert_eq!(incomplete.logically_retired_segments(), 0);
    assert_eq!(active.snapshot()?.blocks().len(), 2);
    let excessive = vec![evidence; 1_025];
    let bounded = active
        .retire_expired_sealed_segments(cutoff, &excessive)
        .expect_err("retention evidence must remain bounded");
    assert_eq!(
        bounded.code(),
        positron_kernel::LedgerFailureCode::LimitExceeded
    );
    let duplicate = active
        .retire_expired_sealed_segments(cutoff, &[evidence, evidence])
        .expect_err("duplicate block evidence must fail before publication");
    assert_eq!(
        duplicate.code(),
        positron_kernel::LedgerFailureCode::InvalidInput
    );
    assert_eq!(active.snapshot()?.blocks().len(), 2);
    drop(evidence_snapshot);

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
        positron_kernel::RetentionCutoffProvenance::LifecycleClock
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
    let before = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::DurabilityRecovery);
    let cancelled = store
        .enforce_retention_observed(
            &active,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
                12_000_000_000,
            ))),
            tenant,
            LogRetentionPolicy::new(1)?,
            &CancelledRetention,
            &RetentionObserver,
        )
        .expect_err("cancelled retention must not publish deletion");
    assert_eq!(
        cancelled.code(),
        positron_signals::LogStoreFailureCode::Cancelled
    );
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::DurabilityRecovery),
        before
    );
    assert_eq!(active.snapshot()?.blocks().len(), 1);
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

struct CancelledRetention;

impl ScanCancellation for CancelledRetention {
    fn is_cancelled(&self) -> bool {
        true
    }
}

struct NeverCancelledRetention;

impl ScanCancellation for NeverCancelledRetention {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct RejectScannedBytes;

impl ScanObserver for RejectScannedBytes {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        Err(ScanObservationFailureCode::BudgetExhausted)
    }
}

struct UnavailableLifecycleClock;

impl LifecycleClockSource for UnavailableLifecycleClock {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
        Err(LifecycleClockFailure::Unavailable)
    }
}

struct RetentionObserver;

impl ScanObserver for RetentionObserver {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}
