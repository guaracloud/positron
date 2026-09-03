use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeNamespace, ByteLimit, CandidateAttributeValue, DynamicValueLimits, RecordLimits,
    ValueLimitProfile, ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, DiskPressureThresholds, GovernorPolicy,
    InstanceId, InventoryCardinalityLimits, MountQualification, ObservedResourceEnvironment,
    OperatorLimits, OrdinaryPoolPolicy, OwnedPrimaryDataVolume, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory, RetentionTimeAuthority,
    SegmentProtectionKey, SegmentScope, StorageKernelResourceAuthority, TenantQuota, WorkClaim,
    WorkKind,
};
use positron_policy::{
    IngestPolicy, NativePolicyAttribute, NativeTraceCandidate, PolicyReceiver,
    TracePolicyEvaluation,
};
use positron_signals::{
    SamplingDecision, ScanLimit, SpanAttributeSet, SpanEvent, SpanKind, SpanLink, SpanObservation,
    SpanObservationDetails, SpanResourceMetadata, SpanScopeMetadata, SpanStatus, SpanStatusCode,
    TraceScan, TraceStore,
};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

#[test]
fn public_trace_store_seam_commits_and_reads_a_native_observation() -> Result<(), Box<dyn Error>> {
    let root = TestRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16])?,
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )?;
    let (retention, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let tenant = TenantId::from_bytes([0x84; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(1)?);
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x85; 32])),
    )?;
    let event_attributes = vec![SpanAttributeSet::checked(
        "cache.hit".to_owned(),
        vec![CandidateAttributeValue::boolean(true)],
        ValueLimitProfile::release_1_system_maximum(),
    )?];
    let link_attributes = vec![SpanAttributeSet::checked(
        "messaging.batch.message_count".to_owned(),
        vec![CandidateAttributeValue::signed_integer(2)],
        ValueLimitProfile::release_1_system_maximum(),
    )?];
    let details = SpanObservationDetails::checked(
        "vendor=positron".to_owned(),
        0x0301,
        SpanStatus::checked(SpanStatusCode::Error, "upstream failed".to_owned())?,
        vec![SpanEvent::checked(
            EventTime::received(UnixNanoseconds::new(15), SourceTimeQuality::Usable)?,
            "exception".to_owned(),
            event_attributes,
            4,
        )?],
        vec![SpanLink::checked(
            [0x90; 16],
            [0x91; 8],
            "vendor=link".to_owned(),
            0x0300,
            link_attributes,
            5,
        )?],
        6,
        7,
        8,
        SpanResourceMetadata::checked(9, "https://resource.example/v1".to_owned())?,
        SpanScopeMetadata::checked(
            "checkout.instrumentation".to_owned(),
            "1.2.3".to_owned(),
            10,
            "https://scope.example/v2".to_owned(),
        )?,
    )?;
    let policy = IngestPolicy::preserving(7)?;
    let evaluated = match policy.evaluate_trace(
        NativeTraceCandidate::new(vec![NativePolicyAttribute::new(
            AttributeNamespace::Resource,
            "k".repeat(SpanObservation::MAX_NAME_BYTES),
            vec![CandidateAttributeValue::boolean(true)],
        )]),
        PolicyReceiver::OtlpGrpc,
    )? {
        TracePolicyEvaluation::Accepted(evaluated) => *evaluated,
        TracePolicyEvaluation::Rejected => return Err("preserving policy rejected span".into()),
    };
    let observation = SpanObservation::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        [0x86; 16],
        [0x87; 8],
        None,
        "public".to_owned(),
        EventTime::received(UnixNanoseconds::new(1), SourceTimeQuality::Usable)?,
        EventTime::missing(),
        SpanKind::Server,
        SamplingDecision::Unknown,
        evaluated,
        details.clone(),
    )?;
    let lowered = profile_with_key_limit(4);
    let over_evaluated = match policy.evaluate_trace(
        NativeTraceCandidate::new(Vec::new()),
        PolicyReceiver::OtlpGrpc,
    )? {
        TracePolicyEvaluation::Accepted(evaluated) => *evaluated,
        TracePolicyEvaluation::Rejected => return Err("preserving policy rejected span".into()),
    };
    let over_observation = SpanObservation::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        [0x86; 16],
        [0x8f; 8],
        None,
        "four".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        over_evaluated,
        details.clone(),
    )?;
    let exact_evaluated = match policy.evaluate_trace(
        NativeTraceCandidate::new(Vec::new()),
        PolicyReceiver::OtlpGrpc,
    )? {
        TracePolicyEvaluation::Accepted(evaluated) => *evaluated,
        TracePolicyEvaluation::Rejected => return Err("preserving policy rejected span".into()),
    };
    let exact = SpanObservation::checked_evaluated(
        lowered,
        [0x86; 16],
        [0x88; 8],
        None,
        "four".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        exact_evaluated,
        SpanObservationDetails::default(),
    )?;
    let exact_prepared = TraceStore::new().prepare_with_profile(
        &lowered,
        ledger.begin_store_block(
            preparation_capacity(&authority, tenant)?,
            positron_kernel::StoreBlockIdentity::new([0x8d; 16])?,
        )?,
        vec![exact],
    )?;
    drop(exact_prepared);
    let over_failure = match TraceStore::new().prepare_with_profile(
        &lowered,
        ledger.begin_store_block(
            preparation_capacity(&authority, tenant)?,
            positron_kernel::StoreBlockIdentity::new([0x8e; 16])?,
        )?,
        vec![over_observation],
    ) {
        Ok(_) => return Err("Trace Store accepted a lowered-profile overflow".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        over_failure.code(),
        positron_signals::TraceStoreFailureCode::LimitExceeded
    );
    let empty_failure = TraceStore::new()
        .prepare(
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant)?,
                positron_kernel::StoreBlockIdentity::new([0x89; 16])?,
            )?,
            Vec::new(),
        )
        .err()
        .ok_or("empty Trace Store preparation unexpectedly succeeded")?;
    assert_eq!(
        empty_failure.code(),
        positron_signals::TraceStoreFailureCode::InvalidInput
    );
    let too_many_failure = TraceStore::new()
        .prepare(
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant)?,
                positron_kernel::StoreBlockIdentity::new([0x8a; 16])?,
            )?,
            vec![observation.clone(); 1_025],
        )
        .err()
        .ok_or("oversized Trace Store preparation unexpectedly succeeded")?;
    assert_eq!(
        too_many_failure.code(),
        positron_signals::TraceStoreFailureCode::LimitExceeded
    );
    let logs_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(2)?);
    let logs_ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        logs_scope,
        SegmentProtectionKey::from_owned(Box::new([0x8b; 32])),
    )?;
    let scope_failure = TraceStore::new()
        .prepare(
            logs_ledger.begin_store_block(
                preparation_capacity(&authority, tenant)?,
                positron_kernel::StoreBlockIdentity::new([0x8c; 16])?,
            )?,
            vec![observation.clone()],
        )
        .err()
        .ok_or("non-Trace preparation unexpectedly succeeded")?;
    assert_eq!(
        scope_failure.code(),
        positron_signals::TraceStoreFailureCode::PhysicalScopeMismatch
    );
    let prepared = TraceStore::new().prepare(
        ledger.begin_store_block(
            preparation_capacity(&authority, tenant)?,
            positron_kernel::StoreBlockIdentity::new([0x88; 16])?,
        )?,
        vec![observation.clone()],
    )?;
    ledger.append(prepared.into_store_block())?;
    let result = TraceStore::new().scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.observations().len(), 1);
    assert_eq!(result.observations()[0].observation(), &observation);
    assert_eq!(result.observations()[0].observation().details(), &details);
    assert_eq!(
        result.observations()[0].observation().attributes()[0]
            .key()
            .len(),
        SpanObservation::MAX_NAME_BYTES
    );
    drop(result);
    let _sealed = ledger.seal()?;
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x85; 32])),
    )?;
    let restarted_result = TraceStore::new().scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert!(restarted_result.complete());
    assert_eq!(
        restarted_result.observations()[0].observation(),
        &observation
    );
    Ok(())
}

#[test]
fn public_trace_store_reads_v1_blocks_with_explicit_absent_detail_defaults()
-> Result<(), Box<dyn Error>> {
    let root = TestRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let (retention, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let tenant = TenantId::from_bytes([0x84; 16])?;
    let shard = VirtualShardId::new(11)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x95; 32])),
    )?;
    let preparation = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        positron_kernel::StoreBlockIdentity::new([0x96; 16])?,
    )?;
    let encoded_ingest_time = preparation.ingest_time().instant().value();
    let block = legacy_v1_block(tenant, encoded_ingest_time);
    let prepared = preparation.finish(block)?;
    ledger.append(prepared)?;

    let result = TraceStore::new().scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    let observation = result
        .observations()
        .first()
        .ok_or("missing v1 observation")?
        .observation();
    assert_eq!(observation.trace_id(), [0xa1; 16]);
    assert_eq!(observation.span_id(), [0xa2; 8]);
    assert_eq!(observation.name(), "legacy");
    assert_eq!(observation.kind(), SpanKind::Server);
    assert_eq!(observation.sampling(), SamplingDecision::NotSampled);
    assert_eq!(observation.details(), &SpanObservationDetails::default());
    assert_eq!(observation.policy_provenance().generation(), 7);
    assert_eq!(observation.policy_provenance().digest(), [0xa3; 32]);
    assert_eq!(
        result.observations()[0].ingest_time().instant().value(),
        encoded_ingest_time
    );
    Ok(())
}

fn legacy_v1_block(tenant: TenantId, ingest_time: i64) -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(b"PTRCBL01");
    block.extend_from_slice(&1_u16.to_be_bytes());
    block.extend_from_slice(&tenant.to_bytes());
    block.extend_from_slice(&1_u16.to_be_bytes());
    block.extend_from_slice(&[0xa1; 16]);
    block.extend_from_slice(&[0xa2; 8]);
    block.push(0);
    block.push(2);
    block.push(1);
    block.push(2);
    block.push(2);
    block.extend_from_slice(&6_u32.to_be_bytes());
    block.extend_from_slice(b"legacy");
    block.extend_from_slice(&0_u16.to_be_bytes());
    block.extend_from_slice(&7_u64.to_be_bytes());
    block.extend_from_slice(&[0xa3; 32]);
    block.extend_from_slice(&0_u16.to_be_bytes());
    block.extend_from_slice(&ingest_time.to_be_bytes());
    block
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "positron-trace-store-integration-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn preparation_capacity(
    authority: &StorageKernelResourceAuthority,
    tenant: TenantId,
) -> Result<positron_kernel::ResourceReservation<'_>, Box<dyn Error>> {
    let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?;
    Ok(authority
        .governor()
        .reserve(WorkClaim::tenant(tenant, WorkKind::Ingest, amounts)?)?)
}

fn authority(
    volume: OwnedPrimaryDataVolume,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
    let observed = ObservedResourceEnvironment::observe(
        &volume,
        RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])?,
    )?;
    let disk = observed.initial_disk().usable_bytes();
    let large = ResourceAmounts::new([
        90_000_000, 4, 4, 90_000_000, 70_000, 4, 4, 4, 4, 16, 40_000_000,
    ]);
    let small = ResourceAmounts::new([2; 11]);
    let durability = add(add(large, large)?, large)?;
    let recovery_capacity = add(
        add(add(durability, large)?, large)?,
        ResourceAmounts::new([12; 11]),
    )?;
    let ordinary = ResourceAmounts::new([
        5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
    ]);
    let governed = add(recovery_capacity, ordinary)?;
    let raw = add(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery_capacity)?,
        cardinality,
        DiskPressureThresholds::new(
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes),
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 2,
            disk,
        )?,
    )?;
    let tenant = TenantId::from_bytes([0x84; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary)?],
        OrdinaryPoolPolicy::new(
            ResourceAmounts::new([8; 11]),
            ResourceAmounts::new([6; 11]),
            ResourceAmounts::new([4; 11]),
            ResourceAmounts::new([2; 11]),
        )?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(inventory, policy, recovery)?,
    )?)
}

fn add(left: ResourceAmounts, right: ResourceAmounts) -> Result<ResourceAmounts, Box<dyn Error>> {
    let value = |dimension| -> Result<u64, Box<dyn Error>> {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or_else(|| "resource capacity overflow".into())
    };
    Ok(ResourceAmounts::new([
        value(ResourceDimension::MemoryBytes)?,
        value(ResourceDimension::QueueSlots)?,
        value(ResourceDimension::TaskSlots)?,
        value(ResourceDimension::BufferCacheBytes)?,
        value(ResourceDimension::BatchItems)?,
        value(ResourceDimension::LeaseSlots)?,
        value(ResourceDimension::RetrySlots)?,
        value(ResourceDimension::IoPermits)?,
        value(ResourceDimension::CpuWorkUnits)?,
        value(ResourceDimension::FileDescriptors)?,
        value(ResourceDimension::DiskHeadroomBytes)?,
    ]))
}

fn profile_with_key_limit(key_path_bytes: u32) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    let dynamic = maximum.effective_limits().dynamic_value();
    let lowered = DynamicValueLimits::new(
        dynamic.individual_value_bytes(),
        dynamic.attributes_per_namespace(),
        ByteLimit::new(key_path_bytes).expect("valid key bound"),
        dynamic.nesting_depth(),
        dynamic.array_entries(),
        dynamic.key_value_list_entries(),
    );
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            maximum.effective_limits().request(),
            RecordLimits::new(
                maximum.effective_limits().record().encoded_bytes(),
                maximum.effective_limits().record().decoded_bytes(),
                maximum.effective_limits().record().log_body_bytes(),
            ),
            lowered,
        )),
    )
    .validate()
    .expect("lowered profile")
}
