use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::{EventTime, ObservedTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSet, AttributeOccurrenceSetCandidate, ByteLimit,
    CandidateAttributeValue, CandidateKeyValue, CollectionLimit, DynamicValueLimits, NestingLimit,
    RecordLimits, RequestLimits, ValidatedAttributeValue, ValueLimitProfile,
    ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, PreparedStoreBlock, PrimaryDataVolume,
    SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};

use super::{
    AttributeRepresentation, LogRecord, LogScan, LogStore, LogStoreFailureCode, PolicyProvenance,
    ScanLimit, StoredLogAttribute, StoredLogRecord,
};
use crate::log_store::tests::support::{
    TemporaryRoot, establish_kernel_authority, preparation_capacity,
};

mod body;
mod capacity;
mod codec;
mod scan;
mod support;
mod time;

#[test]
fn scan_is_bounded_and_refuses_another_physical_scope() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x13; 16])?,
        CatalogSecret::from_owned(Box::new([0x23; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let store = LogStore::new();
    let record = minimal_record("one", 1)?;
    let second = minimal_record("two", 2)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(3)?),
        SegmentProtectionKey::from_owned(Box::new([0x53; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(1),
                tenant,
                VirtualShardId::new(3)?,
                StoreBlockIdentity::new([0x63; 16])?,
                vec![record.clone(), second],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let bounded = store.scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(bounded.records()[0].record(), &record);
    assert!(!bounded.complete());
    let wrong_tenant = store
        .scan(
            authority.governor(),
            TenantId::from_bytes([0x42; 16])?,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("a tenant cannot scan another physical tenant's snapshot");
    assert_eq!(
        wrong_tenant.code(),
        LogStoreFailureCode::PhysicalScopeMismatch
    );
    drop(ledger);

    let trace_ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(4)?),
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )?;
    trace_ledger.append(PreparedStoreBlock::new(
        SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(4)?),
        StoreBlockIdentity::new([0x64; 16])?,
        b"opaque-trace-block".to_vec(),
    )?)?;
    let wrong_signal = store
        .scan(
            authority.governor(),
            tenant,
            &trace_ledger.snapshot()?,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("Log Store cannot scan a Trace Store physical snapshot");
    assert_eq!(
        wrong_signal.code(),
        LogStoreFailureCode::PhysicalScopeMismatch
    );
    Ok(())
}

#[test]
fn sealed_and_successor_active_blocks_share_one_logical_scan() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x14; 16])?,
        CatalogSecret::from_owned(Box::new([0x24; 32]), Box::new([0x34; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(5)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x55; 32]));
    let store = LogStore::new();
    let sealed_record = minimal_record("sealed", 10)?;
    let active_record = minimal_record("active", 11)?;
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(10),
                tenant,
                VirtualShardId::new(5)?,
                StoreBlockIdentity::new([0x65; 16])?,
                vec![sealed_record.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    let successor = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    successor.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(11),
                tenant,
                VirtualShardId::new(5)?,
                StoreBlockIdentity::new([0x66; 16])?,
                vec![active_record.clone()],
            )?
            .into_store_block(),
    )?;

    let result = store.scan(
        authority.governor(),
        tenant,
        &successor.snapshot()?,
        LogScan::all(ScanLimit::new(2)?),
    )?;
    assert_eq!(result.records()[0].record(), &sealed_record);
    assert_eq!(result.records()[1].record(), &active_record);
    assert!(result.complete());
    Ok(())
}

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
fn public_limits_and_failures_are_typed_and_redacted() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let invalid_policy = PolicyProvenance::new(0, [0x70; 32], vec![])
        .expect_err("policy generation zero is not immutable provenance");
    assert_eq!(invalid_policy.code(), LogStoreFailureCode::InvalidInput);
    assert!(!invalid_policy.to_string().contains("secret-canary"));
    assert_eq!(
        PolicyProvenance::new(1, [0; 32], vec![])
            .expect_err("zero digest is not policy identity")
            .code(),
        LogStoreFailureCode::InvalidInput
    );
    assert_eq!(
        PolicyProvenance::new(1, [0x70; 32], vec![String::new()])
            .expect_err("applied rule IDs are nonempty")
            .code(),
        LogStoreFailureCode::InvalidInput
    );
    assert_eq!(
        ScanLimit::new(0)
            .expect_err("unbounded empty scan limit is invalid")
            .code(),
        LogStoreFailureCode::LimitExceeded
    );
    assert_eq!(
        ScanLimit::new(1_025)
            .expect_err("scan limit exceeds the M1 result bound")
            .code(),
        LogStoreFailureCode::LimitExceeded
    );

    let policy = PolicyProvenance::new(1, [0x70; 32], vec![])?;
    let zero_time = LogRecord::checked_minimal(
        Some(0),
        None,
        vec![("scope", "name", "value")],
        policy.clone(),
    )?;
    let positive_time = LogRecord::checked_minimal(
        Some(11),
        None,
        vec![("instrumentation-scope", "name", "value")],
        policy.clone(),
    )?;
    assert_eq!(zero_time.event_time().quality(), SourceTimeQuality::Zero);
    assert_eq!(
        positive_time.event_time().quality(),
        SourceTimeQuality::Usable
    );
    assert_eq!(zero_time.body(), None);
    assert_eq!(
        LogRecord::checked_minimal(
            None,
            None,
            vec![("unknown", "key", "value")],
            policy.clone(),
        )
        .expect_err("only native namespaces are accepted")
        .code(),
        LogStoreFailureCode::InvalidInput
    );

    let profile = value_profile()?;
    let attribute = StoredLogAttribute::generic(occurrences(
        profile,
        AttributeNamespace::Record,
        "bounded",
        vec![CandidateAttributeValue::boolean(true)],
    )?);
    let too_many_attributes = vec![attribute; 1_025];
    assert_eq!(
        LogRecord::checked_native(
            EventTime::missing(),
            None,
            None,
            too_many_attributes,
            policy.clone(),
        )
        .expect_err("record attribute sets are bounded")
        .code(),
        LogStoreFailureCode::LimitExceeded
    );

    let tenant = TenantId::from_bytes([0x41; 16])?;
    let store = LogStore::new();
    let empty_failure = store
        .prepare(
            preparation_capacity(&authority, tenant)?,
            &clock(1),
            tenant,
            VirtualShardId::new(9)?,
            StoreBlockIdentity::new([0x69; 16])?,
            vec![],
        )
        .err()
        .ok_or("an empty canonical block unexpectedly prepared")?;
    assert_eq!(empty_failure.code(), LogStoreFailureCode::LimitExceeded);
    let large_record = LogRecord::checked_minimal(None, Some("x".repeat(262_144)), vec![], policy)?;
    let block_bound = store
        .prepare(
            preparation_capacity(&authority, tenant)?,
            &clock(1),
            tenant,
            VirtualShardId::new(10)?,
            StoreBlockIdentity::new([0x6a; 16])?,
            vec![large_record; 5],
        )
        .err()
        .ok_or("an oversized canonical Store Block unexpectedly prepared")?;
    assert_eq!(block_bound.code(), LogStoreFailureCode::LimitExceeded);
    assert_eq!(block_bound.to_string(), "log store failure: LimitExceeded");
    Ok(())
}

fn minimal_record(body: &str, _ingest_time: i64) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_minimal(
        None,
        Some(body.to_owned()),
        vec![],
        PolicyProvenance::new(1, [0x70; 32], vec![])?,
    )?)
}

fn clock(instant: i64) -> LifecycleClock<FixedLifecycleClockSource> {
    LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        instant,
    )))
}

fn encoded_log_fixture(tenant: TenantId) -> Vec<u8> {
    let mut bytes = b"PLOGBL01".to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&tenant.to_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(2);
    bytes.push(0);
    bytes.extend_from_slice(&1_i64.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(1);
    bytes.push(1);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.push(b'k');
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes
}

fn replaced_byte(bytes: &[u8], offset: usize, value: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut replaced = bytes.to_vec();
    *replaced
        .get_mut(offset)
        .ok_or("malformed fixture replacement offset")? = value;
    Ok(replaced)
}

fn replaced_bytes(bytes: &[u8], offset: usize, values: [u8; 2]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut replaced = bytes.to_vec();
    replaced
        .get_mut(offset..offset + values.len())
        .ok_or("malformed fixture replacement range")?
        .copy_from_slice(&values);
    Ok(replaced)
}

fn occurrences(
    profile: ValueLimitProfile,
    namespace: AttributeNamespace,
    key: &str,
    values: Vec<CandidateAttributeValue>,
) -> Result<AttributeOccurrenceSet, Box<dyn Error>> {
    Ok(
        AttributeOccurrenceSetCandidate::new(namespace, key.to_owned(), values)
            .validate(profile)?,
    )
}

fn value(
    profile: ValueLimitProfile,
    candidate: CandidateAttributeValue,
) -> Result<ValidatedAttributeValue, Box<dyn Error>> {
    let set = occurrences(
        profile,
        AttributeNamespace::Record,
        "value",
        vec![candidate],
    )?;
    Ok(set
        .occurrence(0)
        .ok_or("validated singleton occurrence missing")?
        .clone())
}

fn value_profile() -> Result<ValueLimitProfile, Box<dyn Error>> {
    let request = RequestLimits::new(
        ByteLimit::new(1_048_576)?,
        ByteLimit::new(1_048_576)?,
        CollectionLimit::new(1_024)?,
        CollectionLimit::new(4_096)?,
    );
    let record = RecordLimits::new(
        ByteLimit::new(1_048_576)?,
        ByteLimit::new(1_048_576)?,
        ByteLimit::new(262_144)?,
    );
    let dynamic = DynamicValueLimits::new(
        ByteLimit::new(65_536)?,
        CollectionLimit::new(1_024)?,
        ByteLimit::new(65_536)?,
        NestingLimit::new(16)?,
        CollectionLimit::new(1_024)?,
        CollectionLimit::new(1_024)?,
    );
    Ok(
        ValueLimitProfileCandidate::new(ValueLimitSet::new(request, record, dynamic), None)
            .validate()?,
    )
}
