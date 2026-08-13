use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::{
    EventTime, IngestTime, IngestTimeCandidate, ObservedTime, SourceTimeQuality, UnixNanoseconds,
};
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSet, AttributeOccurrenceSetCandidate, ByteLimit,
    CandidateAttributeValue, CandidateKeyValue, CollectionLimit, DynamicValueLimits, NestingLimit,
    RecordLimits, RequestLimits, ValidatedAttributeValue, ValueLimitProfile,
    ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, MountQualification,
    PreparedStoreBlock, PrimaryDataVolume, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};

use super::{
    AttributeRepresentation, LogRecord, LogScan, LogStore, LogStoreFailureCode, PolicyProvenance,
    ScanLimit, StoredLogAttribute,
};
use crate::log_store::tests::support::{TemporaryRoot, establish_kernel_authority};

mod support;

#[test]
fn committed_native_log_survives_reopen_and_bounded_scan() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x11; 16])?,
        CatalogSecret::from_owned(Box::new([0x21; 32]), Box::new([0x31; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x51; 32]));
    let store = LogStore::new();
    let record = LogRecord::checked_minimal(
        None,
        1_723_456_789_000_000_000,
        Some("".to_owned()),
        vec![
            ("resource", "service.name", "api"),
            ("scope", "version", ""),
            ("record", "attempt", "first"),
            ("record", "attempt", "second"),
        ],
        PolicyProvenance::new(7, [0x71; 32], vec!["redact-password".to_owned()])?,
    )?;
    let prepared = store.prepare(
        tenant,
        StoreBlockIdentity::new([0x61; 16])?,
        vec![record.clone()],
    )?;

    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    ledger.append(prepared.into_store_block())?;
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let result = store.scan(
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;

    assert_eq!(result.records(), &[record]);
    assert!(result.complete());
    Ok(())
}

#[test]
fn native_values_occurrences_namespaces_and_time_provenance_round_trip()
-> Result<(), Box<dyn Error>> {
    let profile = value_profile()?;
    let attributes = vec![
        StoredLogAttribute::generic(occurrences(
            profile,
            AttributeNamespace::Resource,
            "same-key",
            vec![CandidateAttributeValue::string("resource".to_owned())],
        )?),
        StoredLogAttribute::schema_overflow(occurrences(
            profile,
            AttributeNamespace::InstrumentationScope,
            "same-key",
            vec![CandidateAttributeValue::bytes(vec![])],
        )?),
        StoredLogAttribute::generic(occurrences(
            profile,
            AttributeNamespace::Record,
            "same-key",
            vec![
                CandidateAttributeValue::null(),
                CandidateAttributeValue::boolean(false),
                CandidateAttributeValue::signed_integer(-42),
                CandidateAttributeValue::floating_point_bits(f64::NAN.to_bits()),
                CandidateAttributeValue::string(String::new()),
                CandidateAttributeValue::bytes(vec![0, 255]),
                CandidateAttributeValue::array(vec![
                    CandidateAttributeValue::signed_integer(7),
                    CandidateAttributeValue::string("seven".to_owned()),
                ]),
                CandidateAttributeValue::key_value_list(vec![
                    CandidateKeyValue::new(
                        "duplicate".to_owned(),
                        CandidateAttributeValue::boolean(true),
                    ),
                    CandidateKeyValue::new(
                        "duplicate".to_owned(),
                        CandidateAttributeValue::signed_integer(9),
                    ),
                ]),
            ],
        )?),
    ];
    let body = value(
        profile,
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "message".to_owned(),
            CandidateAttributeValue::string(String::new()),
        )]),
    )?;
    let event_time = EventTime::received(UnixNanoseconds::new(-55), SourceTimeQuality::Outlier)?;
    let observed_time =
        ObservedTime::received(UnixNanoseconds::new(88), SourceTimeQuality::Usable)?;
    let ingest_time = IngestTime::assign(IngestTimeCandidate::new(UnixNanoseconds::new(1_000)));
    let record = LogRecord::checked_native(
        event_time,
        Some(observed_time),
        ingest_time,
        Some(body),
        attributes,
        PolicyProvenance::new(9, [0x79; 32], vec![])?,
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let store = LogStore::new();
    let prepared = store.prepare(
        tenant,
        StoreBlockIdentity::new([0x62; 16])?,
        vec![record.clone()],
    )?;

    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x12; 16])?,
        CatalogSecret::from_owned(Box::new([0x22; 32]), Box::new([0x32; 32])),
    )?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(2)?);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x52; 32])),
    )?;
    ledger.append(prepared.into_store_block())?;
    let result = store.scan(
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;

    assert_eq!(result.records(), &[record]);
    assert_eq!(
        result.records()[0].attributes()[1].representation(),
        AttributeRepresentation::SchemaOverflow
    );
    assert_eq!(
        StoredLogAttribute::generic(result.records()[0].attributes()[1].occurrences().clone()),
        result.records()[0].attributes()[1]
    );
    Ok(())
}

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
                tenant,
                StoreBlockIdentity::new([0x63; 16])?,
                vec![record.clone(), second],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let bounded = store.scan(tenant, &snapshot, LogScan::all(ScanLimit::new(1)?))?;
    assert_eq!(bounded.records(), &[record]);
    assert!(!bounded.complete());
    let wrong_tenant = store
        .scan(
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
    trace_ledger.append(
        store
            .prepare(
                tenant,
                StoreBlockIdentity::new([0x64; 16])?,
                vec![minimal_record("trace-scope", 3)?],
            )?
            .into_store_block(),
    )?;
    let wrong_signal = store
        .scan(
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
                tenant,
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
                tenant,
                StoreBlockIdentity::new([0x66; 16])?,
                vec![active_record.clone()],
            )?
            .into_store_block(),
    )?;

    let result = store.scan(
        tenant,
        &successor.snapshot()?,
        LogScan::all(ScanLimit::new(2)?),
    )?;
    assert_eq!(result.records(), &[sealed_record, active_record]);
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
        StoreBlockIdentity::new([0x67; 16])?,
        b"not-a-log-store-block".to_vec(),
    )?)?;
    let failure = LogStore::new()
        .scan(
            tenant,
            &ledger.snapshot()?,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("authenticated but malformed store bytes cannot become telemetry");
    assert_eq!(failure.code(), LogStoreFailureCode::MalformedBlock);
    Ok(())
}

#[test]
fn public_limits_and_failures_are_typed_and_redacted() -> Result<(), Box<dyn Error>> {
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
        10,
        None,
        vec![("scope", "name", "value")],
        policy.clone(),
    )?;
    let positive_time = LogRecord::checked_minimal(
        Some(11),
        12,
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
            1,
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
            IngestTime::assign(IngestTimeCandidate::new(UnixNanoseconds::new(1))),
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
        .prepare(tenant, StoreBlockIdentity::new([0x69; 16])?, vec![])
        .err()
        .ok_or("an empty canonical block unexpectedly prepared")?;
    assert_eq!(empty_failure.code(), LogStoreFailureCode::LimitExceeded);
    let large_record =
        LogRecord::checked_minimal(None, 1, Some("x".repeat(262_144)), vec![], policy)?;
    let kernel_bound = store
        .prepare(
            tenant,
            StoreBlockIdentity::new([0x6a; 16])?,
            vec![large_record; 5],
        )
        .err()
        .ok_or("an oversized canonical Store Block unexpectedly prepared")?;
    assert_eq!(kernel_bound.code(), LogStoreFailureCode::Kernel);
    assert_eq!(kernel_bound.to_string(), "log store failure: Kernel");
    Ok(())
}

fn minimal_record(body: &str, ingest_time: i64) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_minimal(
        None,
        ingest_time,
        Some(body.to_owned()),
        vec![],
        PolicyProvenance::new(1, [0x70; 32], vec![])?,
    )?)
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
