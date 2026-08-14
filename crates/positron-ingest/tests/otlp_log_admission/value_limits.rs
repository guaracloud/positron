use std::error::Error;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, ArrayValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    ByteLimit, DynamicValueLimits, NestingLimit, RecordLimits, ValueLimitProfile,
    ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, IngestFailureCode, IngestOutcome, IngestPolicy, LogIngest,
    OtlpLogsReceiver,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use positron_signals::{LogScan, LogStore, ScanLimit};
use prost::Message;

use super::support::{fixture, temporary_roots};

#[test]
fn effective_nesting_boundary_survives_authenticated_admission_and_reopen()
-> Result<(), Box<dyn Error>> {
    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let credential = claim.ingest_secret().ok_or("missing ingest credential")?;
    let profile = profile_with_nesting(17)?;
    let fixture = fixture(instance.default_tenant_id())?;
    let exact = authenticated_request(
        &instance,
        credential,
        &fixture,
        request_with_body(nested_array(17)),
    )?;
    let batch = OtlpLogsReceiver::with_value_limit_profile(profile)
        .decode(exact)
        .map_err(|failure| format!("exact depth was rejected: {failure:?}"))?;
    let over = authenticated_request(
        &instance,
        credential,
        &fixture,
        request_with_body(nested_array(18)),
    )?;
    let over_batch = OtlpLogsReceiver::with_value_limit_profile(profile)
        .decode(over)
        .expect("structurally safe depth reaches post-policy semantic admission");

    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xf1; 16])?,
        CatalogSecret::from_owned(Box::new([0xf2; 32]), Box::new([0xf3; 32])),
    )?;
    let shard = VirtualShardId::new(141)?;
    let scope = SegmentScope::new(fixture.tenant, SignalKind::Logs, shard);
    let protection_key = || SegmentProtectionKey::from_owned(Box::new([0xf4; 32]));
    let policy = IngestPolicy::preserving(18, [0xf5; 32])?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(600)));
    {
        let ledger =
            ActiveSegmentLedger::open(&fixture.authority, &catalog, scope, protection_key())?;
        let ingest = LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
        );
        assert!(matches!(
            ingest.accept(batch, StoreBlockIdentity::new([0xf6; 16])?),
            IngestOutcome::Full(_)
        ));
        assert_eq!(
            ingest.accept(over_batch, StoreBlockIdentity::new([0xf7; 16])?),
            IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
        );
    }

    let reopened =
        ActiveSegmentLedger::open(&fixture.authority, &catalog, scope, protection_key())?;
    let result = LogStore::new().scan(
        fixture.authority.governor(),
        fixture.tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let mut value = result
        .records()
        .first()
        .and_then(|record| record.body())
        .ok_or("missing round-tripped body")?;
    for _ in 0..17 {
        value = value.array_entry(0).ok_or("missing nested array entry")?;
    }
    assert!(value.is_null());
    Ok(())
}

#[test]
fn decoded_record_boundary_survives_authenticated_admission_and_reopen()
-> Result<(), Box<dyn Error>> {
    const EXACT_DECODED_BYTES: u32 = 540_018;
    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let credential = claim.ingest_secret().ok_or("missing ingest credential")?;
    let profile = profile_with_decoded_record_bytes(EXACT_DECODED_BYTES)?;
    let fixture = fixture(instance.default_tenant_id())?;
    let exact = authenticated_request(
        &instance,
        credential,
        &fixture,
        request_with_byte_attributes(60_000),
    )?;
    let batch = OtlpLogsReceiver::with_value_limit_profile(profile)
        .decode(exact)
        .map_err(|failure| format!("exact decoded bytes were rejected: {failure:?}"))?;
    let over = authenticated_request(
        &instance,
        credential,
        &fixture,
        request_with_byte_attributes(60_001),
    )?;
    let over_batch = OtlpLogsReceiver::with_value_limit_profile(profile)
        .decode(over)
        .expect("system-bounded record reaches post-policy semantic admission");

    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xd1; 16])?,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let shard = VirtualShardId::new(151)?;
    let scope = SegmentScope::new(fixture.tenant, SignalKind::Logs, shard);
    let protection_key = || SegmentProtectionKey::from_owned(Box::new([0xd4; 32]));
    let policy = IngestPolicy::preserving(19, [0xd5; 32])?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(700)));
    {
        let ledger =
            ActiveSegmentLedger::open(&fixture.authority, &catalog, scope, protection_key())?;
        let ingest = LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
        );
        assert!(matches!(
            ingest.accept(batch, StoreBlockIdentity::new([0xd6; 16])?),
            IngestOutcome::Full(_)
        ));
        assert_eq!(
            ingest.accept(over_batch, StoreBlockIdentity::new([0xd7; 16])?),
            IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
        );
    }

    let reopened =
        ActiveSegmentLedger::open(&fixture.authority, &catalog, scope, protection_key())?;
    let result = LogStore::new().scan(
        fixture.authority.governor(),
        fixture.tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let record = result.records().first().ok_or("missing exact record")?;
    assert_eq!(record.attributes().len(), 9);
    assert!(record.attributes().iter().all(|attribute| {
        attribute
            .occurrences()
            .occurrence(0)
            .and_then(|value| value.as_bytes())
            .is_some_and(|value| value.len() == 60_000)
    }));
    Ok(())
}

fn profile_with_nesting(depth: u16) -> Result<ValueLimitProfile, Box<dyn Error>> {
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let dynamic = DynamicValueLimits::new(
        maximum.dynamic_value().individual_value_bytes(),
        maximum.dynamic_value().attributes_per_namespace(),
        maximum.dynamic_value().key_path_bytes(),
        NestingLimit::new(depth)?,
        maximum.dynamic_value().array_entries(),
        maximum.dynamic_value().key_value_list_entries(),
    );
    Ok(ValueLimitProfileCandidate::new(
        maximum,
        Some(ValueLimitSet::new(
            maximum.request(),
            maximum.record(),
            dynamic,
        )),
    )
    .validate()?)
}

fn profile_with_decoded_record_bytes(bytes: u32) -> Result<ValueLimitProfile, Box<dyn Error>> {
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let record = RecordLimits::new(
        maximum.record().encoded_bytes(),
        ByteLimit::new(bytes)?,
        maximum.record().log_body_bytes(),
    );
    Ok(ValueLimitProfileCandidate::new(
        maximum,
        Some(ValueLimitSet::new(
            maximum.request(),
            record,
            maximum.dynamic_value(),
        )),
    )
    .validate()?)
}

fn authenticated_request<'authority>(
    instance: &positron_runtime::InitializedInstance,
    credential: &str,
    fixture: &'authority super::support::Fixture,
    request: ExportLogsServiceRequest,
) -> Result<AuthenticatedOtlpLogsRequest<'authority>, Box<dyn Error>> {
    let context = instance.attribute(
        PresentedCredential::parse(credential)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    Ok(AuthenticatedOtlpLogsRequest::protobuf(
        context,
        fixture.authority.governor(),
        request.encode_to_vec(),
    )?)
}

fn request_with_body(body: AnyValue) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    body: Some(body),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

fn request_with_byte_attributes(first_value_bytes: usize) -> ExportLogsServiceRequest {
    let attributes = (0..9)
        .map(|index| KeyValue {
            key: format!("k{index}"),
            value: Some(AnyValue {
                value: Some(any_value::Value::BytesValue(vec![
                    0;
                    if index == 0 {
                        first_value_bytes
                    } else {
                        60_000
                    }
                ])),
            }),
            ..KeyValue::default()
        })
        .collect();
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    attributes,
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

fn nested_array(depth: usize) -> AnyValue {
    (0..depth).fold(AnyValue { value: None }, |value, _| AnyValue {
        value: Some(any_value::Value::ArrayValue(ArrayValue {
            values: vec![value],
        })),
    })
}
