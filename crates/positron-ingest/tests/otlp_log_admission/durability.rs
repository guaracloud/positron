use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::identity::{PrincipalId, Scope, TenantAttribution};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_signals::{LogScan, LogStore, ScanLimit};
use prost::Message;

use super::support::fixture;

#[test]
fn public_otlp_admission_receipt_survives_restart_and_reads_back() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xb1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(111).expect("shard");
    let scope = SegmentScope::new(fixture.tenant, SignalKind::Logs, shard);
    let policy = IngestPolicy::preserving(1, [0xb4; 32]).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(123)));
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("restart-visible".to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };
    let attribution = TenantAttribution::new(
        PrincipalId::from_bytes([0xb5; 16]).expect("principal"),
        Scope::Ingest,
        fixture.tenant,
    )
    .expect("attribution");
    let batch = OtlpLogsReceiver::new()
        .decode(AuthenticatedOtlpLogsRequest::new(
            attribution,
            request.encode_to_vec(),
        ))
        .expect("decode");
    {
        let ledger = ActiveSegmentLedger::open(
            &fixture.authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0xb6; 32])),
        )
        .expect("ledger");
        let committed = match LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
        )
        .accept(
            batch,
            StoreBlockIdentity::new([0xb7; 16]).expect("identity"),
        ) {
            IngestOutcome::Full(committed) => committed,
            other => panic!("expected durable commit, got {other:?}"),
        };
        assert_eq!(committed.receipt().position().value(), 1);
    }

    let reopened = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xb6; 32])),
    )
    .expect("reopen");
    let result = LogStore::new()
        .scan(
            fixture.authority.governor(),
            fixture.tenant,
            &reopened.snapshot().expect("snapshot"),
            LogScan::all(ScanLimit::new(1).expect("limit")),
        )
        .expect("scan");
    assert_eq!(result.records().len(), 1);
    assert_eq!(
        result.records()[0].body().and_then(|body| body.as_str()),
        Some("restart-visible")
    );
}
