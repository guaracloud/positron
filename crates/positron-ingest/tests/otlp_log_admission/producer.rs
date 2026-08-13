use std::error::Error;
use std::sync::{Arc, Mutex};

use opentelemetry::logs::{AnyValue, LogRecord as _, Logger, LoggerProvider};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLoggerProvider};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver};
use positron_ingest::{IngestOutcome, IngestPolicy, LogIngest};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use prost::Message;

use super::support::{fixture, temporary_roots};

#[derive(Clone, Debug)]
struct WireExporter(Arc<Mutex<Option<Vec<u8>>>>);

impl LogExporter for WireExporter {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let records = batch
            .iter()
            .map(|(record, _)| LogRecord::from(record))
            .collect();
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: records,
                    ..ScopeLogs::default()
                }],
                ..ResourceLogs::default()
            }],
        };
        if let Ok(mut output) = self.0.lock() {
            *output = Some(request.encode_to_vec());
        }
        Ok(())
    }
}

#[test]
fn pinned_opentelemetry_sdk_producer_reaches_public_receiver_path() -> Result<(), Box<dyn Error>> {
    let wire = Arc::new(Mutex::new(None));
    let provider = SdkLoggerProvider::builder()
        .with_simple_exporter(WireExporter(Arc::clone(&wire)))
        .build();
    let logger = provider.logger("positron-producer-compatibility");
    let mut record = logger.create_log_record();
    record.set_body(AnyValue::String("produced-by-sdk".into()));
    logger.emit(record);
    let protobuf = wire
        .lock()
        .map_err(|_| "producer output lock poisoned")?
        .take()
        .ok_or("producer did not export OTLP bytes")?;

    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret())?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let fixture = fixture(instance.default_tenant_id())?;
    let request =
        AuthenticatedOtlpLogsRequest::protobuf(context, fixture.authority.governor(), protobuf)?;
    let batch = OtlpLogsReceiver::new().decode(request)?;
    assert_eq!(batch.records().len(), 1);
    assert!(matches!(
        batch.records().first().and_then(|record| record.body()),
        Some(positron_domain::value::CandidateAttributeValue::String(body))
            if body == "produced-by-sdk"
    ));
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xd1; 16])?,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let shard = VirtualShardId::new(121)?;
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0xd4; 32])),
    )?;
    let policy = IngestPolicy::preserving(1, [0xd5; 32])?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(123)));
    let committed = match LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        fixture.tenant,
        shard,
    )
    .accept(batch, StoreBlockIdentity::new([0xd6; 16])?)
    {
        IngestOutcome::Full(committed) => committed,
        other => return Err(format!("expected durable commit, got {other:?}").into()),
    };
    assert_eq!(committed.records(), 1);
    assert_eq!(committed.receipt().position().value(), 1);
    provider.shutdown()?;
    Ok(())
}
