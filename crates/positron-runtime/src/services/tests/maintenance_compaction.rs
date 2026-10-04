use std::error::Error;
use std::sync::Arc;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::routing::SignalKind;
use positron_kernel::{
    ActiveSegmentLedger, MaintenanceTaskId, MaintenanceTaskPhase, RetentionBucket,
};
use positron_signals::{LogScan, LogStore, ScanLimit, TraceScan, TraceStore};
use prost::Message;

use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, open_catalog, request};

#[test]
fn runtime_worker_executes_a_persisted_log_compaction_and_preserves_it_across_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let tenant = initialized.default_tenant_id();

    services.ingest_otlp_logs(&ingest, request("first compactable log").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(tenant, SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log ledger scope")?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    drop(catalog);

    services.ingest_otlp_logs(&ingest, request("first compactable log").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    let snapshot = ledger.snapshot()?;
    assert_eq!(
        snapshot.blocks().len(),
        2,
        "the fixture must seal two canonical records in one source scope"
    );
    let scanned = LogStore::new().scan(
        initialized._authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(16)?),
    )?;
    let ingest_time = scanned
        .records()
        .first()
        .ok_or("sealed log record")?
        .ingest_time();
    drop((scanned, snapshot));
    let policy = catalog.pin()?.retention_policy(SignalKind::Logs)?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Logs,
        ingest_time,
        policy.retention_seconds(),
    )?;
    let identity =
        MaintenanceTaskId::new([0xc1; 16]).map_err(|failure| format!("task id: {failure:?}"))?;
    let task = ledger.prepare_compaction_task(bucket, identity)?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance coordinator")?;
    task.submit_and_persist(&coordinator, &catalog, 1)?;
    drop(coordinator);
    drop(ledger);
    drop(catalog);

    assert!(
        services.wake_maintenance_worker()?,
        "one public worker wake must execute the queued durable compaction"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance coordinator")?
            .status(identity)
            .map_err(|failure| format!("compaction status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "the worker must terminalize the exact persisted descriptor"
    );
    drop(services);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let _restored_services = ServiceHandle::new(Arc::clone(&reopened))?;
    let catalog = open_catalog(&reopened)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &reopened._authority,
        &reopened.retention_time,
        &catalog,
        scope,
        reopened.tenant_segment_key_for_test(scope)?,
    )?;
    let snapshot = ledger.snapshot()?;
    let records = LogStore::new()
        .scan(
            reopened.resource_governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(16)?),
        )?
        .into_records();
    let bodies = records
        .iter()
        .map(|record| record.stored().body().and_then(|body| body.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        bodies,
        vec![Some("first compactable log"), Some("first compactable log")],
        "the reopened canonical log query retains each compacted record"
    );
    assert_eq!(
        reopened
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "reopened maintenance coordinator")?
            .status(identity)
            .map_err(|failure| format!("restored compaction status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "reopen retains the terminal compaction record"
    );
    Ok(())
}

#[test]
fn runtime_worker_executes_a_persisted_trace_compaction_and_preserves_spans_across_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let tenant = initialized.default_tenant_id();

    services.ingest_otlp_traces(
        &ingest,
        trace_request([0xd1; 16], [0xe1; 8]).encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(tenant, SignalKind::Traces)?
        .into_iter()
        .next()
        .ok_or("trace ledger scope")?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    drop(catalog);

    services.ingest_otlp_traces(
        &ingest,
        trace_request([0xd2; 16], [0xe2; 8]).encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    let snapshot = ledger.snapshot()?;
    assert_eq!(
        snapshot.blocks().len(),
        2,
        "the fixture must seal two canonical spans in one source scope"
    );
    let scanned = TraceStore::new().scan_physical(
        initialized.resource_governor(),
        tenant,
        &snapshot,
        TraceScan::all(ScanLimit::new(16)?),
    )?;
    let ingest_time = scanned
        .observations()
        .first()
        .ok_or("sealed trace observation")?
        .stored()
        .ingest_time();
    drop((scanned, snapshot));
    let policy = catalog.pin()?.retention_policy(SignalKind::Traces)?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Traces,
        ingest_time,
        policy.retention_seconds(),
    )?;
    let identity =
        MaintenanceTaskId::new([0xc2; 16]).map_err(|failure| format!("task id: {failure:?}"))?;
    let task = ledger.prepare_compaction_task(bucket, identity)?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance coordinator")?;
    task.submit_and_persist(&coordinator, &catalog, 1)?;
    drop(coordinator);
    drop(ledger);
    drop(catalog);

    assert!(
        services.wake_maintenance_worker()?,
        "one public worker wake must execute the queued durable compaction"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance coordinator")?
            .status(identity)
            .map_err(|failure| format!("compaction status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "the worker must terminalize the exact persisted descriptor"
    );
    drop(services);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let _restored_services = ServiceHandle::new(Arc::clone(&reopened))?;
    let catalog = open_catalog(&reopened)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &reopened._authority,
        &reopened.retention_time,
        &catalog,
        scope,
        reopened.tenant_segment_key_for_test(scope)?,
    )?;
    let snapshot = ledger.snapshot()?;
    let mut spans = TraceStore::new()
        .scan_physical(
            reopened.resource_governor(),
            tenant,
            &snapshot,
            TraceScan::all(ScanLimit::new(16)?),
        )?
        .observations()
        .iter()
        .map(|span| (span.observation().trace_id(), span.observation().span_id()))
        .collect::<Vec<_>>();
    spans.sort_unstable();
    assert_eq!(
        spans,
        vec![([0xd1; 16], [0xe1; 8]), ([0xd2; 16], [0xe2; 8])],
        "the reopened canonical trace scan retains every compacted span"
    );
    assert_eq!(
        reopened
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "reopened maintenance coordinator")?
            .status(identity)
            .map_err(|failure| format!("restored compaction status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "reopen retains the terminal compaction record"
    );
    Ok(())
}

fn trace_request(trace_id: [u8; 16], span_id: [u8; 8]) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: trace_id.to_vec(),
                    span_id: span_id.to_vec(),
                    name: "compactable-runtime-trace".to_owned(),
                    start_time_unix_nano: 1,
                    end_time_unix_nano: 2,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}
