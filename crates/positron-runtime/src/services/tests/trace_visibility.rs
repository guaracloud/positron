use std::error::Error;
use std::sync::Arc;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::routing::SignalKind;
use positron_domain::time::SourceTimeQuality;
use positron_kernel::ActiveSegmentLedger;
use positron_signals::{ScanLimit, TraceScan, TraceStore};
use prost::Message;

use super::super::ServiceHandle;
use super::schema_maintenance::Fixture;

#[test]
fn contradictory_times_remain_visible_through_restart() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "contradictory-runtime".to_owned(),
                    start_time_unix_nano: 20,
                    end_time_unix_nano: 10,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    assert_eq!(
        services
            .ingest_otlp_traces(&ingest, request.encode_to_vec())?
            .accepted_records(),
        1
    );
    assert_contradictory_observation(&initialized)?;
    drop(services);
    let reopened = ServiceHandle::new(Arc::clone(&initialized))?;
    drop(reopened);
    assert_contradictory_observation(&initialized)
}

fn assert_contradictory_observation(
    initialized: &crate::InitializedInstance,
) -> Result<(), Box<dyn Error>> {
    let catalog = super::schema_maintenance::open_catalog(initialized)?;
    let basis = catalog.pin()?;
    let scope = basis
        .reachable_ledger_scopes(initialized.tenant, SignalKind::Traces)?
        .into_iter()
        .next()
        .ok_or("trace scope")?;
    let protection = initialized.key.segment_key(initialized.instance, scope)?;
    let ledger = ActiveSegmentLedger::open(&initialized._authority, &catalog, scope, protection)?;
    let snapshot = ledger.snapshot()?;
    let result = TraceStore::new().scan(
        initialized.resource_governor(),
        initialized.tenant,
        &snapshot,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    let observation = result
        .observations()
        .first()
        .ok_or("trace observation")?
        .observation();
    assert_eq!(observation.trace_id(), [0x11; 16]);
    assert_eq!(observation.span_id(), [0x22; 8]);
    assert_eq!(
        observation
            .start_time()
            .instant()
            .map(|value| value.value()),
        Some(20)
    );
    assert_eq!(
        observation.end_time().instant().map(|value| value.value()),
        Some(10)
    );
    assert_eq!(
        observation.end_time().quality(),
        SourceTimeQuality::Contradictory
    );
    Ok(())
}
