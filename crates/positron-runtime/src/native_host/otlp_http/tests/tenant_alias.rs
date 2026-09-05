use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;

use super::live::{TestRoots, receive_http_with_tenant, rejected};
use crate::{InitializationPlan, InstanceBootstrap, ServiceHandle};

#[test]
fn live_http_trace_export_accepts_the_authenticated_external_tenant_alias()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let bearer = InstanceBootstrap::claim(&paths)?
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    let services = ServiceHandle::new(std::sync::Arc::new(InstanceBootstrap::reopen(&paths)?))?;
    let body = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x51; 16],
                    span_id: vec![0x52; 8],
                    name: "external-alias".to_owned(),
                    start_time_unix_nano: 10,
                    end_time_unix_nano: 20,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
    .encode_to_vec();

    let accepted = receive_http_with_tenant(
        &services,
        &bearer,
        body.clone(),
        "application/x-protobuf",
        None,
        Some("default"),
        None,
    )?;
    assert_eq!(accepted.status(), 200);
    let response = ExportTraceServiceResponse::decode(accepted.body())?;
    assert!(response.partial_success.is_none());

    let rejected = rejected(receive_http_with_tenant(
        &services,
        &bearer,
        body,
        "application/x-protobuf",
        None,
        Some("other-tenant"),
        None,
    ))?;
    assert_eq!(rejected.status(), 401);
    Ok(())
}
