use super::*;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};
use positron_domain::identity::TenantAttribution;
use positron_signals::{SamplingDecision, SpanKind, SpanStatusCode};
use prost::Message;

fn attribution() -> TenantAttribution {
    TenantAttribution::new(
        positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
        positron_domain::identity::Scope::Ingest,
        positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

#[test]
fn protobuf_receiver_maps_resource_scope_and_span_values() {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_owned(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("checkout".to_owned())),
                    }),
                    ..KeyValue::default()
                }],
                dropped_attributes_count: 0,
                ..Resource::default()
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(
                    opentelemetry_proto::tonic::common::v1::InstrumentationScope {
                        name: "otel".to_owned(),
                        version: "1".to_owned(),
                        attributes: Vec::new(),
                        ..Default::default()
                    },
                ),
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "checkout".to_owned(),
                    start_time_unix_nano: 10,
                    end_time_unix_nano: 20,
                    kind: 2,
                    flags: 1,
                    trace_state: "vendor=span".to_owned(),
                    status: Some(Status {
                        code: 2,
                        message: "upstream failed".to_owned(),
                    }),
                    events: vec![Event {
                        time_unix_nano: 15,
                        name: "cache.miss".to_owned(),
                        dropped_attributes_count: 3,
                        ..Event::default()
                    }],
                    links: vec![Link {
                        trace_id: vec![0x33; 16],
                        span_id: vec![0x44; 8],
                        trace_state: "vendor=link".to_owned(),
                        flags: 0x0402,
                        dropped_attributes_count: 4,
                        ..Link::default()
                    }],
                    dropped_attributes_count: 5,
                    dropped_events_count: 6,
                    dropped_links_count: 7,
                    ..Span::default()
                }],
                schema_url: "https://example.test/scope".to_owned(),
            }],
            schema_url: "https://example.test/resource".to_owned(),
        }],
    };
    let payload = request.encode_to_vec();
    let batch = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            attribution(),
            payload,
        ))
        .expect("trace payload should decode");
    assert_eq!(batch.records().len(), 1);
    let record = batch.records().first().expect("one span");
    assert_eq!(record.trace_id(), [0x11; 16]);
    assert_eq!(record.span_id(), [0x22; 8]);
    assert_eq!(record.kind(), SpanKind::Server);
    assert_eq!(record.sampling(), SamplingDecision::Sampled);
    assert_eq!(record.attributes().len(), 1);
    assert_eq!(
        record.attributes()[0].namespace(),
        positron_domain::value::AttributeNamespace::Resource
    );
    assert_eq!(record.attributes()[0].key(), "service.name");
    let details = record.details();
    assert_eq!(details.trace_state(), "vendor=span");
    assert_eq!(details.flags(), 1);
    assert_eq!(details.status().code(), SpanStatusCode::Error);
    assert_eq!(details.status().message(), "upstream failed");
    assert_eq!(details.events().len(), 1);
    assert_eq!(details.events()[0].name(), "cache.miss");
    assert_eq!(details.events()[0].dropped_attributes_count(), 3);
    assert_eq!(details.links().len(), 1);
    assert_eq!(details.links()[0].trace_id(), [0x33; 16]);
    assert_eq!(details.links()[0].flags(), 0x0402);
    assert_eq!(details.dropped_attributes_count(), 5);
    assert_eq!(details.dropped_events_count(), 6);
    assert_eq!(details.dropped_links_count(), 7);
    assert_eq!(
        details.resource().schema_url(),
        "https://example.test/resource"
    );
    assert_eq!(details.scope().name(), "otel");
    assert_eq!(details.scope().version(), "1");
    assert_eq!(details.scope().schema_url(), "https://example.test/scope");
    assert_eq!(details.scope().dropped_attributes_count(), 0);
}

#[test]
fn receiver_rejects_zero_or_wrong_width_span_ids() {
    for id in [vec![0; 16], vec![1; 15]] {
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![Span {
                        trace_id: id,
                        span_id: vec![2; 8],
                        name: "invalid".to_owned(),
                        ..Span::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let batch = OtlpTracesReceiver::new()
            .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                request.encode_to_vec(),
            ))
            .expect("invalid identifier is a per-span rejection");
        assert_eq!(batch.rejections(), [0, 1, 0]);
    }
}

#[test]
fn json_receiver_uses_streamed_bounds_before_message_materialization() {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "checkout".to_owned(),
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let json = serde_json::to_vec(&request).expect("ProtoJSON encoding");
    let batch = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_json(
            attribution(),
            json,
        ))
        .expect("valid ProtoJSON payload");
    assert_eq!(batch.records().len(), 1);

    let oversized = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span::default(); 1_025],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let failure = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_json(
            attribution(),
            serde_json::to_vec(&oversized).expect("ProtoJSON encoding"),
        ))
        .expect_err("JSON record bound must fail before allocation");
    assert_eq!(failure, TraceReceiveFailure::ValueLimitExceeded);
}
