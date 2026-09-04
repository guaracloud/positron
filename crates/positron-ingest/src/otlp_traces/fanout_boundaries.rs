use super::{AuthenticatedOtlpTracesRequest, OtlpTracesReceiver, TraceReceiveFailure};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;

fn attribution() -> positron_domain::identity::TenantAttribution {
    positron_domain::identity::TenantAttribution::new(
        positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
        positron_domain::identity::Scope::Ingest,
        positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

fn request(resource_attributes: usize) -> Vec<u8> {
    let attributes = (0..resource_attributes)
        .map(|index| KeyValue {
            key: format!("resource-{index}"),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue("value".to_owned())),
            }),
            ..KeyValue::default()
        })
        .collect();
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes,
                ..Resource::default()
            }),
            scope_spans: vec![ScopeSpans {
                spans: (0..1_024)
                    .map(|index| Span {
                        trace_id: vec![u8::try_from(index % 255).expect("bounded") + 1; 16],
                        span_id: vec![u8::try_from(index % 255).expect("bounded") + 1; 8],
                        name: format!("span-{index}"),
                        attributes: vec![KeyValue {
                            key: "span.attribute".to_owned(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::BoolValue(true)),
                            }),
                            ..KeyValue::default()
                        }],
                        ..Span::default()
                    })
                    .collect(),
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
    .encode_to_vec()
}

#[test]
fn resource_scope_fanout_accepts_exact_aggregate_and_refuses_one_over() {
    let exact = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            attribution(),
            request(3),
        ))
        .expect("three resource attributes plus one span attribute per span is exact");
    assert_eq!(exact.records().len(), 1_024);

    let over = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            attribution(),
            request(4),
        ))
        .expect_err("resource fan-out must count every materialized occurrence");
    assert_eq!(over, TraceReceiveFailure::ValueLimitExceeded);
}
