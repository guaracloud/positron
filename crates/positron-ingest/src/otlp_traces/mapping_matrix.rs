use super::{AuthenticatedOtlpTracesRequest, OtlpTracesReceiver};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList, any_value,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};
use positron_domain::value::{AttributeNamespace, AttributeValueKind};
use positron_signals::{SamplingDecision, SpanKind, SpanStatusCode};
use prost::Message;

fn attribution() -> positron_domain::identity::TenantAttribution {
    positron_domain::identity::TenantAttribution::new(
        positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
        positron_domain::identity::Scope::Ingest,
        positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

#[test]
fn receiver_preserves_multi_scope_span_details_and_all_native_value_kinds() {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![
            ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![attribute("service.name", string("checkout"))],
                    dropped_attributes_count: 3,
                    ..Resource::default()
                }),
                schema_url: "https://resource.example/v1".to_owned(),
                scope_spans: vec![
                    ScopeSpans {
                        scope: Some(InstrumentationScope {
                            name: "checkout.instrumentation".to_owned(),
                            version: "1.2.3".to_owned(),
                            attributes: vec![attribute("scope.region", string("us-east"))],
                            dropped_attributes_count: 4,
                        }),
                        schema_url: "https://scope.example/v2".to_owned(),
                        spans: vec![span(0, 0, 0), span(1, 1, 0x402), span(2, 2, 0x401)],
                    },
                    ScopeSpans {
                        scope: Some(InstrumentationScope {
                            name: "worker.instrumentation".to_owned(),
                            version: "2.0.0".to_owned(),
                            attributes: Vec::new(),
                            dropped_attributes_count: 5,
                        }),
                        schema_url: "https://scope.example/worker".to_owned(),
                        spans: vec![span(3, 3, 0x405), span(4, 4, 0x400), span(5, 5, 0x402)],
                    },
                ],
            },
            ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![attribute("service.name", string("worker"))],
                    dropped_attributes_count: 6,
                    ..Resource::default()
                }),
                schema_url: "https://resource.example/worker".to_owned(),
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    schema_url: String::new(),
                    spans: vec![span(6, 5, 0x400)],
                }],
            },
        ],
    };

    let batch = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            attribution(),
            request.encode_to_vec(),
        ))
        .expect("valid OTLP trace matrix");
    assert_eq!(batch.records().len(), 7);

    let expected_kinds = [
        SpanKind::Unspecified,
        SpanKind::Internal,
        SpanKind::Server,
        SpanKind::Client,
        SpanKind::Producer,
        SpanKind::Consumer,
        SpanKind::Consumer,
    ];
    let expected_sampling = [
        SamplingDecision::Unknown,
        SamplingDecision::NotSampled,
        SamplingDecision::Sampled,
        SamplingDecision::Sampled,
        SamplingDecision::NotSampled,
        SamplingDecision::NotSampled,
        SamplingDecision::NotSampled,
    ];
    let expected_statuses = [
        SpanStatusCode::Unset,
        SpanStatusCode::Ok,
        SpanStatusCode::Error,
        SpanStatusCode::Unset,
        SpanStatusCode::Ok,
        SpanStatusCode::Error,
        SpanStatusCode::Unset,
    ];
    for (index, ((record, expected_kind), (expected_sampling, expected_status))) in batch
        .records()
        .iter()
        .zip(expected_kinds)
        .zip(expected_sampling.into_iter().zip(expected_statuses))
        .enumerate()
    {
        assert_eq!(record.kind(), expected_kind);
        assert_eq!(record.sampling(), expected_sampling);
        assert_eq!(record.details().status().code(), expected_status);
        assert_eq!(record.details().trace_state(), "vendor=trace");
        assert_eq!(
            record.details().flags() & 0x400,
            if index == 0 { 0 } else { 0x400 }
        );
        assert!(record.parent_span_id().is_some());
    }

    let first = batch.records().first().expect("first span");
    assert_eq!(first.details().status().message(), "status message");
    assert_eq!(first.details().dropped_attributes_count(), 7);
    assert_eq!(first.details().dropped_events_count(), 8);
    assert_eq!(first.details().dropped_links_count(), 9);
    assert_eq!(first.details().events().len(), 2);
    assert_eq!(first.details().events()[0].name(), "first.event");
    assert_eq!(first.details().events()[1].name(), "second.event");
    assert_eq!(first.details().events()[0].dropped_attributes_count(), 10);
    assert_eq!(first.details().links().len(), 2);
    assert_eq!(first.details().links()[0].trace_state(), "vendor=link-1");
    assert_eq!(first.details().links()[1].trace_state(), "vendor=link-2");
    assert_eq!(first.details().links()[1].flags(), 0x502);
    assert_eq!(first.details().resource().dropped_attributes_count(), 3);
    assert_eq!(
        first.details().resource().schema_url(),
        "https://resource.example/v1"
    );
    assert_eq!(first.details().scope().name(), "checkout.instrumentation");
    assert_eq!(first.details().scope().version(), "1.2.3");
    assert_eq!(first.details().scope().dropped_attributes_count(), 4);
    assert_eq!(
        first.details().scope().schema_url(),
        "https://scope.example/v2"
    );

    let resource_attribute = first
        .attributes()
        .iter()
        .find(|attribute| {
            attribute.namespace() == AttributeNamespace::Resource
                && attribute.key() == "service.name"
        })
        .expect("resource attribute");
    assert_eq!(
        resource_attribute.occurrence(0).expect("value").as_str(),
        Some("checkout")
    );
    let scope_attribute = first
        .attributes()
        .iter()
        .find(|attribute| {
            attribute.namespace() == AttributeNamespace::InstrumentationScope
                && attribute.key() == "scope.region"
        })
        .expect("scope attribute");
    assert_eq!(
        scope_attribute.occurrence(0).expect("value").as_str(),
        Some("us-east")
    );

    let all_values = first
        .attributes()
        .iter()
        .find(|attribute| {
            attribute.namespace() == AttributeNamespace::Record && attribute.key() == "all"
        })
        .expect("all native value variants");
    let value = all_values.occurrence(0).expect("array value");
    assert_eq!(value.kind(), AttributeValueKind::Array);
    assert_eq!(value.array_len(), Some(7));
    assert_eq!(
        value.array_entry(0).and_then(|entry| entry.as_boolean()),
        Some(true)
    );
    assert_eq!(
        value
            .array_entry(1)
            .and_then(|entry| entry.as_signed_integer()),
        Some(-7)
    );
    assert_eq!(
        value
            .array_entry(2)
            .and_then(|entry| entry.as_floating_point_bits()),
        Some(3.5_f64.to_bits())
    );
    assert_eq!(
        value.array_entry(3).and_then(|entry| entry.as_bytes()),
        Some([0, 255].as_slice())
    );
    assert_eq!(
        value.array_entry(4).and_then(|entry| entry.as_str()),
        Some("text")
    );
    let map = value.array_entry(5).expect("key/value list");
    assert_eq!(map.kind(), AttributeValueKind::KeyValueList);
    assert_eq!(map.key_value_list_len(), Some(2));
    assert_eq!(map.key_value_entry(0).expect("map entry").key(), "nested");
    assert_eq!(
        map.key_value_entry(0)
            .expect("map entry")
            .value()
            .as_boolean(),
        Some(false)
    );
    assert!(value.array_entry(6).expect("null").is_null());

    let event_value = first.details().events()[0]
        .attributes()
        .first()
        .expect("event attribute")
        .occurrence(0)
        .expect("event value");
    assert_eq!(event_value.as_str(), Some("event-value"));
    let link_value = first.details().links()[0]
        .attributes()
        .first()
        .expect("link attribute")
        .occurrence(0)
        .expect("link value");
    assert_eq!(link_value.as_signed_integer(), Some(42));

    let second_resource = batch.records().get(6).expect("second resource span");
    assert_eq!(
        second_resource.details().resource().schema_url(),
        "https://resource.example/worker"
    );
    assert_eq!(
        second_resource
            .details()
            .resource()
            .dropped_attributes_count(),
        6
    );
    assert_eq!(second_resource.details().scope().name(), "");
}

fn span(index: usize, kind: i32, flags: u32) -> Span {
    Span {
        trace_id: vec![0x10 + index as u8; 16],
        span_id: vec![0x20 + index as u8; 8],
        parent_span_id: vec![0x30 + index as u8; 8],
        name: format!("span-{index}"),
        start_time_unix_nano: 100 + index as u64,
        end_time_unix_nano: 200 + index as u64,
        kind,
        flags,
        trace_state: "vendor=trace".to_owned(),
        attributes: vec![
            attribute("all", all_values()),
            attribute("duplicate", boolean(index.is_multiple_of(2))),
            attribute("duplicate", integer(index as i64)),
        ],
        status: Some(Status {
            code: (index % 3) as i32,
            message: "status message".to_owned(),
        }),
        events: vec![
            Event {
                time_unix_nano: 0,
                name: "first.event".to_owned(),
                attributes: vec![attribute("event", string("event-value"))],
                dropped_attributes_count: 10,
            },
            Event {
                time_unix_nano: 300,
                name: "second.event".to_owned(),
                ..Event::default()
            },
        ],
        links: vec![
            Link {
                trace_id: vec![0x50 + index as u8; 16],
                span_id: vec![0x60 + index as u8; 8],
                trace_state: "vendor=link-1".to_owned(),
                attributes: vec![attribute("link", integer(42))],
                dropped_attributes_count: 11,
                ..Link::default()
            },
            Link {
                trace_id: vec![0x70 + index as u8; 16],
                span_id: vec![0x80 + index as u8; 8],
                trace_state: "vendor=link-2".to_owned(),
                flags: 0x502,
                ..Link::default()
            },
        ],
        dropped_attributes_count: 7,
        dropped_events_count: 8,
        dropped_links_count: 9,
    }
}

fn all_values() -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::ArrayValue(ArrayValue {
            values: vec![
                boolean(true),
                integer(-7),
                AnyValue {
                    value: Some(any_value::Value::DoubleValue(3.5)),
                },
                AnyValue {
                    value: Some(any_value::Value::BytesValue(vec![0, 255])),
                },
                string("text"),
                AnyValue {
                    value: Some(any_value::Value::KvlistValue(KeyValueList {
                        values: vec![
                            attribute("nested", boolean(false)),
                            attribute("null", null()),
                        ],
                    })),
                },
                null(),
            ],
        })),
    }
}

fn attribute(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(value),
        ..KeyValue::default()
    }
}

fn string(value: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(value.to_owned())),
    }
}

fn boolean(value: bool) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::BoolValue(value)),
    }
}

fn integer(value: i64) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::IntValue(value)),
    }
}

fn null() -> AnyValue {
    AnyValue { value: None }
}
