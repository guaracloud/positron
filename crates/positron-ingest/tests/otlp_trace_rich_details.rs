use std::error::Error;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList, any_value,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{AuthenticatedOtlpTracesRequest, OtlpTracesReceiver};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use positron_signals::{SamplingDecision, SpanKind, SpanStatusCode};
use prost::Message;

#[path = "otlp_trace_admission/support.rs"]
mod support;

#[test]
fn authenticated_receiver_preserves_rich_trace_details_and_occurrences()
-> Result<(), Box<dyn Error>> {
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    let baseline = governor.inspect()?.outstanding_total();
    let request = request();
    let authenticated = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request.encode_to_vec(),
    )?;
    let batch = OtlpTracesReceiver::new().decode(authenticated)?;
    assert_eq!(batch.records().len(), 2);

    let first = &batch.records()[0];
    assert_eq!(first.trace_id(), [0x11; 16]);
    assert_eq!(first.span_id(), [0x21; 8]);
    assert_eq!(first.parent_span_id(), Some([0x31; 8]));
    assert_eq!(first.kind(), SpanKind::Server);
    assert_eq!(first.sampling(), SamplingDecision::Sampled);
    assert_eq!(first.details().trace_state(), "vendor=trace");
    assert_eq!(first.details().flags(), 1);
    assert_eq!(first.details().status().code(), SpanStatusCode::Error);
    assert_eq!(first.details().status().message(), "upstream failed");
    assert_eq!(first.details().dropped_attributes_count(), 5);
    assert_eq!(first.details().dropped_events_count(), 6);
    assert_eq!(first.details().dropped_links_count(), 7);
    assert_eq!(
        first.details().resource().schema_url(),
        "https://resource.test/v1"
    );
    assert_eq!(first.details().resource().dropped_attributes_count(), 3);
    assert_eq!(first.details().scope().name(), "checkout");
    assert_eq!(first.details().scope().version(), "1.2");
    assert_eq!(
        first.details().scope().schema_url(),
        "https://scope.test/v1"
    );
    assert_eq!(first.details().scope().dropped_attributes_count(), 4);

    assert_eq!(first.details().events().len(), 2);
    assert_eq!(first.details().events()[0].name(), "cache.miss");
    assert_eq!(first.details().events()[0].dropped_attributes_count(), 8);
    assert_eq!(first.details().events()[1].name(), "cache.retry");
    assert_eq!(first.details().links().len(), 2);
    assert_eq!(first.details().links()[0].trace_id(), [0x41; 16]);
    assert_eq!(first.details().links()[0].flags(), 0x402);
    assert_eq!(first.details().links()[0].trace_state(), "vendor=link");
    assert_eq!(first.details().links()[1].trace_id(), [0x42; 16]);

    let attributes = first
        .attributes()
        .iter()
        .find(|attribute| attribute.key() == "duplicate")
        .ok_or("duplicate attribute")?;
    assert_eq!(attributes.len(), 2);
    assert_eq!(
        attributes.occurrence(0).and_then(|value| value.as_str()),
        Some("first")
    );
    assert_eq!(
        attributes
            .occurrence(1)
            .and_then(|value| value.as_signed_integer()),
        Some(2)
    );
    let absent = first
        .attributes()
        .iter()
        .find(|attribute| attribute.key() == "absent")
        .ok_or("absent AnyValue")?;
    assert!(absent.occurrence(0).is_some_and(|value| value.is_null()));
    let nested = first
        .attributes()
        .iter()
        .find(|attribute| attribute.key() == "nested")
        .and_then(|attribute| attribute.occurrence(0))
        .ok_or("nested attribute")?;
    assert_eq!(
        nested.kind(),
        positron_domain::value::AttributeValueKind::Array
    );
    assert_eq!(nested.array_len(), Some(2));
    let nested_map = nested.array_entry(1).ok_or("nested map")?;
    assert_eq!(
        nested_map.kind(),
        positron_domain::value::AttributeValueKind::KeyValueList
    );
    assert_eq!(nested_map.key_value_list_len(), Some(1));
    assert_eq!(
        nested_map
            .key_value_entry(0)
            .ok_or("nested map entry")?
            .key(),
        "child"
    );

    let second = &batch.records()[1];
    assert_eq!(second.trace_id(), [0x12; 16]);
    assert_eq!(second.span_id(), [0x22; 8]);
    assert_eq!(second.kind(), SpanKind::Client);
    assert_eq!(second.sampling(), SamplingDecision::NotSampled);
    assert_eq!(second.details().events().len(), 0);
    assert_eq!(second.details().links().len(), 0);

    drop(batch);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    Ok(())
}

fn request() -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![attribute("service.name", string("checkout"))],
                dropped_attributes_count: 3,
                ..Resource::default()
            }),
            schema_url: "https://resource.test/v1".to_owned(),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "checkout".to_owned(),
                    version: "1.2".to_owned(),
                    attributes: vec![attribute("scope.region", string("us-east"))],
                    dropped_attributes_count: 4,
                }),
                schema_url: "https://scope.test/v1".to_owned(),
                spans: vec![rich_span(), simple_span()],
            }],
        }],
    }
}

fn rich_span() -> Span {
    Span {
        trace_id: vec![0x11; 16],
        span_id: vec![0x21; 8],
        parent_span_id: vec![0x31; 8],
        name: "checkout".to_owned(),
        start_time_unix_nano: 10,
        end_time_unix_nano: 20,
        kind: 2,
        flags: 1,
        trace_state: "vendor=trace".to_owned(),
        attributes: vec![
            attribute("duplicate", string("first")),
            attribute("duplicate", integer(2)),
            KeyValue {
                key: "absent".to_owned(),
                value: None,
                ..KeyValue::default()
            },
            attribute(
                "nested",
                AnyValue {
                    value: Some(any_value::Value::ArrayValue(ArrayValue {
                        values: vec![
                            boolean(true),
                            AnyValue {
                                value: Some(any_value::Value::KvlistValue(KeyValueList {
                                    values: vec![attribute("child", string("value"))],
                                })),
                            },
                        ],
                    })),
                },
            ),
        ],
        status: Some(Status {
            code: 2,
            message: "upstream failed".to_owned(),
        }),
        events: vec![
            Event {
                time_unix_nano: 11,
                name: "cache.miss".to_owned(),
                attributes: vec![attribute("event", string("miss"))],
                dropped_attributes_count: 8,
            },
            Event {
                time_unix_nano: 12,
                name: "cache.retry".to_owned(),
                ..Event::default()
            },
        ],
        links: vec![
            Link {
                trace_id: vec![0x41; 16],
                span_id: vec![0x51; 8],
                trace_state: "vendor=link".to_owned(),
                flags: 0x402,
                ..Link::default()
            },
            Link {
                trace_id: vec![0x42; 16],
                span_id: vec![0x52; 8],
                ..Link::default()
            },
        ],
        dropped_attributes_count: 5,
        dropped_events_count: 6,
        dropped_links_count: 7,
    }
}

fn simple_span() -> Span {
    Span {
        trace_id: vec![0x12; 16],
        span_id: vec![0x22; 8],
        name: "worker".to_owned(),
        start_time_unix_nano: 30,
        end_time_unix_nano: 40,
        kind: 3,
        flags: 2,
        ..Span::default()
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

fn integer(value: i64) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::IntValue(value)),
    }
}

fn boolean(value: bool) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::BoolValue(value)),
    }
}
