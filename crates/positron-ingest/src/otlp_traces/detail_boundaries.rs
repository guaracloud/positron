use super::{AuthenticatedOtlpTracesRequest, OtlpTracesReceiver, TraceReceiveFailure};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
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

fn decode(span: Span) -> Result<super::NativeSpanBatch<'static>, TraceReceiveFailure> {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![span],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
        attribution(),
        request.encode_to_vec(),
    ))
}

fn valid_span() -> Span {
    Span {
        trace_id: vec![1; 16],
        span_id: vec![2; 8],
        name: "operation".to_owned(),
        start_time_unix_nano: 10,
        end_time_unix_nano: 20,
        ..Span::default()
    }
}

#[test]
fn detail_attributes_reject_indexed_event_and_link_values() {
    let mut event = valid_span();
    event.events.push(Event {
        name: "exception".to_owned(),
        attributes: vec![KeyValue {
            key: "indexed-event".to_owned(),
            key_strindex: 1,
            ..KeyValue::default()
        }],
        ..Event::default()
    });
    assert!(matches!(
        decode(event),
        Err(TraceReceiveFailure::UnsupportedValue)
    ));

    let mut link = valid_span();
    link.links.push(Link {
        trace_id: vec![3; 16],
        span_id: vec![4; 8],
        attributes: vec![KeyValue {
            key: "indexed-link".to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValueStrindex(1)),
            }),
            ..KeyValue::default()
        }],
        ..Link::default()
    });
    assert!(matches!(
        decode(link),
        Err(TraceReceiveFailure::UnsupportedValue)
    ));
}

#[test]
fn empty_event_names_are_malformed_instead_of_dropped() {
    let mut span = valid_span();
    span.events.push(Event::default());
    assert!(matches!(
        decode(span),
        Err(TraceReceiveFailure::MalformedPayload)
    ));
}
