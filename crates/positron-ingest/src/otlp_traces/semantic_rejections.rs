use super::{AuthenticatedOtlpTracesRequest, OtlpTracesReceiver, TraceReceiveFailure};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, EntityRef, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::Link;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};
use prost::Message;

fn attribution() -> positron_domain::identity::TenantAttribution {
    positron_domain::identity::TenantAttribution::new(
        positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
        positron_domain::identity::Scope::Ingest,
        positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

fn request(span: Span) -> Vec<u8> {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![span],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
    .encode_to_vec()
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

fn decode(span: Span) -> Result<super::NativeSpanBatch<'static>, TraceReceiveFailure> {
    OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
        attribution(),
        request(span),
    ))
}

#[test]
fn development_entity_references_are_explicitly_rejected() {
    let payload = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                entity_refs: vec![EntityRef {
                    r#type: "service".to_owned(),
                    id_keys: vec!["service.name".to_owned()],
                    ..EntityRef::default()
                }],
                ..Resource::default()
            }),
            scope_spans: vec![ScopeSpans {
                spans: vec![valid_span()],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
    .encode_to_vec();
    assert!(matches!(
        OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            attribution(),
            payload,
        )),
        Err(TraceReceiveFailure::UnsupportedValue)
    ));
}

#[test]
fn indexed_wire_strings_are_rejected_instead_of_silently_dropped() {
    let mut span = valid_span();
    span.attributes.push(KeyValue {
        key: "indexed".to_owned(),
        key_strindex: 1,
        ..KeyValue::default()
    });
    assert!(matches!(
        decode(span),
        Err(TraceReceiveFailure::UnsupportedValue)
    ));

    let mut span = valid_span();
    span.attributes.push(KeyValue {
        key: "indexed-value".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValueStrindex(1)),
        }),
        ..KeyValue::default()
    });
    assert!(matches!(
        decode(span),
        Err(TraceReceiveFailure::UnsupportedValue)
    ));
}

#[test]
fn invalid_kind_status_timestamps_and_identifiers_have_stable_failures() {
    let mut invalid_kind = valid_span();
    invalid_kind.kind = 99;
    assert!(matches!(
        decode(invalid_kind),
        Err(TraceReceiveFailure::MalformedPayload)
    ));

    let mut invalid_status = valid_span();
    invalid_status.status = Some(Status {
        code: 99,
        message: String::new(),
    });
    assert!(matches!(
        decode(invalid_status),
        Err(TraceReceiveFailure::MalformedPayload)
    ));

    let mut out_of_range = valid_span();
    out_of_range.start_time_unix_nano = i64::MAX as u64 + 1;
    assert!(matches!(
        decode(out_of_range),
        Err(TraceReceiveFailure::TimestampOutOfRange)
    ));

    let mut reversed = valid_span();
    reversed.start_time_unix_nano = 21;
    assert!(matches!(
        decode(reversed),
        Err(TraceReceiveFailure::MalformedPayload)
    ));

    let mut invalid_link = valid_span();
    invalid_link.links.push(Link {
        trace_id: vec![0; 16],
        span_id: vec![3; 8],
        ..Link::default()
    });
    assert!(matches!(
        decode(invalid_link),
        Err(TraceReceiveFailure::MalformedPayload)
    ));
}

#[test]
fn malformed_utf8_and_conflicting_wire_values_fail_closed() {
    // Span.name is a protobuf string. The structural scanner may inspect the
    // bytes, but generated decode remains the owner of UTF-8 validity.
    let mut malformed_span = valid_span().encode_to_vec();
    malformed_span.extend_from_slice(&[0x2a, 0x01, 0xff]);
    let scope = length_delimited(2, &malformed_span);
    let resource = length_delimited(2, &scope);
    let payload = length_delimited(1, &resource);
    assert!(matches!(
        OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            attribution(),
            payload,
        )),
        Err(TraceReceiveFailure::MalformedPayload)
    ));
}

fn length_delimited(field: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = vec![field << 3 | 2];
    let mut length = value.len() as u64;
    while length >= 0x80 {
        encoded.push((length as u8 & 0x7f) | 0x80);
        length >>= 7;
    }
    encoded.push(length as u8);
    encoded.extend_from_slice(value);
    encoded
}
