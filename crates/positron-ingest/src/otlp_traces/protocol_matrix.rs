use super::{
    AuthenticatedOtlpTracesRequest, OtlpTracesReceiver, TraceReceiveFailure,
    preflight_otlp_traces_gzip, preflight_otlp_traces_json, preflight_otlp_traces_protobuf,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, KeyValue, KeyValueList, any_value,
};
use opentelemetry_proto::tonic::trace::v1::Span;
use prost::Message;
use std::io::Write;

#[test]
fn protobuf_and_protojson_preserve_the_same_public_native_batch() {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![opentelemetry_proto::tonic::trace::v1::ResourceSpans {
            scope_spans: vec![opentelemetry_proto::tonic::trace::v1::ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "parity".to_owned(),
                    attributes: vec![
                        KeyValue {
                            key: "attribute".to_owned(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::IntValue(-9)),
                            }),
                            ..Default::default()
                        },
                        KeyValue {
                            key: "all".to_owned(),
                            value: Some(all_values()),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let attribution = test_attribution();
    let protobuf = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            attribution,
            request.encode_to_vec(),
        ))
        .expect("protobuf payload");
    let json = serde_json::to_vec(&request).expect("ProtoJSON payload");
    let protojson = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_json(
            test_attribution(),
            json,
        ))
        .expect("ProtoJSON payload");
    assert_eq!(protobuf.records(), protojson.records());
}

#[test]
fn gzip_protobuf_and_json_use_bounded_public_preflight() {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![Default::default()],
    };
    let protobuf = request.encode_to_vec();
    let json = serde_json::to_vec(&request).expect("ProtoJSON payload");
    assert!(preflight_otlp_traces_protobuf(&protobuf).is_ok());
    assert!(preflight_otlp_traces_json(&json).is_ok());

    let compressed_protobuf = gzip(&protobuf);
    let compressed_json = gzip(&json);
    assert!(preflight_otlp_traces_gzip(&compressed_protobuf, false).is_ok());
    assert!(preflight_otlp_traces_gzip(&compressed_json, true).is_ok());
    let gzip_protobuf = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_gzip_protobuf(
            test_attribution(),
            compressed_protobuf,
        ))
        .expect("gzip protobuf payload");
    let gzip_json = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_gzip_json(
            test_attribution(),
            compressed_json,
        ))
        .expect("gzip ProtoJSON payload");
    assert_eq!(gzip_protobuf.records(), gzip_json.records());
    assert_eq!(
        preflight_otlp_traces_gzip(&[0x1f, 0x8b, 0x08, 0x00], false),
        Err(TraceReceiveFailure::MalformedCompression)
    );
    let failure = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
            test_attribution(),
            vec![0; 1_048_577],
        ))
        .expect_err("oversized protobuf transport");
    assert_eq!(failure, TraceReceiveFailure::TransportLimitExceeded);
}

#[test]
fn unknown_protobuf_wire_shapes_are_skipped_but_truncation_is_rejected() {
    let mut unknown = ExportTraceServiceRequest::default().encode_to_vec();
    // Unknown field 99 using each supported protobuf wire shape. The group is
    // properly terminated and therefore remains ignorable protocol data.
    unknown.extend_from_slice(&[0x98, 0x06, 0x01]); // varint
    unknown.extend_from_slice(&[0x99, 0x06]);
    unknown.extend_from_slice(&[0; 8]); // fixed64
    unknown.extend_from_slice(&[0x9a, 0x06, 0x02, 0xaa, 0xbb]); // bytes
    unknown.extend_from_slice(&[0x9b, 0x06, 0x98, 0x06, 0x01, 0x9c, 0x06]); // group
    unknown.extend_from_slice(&[0x9d, 0x06]); // fixed32
    unknown.extend_from_slice(&[0; 4]);
    assert!(preflight_otlp_traces_protobuf(&unknown).is_ok());

    let truncated = [0x9a, 0x06, 0x04, 0xaa];
    assert_eq!(
        preflight_otlp_traces_protobuf(&truncated),
        Err(TraceReceiveFailure::MalformedPayload)
    );
}

#[test]
fn json_structure_and_syntax_fail_before_message_materialization() {
    let too_many_entries = format!(r#"{{"resourceSpans":[{}]}}"#, vec!["{}"; 1_025].join(","));
    assert_eq!(
        preflight_otlp_traces_json(too_many_entries.as_bytes()),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );
    assert_eq!(
        preflight_otlp_traces_json(br#"{"resourceSpans":["#),
        Err(TraceReceiveFailure::MalformedPayload)
    );
    let malformed = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_json(
            test_attribution(),
            br#"{"resourceSpans":["#.to_vec(),
        ))
        .expect_err("truncated ProtoJSON");
    assert_eq!(malformed, TraceReceiveFailure::MalformedPayload);
}

#[test]
fn protojson_base64_bytes_use_the_native_byte_limit_not_encoded_text_length() {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![opentelemetry_proto::tonic::trace::v1::ResourceSpans {
            scope_spans: vec![opentelemetry_proto::tonic::trace::v1::ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "bytes-boundary".to_owned(),
                    attributes: vec![KeyValue {
                        key: "bytes".to_owned(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::BytesValue(vec![0x5a; 65_536])),
                        }),
                        ..KeyValue::default()
                    }],
                    ..Span::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let json = serde_json::to_vec(&request).expect("ProtoJSON payload");
    let batch = OtlpTracesReceiver::new()
        .decode(AuthenticatedOtlpTracesRequest::test_only_json(
            test_attribution(),
            json,
        ))
        .expect("exact native bytes should survive ProtoJSON base64 expansion");
    let value = batch.records()[0].attributes()[0]
        .occurrence(0)
        .expect("bytes attribute");
    assert_eq!(value.as_bytes().map(|bytes| bytes.len()), Some(65_536));

    let over = ExportTraceServiceRequest {
        resource_spans: vec![opentelemetry_proto::tonic::trace::v1::ResourceSpans {
            scope_spans: vec![opentelemetry_proto::tonic::trace::v1::ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "bytes-over-boundary".to_owned(),
                    attributes: vec![KeyValue {
                        key: "bytes".to_owned(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::BytesValue(vec![0x5a; 65_537])),
                        }),
                        ..KeyValue::default()
                    }],
                    ..Span::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    assert!(matches!(
        OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::test_only_json(
            test_attribution(),
            serde_json::to_vec(&over).expect("ProtoJSON payload"),
        )),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    ));
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn all_values() -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::ArrayValue(ArrayValue {
            values: vec![
                AnyValue {
                    value: Some(any_value::Value::BoolValue(true)),
                },
                AnyValue {
                    value: Some(any_value::Value::IntValue(-7)),
                },
                AnyValue {
                    value: Some(any_value::Value::DoubleValue(3.5)),
                },
                AnyValue {
                    value: Some(any_value::Value::BytesValue(vec![0, 255])),
                },
                AnyValue {
                    value: Some(any_value::Value::StringValue("text".to_owned())),
                },
                AnyValue {
                    value: Some(any_value::Value::KvlistValue(KeyValueList {
                        values: vec![KeyValue {
                            key: "nested".to_owned(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::BoolValue(false)),
                            }),
                            ..Default::default()
                        }],
                    })),
                },
            ],
        })),
    }
}

fn test_attribution() -> positron_domain::identity::TenantAttribution {
    positron_domain::identity::TenantAttribution::new(
        positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
        positron_domain::identity::Scope::Ingest,
        positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}
