use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId};
use prost::Message;
use std::io::Write;

use super::super::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, ReceiveFailure};

#[test]
fn canonical_json_and_protobuf_map_to_identical_native_candidates() {
    let attribution = TenantAttribution::new(
        PrincipalId::from_bytes([1; 16]).expect("principal"),
        Scope::Ingest,
        TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution");
    let request = semantic_request();
    let protobuf = OtlpLogsReceiver::new()
        .decode(AuthenticatedOtlpLogsRequest::test_only_protobuf(
            attribution,
            request.encode_to_vec(),
        ))
        .expect("protobuf decode");
    let json = OtlpLogsReceiver::new()
        .decode(AuthenticatedOtlpLogsRequest::test_only_json(
            attribution,
            serde_json::to_vec(&request).expect("canonical JSON"),
        ))
        .expect("JSON decode");

    assert_eq!(json.attribution(), protobuf.attribution());
    assert_eq!(json.records(), protobuf.records());
    assert_eq!(json.value_limit_profile(), protobuf.value_limit_profile());
}

#[test]
fn gzip_json_decodes_and_plain_json_obeys_the_transport_bound() {
    let attribution = attribution();
    let json = serde_json::to_vec(&semantic_request()).expect("canonical JSON");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&json).expect("gzip write");
    let gzip = encoder.finish().expect("gzip finish");

    let decoded = OtlpLogsReceiver::new()
        .decode(AuthenticatedOtlpLogsRequest::test_only_gzip_json(
            attribution,
            gzip,
        ))
        .expect("gzip JSON decode");
    assert_eq!(decoded.records().len(), 1);

    let oversized =
        AuthenticatedOtlpLogsRequest::test_only_json(attribution, vec![b' '; 1_048_577]);
    assert!(matches!(
        OtlpLogsReceiver::new().decode(oversized),
        Err(ReceiveFailure::TransportLimitExceeded)
    ));

    let oversized_gzip =
        AuthenticatedOtlpLogsRequest::test_only_gzip_json(attribution, vec![0; 1_048_577]);
    assert!(matches!(
        OtlpLogsReceiver::new().decode(oversized_gzip),
        Err(ReceiveFailure::TransportLimitExceeded)
    ));
}

fn attribution() -> TenantAttribution {
    TenantAttribution::new(
        PrincipalId::from_bytes([1; 16]).expect("principal"),
        Scope::Ingest,
        TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

fn semantic_request() -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![key_value("service.name", string("semantic-service"))],
                dropped_attributes_count: 2,
                entity_refs: Vec::new(),
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "semantic-scope".to_owned(),
                    version: "1.2.3".to_owned(),
                    attributes: vec![key_value("scope.enabled", boolean(true))],
                    dropped_attributes_count: 3,
                }),
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    observed_time_unix_nano: 84,
                    severity_number: 13,
                    severity_text: "WARN".to_owned(),
                    body: Some(AnyValue {
                        value: Some(any_value::Value::KvlistValue(
                            opentelemetry_proto::tonic::common::v1::KeyValueList {
                                values: vec![key_value("nested", integer(7))],
                            },
                        )),
                    }),
                    attributes: vec![key_value(
                        "array",
                        AnyValue {
                            value: Some(any_value::Value::ArrayValue(
                                opentelemetry_proto::tonic::common::v1::ArrayValue {
                                    values: vec![string("one"), boolean(false)],
                                },
                            )),
                        },
                    )],
                    dropped_attributes_count: 4,
                    flags: 1,
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    event_name: "semantic-event".to_owned(),
                }],
                schema_url: "https://example.test/scope".to_owned(),
            }],
            schema_url: "https://example.test/resource".to_owned(),
        }],
    }
}

fn key_value(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(value),
        key_strindex: 0,
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
