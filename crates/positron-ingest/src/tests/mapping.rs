use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, KeyValue, KeyValueList, any_value,
};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, CandidateKeyValue};
use prost::Message;

use crate::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, ReceiveFailure};

use super::support::{attribution, protobuf_request};

#[test]
fn attributed_otlp_maps_to_checked_native_log_namespaces() {
    let batch = OtlpLogsReceiver::new()
        .decode(protobuf_request())
        .expect("valid OTLP");

    assert_eq!(batch.records().len(), 1);
    let record = batch.records().first().expect("record");
    assert!(matches!(
        record.body(),
        Some(CandidateAttributeValue::String(body)) if body == "paid"
    ));
    assert_eq!(record.event_time_unix_nanos(), Some(42));
    assert!(record.attributes().iter().any(|attribute| {
        attribute.namespace() == AttributeNamespace::Resource && attribute.key() == "service.name"
    }));
    assert!(record.attributes().iter().any(|attribute| {
        attribute.namespace() == AttributeNamespace::Record && attribute.key() == "order.id"
    }));
}

#[test]
fn every_otlp_log_value_variant_remains_native_and_duplicate_occurrences_remain_ordered() {
    let body = any(any_value::Value::ArrayValue(ArrayValue {
        values: vec![
            any(any_value::Value::BoolValue(true)),
            any(any_value::Value::IntValue(-7)),
            any(any_value::Value::DoubleValue(3.5)),
            any(any_value::Value::BytesValue(vec![0, 0xff])),
            any(any_value::Value::KvlistValue(KeyValueList {
                values: vec![
                    KeyValue {
                        key: "present".to_owned(),
                        value: Some(any(any_value::Value::StringValue("value".to_owned()))),
                        ..KeyValue::default()
                    },
                    KeyValue {
                        key: "missing".to_owned(),
                        value: None,
                        ..KeyValue::default()
                    },
                ],
            })),
            AnyValue { value: None },
        ],
    }));
    let request = proto_request(LogRecord {
        body: Some(body),
        observed_time_unix_nano: 99,
        attributes: vec![
            KeyValue {
                key: "duplicate".to_owned(),
                value: Some(any(any_value::Value::BoolValue(false))),
                ..KeyValue::default()
            },
            KeyValue {
                key: "duplicate".to_owned(),
                value: Some(any(any_value::Value::IntValue(8))),
                ..KeyValue::default()
            },
            KeyValue {
                key: "missing".to_owned(),
                value: None,
                ..KeyValue::default()
            },
        ],
        ..LogRecord::default()
    });

    let batch = OtlpLogsReceiver::new().decode(request).expect("valid OTLP");
    let record = batch.records().first().expect("record");
    assert_eq!(
        record.body(),
        Some(&CandidateAttributeValue::array(vec![
            CandidateAttributeValue::boolean(true),
            CandidateAttributeValue::signed_integer(-7),
            CandidateAttributeValue::floating_point_bits(3.5_f64.to_bits()),
            CandidateAttributeValue::bytes(vec![0, 0xff]),
            CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new(
                    "present".to_owned(),
                    CandidateAttributeValue::string("value".to_owned()),
                ),
                CandidateKeyValue::new("missing".to_owned(), CandidateAttributeValue::null()),
            ]),
            CandidateAttributeValue::null(),
        ]))
    );
    let duplicate = record
        .attributes()
        .iter()
        .find(|attribute| attribute.key() == "duplicate")
        .expect("duplicate occurrence set");
    assert_eq!(
        duplicate.occurrences(),
        &[
            CandidateAttributeValue::boolean(false),
            CandidateAttributeValue::signed_integer(8),
        ]
    );
    let missing = record
        .attributes()
        .iter()
        .find(|attribute| attribute.key() == "missing")
        .expect("missing-valued attribute");
    assert_eq!(missing.occurrences(), &[CandidateAttributeValue::null()]);
}

#[test]
fn profile_string_table_references_are_rejected_from_logs() {
    let request = proto_request(LogRecord {
        body: Some(any(any_value::Value::StringValueStrindex(4))),
        ..LogRecord::default()
    });

    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(request)
            .expect_err("profile-only value cannot be represented as a Log"),
        ReceiveFailure::UnsupportedValue,
    );
}

#[test]
fn timestamps_preserve_zero_and_i64_max_but_reject_larger_u64_values() {
    let boundary = proto_request(LogRecord {
        time_unix_nano: 0,
        observed_time_unix_nano: i64::MAX as u64,
        ..LogRecord::default()
    });
    let batch = OtlpLogsReceiver::new()
        .decode(boundary)
        .expect("typed timestamp boundaries");
    let record = batch.records().first().expect("record");
    assert_eq!(record.event_time_unix_nanos(), Some(0));
    assert_eq!(record.observed_time_unix_nanos(), Some(i64::MAX));

    for record in [
        LogRecord {
            time_unix_nano: i64::MAX as u64 + 1,
            ..LogRecord::default()
        },
        LogRecord {
            observed_time_unix_nano: i64::MAX as u64 + 1,
            ..LogRecord::default()
        },
    ] {
        assert_eq!(
            OtlpLogsReceiver::new()
                .decode(proto_request(record))
                .expect_err("out-of-range timestamp"),
            ReceiveFailure::TimestampOutOfRange,
        );
    }
}

fn proto_request(record: LogRecord) -> AuthenticatedOtlpLogsRequest<'static> {
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![record],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };
    AuthenticatedOtlpLogsRequest::test_only_protobuf(attribution(), request.encode_to_vec())
}

fn any(value: any_value::Value) -> AnyValue {
    AnyValue { value: Some(value) }
}
