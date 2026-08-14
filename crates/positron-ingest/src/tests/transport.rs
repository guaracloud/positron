use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, ArrayValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::value::{
    ByteLimit, RecordLimits, RequestLimits, ValueLimitProfile, ValueLimitProfileCandidate,
    ValueLimitSet,
};
use prost::Message;

use crate::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, ReceiveFailure};

use super::support::{attribution, protobuf_bytes};

#[test]
fn bounded_gzip_protobuf_decodes_after_attribution() {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(&protobuf_bytes(&["compressed"]))
        .expect("gzip write");
    let request = AuthenticatedOtlpLogsRequest::test_only_gzip(
        attribution(),
        encoder.finish().expect("gzip finish"),
    );
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(request)
            .expect("valid gzip")
            .records()
            .len(),
        1
    );
}

#[test]
fn malformed_and_expanding_gzip_are_permanent_transport_failures() {
    let malformed = AuthenticatedOtlpLogsRequest::test_only_gzip(attribution(), vec![1, 2, 3]);
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(malformed)
            .expect_err("malformed gzip"),
        ReceiveFailure::MalformedCompression
    );

    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(&vec![0_u8; 1_048_577])
        .expect("expansion source");
    let expansion = AuthenticatedOtlpLogsRequest::test_only_gzip(
        attribution(),
        encoder.finish().expect("gzip finish"),
    );
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(expansion)
            .expect_err("decompressed bound"),
        ReceiveFailure::TransportLimitExceeded
    );
}

#[test]
fn protobuf_bytes_are_bounded_before_decode() {
    let request =
        AuthenticatedOtlpLogsRequest::test_only_protobuf(attribution(), vec![0; 1_048_577]);
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(request)
            .expect_err("transport bound"),
        ReceiveFailure::TransportLimitExceeded
    );
}

#[test]
fn tenant_lowered_transport_limit_is_applied_from_the_request_profile() {
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let tenant_request = RequestLimits::new(
        ByteLimit::new(1).expect("fixture limit is nonzero"),
        maximum.request().decompressed_bytes(),
        maximum.request().records(),
        maximum.request().aggregate_attributes(),
    );
    let tenant = ValueLimitSet::new(tenant_request, maximum.record(), maximum.dynamic_value());
    let profile = ValueLimitProfileCandidate::new(maximum, Some(tenant))
        .validate()
        .expect("tenant profile only lowers the compressed-byte limit");
    let request = AuthenticatedOtlpLogsRequest::test_only_protobuf(
        attribution(),
        protobuf_bytes(&["profile-bound"]),
    );

    assert_eq!(
        OtlpLogsReceiver::with_value_limit_profile(profile)
            .decode(request)
            .expect_err("the effective compressed-byte limit applies before decode"),
        ReceiveFailure::TransportLimitExceeded
    );
}

#[test]
fn tenant_encoded_record_limit_accepts_exact_and_rejects_one_byte_over() {
    let exact_record = LogRecord {
        body: Some(AnyValue {
            value: Some(any_value::Value::StringValue("1234".to_owned())),
        }),
        ..LogRecord::default()
    };
    let over_record = LogRecord {
        body: Some(AnyValue {
            value: Some(any_value::Value::StringValue("12345".to_owned())),
        }),
        ..LogRecord::default()
    };
    let encoded_limit = exact_record.encoded_len();
    assert_eq!(over_record.encoded_len(), encoded_limit + 1);
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let tenant_record = RecordLimits::new(
        ByteLimit::new(u32::try_from(encoded_limit).expect("fixture size fits u32"))
            .expect("fixture limit is nonzero"),
        maximum.record().decoded_bytes(),
        maximum.record().log_body_bytes(),
    );
    let profile = ValueLimitProfileCandidate::new(
        maximum,
        Some(ValueLimitSet::new(
            maximum.request(),
            tenant_record,
            maximum.dynamic_value(),
        )),
    )
    .validate()
    .expect("tenant profile only lowers encoded-record bytes");
    let receiver = OtlpLogsReceiver::with_value_limit_profile(profile);

    assert_eq!(
        receiver
            .decode(proto_request(vec![exact_record]))
            .expect("exact encoded-record boundary")
            .records()
            .len(),
        1
    );
    assert_eq!(
        receiver
            .decode(proto_request(vec![over_record]))
            .expect_err("one byte over the effective encoded-record boundary"),
        ReceiveFailure::ValueLimitExceeded
    );
}

#[test]
fn compressed_bytes_records_and_native_value_depth_have_independent_bounds() {
    let oversized_compressed =
        AuthenticatedOtlpLogsRequest::test_only_gzip(attribution(), vec![0; 1_048_577]);
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(oversized_compressed)
            .expect_err("compressed byte bound"),
        ReceiveFailure::TransportLimitExceeded
    );

    let too_many_records = proto_request(vec![LogRecord::default(); 1_025]);
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(too_many_records)
            .expect_err("record count bound"),
        ReceiveFailure::ValueLimitExceeded
    );

    let mut nested = AnyValue { value: None };
    for _ in 0..129 {
        nested = AnyValue {
            value: Some(any_value::Value::ArrayValue(ArrayValue {
                values: vec![nested],
            })),
        };
    }
    let too_deep = proto_request(vec![LogRecord {
        body: Some(nested),
        ..LogRecord::default()
    }]);
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(too_deep)
            .expect_err("native value depth bound"),
        ReceiveFailure::ValueLimitExceeded
    );
}

#[test]
fn decoded_record_bytes_accept_the_exact_limit_and_reject_one_byte_more() {
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let record = RecordLimits::new(
        maximum.record().encoded_bytes(),
        ByteLimit::new(524_288).expect("fixture decoded limit is nonzero"),
        maximum.record().log_body_bytes(),
    );
    let profile = ValueLimitProfileCandidate::new(
        ValueLimitSet::new(maximum.request(), record, maximum.dynamic_value()),
        None,
    )
    .validate()
    .expect("configured system profile lowers decoded-record bytes");
    let exact = proto_request(vec![LogRecord {
        body: Some(AnyValue {
            value: Some(any_value::Value::BytesValue(vec![0; 524_288])),
        }),
        ..LogRecord::default()
    }]);
    assert_eq!(
        OtlpLogsReceiver::with_value_limit_profile(profile)
            .decode(exact)
            .expect("inclusive decoded-record boundary")
            .records()
            .len(),
        1
    );

    let over = proto_request(vec![LogRecord {
        body: Some(AnyValue {
            value: Some(any_value::Value::BytesValue(vec![0; 524_289])),
        }),
        ..LogRecord::default()
    }]);
    assert_eq!(
        OtlpLogsReceiver::with_value_limit_profile(profile)
            .decode(over)
            .expect_err("exclusive decoded-record boundary"),
        ReceiveFailure::ValueLimitExceeded
    );
}

fn proto_request(records: Vec<LogRecord>) -> AuthenticatedOtlpLogsRequest<'static> {
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: records,
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };
    AuthenticatedOtlpLogsRequest::test_only_protobuf(attribution(), request.encode_to_vec())
}
