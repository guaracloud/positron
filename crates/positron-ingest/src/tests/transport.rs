use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, ArrayValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use prost::Message;

use crate::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, ReceiveFailure};

use super::support::{attribution, protobuf_bytes};

#[test]
fn bounded_gzip_protobuf_decodes_after_attribution() {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(&protobuf_bytes(&["compressed"]))
        .expect("gzip write");
    let request =
        AuthenticatedOtlpLogsRequest::gzip(attribution(), encoder.finish().expect("gzip finish"));
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
    let malformed = AuthenticatedOtlpLogsRequest::gzip(attribution(), vec![1, 2, 3]);
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
    let expansion =
        AuthenticatedOtlpLogsRequest::gzip(attribution(), encoder.finish().expect("gzip finish"));
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(expansion)
            .expect_err("decompressed bound"),
        ReceiveFailure::TransportLimitExceeded
    );
}

#[test]
fn protobuf_bytes_are_bounded_before_decode() {
    let request = AuthenticatedOtlpLogsRequest::new(attribution(), vec![0; 1_048_577]);
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(request)
            .expect_err("transport bound"),
        ReceiveFailure::TransportLimitExceeded
    );
}

#[test]
fn compressed_bytes_records_and_native_value_depth_have_independent_bounds() {
    let oversized_compressed =
        AuthenticatedOtlpLogsRequest::gzip(attribution(), vec![0; 1_048_577]);
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
    for _ in 0..18 {
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

fn proto_request(records: Vec<LogRecord>) -> AuthenticatedOtlpLogsRequest {
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: records,
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };
    AuthenticatedOtlpLogsRequest::new(attribution(), request.encode_to_vec())
}
