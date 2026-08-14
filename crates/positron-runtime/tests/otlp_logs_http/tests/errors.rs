use prost::Message;

use super::support::{HttpEncoding, HttpResponse, LiveHttpHarness};

#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
}

#[test]
fn malformed_and_unsupported_requests_have_stable_otlp_status_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("http-errors")?;

    let malformed_protobuf = harness.export_body(HttpEncoding::Protobuf, None, &[0xff, 0xff])?;
    assert_rpc_status(
        malformed_protobuf,
        HttpEncoding::Protobuf,
        400,
        3,
        "OTLP Logs request was rejected",
    )?;

    let malformed_json = harness.export_body(HttpEncoding::Json, None, b"{not-json}")?;
    assert_rpc_status(
        malformed_json,
        HttpEncoding::Json,
        400,
        3,
        "OTLP Logs request was rejected",
    )?;

    let unsupported_type =
        harness.request_authenticated(&[("Content-Type", "text/plain".to_owned())], b"")?;
    assert_rpc_status(
        unsupported_type,
        HttpEncoding::Json,
        415,
        3,
        "OTLP Logs Content-Type is unsupported",
    )?;

    let unsupported_compression = harness.request_authenticated(
        &[
            ("Content-Type", "application/x-protobuf".to_owned()),
            ("Content-Encoding", "br".to_owned()),
        ],
        b"",
    )?;
    assert_rpc_status(
        unsupported_compression,
        HttpEncoding::Protobuf,
        415,
        3,
        "OTLP Logs Content-Encoding is unsupported",
    )?;

    for (name, value) in [
        ("Content-Type", "application/json"),
        ("Content-Encoding", "identity"),
        ("X-Scope-OrgID", "tenant"),
    ] {
        let duplicate = harness
            .request_authenticated(&[(name, value.to_owned()), (name, value.to_owned())], b"")?;
        assert_eq!(duplicate.status(), 400, "duplicate {name} was accepted");
    }
    Ok(())
}

fn assert_rpc_status(
    response: HttpResponse,
    encoding: HttpEncoding,
    http_status: u16,
    rpc_code: i32,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), http_status);
    assert_eq!(
        response.header("content-type"),
        Some(encoding.content_type())
    );
    assert!(
        !response.body().is_empty(),
        "OTLP error body was empty for HTTP {http_status}"
    );
    match encoding {
        HttpEncoding::Protobuf => {
            let status = RpcStatus::decode(response.body())?;
            assert_eq!((status.code, status.message.as_str()), (rpc_code, message));
        },
        HttpEncoding::Json => {
            let status: serde_json::Value = serde_json::from_slice(response.body())?;
            assert_eq!(status["code"], rpc_code);
            assert_eq!(status["message"], message);
            assert_eq!(status["details"], serde_json::json!([]));
        },
    }
    Ok(())
}
