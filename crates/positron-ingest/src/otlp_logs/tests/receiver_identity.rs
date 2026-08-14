use std::io::Write;

use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId};

use super::super::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, OtlpPayload};
use crate::PolicyReceiver;

#[test]
fn every_otlp_route_and_encoding_keeps_exact_identity_through_compression() {
    let protobuf = Vec::new();
    let json = br#"{"resourceLogs":[]}"#.to_vec();
    for (payload, receiver) in [
        (
            OtlpPayload::Decoded(Box::default()),
            PolicyReceiver::OtlpGrpc,
        ),
        (
            OtlpPayload::Protobuf(protobuf.clone()),
            PolicyReceiver::OtlpHttpProtobuf,
        ),
        (
            OtlpPayload::Json(json.clone()),
            PolicyReceiver::OtlpHttpJson,
        ),
        (
            OtlpPayload::Protobuf(protobuf.clone()),
            PolicyReceiver::LokiOtlpProtobuf,
        ),
        (
            OtlpPayload::Json(json.clone()),
            PolicyReceiver::LokiOtlpJson,
        ),
        (
            OtlpPayload::GzipProtobuf(gzip(&protobuf)),
            PolicyReceiver::OtlpHttpProtobuf,
        ),
        (
            OtlpPayload::GzipJson(gzip(&json)),
            PolicyReceiver::OtlpHttpJson,
        ),
    ] {
        let request =
            AuthenticatedOtlpLogsRequest::test_only_with_receiver(attribution(), payload, receiver);
        let batch = OtlpLogsReceiver::new()
            .decode(request)
            .expect("route decode");
        assert_eq!(batch.receiver(), receiver);
    }
}

fn attribution() -> TenantAttribution {
    TenantAttribution::new(
        PrincipalId::from_bytes([1; 16]).expect("principal"),
        Scope::Ingest,
        TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).expect("gzip input");
    encoder.finish().expect("gzip output")
}
