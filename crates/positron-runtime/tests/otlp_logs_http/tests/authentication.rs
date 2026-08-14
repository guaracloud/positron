use super::support::{HttpEncoding, LiveHttpHarness, otlp_request};
use prost::Message;

#[test]
fn tenant_attribution_precedes_body_bounds_decompression_and_decode()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("http-auth-order")?;

    let unauthorized =
        harness.export_unauthorized(HttpEncoding::Json, Some("gzip"), &[0xff, 0xff])?;
    assert_eq!(unauthorized.status(), 401);

    let conflicting = harness.export_with_tenant_hint(
        HttpEncoding::Protobuf,
        "other-tenant",
        &vec![0_u8; 1_048_577],
    )?;
    assert_eq!(conflicting.status(), 401);

    let invalid_hint = harness.export_with_tenant_hint(
        HttpEncoding::Protobuf,
        "bad alias",
        &otlp_request("invalid-hint").encode_to_vec(),
    )?;
    assert_eq!(invalid_hint.status(), 401);

    let retry = harness.export(HttpEncoding::Protobuf, otlp_request("after-auth-failure"))?;
    assert_eq!(retry.status(), 200);
    Ok(())
}
