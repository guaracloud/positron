use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId};

use crate::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, ReceiveFailure};

#[test]
fn authenticated_request_rejects_malformed_protobuf_permanently() {
    let attribution = TenantAttribution::new(
        PrincipalId::from_bytes([1; 16]).expect("principal"),
        Scope::Ingest,
        TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("ingest attribution");
    let request = AuthenticatedOtlpLogsRequest::new(attribution, vec![0xff]);

    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(request)
            .expect_err("malformed protobuf must fail"),
        ReceiveFailure::MalformedPayload,
    );
}
