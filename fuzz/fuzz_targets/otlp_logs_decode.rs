#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId};
use positron_ingest::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver};

fuzz_target!(|data: &[u8]| {
    let attribution = TenantAttribution::new(
        PrincipalId::from_bytes([1; 16]).expect("fixed principal"),
        Scope::Ingest,
        TenantId::from_bytes([2; 16]).expect("fixed tenant"),
    )
    .expect("fixed attribution");
    let payload = data.get(1..).unwrap_or_default().to_vec();
    let request = match data.first().map_or(0, |byte| byte & 0b11) {
        0 => AuthenticatedOtlpLogsRequest::test_only_protobuf(attribution, payload),
        1 => AuthenticatedOtlpLogsRequest::test_only_gzip(attribution, payload),
        2 => AuthenticatedOtlpLogsRequest::test_only_json(attribution, payload),
        _ => AuthenticatedOtlpLogsRequest::test_only_gzip_json(
            attribution,
            payload,
        ),
    };
    let _ = OtlpLogsReceiver::new().decode(request);
});
