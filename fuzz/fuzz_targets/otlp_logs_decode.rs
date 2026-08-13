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
    let request = if data.first().is_some_and(|byte| byte & 1 == 1) {
        AuthenticatedOtlpLogsRequest::test_only_gzip(
            attribution,
            data.get(1..).unwrap_or_default().to_vec(),
        )
    } else {
        AuthenticatedOtlpLogsRequest::test_only_protobuf(
            attribution,
            data.get(1..).unwrap_or_default().to_vec(),
        )
    };
    let _ = OtlpLogsReceiver::new().decode(request);
});
