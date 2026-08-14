#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_ingest::{preflight_otlp_logs_json, preflight_otlp_logs_protobuf};

fuzz_target!(|data: &[u8]| {
    let payload = data.get(1..).unwrap_or_default();
    if data.first().is_some_and(|byte| byte & 1 == 0) {
        let _ = preflight_otlp_logs_protobuf(payload);
    } else {
        let _ = preflight_otlp_logs_json(payload);
    }
});
