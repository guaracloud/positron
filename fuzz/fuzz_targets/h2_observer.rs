#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = positron_runtime::fuzz_h2_observer(data); });
