#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 4_096 {
        positron_kernel::fuzz_retention_time_stateful(data);
    }
});
