#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    positron_runtime::fuzz_process_inputs(data);
});
