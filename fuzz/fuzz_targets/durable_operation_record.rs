#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_governance::fuzz_durable_operation_record;

fuzz_target!(|data: &[u8]| {
    fuzz_durable_operation_record(data);
});
