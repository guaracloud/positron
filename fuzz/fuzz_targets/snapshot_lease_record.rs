#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    positron_kernel::fuzz_snapshot_lease_record(data);
});
