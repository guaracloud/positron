#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_kernel::fuzz_catalog_stateful;

fuzz_target!(|data: &[u8]| {
    fuzz_catalog_stateful(data);
});
