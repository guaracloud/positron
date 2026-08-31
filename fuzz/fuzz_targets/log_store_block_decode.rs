#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    positron_signals::fuzz_log_store_block(data);
    positron_kernel::fuzz_retention_prepared_block(
        data,
        positron_signals::fuzz_log_retention_block,
    );
});
