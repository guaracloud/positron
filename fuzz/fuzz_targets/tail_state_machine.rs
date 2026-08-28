#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    positron_runtime::fuzz_tail_state_machine(data);
});
