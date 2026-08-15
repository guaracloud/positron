#![no_main]

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;

#[path = "schema_discovery_query/authority.rs"]
mod authority;
#[path = "schema_discovery_query/fixture.rs"]
mod fixture;

const MAX_INPUT_BYTES: usize = 4_096;

thread_local! {
    static FIXTURE: RefCell<Option<fixture::FuzzFixture>> =
        RefCell::new(fixture::FuzzFixture::establish());
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }
    FIXTURE.with(|fixture| {
        if let Some(fixture) = fixture.borrow().as_ref() {
            fixture.exercise(data);
        }
    });
});
