use positron_kernel::{ResourceDimension, StoreBlockIdentity};
use positron_signals::SchemaBudget;

use super::super::peak_resources;

#[test]
fn replay_peak_holds_reachable_indexes_and_checkpoint_encoding_atomically() {
    let source_bytes = 1_048_576_u64;
    let working = SchemaBudget::replay_working_memory_bytes(1_048_576).expect("working bound");
    let reachable = SchemaBudget::system_max_entries()
        .checked_mul(std::mem::size_of::<(StoreBlockIdentity, [u8; 32])>())
        .expect("reachable bound");
    let serialized = SchemaBudget::release_1()
        .expect("budget")
        .max_persistent_bytes();
    let expected = u64::try_from(
        working
            .checked_add(reachable)
            .and_then(|bytes| bytes.checked_add(serialized))
            .expect("peak"),
    )
    .expect("u64 peak")
    .checked_add(source_bytes)
    .expect("source peak");

    assert_eq!(
        peak_resources(source_bytes)
            .expect("resources")
            .get(ResourceDimension::MemoryBytes),
        expected
    );
}
