use positron_domain::identity::TenantId;

use super::codec;

const MAX_STORE_BLOCK_BYTES: usize = 1_048_576;

/// Exercises the bounded canonical Log Store Block decoder with untrusted bytes.
#[doc(hidden)]
pub fn fuzz_log_store_block(data: &[u8]) {
    let bounded_end = data.len().min(MAX_STORE_BLOCK_BYTES.saturating_add(1));
    let bounded = data.get(..bounded_end).unwrap_or_default();
    let tenant = TenantId::from_bytes([0x41; 16]);
    if let Ok(tenant) = tenant {
        let _ = codec::fuzz_decode_block(tenant, bounded);
    }
}

/// Exercises block-aware Log retention over real kernel-authenticated evidence.
#[doc(hidden)]
pub fn fuzz_log_retention_block(
    ledger: &positron_kernel::ActiveSegmentLedger<'_, '_>,
    tenant: TenantId,
) {
    let Ok(snapshot) = ledger.current_catalog_snapshot() else {
        return;
    };
    let Ok(policy) = super::LogRetentionPolicy::from_catalog(&snapshot) else {
        return;
    };
    let _ = super::LogStore::new().enforce_retention(ledger, tenant, policy);
}
