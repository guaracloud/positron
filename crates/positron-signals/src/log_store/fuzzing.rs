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
