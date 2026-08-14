use positron_domain::identity::TenantId;

use super::limits::CodecLimits;
use super::{Input, MAGIC, VERSION, decode_record};
use crate::log_store::LogStoreFailure;

pub(in crate::log_store) fn fuzz_decode_block(
    expected_tenant: TenantId,
    bytes: &[u8],
) -> Result<(), LogStoreFailure> {
    let mut input = Input::new(bytes);
    if input.take(MAGIC.len())? != MAGIC || input.u16()? != VERSION {
        return Err(LogStoreFailure::malformed_block());
    }
    let tenant: [u8; 16] = input
        .take(16)?
        .try_into()
        .map_err(|_| LogStoreFailure::malformed_block())?;
    if tenant != expected_tenant.to_bytes() {
        return Err(LogStoreFailure::physical_scope_mismatch());
    }
    let limits = CodecLimits::release_1()?;
    let count = input.count(limits.records)?;
    if count == 0 {
        return Err(LogStoreFailure::malformed_block());
    }
    for _ in 0..count {
        let _ = decode_record(&mut input, limits)?;
    }
    if !input.is_empty() {
        return Err(LogStoreFailure::malformed_block());
    }
    Ok(())
}
