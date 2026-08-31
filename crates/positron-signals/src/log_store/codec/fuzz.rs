use positron_domain::identity::TenantId;

use crate::log_store::LogStoreFailure;

pub(in crate::log_store) fn fuzz_decode_block(
    expected_tenant: TenantId,
    bytes: &[u8],
) -> Result<(), LogStoreFailure> {
    let cancellation = super::super::scan::NeverCancelled;
    let observer = super::super::scan::Unobserved;
    let mut decoder =
        super::BlockDecode::observed(expected_tenant, bytes, &cancellation, &observer)?;
    let version = decoder.version;
    let limits = decoder.limits;
    for _ in 0..decoder.record_count() {
        super::record::validate_structure(&mut decoder.input, limits, version)?;
    }
    decoder.input.finish_component_observation()?;
    if decoder.input.is_empty() {
        Ok(())
    } else {
        Err(LogStoreFailure::malformed_block())
    }
}
