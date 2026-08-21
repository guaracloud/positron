use positron_domain::identity::TenantId;

use crate::log_store::LogStoreFailure;

pub(in crate::log_store) fn fuzz_decode_block(
    expected_tenant: TenantId,
    bytes: &[u8],
) -> Result<(), LogStoreFailure> {
    super::preflight_block_record_count(expected_tenant, bytes)?;
    super::validate_block(
        expected_tenant,
        bytes,
        &super::super::scan::NeverCancelled,
        &super::super::scan::Unobserved,
    )
}
