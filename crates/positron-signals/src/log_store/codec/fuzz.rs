use positron_domain::identity::TenantId;

use crate::log_store::LogStoreFailure;

pub(in crate::log_store) fn fuzz_decode_block(
    expected_tenant: TenantId,
    bytes: &[u8],
) -> Result<(), LogStoreFailure> {
    let cancellation = super::super::scan::NeverCancelled;
    let observer = super::super::scan::Unobserved;
    super::BlockDecode::observed(expected_tenant, bytes, &cancellation, &observer)?
        .validate(&cancellation)
}
