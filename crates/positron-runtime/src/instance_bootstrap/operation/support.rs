use positron_kernel::{BootstrapKeyIdentity, OwnedPrimaryDataVolume, PrimaryDataVolume};

use super::super::codec::BootstrapRecord;
use super::super::{BootstrapFailure, BootstrapFailureCode, BootstrapPaths};

pub(super) fn acquire(paths: &BootstrapPaths) -> Result<OwnedPrimaryDataVolume, BootstrapFailure> {
    PrimaryDataVolume::acquire(&paths.data, paths.qualification)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::StorageUnavailable))
}

pub(crate) fn require_key_identity(
    record: &BootstrapRecord,
    actual: BootstrapKeyIdentity,
) -> Result<(), BootstrapFailure> {
    if record.key == actual {
        Ok(())
    } else {
        Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ))
    }
}

pub(crate) fn format_secret(secret: &[u8; 32]) -> String {
    let mut result = String::with_capacity(68);
    result.push_str("pos_");
    for byte in secret {
        result.push(hex_digit(byte >> 4));
        result.push(hex_digit(byte & 0x0f));
    }
    result
}

const fn hex_digit(value: u8) -> char {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    if value < 16 {
        DIGITS[value as usize] as char
    } else {
        '?'
    }
}

pub(crate) fn inconsistent() -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::InconsistentRoots)
}

pub(crate) fn entropy_failure() -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::EntropyUnavailable)
}

pub(crate) fn key_failure(failure: positron_kernel::BootstrapKeyFailure) -> BootstrapFailure {
    let code = match failure {
        positron_kernel::BootstrapKeyFailure::Custody => {
            BootstrapFailureCode::KeyCustodyUnavailable
        },
        positron_kernel::BootstrapKeyFailure::Entropy => BootstrapFailureCode::EntropyUnavailable,
        positron_kernel::BootstrapKeyFailure::Authentication
        | positron_kernel::BootstrapKeyFailure::InvalidInput
        | positron_kernel::BootstrapKeyFailure::LimitExceeded => BootstrapFailureCode::CorruptState,
    };
    BootstrapFailure::new(code)
}

pub(super) fn catalog_failure(_failure: positron_kernel::CatalogFailure) -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable)
}
