use positron_kernel::CatalogFailureCode;

use super::{ServiceFailure, classify_catalog_failure_code};

#[test]
fn every_catalog_failure_keeps_its_quiescent_maintenance_class() {
    let cases = [
        (
            CatalogFailureCode::ResourceAdmissionRefused,
            ServiceFailure::CapacityUnavailable,
        ),
        (
            CatalogFailureCode::LimitExceeded,
            ServiceFailure::CapacityUnavailable,
        ),
        (
            CatalogFailureCode::StorageUnavailable,
            ServiceFailure::StorageUnavailable,
        ),
        (
            CatalogFailureCode::IntegrityCorruption,
            ServiceFailure::CorruptState,
        ),
        (
            CatalogFailureCode::AuthenticationFailed,
            ServiceFailure::CorruptState,
        ),
        (
            CatalogFailureCode::UnsupportedFormat,
            ServiceFailure::CorruptState,
        ),
        (
            CatalogFailureCode::InvalidInput,
            ServiceFailure::CorruptState,
        ),
        (
            CatalogFailureCode::StaleGeneration,
            ServiceFailure::CatalogUnavailable,
        ),
        (
            CatalogFailureCode::ConcurrentWriter,
            ServiceFailure::CatalogUnavailable,
        ),
        (
            CatalogFailureCode::IdempotencyConflict,
            ServiceFailure::CatalogUnavailable,
        ),
    ];

    for (code, expected) in cases {
        assert_eq!(classify_catalog_failure_code(code), expected);
    }
}
