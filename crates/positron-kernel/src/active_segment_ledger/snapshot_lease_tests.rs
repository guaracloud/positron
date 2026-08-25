use super::{LedgerFailureCode, map_catalog_failure};
use crate::CatalogFailureCode;

#[test]
fn catalog_failure_mapping_preserves_typed_lease_failures() {
    let cases = [
        (
            CatalogFailureCode::InvalidInput,
            LedgerFailureCode::InvalidInput,
        ),
        (
            CatalogFailureCode::LimitExceeded,
            LedgerFailureCode::LimitExceeded,
        ),
        (
            CatalogFailureCode::StaleGeneration,
            LedgerFailureCode::StaleGeneration,
        ),
        (
            CatalogFailureCode::IdempotencyConflict,
            LedgerFailureCode::IdempotencyConflict,
        ),
        (
            CatalogFailureCode::StorageUnavailable,
            LedgerFailureCode::StorageUnavailable,
        ),
        (
            CatalogFailureCode::IntegrityCorruption,
            LedgerFailureCode::IntegrityCorruption,
        ),
        (
            CatalogFailureCode::AuthenticationFailed,
            LedgerFailureCode::AuthenticationFailed,
        ),
        (
            CatalogFailureCode::ConcurrentWriter,
            LedgerFailureCode::ConcurrentWriter,
        ),
        (
            CatalogFailureCode::ResourceAdmissionRefused,
            LedgerFailureCode::ResourceAdmissionRefused,
        ),
        (
            CatalogFailureCode::UnsupportedFormat,
            LedgerFailureCode::UnsupportedFormat,
        ),
    ];

    for (catalog, expected) in cases {
        assert_eq!(map_catalog_failure(catalog), expected);
    }
}
