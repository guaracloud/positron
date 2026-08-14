use positron_kernel::CatalogFailureCode;

use super::super::SchemaCatalogLoadFailure;

#[test]
fn catalog_failure_codes_remain_typed_at_the_ingest_boundary() {
    for code in [
        CatalogFailureCode::StaleGeneration,
        CatalogFailureCode::IdempotencyConflict,
        CatalogFailureCode::ResourceAdmissionRefused,
        CatalogFailureCode::StorageUnavailable,
        CatalogFailureCode::IntegrityCorruption,
    ] {
        assert_eq!(
            SchemaCatalogLoadFailure::Catalog(code).catalog_code(),
            Some(code)
        );
    }
}
