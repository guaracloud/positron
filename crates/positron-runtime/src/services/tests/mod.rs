use positron_ingest::{AdmissionGroupPlanFailure, ReceiveFailure};
use positron_kernel::{CatalogFailureCode, LedgerFailureCode};
use positron_query::QueryFailureCode;

use super::{
    ServiceFailure, classify_bootstrap_failure_code, map_admission_group_plan_failure,
    map_query_failure_code, map_receive_failure,
};

mod schema_maintenance;
mod schema_replay_integrity;
mod schema_routes;
mod trace_visibility;

#[test]
fn service_diagnostics_are_stable_and_secret_free() {
    assert_eq!(
        ServiceFailure::Unauthorized.to_string(),
        "runtime service request failed"
    );
}

#[test]
fn receiver_failures_preserve_auth_capacity_and_request_classes() {
    assert_eq!(
        map_receive_failure(ReceiveFailure::AuthenticationRejected),
        ServiceFailure::Unauthorized
    );
    assert_eq!(
        map_receive_failure(ReceiveFailure::CapacityUnavailable),
        ServiceFailure::CapacityUnavailable
    );
    assert_eq!(
        map_receive_failure(ReceiveFailure::TransportLimitExceeded),
        ServiceFailure::RequestTooLarge
    );
    for failure in [
        ReceiveFailure::MalformedPayload,
        ReceiveFailure::MalformedCompression,
        ReceiveFailure::ValueLimitExceeded,
        ReceiveFailure::TimestampOutOfRange,
        ReceiveFailure::UnsupportedValue,
    ] {
        assert_eq!(map_receive_failure(failure), ServiceFailure::InvalidRequest);
    }
}

#[test]
fn planner_failures_preserve_permanent_retryable_and_invariant_classes() {
    assert_eq!(
        map_admission_group_plan_failure(AdmissionGroupPlanFailure::UnsupportedSignal),
        ServiceFailure::InvalidRequest
    );
    assert_eq!(
        map_admission_group_plan_failure(AdmissionGroupPlanFailure::AssignmentUnavailable),
        ServiceFailure::CapacityUnavailable
    );
    assert_eq!(
        map_admission_group_plan_failure(AdmissionGroupPlanFailure::RecordCountExceeded),
        ServiceFailure::Internal
    );
}

#[test]
fn cancellation_is_not_reclassified_as_a_storage_failure() {
    assert_eq!(
        ServiceFailure::Cancelled.bootstrap_code(),
        crate::BootstrapFailureCode::ResourceUnavailable
    );
}

#[test]
fn bootstrap_failures_use_an_exhaustive_service_classification_table() {
    for (code, expected) in [
        (
            crate::BootstrapFailureCode::InvalidRoots,
            ServiceFailure::Internal,
        ),
        (
            crate::BootstrapFailureCode::InconsistentRoots,
            ServiceFailure::Internal,
        ),
        (
            crate::BootstrapFailureCode::AlreadyInitialized,
            ServiceFailure::Internal,
        ),
        (
            crate::BootstrapFailureCode::StorageUnavailable,
            ServiceFailure::StorageUnavailable,
        ),
        (
            crate::BootstrapFailureCode::KeyCustodyUnavailable,
            ServiceFailure::KeyUnavailable,
        ),
        (
            crate::BootstrapFailureCode::ResourceUnavailable,
            ServiceFailure::CapacityUnavailable,
        ),
        (
            crate::BootstrapFailureCode::CatalogUnavailable,
            ServiceFailure::StorageUnavailable,
        ),
        (
            crate::BootstrapFailureCode::LedgerUnavailable,
            ServiceFailure::Internal,
        ),
        (
            crate::BootstrapFailureCode::CorruptState,
            ServiceFailure::CorruptState,
        ),
        (
            crate::BootstrapFailureCode::IdentityMismatch,
            ServiceFailure::CorruptState,
        ),
        (
            crate::BootstrapFailureCode::ClaimUnavailable,
            ServiceFailure::Internal,
        ),
        (
            crate::BootstrapFailureCode::ClaimDestructionFailed,
            ServiceFailure::Internal,
        ),
        (
            crate::BootstrapFailureCode::EntropyUnavailable,
            ServiceFailure::Internal,
        ),
    ] {
        assert_eq!(classify_bootstrap_failure_code(code), expected, "{code:?}");
    }
}

#[test]
fn replay_failures_preserve_resource_integrity_and_cancellation_classes() {
    assert_eq!(
        super::schema_bootstrap::classify_replay_failure(
            positron_ingest::SchemaSessionFailure::StateUnavailable
        ),
        ServiceFailure::CapacityUnavailable
    );
    assert_eq!(
        super::schema_bootstrap::classify_replay_failure(
            positron_ingest::SchemaSessionFailure::ReplayLimitExceeded
        ),
        ServiceFailure::CapacityUnavailable
    );
    assert_eq!(
        super::schema_bootstrap::classify_replay_failure(
            positron_ingest::SchemaSessionFailure::Schema(
                positron_signals::SchemaFailure::MalformedCatalog,
            )
        ),
        ServiceFailure::CorruptState
    );
    assert_eq!(
        super::schema_bootstrap::classify_replay_failure(
            positron_ingest::SchemaSessionFailure::Cancelled
        ),
        ServiceFailure::Cancelled
    );
}

#[test]
fn query_failures_preserve_runtime_error_classes() {
    for (code, expected) in [
        (QueryFailureCode::Unauthorized, ServiceFailure::Unauthorized),
        (
            QueryFailureCode::AuthorizationChanged,
            ServiceFailure::Unauthorized,
        ),
        (
            QueryFailureCode::InvalidBudget,
            ServiceFailure::InvalidRequest,
        ),
        (
            QueryFailureCode::InvalidCursor,
            ServiceFailure::InvalidRequest,
        ),
        (
            QueryFailureCode::SnapshotExpired,
            ServiceFailure::InvalidRequest,
        ),
        (
            QueryFailureCode::UnsupportedQuery,
            ServiceFailure::InvalidRequest,
        ),
        (
            QueryFailureCode::BudgetExhausted,
            ServiceFailure::CapacityUnavailable,
        ),
        (
            QueryFailureCode::ResourceAdmissionRefused,
            ServiceFailure::CapacityUnavailable,
        ),
        (
            QueryFailureCode::ResourceExhausted,
            ServiceFailure::CapacityUnavailable,
        ),
        (QueryFailureCode::Cancelled, ServiceFailure::Cancelled),
        (
            QueryFailureCode::MalformedPersistentData,
            ServiceFailure::CorruptState,
        ),
        (
            QueryFailureCode::StoreUnavailable,
            ServiceFailure::StorageUnavailable,
        ),
        (QueryFailureCode::Internal, ServiceFailure::Internal),
    ] {
        assert_eq!(map_query_failure_code(code), expected, "{code:?}");
    }
}

#[test]
fn query_result_without_complete_terminal_is_not_success() {
    assert_eq!(
        super::failure::collect_query_bodies(std::iter::empty()),
        Err(ServiceFailure::Internal)
    );
    for (failure, expected) in [
        (
            ServiceFailure::CorruptState,
            crate::BootstrapFailureCode::CorruptState,
        ),
        (
            ServiceFailure::KeyUnavailable,
            crate::BootstrapFailureCode::KeyCustodyUnavailable,
        ),
        (
            ServiceFailure::CatalogUnavailable,
            crate::BootstrapFailureCode::CatalogUnavailable,
        ),
        (
            ServiceFailure::StorageUnavailable,
            crate::BootstrapFailureCode::CatalogUnavailable,
        ),
        (
            ServiceFailure::LedgerUnavailable,
            crate::BootstrapFailureCode::LedgerUnavailable,
        ),
        (
            ServiceFailure::CapacityUnavailable,
            crate::BootstrapFailureCode::ResourceUnavailable,
        ),
    ] {
        assert_eq!(failure.bootstrap_code(), expected);
    }
}

#[test]
fn query_setup_failures_use_one_catalog_and_ledger_classification_table() {
    for (code, expected) in [
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
    ] {
        assert_eq!(
            super::failure::classify_catalog_failure_code(code),
            expected,
            "{code:?}"
        );
    }

    for (code, expected) in [
        (
            LedgerFailureCode::ResourceAdmissionRefused,
            ServiceFailure::CapacityUnavailable,
        ),
        (
            LedgerFailureCode::LimitExceeded,
            ServiceFailure::CapacityUnavailable,
        ),
        (
            LedgerFailureCode::StorageExhausted,
            ServiceFailure::CapacityUnavailable,
        ),
        (
            LedgerFailureCode::StorageUnavailable,
            ServiceFailure::StorageUnavailable,
        ),
        (
            LedgerFailureCode::IntegrityCorruption,
            ServiceFailure::CorruptState,
        ),
        (
            LedgerFailureCode::AuthenticationFailed,
            ServiceFailure::CorruptState,
        ),
        (
            LedgerFailureCode::UnsupportedFormat,
            ServiceFailure::CorruptState,
        ),
        (
            LedgerFailureCode::InvalidInput,
            ServiceFailure::CorruptState,
        ),
        (
            LedgerFailureCode::PhysicalScopeMismatch,
            ServiceFailure::CorruptState,
        ),
        (
            LedgerFailureCode::RecoveryRequired,
            ServiceFailure::CorruptState,
        ),
        (
            LedgerFailureCode::StaleGeneration,
            ServiceFailure::CatalogUnavailable,
        ),
        (
            LedgerFailureCode::ConcurrentWriter,
            ServiceFailure::CatalogUnavailable,
        ),
        (
            LedgerFailureCode::IdempotencyConflict,
            ServiceFailure::CatalogUnavailable,
        ),
        (
            LedgerFailureCode::SnapshotExpired,
            ServiceFailure::CatalogUnavailable,
        ),
        (
            LedgerFailureCode::StaleResumeMarker,
            ServiceFailure::InvalidRequest,
        ),
        (LedgerFailureCode::Cancelled, ServiceFailure::Cancelled),
    ] {
        assert_eq!(
            super::failure::classify_ledger_failure_code(code),
            expected,
            "{code:?}"
        );
        let expected_ingest = if expected == ServiceFailure::CapacityUnavailable {
            positron_ingest::IngestFailureCode::CapacityUnavailable
        } else {
            positron_ingest::IngestFailureCode::StorageUnavailable
        };
        assert_eq!(
            super::ingest::map_ledger_failure_code(code),
            expected_ingest,
            "ingest mapping: {code:?}"
        );
    }
}
