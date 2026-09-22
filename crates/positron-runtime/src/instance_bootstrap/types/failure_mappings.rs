use super::*;

pub(super) fn map_api_key_failure(failure: ApiKeyAdministrationFailure) -> BootstrapFailure {
    let code = match failure {
        ApiKeyAdministrationFailure::CapacityExceeded => BootstrapFailureCode::ResourceUnavailable,
        ApiKeyAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
        ApiKeyAdministrationFailure::Unauthorized => BootstrapFailureCode::ApiKeyUnauthorized,
        ApiKeyAdministrationFailure::StaleGeneration => BootstrapFailureCode::ApiKeyStaleGeneration,
        ApiKeyAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::ApiKeyIdempotencyConflict
        },
        ApiKeyAdministrationFailure::CredentialUnavailable => {
            BootstrapFailureCode::ApiKeyUnavailable
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_tenant_lifecycle_failure(
    failure: TenantLifecycleAdministrationFailure,
) -> BootstrapFailure {
    let code = match failure {
        TenantLifecycleAdministrationFailure::Unauthorized => {
            BootstrapFailureCode::TenantLifecycleUnauthorized
        },
        TenantLifecycleAdministrationFailure::UnknownTenant => {
            BootstrapFailureCode::TenantLifecycleUnknownTenant
        },
        TenantLifecycleAdministrationFailure::InvalidTransition => {
            BootstrapFailureCode::TenantLifecycleInvalidTransition
        },
        TenantLifecycleAdministrationFailure::PurgeCompletionUnavailable => {
            BootstrapFailureCode::TenantLifecyclePurgeCompletionUnavailable
        },
        TenantLifecycleAdministrationFailure::StaleGeneration(conflict) => {
            return BootstrapFailure::with_lifecycle_generation_conflict(conflict);
        },
        TenantLifecycleAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::TenantLifecycleIdempotencyConflict
        },
        TenantLifecycleAdministrationFailure::CapacityExceeded
        | TenantLifecycleAdministrationFailure::TimeUnavailable
        | TenantLifecycleAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_tenant_alias_failure(
    failure: TenantAliasAdministrationFailure,
) -> BootstrapFailure {
    let code = match failure {
        TenantAliasAdministrationFailure::Unauthorized => {
            BootstrapFailureCode::TenantAliasUnauthorized
        },
        TenantAliasAdministrationFailure::UnknownTenant => {
            BootstrapFailureCode::TenantAliasUnknownTenant
        },
        TenantAliasAdministrationFailure::AliasAlreadyBound => {
            BootstrapFailureCode::TenantAliasAlreadyBound
        },
        TenantAliasAdministrationFailure::AliasConflict => {
            BootstrapFailureCode::TenantAliasConflict
        },
        TenantAliasAdministrationFailure::StaleGeneration(_) => {
            BootstrapFailureCode::TenantAliasStaleGeneration
        },
        TenantAliasAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::TenantAliasIdempotencyConflict
        },
        TenantAliasAdministrationFailure::CapacityExceeded
        | TenantAliasAdministrationFailure::TimeUnavailable
        | TenantAliasAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_tenant_retention_failure(
    failure: TenantRetentionAdministrationFailure,
) -> BootstrapFailure {
    if let TenantRetentionAdministrationFailure::StaleGeneration(conflict) = failure {
        return BootstrapFailure::with_retention_generation_conflict(conflict);
    }
    let code = match failure {
        TenantRetentionAdministrationFailure::Unauthorized => {
            BootstrapFailureCode::TenantRetentionUnauthorized
        },
        TenantRetentionAdministrationFailure::UnknownTenant => {
            BootstrapFailureCode::TenantRetentionUnknownTenant
        },
        TenantRetentionAdministrationFailure::InvalidConfirmation => {
            BootstrapFailureCode::TenantRetentionInvalidConfirmation
        },
        TenantRetentionAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::TenantRetentionIdempotencyConflict
        },
        TenantRetentionAdministrationFailure::InvalidInput
        | TenantRetentionAdministrationFailure::CapacityExceeded
        | TenantRetentionAdministrationFailure::TimeUnavailable
        | TenantRetentionAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
        TenantRetentionAdministrationFailure::StaleGeneration(_) => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_system_audit_retention_failure(
    failure: positron_governance::SystemAuditRetentionAdministrationFailure,
) -> BootstrapFailure {
    use positron_governance::SystemAuditRetentionAdministrationFailure as Failure;
    let code = match failure {
        Failure::Unauthorized => BootstrapFailureCode::SystemAuditRetentionUnauthorized,
        Failure::StaleGeneration => BootstrapFailureCode::SystemAuditRetentionStaleGeneration,
        Failure::IdempotencyConflict => {
            BootstrapFailureCode::SystemAuditRetentionIdempotencyConflict
        },
        Failure::InvalidInput | Failure::CapacityExceeded | Failure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_tenant_quota_failure(
    failure: positron_governance::TenantQuotaAdministrationFailure,
) -> BootstrapFailure {
    if let Some(conflict) = failure.generation_conflict() {
        return BootstrapFailure::with_quota_generation_conflict(conflict);
    }
    let code = match failure.code() {
        positron_governance::TenantQuotaAdministrationFailureCode::Unauthorized => {
            BootstrapFailureCode::TenantQuotaUnauthorized
        },
        positron_governance::TenantQuotaAdministrationFailureCode::StaleResourceGeneration => {
            BootstrapFailureCode::TenantQuotaStaleGeneration
        },
        positron_governance::TenantQuotaAdministrationFailureCode::IdempotencyConflict => {
            BootstrapFailureCode::TenantQuotaIdempotencyConflict
        },
        positron_governance::TenantQuotaAdministrationFailureCode::InvalidInput
        | positron_governance::TenantQuotaAdministrationFailureCode::PersistenceUnavailable
        | positron_governance::TenantQuotaAdministrationFailureCode::CorruptState => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_tenant_profile_failure(
    failure: TenantProfileAdministrationFailure,
) -> BootstrapFailure {
    if let Some(conflict) = failure.generation_conflict() {
        return BootstrapFailure::with_display_generation_conflict(conflict);
    }
    let code = match failure.code() {
        TenantProfileAdministrationFailureCode::Unauthorized => {
            BootstrapFailureCode::TenantDisplayNameUnauthorized
        },
        TenantProfileAdministrationFailureCode::IdempotencyConflict => {
            BootstrapFailureCode::TenantDisplayNameIdempotencyConflict
        },
        TenantProfileAdministrationFailureCode::InvalidInput
        | TenantProfileAdministrationFailureCode::UnknownTenant
        | TenantProfileAdministrationFailureCode::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
        TenantProfileAdministrationFailureCode::StaleDisplayGeneration => {
            BootstrapFailureCode::TenantDisplayNameStaleGeneration
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_tenant_administration_failure(
    failure: positron_governance::TenantAdministrationFailure,
) -> BootstrapFailure {
    let code = match failure {
        positron_governance::TenantAdministrationFailure::Unauthorized => {
            BootstrapFailureCode::ApiKeyUnauthorized
        },
        positron_governance::TenantAdministrationFailure::StaleGeneration => {
            BootstrapFailureCode::ApiKeyStaleGeneration
        },
        positron_governance::TenantAdministrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::ApiKeyIdempotencyConflict
        },
        positron_governance::TenantAdministrationFailure::DuplicateTenant => {
            BootstrapFailureCode::TenantCreateConflict
        },
        positron_governance::TenantAdministrationFailure::InvalidInput
        | positron_governance::TenantAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_catalog_format_migration_failure(
    failure: CatalogFormatMigrationFailure,
) -> BootstrapFailure {
    let code = match failure {
        CatalogFormatMigrationFailure::Unauthorized => BootstrapFailureCode::ApiKeyUnauthorized,
        CatalogFormatMigrationFailure::IdempotencyConflict => {
            BootstrapFailureCode::ApiKeyIdempotencyConflict
        },
        CatalogFormatMigrationFailure::InvalidState
        | CatalogFormatMigrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_durable_operation_failure(failure: DurableOperationFailure) -> BootstrapFailure {
    let code = match failure {
        DurableOperationFailure::Unauthorized => BootstrapFailureCode::ApiKeyUnauthorized,
        DurableOperationFailure::IdempotencyConflict => {
            BootstrapFailureCode::ApiKeyIdempotencyConflict
        },
        DurableOperationFailure::CapacityExceeded => BootstrapFailureCode::ResourceUnavailable,
        DurableOperationFailure::UnknownOperation => BootstrapFailureCode::DurableOperationUnknown,
        DurableOperationFailure::CompletedLookupExpired => {
            BootstrapFailureCode::DurableOperationLookupExpired
        },
        DurableOperationFailure::CancellationUnavailable => {
            BootstrapFailureCode::DurableOperationCancellationUnavailable
        },
        DurableOperationFailure::InvalidInput
        | DurableOperationFailure::InvalidState
        | DurableOperationFailure::StaleGeneration
        | DurableOperationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
    };
    BootstrapFailure::new(code)
}

pub(super) fn map_listener_transport_failure(
    failure: ListenerTransportAdministrationFailure,
) -> BootstrapFailure {
    let code = match failure {
        ListenerTransportAdministrationFailure::PersistenceUnavailable => {
            BootstrapFailureCode::CatalogUnavailable
        },
        ListenerTransportAdministrationFailure::CorruptState => BootstrapFailureCode::CorruptState,
    };
    BootstrapFailure::new(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_operation_lookup_and_cancellation_failures_are_not_catalog_outages() {
        assert_eq!(
            map_durable_operation_failure(DurableOperationFailure::CompletedLookupExpired).code(),
            BootstrapFailureCode::DurableOperationLookupExpired
        );
        assert_eq!(
            map_durable_operation_failure(DurableOperationFailure::UnknownOperation).code(),
            BootstrapFailureCode::DurableOperationUnknown
        );
        assert_eq!(
            map_durable_operation_failure(DurableOperationFailure::CancellationUnavailable).code(),
            BootstrapFailureCode::DurableOperationCancellationUnavailable
        );
    }
}
