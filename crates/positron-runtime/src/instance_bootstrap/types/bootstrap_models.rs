use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapState {
    Empty,
    Incomplete,
    Initialized,
    Inconsistent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapFailureCode {
    InvalidRoots,
    InconsistentRoots,
    AlreadyInitialized,
    StorageUnavailable,
    KeyCustodyUnavailable,
    ResourceUnavailable,
    CatalogUnavailable,
    LedgerUnavailable,
    CorruptState,
    IdentityMismatch,
    ClaimUnavailable,
    ClaimDestructionFailed,
    EntropyUnavailable,
    ApiKeyUnauthorized,
    ApiKeyStaleGeneration,
    ApiKeyIdempotencyConflict,
    ApiKeyUnavailable,
    TenantLifecycleUnauthorized,
    TenantLifecycleUnknownTenant,
    TenantLifecycleInvalidTransition,
    TenantLifecyclePurgeCompletionUnavailable,
    TenantLifecycleStaleGeneration,
    TenantLifecycleIdempotencyConflict,
    TenantQuotaUnauthorized,
    TenantQuotaStaleGeneration,
    TenantQuotaIdempotencyConflict,
    TenantDisplayNameUnauthorized,
    TenantDisplayNameStaleGeneration,
    TenantDisplayNameIdempotencyConflict,
    TenantAliasUnauthorized,
    TenantAliasUnknownTenant,
    TenantAliasAlreadyBound,
    TenantAliasConflict,
    TenantAliasStaleGeneration,
    TenantAliasIdempotencyConflict,
    TenantRetentionUnauthorized,
    TenantRetentionUnknownTenant,
    TenantRetentionInvalidConfirmation,
    TenantRetentionStaleGeneration,
    TenantRetentionIdempotencyConflict,
    SystemAuditRetentionUnauthorized,
    SystemAuditRetentionStaleGeneration,
    SystemAuditRetentionIdempotencyConflict,
    TenantCreateConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapFailure {
    code: BootstrapFailureCode,
    lifecycle_generation_conflict: Option<positron_governance::TenantLifecycleGenerationConflict>,
    quota_generation_conflict: Option<positron_governance::TenantQuotaGenerationConflict>,
    display_generation_conflict: Option<TenantDisplayGenerationConflict>,
    retention_generation_conflict: Option<positron_governance::TenantRetentionGenerationConflict>,
}

impl BootstrapFailure {
    pub(crate) const fn new(code: BootstrapFailureCode) -> Self {
        Self {
            code,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: None,
        }
    }

    pub(super) const fn with_lifecycle_generation_conflict(
        conflict: positron_governance::TenantLifecycleGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantLifecycleStaleGeneration,
            lifecycle_generation_conflict: Some(conflict),
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: None,
        }
    }

    pub(super) const fn with_quota_generation_conflict(
        conflict: positron_governance::TenantQuotaGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantQuotaStaleGeneration,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: Some(conflict),
            display_generation_conflict: None,
            retention_generation_conflict: None,
        }
    }

    pub(super) const fn with_display_generation_conflict(
        conflict: TenantDisplayGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantDisplayNameStaleGeneration,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: Some(conflict),
            retention_generation_conflict: None,
        }
    }

    pub(super) const fn with_retention_generation_conflict(
        conflict: positron_governance::TenantRetentionGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantRetentionStaleGeneration,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: Some(conflict),
        }
    }

    #[must_use]
    pub const fn code(self) -> BootstrapFailureCode {
        self.code
    }

    #[must_use]
    pub const fn lifecycle_generation_conflict(
        self,
    ) -> Option<positron_governance::TenantLifecycleGenerationConflict> {
        self.lifecycle_generation_conflict
    }

    #[must_use]
    pub const fn quota_generation_conflict(&self) -> Option<ResourceGeneration> {
        match self.quota_generation_conflict {
            Some(conflict) => Some(conflict.current_generation()),
            None => None,
        }
    }

    #[must_use]
    pub const fn quota_generation_conflict_detail(
        &self,
    ) -> Option<positron_governance::TenantQuotaGenerationConflict> {
        self.quota_generation_conflict
    }

    #[must_use]
    pub const fn display_generation_conflict(&self) -> Option<TenantDisplayGenerationConflict> {
        self.display_generation_conflict
    }

    #[must_use]
    pub const fn retention_generation_conflict(
        &self,
    ) -> Option<positron_governance::TenantRetentionGenerationConflict> {
        self.retention_generation_conflict
    }
}

impl Display for BootstrapFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("instance bootstrap failed")
    }
}

impl Error for BootstrapFailure {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapPaths {
    pub(in crate::instance_bootstrap) storage: InstanceBootstrapStorage,
    #[cfg(test)]
    data: std::path::PathBuf,
    #[cfg(test)]
    secrets: std::path::PathBuf,
}

impl BootstrapPaths {
    pub fn new(
        data: &Path,
        secrets: &Path,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapFailure> {
        Ok(Self {
            storage: InstanceBootstrapStorage::new(data, secrets, qualification)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::InvalidRoots))?,
            #[cfg(test)]
            data: data.to_owned(),
            #[cfg(test)]
            secrets: secrets.to_owned(),
        })
    }

    /// Binds bootstrap custody to the exact effective local-key reference.
    pub fn with_local_key(
        data: &Path,
        secrets: &Path,
        local_key_file: &Path,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapFailure> {
        if local_key_file != secrets.join("local-root-key.v1") {
            return Err(BootstrapFailure::new(BootstrapFailureCode::InvalidRoots));
        }
        Self::new(data, secrets, qualification)
    }

    #[cfg(test)]
    pub(in crate::instance_bootstrap) fn data_root(&self) -> &Path {
        &self.data
    }

    #[cfg(test)]
    pub(in crate::instance_bootstrap) fn secrets_root(&self) -> &Path {
        &self.secrets
    }

    #[must_use]
    pub const fn mount_qualification(&self) -> MountQualification {
        self.storage.qualification()
    }

    pub(crate) fn retain_volume(&self) -> Result<OwnedPrimaryDataVolume, BootstrapFailure> {
        self.storage
            .acquire()
            .map(|(volume, _)| volume)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
    }

    #[doc(hidden)]
    pub fn retain_volume_for_test(&self) -> Result<OwnedPrimaryDataVolume, BootstrapFailure> {
        self.retain_volume()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializationPlan {
    non_interactive: bool,
    external_alias: Option<ExternalTenantAlias>,
}

impl InitializationPlan {
    #[must_use]
    pub const fn non_interactive() -> Self {
        Self {
            non_interactive: true,
            external_alias: None,
        }
    }

    /// Creates a non-interactive plan with an explicitly bound protocol alias.
    pub fn non_interactive_with_external_tenant_alias(
        alias: &str,
    ) -> Result<Self, BootstrapFailure> {
        let external_alias = ExternalTenantAlias::parse(alias)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::InvalidRoots))?;
        Ok(Self {
            non_interactive: true,
            external_alias: Some(external_alias),
        })
    }

    pub(in crate::instance_bootstrap) const fn creates_claim(&self) -> bool {
        self.non_interactive
    }

    pub(in crate::instance_bootstrap) fn external_alias(
        &self,
    ) -> Result<ExternalTenantAlias, BootstrapFailure> {
        self.external_alias.clone().map_or_else(
            || {
                ExternalTenantAlias::parse("trace-external")
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
            },
            Ok,
        )
    }
}

pub struct InitializedInstance {
    pub(crate) key: BootstrapKeyCustody,
    // Fixture-only inspection data; product authorization always reads the
    // current durable identity through `durable_identity`.
    #[cfg(any(test, fuzzing))]
    pub(crate) identity: positron_governance::Identity,
    #[cfg(any(test, fuzzing))]
    pub(in crate::instance_bootstrap) audit: Vec<positron_governance::GovernanceAuditEntry>,
    pub(crate) _authority: StorageKernelResourceAuthority,
    pub(crate) retention_time: RetentionTimeAuthority,
    pub(crate) instance: InstanceId,
    pub(crate) tenant: TenantId,
    pub(crate) logs_shard: positron_domain::routing::VirtualShardId,
    pub(crate) value_limit_profile: positron_domain::value::ValueLimitProfile,
    pub(crate) admission_group_planner: Arc<dyn positron_ingest::AdmissionGroupPlanner>,
    pub(in crate::instance_bootstrap) tenant_drains: TenantDrainRegistry,
    #[cfg(test)]
    pub(in crate::instance_bootstrap) lifecycle_preflight_hook:
        Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    pub(in crate::instance_bootstrap) catalog_migration_preflight_hook:
        Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    pub(in crate::instance_bootstrap) tenant_slug: TenantSlug,
    pub(in crate::instance_bootstrap) administrator: PrincipalId,
    pub(in crate::instance_bootstrap) integrity_key_fingerprint: [u8; 32],
    pub(in crate::instance_bootstrap) catalog_generation: u64,
    pub(in crate::instance_bootstrap) governance_audit_frontier: u64,
    pub(in crate::instance_bootstrap) claim_available: bool,
}

impl std::fmt::Debug for InitializedInstance {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitializedInstance")
            .field("instance", &self.instance)
            .field("tenant", &self.tenant)
            .field("catalog_generation", &self.catalog_generation)
            .field("claim_available", &self.claim_available)
            .finish_non_exhaustive()
    }
}
