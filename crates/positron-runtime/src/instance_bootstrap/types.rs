use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;

use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};
use positron_kernel::{
    BootstrapKeyCustody, InstanceBootstrapStorage, InstanceId, MountQualification,
    OwnedPrimaryDataVolume, StorageKernelResourceAuthority,
};
use zeroize::Zeroizing;

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapFailure {
    code: BootstrapFailureCode,
}

impl BootstrapFailure {
    pub(super) const fn new(code: BootstrapFailureCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> BootstrapFailureCode {
        self.code
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
    pub(super) storage: InstanceBootstrapStorage,
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
    pub(super) fn data_root(&self) -> &Path {
        &self.data
    }

    #[cfg(test)]
    pub(super) fn secrets_root(&self) -> &Path {
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializationPlan {
    non_interactive: bool,
}

impl InitializationPlan {
    #[must_use]
    pub const fn non_interactive() -> Self {
        Self {
            non_interactive: true,
        }
    }

    pub(super) const fn creates_claim(self) -> bool {
        self.non_interactive
    }
}

pub struct InitializedInstance {
    pub(crate) key: BootstrapKeyCustody,
    pub(super) identity: positron_governance::Identity,
    pub(super) audit: Vec<positron_governance::GovernanceAuditEntry>,
    pub(crate) _authority: StorageKernelResourceAuthority,
    pub(crate) instance: InstanceId,
    pub(crate) tenant: TenantId,
    pub(super) tenant_slug: TenantSlug,
    pub(super) administrator: PrincipalId,
    pub(super) integrity_key_fingerprint: [u8; 32],
    pub(super) catalog_generation: u64,
    pub(super) governance_audit_frontier: u64,
    pub(super) claim_available: bool,
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

impl InitializedInstance {
    pub(crate) fn begin_shutdown(&self) -> Result<(), BootstrapFailure> {
        self._authority
            .begin_shutdown()
            .map(|_| ())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
    }

    pub fn attribute(
        &self,
        credential: positron_governance::PresentedCredential,
        intent: positron_governance::RequestedIntent,
        hints: positron_governance::CompatibilityHints,
    ) -> Result<positron_governance::AuthorizedContext, positron_governance::AttributionFailure>
    {
        self.identity
            .attribute(&self.key, credential, intent, hints)
    }

    /// Borrows the initialized instance's ordinary resource-admission authority.
    #[must_use]
    pub const fn resource_governor(&self) -> positron_kernel::ResourceGovernor<'_> {
        self._authority.governor()
    }

    pub fn inspect_governance(
        &self,
        context: positron_governance::AuthorizedContext,
    ) -> Result<
        positron_governance::GovernanceInspection<'_, '_>,
        positron_governance::AttributionFailure,
    > {
        self.identity.inspect(context, &self.audit)
    }

    #[must_use]
    pub const fn instance_id(&self) -> InstanceId {
        self.instance
    }

    #[must_use]
    pub const fn default_tenant_id(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn default_tenant_slug(&self) -> &TenantSlug {
        &self.tenant_slug
    }

    #[must_use]
    pub const fn system_administrator_id(&self) -> PrincipalId {
        self.administrator
    }

    #[must_use]
    pub const fn integrity_key_fingerprint(&self) -> [u8; 32] {
        self.integrity_key_fingerprint
    }

    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    #[must_use]
    pub const fn governance_audit_frontier(&self) -> u64 {
        self.governance_audit_frontier
    }

    #[must_use]
    pub const fn claim_available(&self) -> bool {
        self.claim_available
    }
}

pub struct BootstrapClaim {
    pub(super) principal: PrincipalId,
    pub(super) secret: Zeroizing<String>,
    pub(super) ingest: Option<(PrincipalId, Zeroizing<String>)>,
    pub(super) query: Option<(PrincipalId, Zeroizing<String>)>,
}

impl BootstrapClaim {
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub fn secret(&self) -> &str {
        self.secret.as_str()
    }

    #[must_use]
    pub fn ingest_principal_id(&self) -> Option<PrincipalId> {
        self.ingest.as_ref().map(|(principal, _)| *principal)
    }

    #[must_use]
    pub fn ingest_secret(&self) -> Option<&str> {
        self.ingest.as_ref().map(|(_, secret)| secret.as_str())
    }

    #[must_use]
    pub fn query_principal_id(&self) -> Option<PrincipalId> {
        self.query.as_ref().map(|(principal, _)| *principal)
    }

    #[must_use]
    pub fn query_secret(&self) -> Option<&str> {
        self.query.as_ref().map(|(_, secret)| secret.as_str())
    }
}

impl std::fmt::Debug for BootstrapClaim {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BootstrapClaim { <redacted> }")
    }
}
