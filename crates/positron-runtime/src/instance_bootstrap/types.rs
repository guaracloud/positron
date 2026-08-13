use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};
use positron_kernel::InstanceId;
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
    pub(super) data: PathBuf,
    pub(super) secrets: PathBuf,
}

impl BootstrapPaths {
    pub fn new(data: &Path, secrets: &Path) -> Result<Self, BootstrapFailure> {
        let data = std::fs::canonicalize(data)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::InvalidRoots))?;
        let secrets = std::fs::canonicalize(secrets)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::InvalidRoots))?;
        let separate = data != secrets
            && !data.starts_with(&secrets)
            && !secrets.starts_with(&data)
            && data.is_absolute()
            && secrets.is_absolute();
        if !separate {
            return Err(BootstrapFailure::new(BootstrapFailureCode::InvalidRoots));
        }
        Ok(Self { data, secrets })
    }

    #[must_use]
    pub fn data_root(&self) -> &Path {
        &self.data
    }

    #[must_use]
    pub fn secrets_root(&self) -> &Path {
        &self.secrets
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializedInstance {
    pub(super) instance: InstanceId,
    pub(super) tenant: TenantId,
    pub(super) tenant_slug: TenantSlug,
    pub(super) administrator: PrincipalId,
    pub(super) integrity_key_fingerprint: [u8; 32],
    pub(super) catalog_generation: u64,
    pub(super) governance_audit_frontier: u64,
    pub(super) claim_available: bool,
}

impl InitializedInstance {
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
}

impl std::fmt::Debug for BootstrapClaim {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BootstrapClaim { <redacted> }")
    }
}
