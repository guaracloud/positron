use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope, TenantId};
use positron_kernel::{
    AuditIntent, BootstrapKeyCustody, Catalog, CatalogCredential, CatalogFailureCode,
    CatalogObject, CatalogProposal, CatalogSnapshot, PreparedTransactionResolution, TransactionId,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::ApiKeyLifecycleAuditEntry;
use crate::{
    AdministrativeIdempotencyKey, ApiKeyLifecycleAction, AuthorizedContext, ResourceGeneration,
    TenantAdministration,
};

const TENANT_KEYRING_MAGIC: [u8; 8] = *b"POSTKC01";

pub(crate) struct TenantCredentialIdentity {
    pub(crate) tenant: TenantId,
    pub(crate) credentials: Vec<CatalogCredential>,
}

/// One secret-safe result from a newly created or rotated API key.
pub struct ApiKeyCreation {
    principal: PrincipalId,
    secret: Option<Zeroizing<String>>,
}

/// Canonical, bounded create request bound to an administrative idempotency key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyCreateRequest {
    actor: AuthorizedContext,
    tenant: Option<TenantId>,
    scope: Scope,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
    idempotency: AdministrativeIdempotencyKey,
}

/// Redacted API-key lifecycle inspection result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyDescriptor {
    principal: PrincipalId,
    scope: Scope,
    active: bool,
    expires_at_unix_seconds: Option<u64>,
    generation: ResourceGeneration,
}

impl ApiKeyDescriptor {
    #[must_use]
    pub const fn principal_id(self) -> PrincipalId {
        self.principal
    }
    #[must_use]
    pub const fn scope(self) -> Scope {
        self.scope
    }
    #[must_use]
    pub const fn is_active(self) -> bool {
        self.active
    }
    #[must_use]
    pub const fn expires_at_unix_seconds(self) -> Option<u64> {
        self.expires_at_unix_seconds
    }
    #[must_use]
    pub const fn generation(self) -> ResourceGeneration {
        self.generation
    }
}

impl ApiKeyCreateRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        scope: Scope,
        expires_at_unix_seconds: Option<u64>,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            tenant: None,
            scope,
            expires_at_unix_seconds,
            expected,
            idempotency,
        }
    }

    #[must_use]
    pub const fn for_tenant(mut self, tenant: TenantId) -> Self {
        self.tenant = Some(tenant);
        self
    }
}

/// Canonical, bounded rotation request for one default or named tenant keyring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyRotationRequest {
    actor: AuthorizedContext,
    tenant: Option<TenantId>,
    predecessor: PrincipalId,
    expected: ResourceGeneration,
    idempotency: AdministrativeIdempotencyKey,
}

impl ApiKeyRotationRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        predecessor: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            tenant: None,
            predecessor,
            expected,
            idempotency,
        }
    }

    #[must_use]
    pub const fn for_tenant(mut self, tenant: TenantId) -> Self {
        self.tenant = Some(tenant);
        self
    }
}

impl ApiKeyCreation {
    #[must_use]
    pub fn secret(&self) -> Option<&str> {
        self.secret.as_deref().map(String::as_str)
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal
    }
}

impl std::fmt::Debug for ApiKeyCreation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApiKeyCreation { <redacted> }")
    }
}

/// Closed outcomes for Administration-owned API-key lifecycle work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyAdministrationFailure {
    Unauthorized,
    StaleGeneration,
    IdempotencyConflict,
    CapacityExceeded,
    CredentialUnavailable,
    PersistenceUnavailable,
}

impl Display for ApiKeyAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("API-key administration failed")
    }
}

impl Error for ApiKeyAdministrationFailure {}

/// Administration owns semantic API-key lifecycle mutation; Catalog remains
/// the only durable publication authority and Identity remains read-only.
pub struct ApiKeyAdministration;

#[path = "api_key_administration_commit.rs"]
mod api_key_administration_commit;
#[path = "api_key_administration_default.rs"]
mod api_key_administration_default;
#[path = "api_key_administration_digest.rs"]
mod api_key_administration_digest;
#[path = "api_key_administration_provisioned.rs"]
mod api_key_administration_provisioned;
#[path = "api_key_administration_support.rs"]
mod api_key_administration_support;

use api_key_administration_commit::*;
use api_key_administration_digest::*;
use api_key_administration_support::*;

#[path = "api_key_administration_replay.rs"]
mod api_key_administration_replay;
use api_key_administration_replay::*;

#[path = "api_key_administration_keyring.rs"]
mod api_key_administration_keyring;
use api_key_administration_keyring::*;
