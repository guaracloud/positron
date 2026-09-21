use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope, TenantId, TenantSlug};
use positron_kernel::{CatalogFailure, CatalogFailureCode};

use crate::{AdministrativeIdempotencyKey, AuthorizedContext, ResourceGeneration};

#[path = "tenant_administration_proposal.rs"]
mod tenant_administration_proposal;
#[path = "tenant_administration_registry.rs"]
mod tenant_administration_registry;
#[path = "tenant_administration_registry_codec.rs"]
mod tenant_administration_registry_codec;
#[path = "tenant_administration_replay.rs"]
mod tenant_administration_replay;
#[cfg(test)]
#[path = "tenant_administration_tests.rs"]
mod tenant_administration_tests;

pub use tenant_administration_registry::{
    TenantInspection, TenantInspectionPage, TenantListContinuation,
};
pub(crate) use tenant_administration_registry_codec::is_registry;
pub(crate) use tenant_administration_replay::legacy_receipt_object;

/// Public redacted outcome of a tenant creation publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantCreation {
    tenant: TenantId,
    generation: ResourceGeneration,
    audit_position: u64,
}

impl TenantCreation {
    pub(super) const fn new(
        tenant: TenantId,
        generation: ResourceGeneration,
        audit_position: u64,
    ) -> Self {
        Self {
            tenant,
            generation,
            audit_position,
        }
    }

    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn resource_generation(self) -> ResourceGeneration {
        self.generation
    }

    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

/// Bounded tenant creation input. Tenant credentials are intentionally absent:
/// a system administrator creates registry state but never receives data-plane
/// authority for the new tenant.
#[derive(Clone)]
pub struct TenantCreateRequest {
    pub(super) actor: AuthorizedContext,
    pub(super) slug: TenantSlug,
    pub(super) display_name: String,
    pub(super) retention_seconds: u64,
    pub(super) weight: u32,
    pub(super) resources: [u64; 11],
    pub(super) idempotency: AdministrativeIdempotencyKey,
}

/// A server-selected tenant identity bound to one validated creation request.
///
/// It remains private to the governance publication path so callers cannot
/// select tenant identities through the administrative request contract.
#[derive(Clone)]
pub struct TenantCreateCandidate {
    pub(super) request: TenantCreateRequest,
    pub(super) tenant: TenantId,
}

/// Bounded durable attributes for a newly created tenant.
#[derive(Clone)]
pub struct TenantCreateConfiguration {
    slug: TenantSlug,
    display_name: String,
    retention_seconds: u64,
    weight: u32,
    resources: [u64; 11],
}

impl TenantCreateConfiguration {
    #[must_use]
    pub fn new(
        slug: TenantSlug,
        display_name: &str,
        retention_seconds: u64,
        weight: u32,
        resources: [u64; 11],
    ) -> Self {
        Self {
            slug,
            display_name: display_name.to_owned(),
            retention_seconds,
            weight,
            resources,
        }
    }

    #[must_use]
    pub const fn resources(&self) -> [u64; 11] {
        self.resources
    }

    #[must_use]
    pub const fn weight(&self) -> u32 {
        self.weight
    }
}

impl TenantCreateRequest {
    #[must_use]
    pub fn new(
        actor: AuthorizedContext,
        configuration: TenantCreateConfiguration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            slug: configuration.slug,
            display_name: configuration.display_name,
            retention_seconds: configuration.retention_seconds,
            weight: configuration.weight,
            resources: configuration.resources,
            idempotency,
        }
    }

    #[must_use]
    pub fn with_generated_tenant(self, tenant: TenantId) -> TenantCreateCandidate {
        TenantCreateCandidate {
            request: self,
            tenant,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantAdministrationFailure {
    Unauthorized,
    InvalidInput,
    DuplicateTenant,
    StaleGeneration,
    IdempotencyConflict,
    PersistenceUnavailable,
}

impl Display for TenantAdministrationFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("tenant administration failed")
    }
}

impl Error for TenantAdministrationFailure {}

/// Administration owns validation and idempotency; Catalog alone publishes.
pub struct TenantAdministration;

pub(super) fn validate_request(
    administrator: PrincipalId,
    request: &TenantCreateRequest,
) -> Result<(), TenantAdministrationFailure> {
    if request.actor.principal_id() != administrator
        || request.actor.scope() != Scope::SystemAdministration
        || request.actor.tenant_attribution().is_some()
    {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    if request.display_name.is_empty()
        || request.display_name.len() > 128
        || request.retention_seconds == 0
        || request.weight == 0
        || request.weight > u32::from(u16::MAX)
        || request.resources.contains(&0)
    {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    Ok(())
}

pub(super) fn generation_at(
    bytes: &[u8],
    at: usize,
) -> Result<ResourceGeneration, TenantAdministrationFailure> {
    ResourceGeneration::new(u64::from_be_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
    ))
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}

pub(super) fn map_catalog(failure: CatalogFailure) -> TenantAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::IdempotencyConflict => TenantAdministrationFailure::IdempotencyConflict,
        _ => TenantAdministrationFailure::PersistenceUnavailable,
    }
}
