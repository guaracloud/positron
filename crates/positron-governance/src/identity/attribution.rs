use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{
    ExternalTenantAlias, PrincipalId, Scope, TenantAttribution, TenantId, TenantSlug,
};
use positron_domain::lifecycle::TenantLifecycleState;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::GovernanceAuditEntry;

/// A presented bearer credential whose decoded secret is zeroized on drop.
pub struct PresentedCredential {
    secret: Zeroizing<[u8; 32]>,
}

impl PresentedCredential {
    /// Parses the canonical `pos_` bootstrap credential without retaining its
    /// textual representation.
    pub fn parse(source: &str) -> Result<Self, AttributionFailure> {
        let encoded = source.strip_prefix("pos_").ok_or(AttributionFailure)?;
        if encoded.len() != 64 {
            return Err(AttributionFailure);
        }
        let mut secret = Zeroizing::new([0_u8; 32]);
        for (destination, pair) in secret.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
            let high = decode_hex(*pair.first().ok_or(AttributionFailure)?)?;
            let low = decode_hex(*pair.get(1).ok_or(AttributionFailure)?)?;
            *destination = (high << 4) | low;
        }
        Ok(Self { secret })
    }

    pub(super) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl std::fmt::Debug for PresentedCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PresentedCredential { <redacted> }")
    }
}

fn decode_hex(byte: u8) -> Result<u8, AttributionFailure> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AttributionFailure),
    }
}

/// The closed Release 1 action taxonomy used by the first identity slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedIntent {
    Ingest,
    Query,
    TenantAdministration,
    SystemAdministration,
}

/// Compatibility evidence that may validate, but never select, authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityHints {
    pub(super) external_alias: Option<ExternalTenantAlias>,
    pub(super) proxy_actor: Option<ProxyActorContext>,
    #[cfg(fuzzing)]
    untrusted_proxy_actor: bool,
    #[cfg(fuzzing)]
    tenant_claims: Vec<[u8; 16]>,
}

impl CompatibilityHints {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            external_alias: None,
            proxy_actor: None,
            #[cfg(fuzzing)]
            untrusted_proxy_actor: false,
            #[cfg(fuzzing)]
            tenant_claims: Vec::new(),
        }
    }

    /// Parses one bounded compatibility alias. It remains validation evidence
    /// and can never select a Principal, Scope, or Tenant ID.
    pub fn external_tenant_alias(alias: &str) -> Result<Self, AttributionFailure> {
        let alias = ExternalTenantAlias::parse(alias).map_err(|_| AttributionFailure)?;
        Ok(Self {
            external_alias: Some(alias),
            proxy_actor: None,
            #[cfg(fuzzing)]
            untrusted_proxy_actor: false,
            #[cfg(fuzzing)]
            tenant_claims: Vec::new(),
        })
    }

    /// Preserves bounded, trusted-proxy actor evidence while keeping the
    /// credential-derived Principal, Scope, and Tenant authoritative.
    pub fn trusted_proxy(
        external_alias: Option<&str>,
        actor: Option<&str>,
    ) -> Result<Self, AttributionFailure> {
        let external_alias = external_alias
            .map(ExternalTenantAlias::parse)
            .transpose()
            .map_err(|_| AttributionFailure)?;
        let proxy_actor = actor.map(ProxyActorContext::new).transpose()?;
        Ok(Self {
            external_alias,
            proxy_actor,
            #[cfg(fuzzing)]
            untrusted_proxy_actor: false,
            #[cfg(fuzzing)]
            tenant_claims: Vec::new(),
        })
    }

    /// Builds untrusted proxy and tenant-selection evidence only in fuzz
    /// builds so arbitrary inputs exercise the real attribution boundary.
    #[cfg(fuzzing)]
    pub fn fuzz_adversarial(source: &[u8]) -> Self {
        let mut tenant_claims = source
            .chunks(16)
            .take(2)
            .map(|chunk| {
                let mut claim = [0_u8; 16];
                claim[..chunk.len()].copy_from_slice(chunk);
                claim
            })
            .collect::<Vec<_>>();
        if tenant_claims.is_empty() {
            tenant_claims.push([1; 16]);
        }
        Self {
            external_alias: None,
            proxy_actor: None,
            untrusted_proxy_actor: source.first().is_none_or(|byte| byte & 1 != 0),
            tenant_claims,
        }
    }

    pub(super) fn has_untrusted_authority_claims(&self) -> bool {
        #[cfg(fuzzing)]
        {
            self.untrusted_proxy_actor || !self.tenant_claims.is_empty()
        }
        #[cfg(not(fuzzing))]
        {
            false
        }
    }
}

/// A one-way digest of a proxy-supplied user or service identifier. The raw
/// forwarded value is never retained in the authorization context.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProxyActorContext {
    digest: [u8; 32],
}

impl ProxyActorContext {
    fn new(actor: &str) -> Result<Self, AttributionFailure> {
        if !(1..=128).contains(&actor.len()) || !actor.as_bytes().iter().all(u8::is_ascii_graphic) {
            return Err(AttributionFailure);
        }
        Ok(Self {
            digest: Sha256::digest(actor.as_bytes()).into(),
        })
    }
}

impl std::fmt::Debug for ProxyActorContext {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProxyActorContext { <redacted> }")
    }
}

/// An authenticated context. Tenant data contexts can only contain a checked
/// [`TenantAttribution`]; a system administrator has no tenant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedContext {
    pub(super) principal: PrincipalId,
    pub(super) scope: Scope,
    pub(super) tenant: Option<TenantAttribution>,
    pub(super) authority: [u8; 16],
    pub(super) generation: u64,
    pub(super) lifecycle: TenantLifecycleState,
    pub(super) proxy_actor: Option<ProxyActorContext>,
}

impl AuthorizedContext {
    #[must_use]
    pub const fn principal_id(self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub const fn scope(self) -> Scope {
        self.scope
    }

    #[must_use]
    pub const fn tenant_attribution(self) -> Option<TenantAttribution> {
        self.tenant
    }

    #[must_use]
    pub const fn authorization_generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn tenant_lifecycle(self) -> TenantLifecycleState {
        self.lifecycle
    }

    /// Returns only the presence of redacted proxy-actor evidence. It cannot
    /// alter this context's Principal, Scope, or Tenant Attribution.
    #[must_use]
    pub const fn has_proxy_actor_context(self) -> bool {
        self.proxy_actor.is_some()
    }
}

/// Constant-shape authentication and authorization rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributionFailure;

impl Display for AttributionFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("credential or authority was rejected")
    }
}

impl Error for AttributionFailure {}

/// A closed failure for missing, duplicate, or malformed Catalog identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityFailure;

impl Display for IdentityFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("identity state is unavailable")
    }
}

impl Error for IdentityFailure {}

/// A closed, read-only governance capability created only from an authorized
/// system-administration context bound to this identity authority.
#[derive(Debug)]
pub struct GovernanceInspection<'identity, 'audit> {
    identity_tenant: TenantId,
    identity_slug: &'identity TenantSlug,
    audit: &'audit [GovernanceAuditEntry],
}

impl GovernanceInspection<'_, '_> {
    pub(super) fn new<'slug, 'audit>(
        identity_tenant: TenantId,
        identity_slug: &'slug TenantSlug,
        audit: &'audit [GovernanceAuditEntry],
    ) -> GovernanceInspection<'slug, 'audit> {
        GovernanceInspection {
            identity_tenant,
            identity_slug,
            audit,
        }
    }

    #[must_use]
    pub const fn audit_records(&self) -> &[GovernanceAuditEntry] {
        self.audit
    }

    #[must_use]
    pub fn contains_tenant_id(&self, candidate: TenantId) -> bool {
        self.identity_tenant == candidate
    }

    #[must_use]
    pub fn contains_tenant_slug(&self, candidate: &TenantSlug) -> bool {
        self.identity_slug == candidate
    }
}
