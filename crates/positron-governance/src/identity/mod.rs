//! Generation-pinned identity and Tenant Attribution for the M1 bootstrap state.

pub(super) mod codec;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::{BootstrapKeyCustody, CatalogSnapshot};
use zeroize::Zeroizing;

use crate::GovernanceAuditEntry;

use codec::{
    GOVERNANCE_OBJECT_MAGIC_V1, GOVERNANCE_OBJECT_MAGIC_V2, GOVERNANCE_OBJECT_MAGIC_V3,
    decode_initial_identity,
};

#[derive(Clone)]
struct IngestIdentity {
    principal: PrincipalId,
    salt: [u8; 32],
    hash: [u8; 32],
}

#[derive(Clone)]
struct QueryIdentity {
    principal: PrincipalId,
    salt: [u8; 32],
    hash: [u8; 32],
}

/// The sole immutable identity view reconstructed from one Catalog Generation.
#[derive(Clone)]
pub struct Identity {
    instance: [u8; 16],
    generation: u64,
    principal: PrincipalId,
    tenant: TenantId,
    tenant_slug: TenantSlug,
    salt: [u8; 32],
    hash: [u8; 32],
    ingest: Option<IngestIdentity>,
    query: Option<QueryIdentity>,
    lifecycle: TenantLifecycleState,
}

impl Identity {
    pub(super) fn authorize_policy_activation(
        &self,
        context: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<PrincipalId, AttributionFailure> {
        if context.principal != self.principal
            || context.scope != Scope::SystemAdministration
            || context.tenant.is_some()
            || context.authority != self.instance
            || tenant != self.tenant
        {
            return Err(AttributionFailure);
        }
        Ok(context.principal)
    }

    /// Reconstructs the unique initialization identity from a pinned Catalog.
    pub fn open(snapshot: &CatalogSnapshot) -> Result<Self, IdentityFailure> {
        let mut identity = None;
        for object_id in snapshot.object_identities() {
            let object = snapshot
                .object(object_id)
                .map_err(|_| IdentityFailure)?
                .ok_or(IdentityFailure)?;
            if !object.starts_with(&GOVERNANCE_OBJECT_MAGIC_V1)
                && !object.starts_with(&GOVERNANCE_OBJECT_MAGIC_V2)
                && !object.starts_with(&GOVERNANCE_OBJECT_MAGIC_V3)
            {
                continue;
            }
            if identity.is_some() {
                return Err(IdentityFailure);
            }
            let mut decoded = decode_initial_identity(object)?;
            // Lease, query-marker, and other catalog objects may advance the
            // catalog generation without changing authorization. Bind query
            // revalidation to this immutable governance object instead, so a
            // reconnect after ordinary catalog churn remains authorized while
            // replacing the identity object still changes the binding.
            let object_bytes = object_id.to_bytes();
            decoded.generation = object_bytes
                .get(..8)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes)
                .unwrap_or(1)
                .max(1);
            identity = Some(decoded);
        }
        identity.ok_or(IdentityFailure)
    }

    /// Authenticates and authorizes before a decoder or data-plane admission
    /// boundary can receive a tenant context.
    pub fn attribute(
        &self,
        keys: &BootstrapKeyCustody,
        credential: PresentedCredential,
        intent: RequestedIntent,
        hints: CompatibilityHints,
    ) -> Result<AuthorizedContext, AttributionFailure> {
        if hints.external_alias.is_some() || hints.has_untrusted_authority_claims() {
            return Err(AttributionFailure);
        }
        match intent {
            RequestedIntent::SystemAdministration
                if keys
                    .verify_salted_secret_hash(&self.salt, credential.secret(), &self.hash)
                    .map_err(|_| AttributionFailure)? =>
            {
                Ok(AuthorizedContext {
                    principal: self.principal,
                    scope: Scope::SystemAdministration,
                    tenant: None,
                    authority: self.instance,
                    generation: self.generation,
                    lifecycle: self.lifecycle,
                })
            },
            RequestedIntent::Ingest => {
                if self.lifecycle != TenantLifecycleState::Active {
                    return Err(AttributionFailure);
                }
                let ingest = self.ingest.as_ref().ok_or(AttributionFailure)?;
                if !keys
                    .verify_salted_secret_hash(&ingest.salt, credential.secret(), &ingest.hash)
                    .map_err(|_| AttributionFailure)?
                {
                    return Err(AttributionFailure);
                }
                Ok(AuthorizedContext {
                    principal: ingest.principal,
                    scope: Scope::Ingest,
                    tenant: Some(
                        TenantAttribution::new(ingest.principal, Scope::Ingest, self.tenant)
                            .map_err(|_| AttributionFailure)?,
                    ),
                    authority: self.instance,
                    generation: self.generation,
                    lifecycle: self.lifecycle,
                })
            },
            RequestedIntent::Query => {
                if !is_query_readable(self.lifecycle) {
                    return Err(AttributionFailure);
                }
                let query = self.query.as_ref().ok_or(AttributionFailure)?;
                if !keys
                    .verify_salted_secret_hash(&query.salt, credential.secret(), &query.hash)
                    .map_err(|_| AttributionFailure)?
                {
                    return Err(AttributionFailure);
                }
                Ok(AuthorizedContext {
                    principal: query.principal,
                    scope: Scope::Query,
                    tenant: Some(
                        TenantAttribution::new(query.principal, Scope::Query, self.tenant)
                            .map_err(|_| AttributionFailure)?,
                    ),
                    authority: self.instance,
                    generation: self.generation,
                    lifecycle: self.lifecycle,
                })
            },
            RequestedIntent::TenantAdministration | RequestedIntent::SystemAdministration => {
                Err(AttributionFailure)
            },
        }
    }

    /// Revalidates a previously attributed query context against this
    /// generation-pinned identity and its current durable lifecycle state.
    ///
    /// This is intentionally the same constant-shape failure as attribution:
    /// a caller cannot learn whether a tenant was suspended, purged, or merely
    /// presented with a stale context.
    pub fn validate_query_context(
        &self,
        context: AuthorizedContext,
    ) -> Result<(), AttributionFailure> {
        let tenant = context.tenant.ok_or(AttributionFailure)?;
        if self
            .query
            .as_ref()
            .is_none_or(|query| context.principal != query.principal)
            || context.scope != Scope::Query
            || tenant.principal_id() != context.principal
            || tenant.scope() != Scope::Query
            || tenant.tenant_id() != self.tenant
            || context.authority != self.instance
            || context.generation != self.generation
            || context.lifecycle != self.lifecycle
            || !is_query_readable(self.lifecycle)
        {
            return Err(AttributionFailure);
        }
        Ok(())
    }

    /// Revalidates a previously attributed ingest context against this
    /// generation-pinned identity and its current durable lifecycle state.
    pub fn validate_ingest_context(
        &self,
        context: AuthorizedContext,
    ) -> Result<(), AttributionFailure> {
        let tenant = context.tenant.ok_or(AttributionFailure)?;
        if self
            .ingest
            .as_ref()
            .is_none_or(|ingest| context.principal != ingest.principal)
            || context.scope != Scope::Ingest
            || tenant.principal_id() != context.principal
            || tenant.scope() != Scope::Ingest
            || tenant.tenant_id() != self.tenant
            || context.authority != self.instance
            || context.generation != self.generation
            || context.lifecycle != self.lifecycle
            || self.lifecycle != TenantLifecycleState::Active
        {
            return Err(AttributionFailure);
        }
        Ok(())
    }

    /// Revalidates a previously attributed query context against the current
    /// durable identity and lifecycle authority.
    pub fn revalidate_query_context(
        &self,
        context: AuthorizedContext,
    ) -> Result<(), AttributionFailure> {
        self.validate_query_context(context)
    }

    /// Authorizes the narrow read-only governance view without introducing a
    /// general administration API.
    pub fn inspect<'identity, 'audit>(
        &'identity self,
        context: AuthorizedContext,
        audit: &'audit [GovernanceAuditEntry],
    ) -> Result<GovernanceInspection<'identity, 'audit>, AttributionFailure> {
        if context.principal != self.principal
            || context.scope != Scope::SystemAdministration
            || context.tenant.is_some()
            || context.authority != self.instance
        {
            return Err(AttributionFailure);
        }
        Ok(GovernanceInspection {
            identity: self,
            audit,
        })
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("principal", &self.principal)
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

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
    external_alias: Option<String>,
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
            #[cfg(fuzzing)]
            untrusted_proxy_actor: false,
            #[cfg(fuzzing)]
            tenant_claims: Vec::new(),
        }
    }

    /// Parses one bounded compatibility alias. It remains validation evidence
    /// and can never select a Principal, Scope, or Tenant ID.
    pub fn external_tenant_alias(alias: &str) -> Result<Self, AttributionFailure> {
        if alias.is_empty()
            || alias.len() > 128
            || !alias
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(AttributionFailure);
        }
        Ok(Self {
            external_alias: Some(alias.to_owned()),
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
            untrusted_proxy_actor: source.first().is_none_or(|byte| byte & 1 != 0),
            tenant_claims,
        }
    }

    fn has_untrusted_authority_claims(&self) -> bool {
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

/// An authenticated context. Tenant data contexts can only contain a checked
/// [`TenantAttribution`]; a system administrator has no tenant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedContext {
    principal: PrincipalId,
    scope: Scope,
    tenant: Option<TenantAttribution>,
    authority: [u8; 16],
    generation: u64,
    lifecycle: TenantLifecycleState,
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
}

const fn is_query_readable(state: TenantLifecycleState) -> bool {
    matches!(
        state,
        TenantLifecycleState::Active | TenantLifecycleState::ReadOnly
    )
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
    identity: &'identity Identity,
    audit: &'audit [GovernanceAuditEntry],
}

impl GovernanceInspection<'_, '_> {
    #[must_use]
    pub const fn audit_records(&self) -> &[GovernanceAuditEntry] {
        self.audit
    }

    #[must_use]
    pub fn contains_tenant_id(&self, candidate: TenantId) -> bool {
        self.identity.tenant == candidate
    }

    #[must_use]
    pub fn contains_tenant_slug(&self, candidate: &TenantSlug) -> bool {
        &self.identity.tenant_slug == candidate
    }
}
