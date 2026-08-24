//! Generation-pinned identity and Tenant Attribution for the M1 bootstrap state.

mod attribution;
pub(super) mod codec;

pub use attribution::{
    AttributionFailure, AuthorizedContext, CompatibilityHints, GovernanceInspection,
    IdentityFailure, PresentedCredential, RequestedIntent,
};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

use std::fmt::Formatter;

use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::{BootstrapKeyCustody, CatalogSnapshot};

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
        Ok(GovernanceInspection::new(
            self.tenant,
            &self.tenant_slug,
            audit,
        ))
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

const fn is_query_readable(state: TenantLifecycleState) -> bool {
    matches!(
        state,
        TenantLifecycleState::Active | TenantLifecycleState::ReadOnly
    )
}
