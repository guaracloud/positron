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

use positron_domain::identity::{
    ExternalTenantAlias, PrincipalId, Scope, TenantAttribution, TenantId, TenantSlug,
};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::{BootstrapKeyCustody, CatalogObjectId, CatalogSnapshot};

use crate::GovernanceAuditEntry;

use codec::identity_from_catalog;

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

#[derive(Clone)]
pub(super) struct CredentialIdentity {
    pub(super) principal: PrincipalId,
    pub(super) scope: Scope,
    pub(super) active: bool,
    pub(super) expires_at_unix_seconds: Option<u64>,
    pub(super) salt: [u8; 32],
    pub(super) hash: [u8; 32],
}

/// The sole immutable identity view reconstructed from one Catalog Generation.
#[derive(Clone)]
pub struct Identity {
    instance: [u8; 16],
    generation: u64,
    principal: PrincipalId,
    tenant: TenantId,
    tenant_slug: TenantSlug,
    external_alias: Option<ExternalTenantAlias>,
    salt: [u8; 32],
    hash: [u8; 32],
    ingest: Option<IngestIdentity>,
    query: Option<QueryIdentity>,
    credentials: Vec<CredentialIdentity>,
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
        Self::open_with_object(snapshot).map(|(identity, _)| identity)
    }

    fn open_with_object(
        snapshot: &CatalogSnapshot,
    ) -> Result<(Self, CatalogObjectId), IdentityFailure> {
        let (object_id, governance) = snapshot.governance_object().map_err(|_| IdentityFailure)?;
        let mut decoded = identity_from_catalog(governance)?;
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
        Ok((decoded, object_id))
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
        self.attribute_at(keys, credential, intent, hints, None)
    }

    /// Attributes a credential against a Storage Kernel lifecycle-clock
    /// observation. Expiring credentials fail closed if that authority is not
    /// available; wall-clock values are never accepted here.
    pub fn attribute_at(
        &self,
        keys: &BootstrapKeyCustody,
        credential: PresentedCredential,
        intent: RequestedIntent,
        hints: CompatibilityHints,
        lifecycle_seconds: Option<u64>,
    ) -> Result<AuthorizedContext, AttributionFailure> {
        let alias_matches = match (&self.external_alias, &hints.external_alias) {
            (_, None) => true,
            (Some(bound), Some(presented)) => bound == presented,
            (None, Some(_)) => false,
        };
        if hints.has_untrusted_authority_claims()
            || (matches!(intent, RequestedIntent::SystemAdministration)
                && hints.external_alias.is_some())
            || !alias_matches
        {
            return Err(AttributionFailure);
        }
        if !self.credentials.is_empty() {
            let scope = match intent {
                RequestedIntent::Ingest => Scope::Ingest,
                RequestedIntent::Query => Scope::Query,
                RequestedIntent::TenantAdministration => Scope::TenantAdministration,
                RequestedIntent::SystemAdministration => Scope::SystemAdministration,
            };
            let mut selected = None;
            for candidate in &self.credentials {
                let matches = keys
                    .verify_salted_secret_hash(
                        &candidate.salt,
                        credential.secret(),
                        &candidate.hash,
                    )
                    .map_err(|_| AttributionFailure)?;
                let unexpired = candidate
                    .expires_at_unix_seconds
                    .is_none_or(|expiry| lifecycle_seconds.is_some_and(|now| now < expiry));
                if matches && candidate.active && unexpired && candidate.scope == scope {
                    selected = Some(candidate);
                }
            }
            let candidate = selected.ok_or(AttributionFailure)?;
            if scope == Scope::Ingest && self.lifecycle != TenantLifecycleState::Active {
                return Err(AttributionFailure);
            }
            if scope == Scope::Query && !is_query_readable(self.lifecycle) {
                return Err(AttributionFailure);
            }
            return Ok(AuthorizedContext {
                principal: candidate.principal,
                scope,
                tenant: scope
                    .is_tenant_scoped()
                    .then(|| TenantAttribution::new(candidate.principal, scope, self.tenant))
                    .transpose()
                    .map_err(|_| AttributionFailure)?,
                authority: self.instance,
                generation: self.generation,
                lifecycle: self.lifecycle,
            });
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
