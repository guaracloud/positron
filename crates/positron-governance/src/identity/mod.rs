//! Generation-pinned identity and Tenant Attribution for the M1 bootstrap state.

mod attribution;
pub(super) mod codec;

pub use attribution::{
    AttributionFailure, AuthorizedContext, CompatibilityHints, GovernanceAuditInspection,
    GovernanceInspection, IdentityFailure, PresentedCredential, RequestedIntent,
};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

use std::fmt::Formatter;

use positron_domain::identity::{
    ExternalTenantAlias, PrincipalId, Scope, TenantAttribution, TenantId, TenantSlug,
};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::{BootstrapKeyCustody, CatalogSnapshot, FormatEpoch};

use crate::tenant_quota_record::tenant_alias_record;
use crate::{ApiKeyAdministration, GovernanceAuditEntry, TenantAdministration};

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

#[derive(Clone)]
struct AdditionalTenantIdentity {
    tenant: TenantId,
    lifecycle: TenantLifecycleState,
    external_alias: Option<ExternalTenantAlias>,
    credentials: Vec<CredentialIdentity>,
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
    tenant_key_envelope: Vec<u8>,
    additional_tenant_key_envelopes: Vec<(TenantId, Vec<u8>)>,
    additional_tenant_lifecycles: Vec<(TenantId, TenantLifecycleState)>,
    additional_tenants: Vec<AdditionalTenantIdentity>,
}

impl Identity {
    /// Authorizes a system-wide Governance Audit retention mutation. Tenant
    /// scopes and data-plane credentials never acquire this authority.
    pub fn authorize_system_audit_retention(
        &self,
        context: AuthorizedContext,
    ) -> Result<PrincipalId, AttributionFailure> {
        if context.authority == self.instance
            && context.scope == Scope::SystemAdministration
            && context.principal == self.principal
            && context.tenant.is_none()
            && (self.credentials.is_empty()
                || self.credentials.iter().any(|credential| {
                    credential.principal == context.principal
                        && credential.scope == Scope::SystemAdministration
                        && credential.active
                }))
        {
            Ok(context.principal)
        } else {
            Err(AttributionFailure)
        }
    }

    /// Authorizes a retention preview or confirmed update for one tenant.
    /// Tenant administrators are bound to their own active or read-only
    /// tenant; system administration is reserved for in-process governance
    /// recovery workflows.
    pub fn authorize_tenant_retention(
        &self,
        context: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<PrincipalId, AttributionFailure> {
        self.authorize_policy_activation(context, tenant)
    }

    pub(super) fn authorize_policy_activation(
        &self,
        context: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<PrincipalId, AttributionFailure> {
        let lifecycle = self.tenant_lifecycle(tenant).ok_or(AttributionFailure)?;
        if context.authority != self.instance {
            return Err(AttributionFailure);
        }
        match context.scope {
            Scope::SystemAdministration
                if context.principal == self.principal && context.tenant.is_none() =>
            {
                Ok(context.principal)
            },
            Scope::TenantAdministration
                if matches!(
                    lifecycle,
                    TenantLifecycleState::Active | TenantLifecycleState::ReadOnly
                ) && context.lifecycle == lifecycle
                    && context.tenant.is_some_and(|attribution| {
                        attribution.principal_id() == context.principal
                            && attribution.scope() == Scope::TenantAdministration
                            && attribution.tenant_id() == tenant
                    })
                    && self.active_tenant_credential(
                        tenant,
                        context.principal,
                        Scope::TenantAdministration,
                    ) =>
            {
                Ok(context.principal)
            },
            Scope::Ingest
            | Scope::Query
            | Scope::TenantAdministration
            | Scope::SystemAdministration => Err(AttributionFailure),
        }
    }

    pub(super) fn authorize_quota_update(
        &self,
        context: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<PrincipalId, AttributionFailure> {
        self.authorize_policy_activation(context, tenant)
    }

    /// Reconstructs the unique initialization identity from a pinned Catalog.
    pub fn open(snapshot: &CatalogSnapshot) -> Result<Self, IdentityFailure> {
        let (_, governance) = snapshot.governance_object().map_err(|_| IdentityFailure)?;
        let mut identity = identity_from_catalog(governance)?;
        if snapshot.format_epoch() == Some(FormatEpoch::CATALOG_V2)
            && !TenantAdministration::registered_tenant_ids(snapshot)
                .map_err(|_| IdentityFailure)?
                .contains(&identity.tenant)
        {
            return Err(IdentityFailure);
        }
        if snapshot.format_epoch() == Some(FormatEpoch::CATALOG_V2) {
            let lifecycles = TenantAdministration::registered_tenant_lifecycles(snapshot)
                .map_err(|_| IdentityFailure)?;
            identity.additional_tenant_lifecycles = lifecycles
                .iter()
                .filter_map(|(tenant, lifecycle)| {
                    (*tenant != identity.tenant).then_some((*tenant, *lifecycle))
                })
                .collect();
            identity.additional_tenant_key_envelopes =
                TenantAdministration::registered_tenant_key_envelopes(snapshot)
                    .map_err(|_| IdentityFailure)?;
            identity.additional_tenants =
                ApiKeyAdministration::tenant_credential_identities(snapshot)
                    .map_err(|_| IdentityFailure)?
                    .into_iter()
                    .map(|record| {
                        let lifecycle = lifecycles
                            .iter()
                            .find_map(|(tenant, lifecycle)| {
                                (*tenant == record.tenant).then_some(*lifecycle)
                            })
                            .ok_or(IdentityFailure)?;
                        let credentials = record
                            .credentials
                            .into_iter()
                            .map(|credential| {
                                let scope = match credential.scope_code() {
                                    1 => Scope::Ingest,
                                    2 => Scope::Query,
                                    3 => Scope::TenantAdministration,
                                    _ => return Err(IdentityFailure),
                                };
                                let (salt, hash) = credential.salted_hash();
                                Ok(CredentialIdentity {
                                    principal: credential.principal(),
                                    scope,
                                    active: credential.is_active(),
                                    expires_at_unix_seconds: credential.expires_at_unix_seconds(),
                                    salt,
                                    hash,
                                })
                            })
                            .collect::<Result<Vec<_>, IdentityFailure>>()?;
                        let external_alias = tenant_alias_record(snapshot, record.tenant)
                            .map_err(|_| IdentityFailure)?
                            .ok_or(IdentityFailure)?
                            .alias;
                        Ok(AdditionalTenantIdentity {
                            tenant: record.tenant,
                            lifecycle,
                            external_alias,
                            credentials,
                        })
                    })
                    .collect::<Result<Vec<_>, IdentityFailure>>()?;
        }
        Ok(identity)
    }

    /// Returns the opaque tenant KEK envelope only when the requested tenant
    /// is this immutable identity's authenticated tenant.
    pub fn tenant_key_envelope(&self, tenant: TenantId) -> Result<&[u8], IdentityFailure> {
        if tenant == self.tenant {
            return (!self.tenant_key_envelope.is_empty())
                .then_some(self.tenant_key_envelope.as_slice())
                .ok_or(IdentityFailure);
        }
        self.additional_tenant_key_envelopes
            .iter()
            .find_map(|(candidate, envelope)| (*candidate == tenant).then_some(envelope.as_slice()))
            .ok_or(IdentityFailure)
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
        if hints.has_untrusted_authority_claims()
            || (matches!(intent, RequestedIntent::SystemAdministration)
                && hints.external_alias.is_some())
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
                    selected = Some((candidate.principal, self.tenant, self.lifecycle));
                }
            }
            for identity in &self.additional_tenants {
                for candidate in &identity.credentials {
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
                    if matches
                        && candidate.active
                        && unexpired
                        && candidate.scope == scope
                        && selected
                            .replace((candidate.principal, identity.tenant, identity.lifecycle))
                            .is_some()
                    {
                        return Err(AttributionFailure);
                    }
                }
            }
            let (principal, tenant, lifecycle) = selected.ok_or(AttributionFailure)?;
            let bound_alias = if tenant == self.tenant {
                self.external_alias.as_ref()
            } else {
                self.additional_tenants
                    .iter()
                    .find_map(|identity| {
                        (identity.tenant == tenant).then_some(identity.external_alias.as_ref())
                    })
                    .flatten()
            };
            if !alias_matches(bound_alias, hints.external_alias.as_ref()) {
                return Err(AttributionFailure);
            }
            if scope == Scope::Ingest && lifecycle != TenantLifecycleState::Active {
                return Err(AttributionFailure);
            }
            if scope == Scope::Query && !is_query_readable(lifecycle) {
                return Err(AttributionFailure);
            }
            return Ok(AuthorizedContext {
                principal,
                scope,
                tenant: scope
                    .is_tenant_scoped()
                    .then(|| TenantAttribution::new(principal, scope, tenant))
                    .transpose()
                    .map_err(|_| AttributionFailure)?,
                authority: self.instance,
                generation: self.generation,
                lifecycle,
                proxy_actor: hints.proxy_actor,
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
                    proxy_actor: hints.proxy_actor,
                })
            },
            RequestedIntent::Ingest => {
                if !alias_matches(self.external_alias.as_ref(), hints.external_alias.as_ref()) {
                    return Err(AttributionFailure);
                }
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
                    proxy_actor: hints.proxy_actor,
                })
            },
            RequestedIntent::Query => {
                if !alias_matches(self.external_alias.as_ref(), hints.external_alias.as_ref()) {
                    return Err(AttributionFailure);
                }
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
                    proxy_actor: hints.proxy_actor,
                })
            },
            RequestedIntent::TenantAdministration | RequestedIntent::SystemAdministration => {
                Err(AttributionFailure)
            },
        }
    }

    /// Revalidates a previously attributed query context against this
    /// credential-generation-pinned identity and its current durable lifecycle
    /// state.
    ///
    /// This is intentionally the same constant-shape failure as attribution:
    /// a caller cannot learn whether a tenant was suspended, purged, or merely
    /// presented with a stale context.
    pub fn validate_query_context(
        &self,
        context: AuthorizedContext,
    ) -> Result<(), AttributionFailure> {
        let tenant = context.tenant.ok_or(AttributionFailure)?;
        let lifecycle = self
            .tenant_lifecycle(tenant.tenant_id())
            .ok_or(AttributionFailure)?;
        if context.scope != Scope::Query
            || tenant.principal_id() != context.principal
            || tenant.scope() != Scope::Query
            || context.authority != self.instance
            || context.generation != self.generation
            || context.lifecycle != lifecycle
            || !is_query_readable(lifecycle)
            || !self.active_tenant_credential(tenant.tenant_id(), context.principal, Scope::Query)
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
        let lifecycle = self
            .tenant_lifecycle(tenant.tenant_id())
            .ok_or(AttributionFailure)?;
        if context.scope != Scope::Ingest
            || tenant.principal_id() != context.principal
            || tenant.scope() != Scope::Ingest
            || context.authority != self.instance
            || context.generation != self.generation
            || context.lifecycle != lifecycle
            || lifecycle != TenantLifecycleState::Active
            || !self.active_tenant_credential(tenant.tenant_id(), context.principal, Scope::Ingest)
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

    fn active_tenant_credential(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
        scope: Scope,
    ) -> bool {
        if tenant == self.tenant {
            return self.credentials.iter().any(|credential| {
                credential.principal == principal && credential.scope == scope && credential.active
            });
        }
        self.additional_tenants.iter().any(|identity| {
            identity.tenant == tenant
                && identity.credentials.iter().any(|credential| {
                    credential.principal == principal
                        && credential.scope == scope
                        && credential.active
                })
        })
    }

    fn tenant_lifecycle(&self, tenant: TenantId) -> Option<TenantLifecycleState> {
        if tenant == self.tenant {
            return Some(self.lifecycle);
        }
        self.additional_tenants
            .iter()
            .find_map(|identity| (identity.tenant == tenant).then_some(identity.lifecycle))
            .or_else(|| {
                self.additional_tenant_lifecycles
                    .iter()
                    .find_map(|(candidate, lifecycle)| (*candidate == tenant).then_some(*lifecycle))
            })
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
            || !self.credentials.iter().any(|credential| {
                credential.principal == context.principal
                    && credential.scope == Scope::SystemAdministration
                    && credential.active
            })
        {
            return Err(AttributionFailure);
        }
        Ok(GovernanceInspection::new(
            self.tenant,
            &self.tenant_slug,
            audit,
        ))
    }

    /// Authorizes a read-only Governance Audit view. System administrators see
    /// every decoded record; tenant administrators see only the records whose
    /// immutable audit meaning explicitly names their attributed tenant.
    pub fn inspect_audit<'audit>(
        &self,
        context: AuthorizedContext,
        audit: &'audit [GovernanceAuditEntry],
    ) -> Result<GovernanceAuditInspection<'audit>, AttributionFailure> {
        if context.scope() == Scope::SystemAdministration {
            self.inspect(context, audit)?;
            return Ok(GovernanceAuditInspection::system(audit));
        }
        if context.scope() != Scope::TenantAdministration {
            return Err(AttributionFailure);
        }
        let tenant = context
            .tenant_attribution()
            .ok_or(AttributionFailure)?
            .tenant_id();
        self.authorize_policy_activation(context, tenant)?;
        Ok(GovernanceAuditInspection::tenant(audit, tenant))
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

fn alias_matches(
    bound: Option<&ExternalTenantAlias>,
    presented: Option<&ExternalTenantAlias>,
) -> bool {
    match (bound, presented) {
        (_, None) => true,
        (Some(bound), Some(presented)) => bound == presented,
        (None, Some(_)) => false,
    }
}

const fn is_query_readable(state: TenantLifecycleState) -> bool {
    matches!(
        state,
        TenantLifecycleState::Active | TenantLifecycleState::ReadOnly
    )
}
