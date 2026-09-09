//! Positron Administration-owned governance intent.
//!
//! The implemented slice owns the semantic initial tenant, principal, policy,
//! quota, key-hash, integrity-identity, and audit intent used by Instance
//! Bootstrap. The Storage Kernel remains the sole durable publication owner.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, TenantId, TenantSlug};

mod api_key_administration;
mod audit;
mod identity;
mod listener_transport_administration;
mod policy_administration;
mod tenant_lifecycle_administration;

pub use api_key_administration::{
    ApiKeyAdministration, ApiKeyAdministrationFailure, ApiKeyCreateRequest, ApiKeyCreation,
    ApiKeyDescriptor,
};
pub use audit::{
    ApiKeyLifecycleAction, CatalogRootRotationAuditEntry, CatalogRootRotationStage,
    GovernanceAuditEntry, IngestPolicyActivationAuditEntry, InitialAuditMetadata,
    InitializationAuditEntry, ListenerTransportAuditEntry, SchemaCheckpointAuditEntry,
    schema_checkpoint_audit_intent,
};
pub use identity::{
    AttributionFailure, AuthorizedContext, CompatibilityHints, GovernanceInspection, Identity,
    IdentityFailure, PresentedCredential, RequestedIntent,
};
pub use listener_transport_administration::{
    ListenerTransportActivation, ListenerTransportAdministration,
    ListenerTransportAdministrationFailure,
};
pub use policy_administration::{
    AdministrativeIdempotencyKey, IngestPolicyActivation, IngestPolicyAdministration,
    IngestPolicyServingSnapshot, PolicyAdministrationFailure, PolicyAdministrationFailureCode,
    ResourceGeneration,
};
pub use tenant_lifecycle_administration::{
    TenantLifecycleAdministration, TenantLifecycleAdministrationFailure,
    TenantLifecycleGenerationConflict, TenantLifecycleTransition, TenantLifecycleTransitionRequest,
};

const GOVERNANCE_OBJECT_MAGIC: [u8; 8] = *b"POSGOV05";
const GOVERNANCE_AUDIT_MAGIC: [u8; 8] = *b"POSAUD02";
const DEFAULT_EXTERNAL_TENANT_ALIAS: &str = "trace-external";

/// Administration-owned semantic proposal for the initial governance state.
pub struct InitialGovernanceIntent {
    object: Vec<u8>,
    audit: Vec<u8>,
}

pub struct InitialTenantIntent {
    instance: [u8; 16],
    tenant: TenantId,
    slug: TenantSlug,
    external_alias: ExternalTenantAlias,
    display_name: String,
    principal: PrincipalId,
    api_key_salt: [u8; 32],
    api_key_hash: [u8; 32],
    ingest_principal: PrincipalId,
    ingest_api_key_salt: [u8; 32],
    ingest_api_key_hash: [u8; 32],
    query_principal: PrincipalId,
    query_api_key_salt: [u8; 32],
    query_api_key_hash: [u8; 32],
    integrity_public_key: [u8; 32],
    integrity_key_fingerprint: [u8; 32],
    protected_integrity_key: Vec<u8>,
    tenant_key_envelope: Vec<u8>,
    retention_seconds: u64,
    quota_generation: u64,
    quota_weight: u32,
    quota_resources: [u64; 11],
    audit: InitialAuditContext,
}

/// Deterministic, non-secret evidence assigned by Instance Bootstrap before
/// the joint Catalog and governance-audit commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialAuditContext {
    ingest_time_unix_seconds: u64,
    request_id: [u8; 16],
    non_interactive: bool,
}

impl InitialAuditContext {
    pub fn new(
        ingest_time_unix_seconds: u64,
        request_id: [u8; 16],
        non_interactive: bool,
    ) -> Result<Self, GovernanceIntentFailure> {
        if ingest_time_unix_seconds == 0 || request_id.iter().all(|byte| *byte == 0) {
            return Err(GovernanceIntentFailure);
        }
        Ok(Self {
            ingest_time_unix_seconds,
            request_id,
            non_interactive,
        })
    }
}

impl InitialTenantIntent {
    #[expect(
        clippy::too_many_arguments,
        reason = "compatibility constructor delegates to the explicitly bound alias constructor"
    )]
    pub fn new(
        instance: [u8; 16],
        tenant: TenantId,
        slug: TenantSlug,
        display_name: &str,
        principal: PrincipalId,
        api_key_salt: [u8; 32],
        api_key_hash: [u8; 32],
        ingest_principal: PrincipalId,
        ingest_api_key_salt: [u8; 32],
        ingest_api_key_hash: [u8; 32],
        query_principal: PrincipalId,
        query_api_key_salt: [u8; 32],
        query_api_key_hash: [u8; 32],
        integrity_public_key: [u8; 32],
        integrity_key_fingerprint: [u8; 32],
        protected_integrity_key: Vec<u8>,
        tenant_key_envelope: Vec<u8>,
        retention_seconds: u64,
        quota_generation: u64,
        quota_weight: u32,
        quota_resources: [u64; 11],
        audit: InitialAuditContext,
    ) -> Result<Self, GovernanceIntentFailure> {
        let external_alias = ExternalTenantAlias::parse(DEFAULT_EXTERNAL_TENANT_ALIAS)
            .map_err(|_| GovernanceIntentFailure)?;
        Self::new_with_external_tenant_alias(
            instance,
            tenant,
            slug,
            external_alias,
            display_name,
            principal,
            api_key_salt,
            api_key_hash,
            ingest_principal,
            ingest_api_key_salt,
            ingest_api_key_hash,
            query_principal,
            query_api_key_salt,
            query_api_key_hash,
            integrity_public_key,
            integrity_key_fingerprint,
            protected_integrity_key,
            tenant_key_envelope,
            retention_seconds,
            quota_generation,
            quota_weight,
            quota_resources,
            audit,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "canonical tenant creation requires every jointly committed authority"
    )]
    pub fn new_with_external_tenant_alias(
        instance: [u8; 16],
        tenant: TenantId,
        slug: TenantSlug,
        external_alias: ExternalTenantAlias,
        display_name: &str,
        principal: PrincipalId,
        api_key_salt: [u8; 32],
        api_key_hash: [u8; 32],
        ingest_principal: PrincipalId,
        ingest_api_key_salt: [u8; 32],
        ingest_api_key_hash: [u8; 32],
        query_principal: PrincipalId,
        query_api_key_salt: [u8; 32],
        query_api_key_hash: [u8; 32],
        integrity_public_key: [u8; 32],
        integrity_key_fingerprint: [u8; 32],
        protected_integrity_key: Vec<u8>,
        tenant_key_envelope: Vec<u8>,
        retention_seconds: u64,
        quota_generation: u64,
        quota_weight: u32,
        quota_resources: [u64; 11],
        audit: InitialAuditContext,
    ) -> Result<Self, GovernanceIntentFailure> {
        if instance.iter().all(|byte| *byte == 0)
            || display_name.is_empty()
            || display_name.len() > 128
            || protected_integrity_key.is_empty()
            || tenant_key_envelope.is_empty()
            || retention_seconds == 0
            || quota_generation == 0
            || quota_weight == 0
            || quota_resources.contains(&0)
        {
            return Err(GovernanceIntentFailure);
        }
        Ok(Self {
            instance,
            tenant,
            slug,
            external_alias,
            display_name: display_name.to_owned(),
            principal,
            api_key_salt,
            api_key_hash,
            ingest_principal,
            ingest_api_key_salt,
            ingest_api_key_hash,
            query_principal,
            query_api_key_salt,
            query_api_key_hash,
            integrity_public_key,
            integrity_key_fingerprint,
            protected_integrity_key,
            tenant_key_envelope,
            retention_seconds,
            quota_generation,
            quota_weight,
            quota_resources,
            audit,
        })
    }
}

impl InitialGovernanceIntent {
    pub fn create_tenant(intent: InitialTenantIntent) -> Result<Self, GovernanceIntentFailure> {
        let InitialTenantIntent {
            instance,
            tenant,
            slug,
            external_alias,
            display_name,
            principal,
            api_key_salt,
            api_key_hash,
            ingest_principal,
            ingest_api_key_salt,
            ingest_api_key_hash,
            query_principal,
            query_api_key_salt,
            query_api_key_hash,
            integrity_public_key,
            integrity_key_fingerprint,
            protected_integrity_key,
            tenant_key_envelope,
            retention_seconds,
            quota_generation,
            quota_weight,
            quota_resources,
            audit: audit_context,
        } = intent;
        if protected_integrity_key.is_empty() || protected_integrity_key.len() > u16::MAX as usize {
            return Err(GovernanceIntentFailure);
        }
        let slug_bytes = slug.as_str().as_bytes();
        let slug_length = u8::try_from(slug_bytes.len()).map_err(|_| GovernanceIntentFailure)?;
        let display_bytes = display_name.as_bytes();
        let display_length =
            u8::try_from(display_bytes.len()).map_err(|_| GovernanceIntentFailure)?;
        let integrity_length =
            u16::try_from(protected_integrity_key.len()).map_err(|_| GovernanceIntentFailure)?;
        let tenant_key_length =
            u16::try_from(tenant_key_envelope.len()).map_err(|_| GovernanceIntentFailure)?;
        let mut object = Vec::with_capacity(
            8 + 16
                + 16
                + 1
                + slug_bytes.len()
                + 16
                + 32
                + 32
                + 32
                + 32
                + 2
                + protected_integrity_key.len()
                + 6,
        );
        object.extend_from_slice(&GOVERNANCE_OBJECT_MAGIC);
        object.extend_from_slice(&instance);
        object.extend_from_slice(&tenant.to_bytes());
        object.push(slug_length);
        object.extend_from_slice(slug_bytes);
        object.push(1);
        let alias_bytes = external_alias.as_str().as_bytes();
        object.push(u8::try_from(alias_bytes.len()).map_err(|_| GovernanceIntentFailure)?);
        object.extend_from_slice(alias_bytes);
        object.push(display_length);
        object.extend_from_slice(display_bytes);
        object.extend_from_slice(&principal.to_bytes());
        object.extend_from_slice(&api_key_salt);
        object.extend_from_slice(&api_key_hash);
        object.extend_from_slice(&ingest_principal.to_bytes());
        object.extend_from_slice(&ingest_api_key_salt);
        object.extend_from_slice(&ingest_api_key_hash);
        object.extend_from_slice(&query_principal.to_bytes());
        object.extend_from_slice(&query_api_key_salt);
        object.extend_from_slice(&query_api_key_hash);
        object.extend_from_slice(&integrity_public_key);
        object.extend_from_slice(&integrity_key_fingerprint);
        object.extend_from_slice(&integrity_length.to_be_bytes());
        object.extend_from_slice(&protected_integrity_key);
        object.extend_from_slice(&tenant_key_length.to_be_bytes());
        object.extend_from_slice(&tenant_key_envelope);
        object.extend_from_slice(&retention_seconds.to_be_bytes());
        object.extend_from_slice(&quota_generation.to_be_bytes());
        object.extend_from_slice(&quota_weight.to_be_bytes());
        for resource in quota_resources {
            object.extend_from_slice(&resource.to_be_bytes());
        }
        // Active lifecycle, system-administration scope, policy generation 1,
        // and independent local-key recovery required.
        object.extend_from_slice(&[1, 4, 0, 1, 1]);
        object.extend_from_slice(&1_u64.to_be_bytes());
        object.extend_from_slice(&3_u16.to_be_bytes());
        for (credential_principal, scope, salt, hash) in [
            (principal, 4_u8, api_key_salt, api_key_hash),
            (
                ingest_principal,
                1,
                ingest_api_key_salt,
                ingest_api_key_hash,
            ),
            (query_principal, 2, query_api_key_salt, query_api_key_hash),
        ] {
            object.extend_from_slice(&credential_principal.to_bytes());
            object.push(scope);
            object.push(1);
            object.extend_from_slice(&0_u64.to_be_bytes());
            object.extend_from_slice(&salt);
            object.extend_from_slice(&hash);
        }
        let mut audit = Vec::with_capacity(160);
        audit.extend_from_slice(&GOVERNANCE_AUDIT_MAGIC);
        audit.extend_from_slice(&audit_context.ingest_time_unix_seconds.to_be_bytes());
        audit.extend_from_slice(&principal.to_bytes());
        audit.push(1);
        audit.extend_from_slice(&tenant.to_bytes());
        audit.push(19);
        audit.extend_from_slice(b"instance.initialize");
        audit.push(1);
        audit.extend_from_slice(&instance);
        audit.push(9);
        audit.extend_from_slice(b"succeeded");
        audit.extend_from_slice(&audit_context.request_id);
        audit.push(u8::from(audit_context.non_interactive));
        audit.push(slug_length);
        audit.extend_from_slice(slug_bytes);
        audit.push(u8::try_from(alias_bytes.len()).map_err(|_| GovernanceIntentFailure)?);
        audit.extend_from_slice(alias_bytes);
        Ok(Self { object, audit })
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.object, self.audit)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernanceIntentFailure;

impl Display for GovernanceIntentFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("initial governance intent is invalid")
    }
}

impl Error for GovernanceIntentFailure {}

/// Narrow parser entry point used only by the fuzz build. Product callers use
/// generation-pinned [`Identity`] and committed [`GovernanceAuditEntry`] values.
#[cfg(fuzzing)]
pub fn fuzz_parse_governance(identity: &[u8], audit: &[u8]) {
    let _ = identity::codec::decode_initial_identity(identity);
    let mut transaction = [0_u8; 16];
    if let Some(suffix) = audit.get(audit.len().saturating_sub(16)..) {
        transaction[..suffix.len()].copy_from_slice(suffix);
    }
    let _ = GovernanceAuditEntry::decode_fields(1, transaction, audit);
}

/// Exercises the closed heterogeneous audit decoder with arbitrary fields in
/// fuzz builds; production callers receive kernel-authenticated records.
#[cfg(fuzzing)]
pub fn fuzz_decode_governance_audit(
    position: u64,
    transaction_id: [u8; 16],
    intent: &[u8],
) -> Result<GovernanceAuditEntry, IdentityFailure> {
    GovernanceAuditEntry::decode_fields(position, transaction_id, intent)
}

#[cfg(test)]
#[path = "tests/initial_tenant.rs"]
mod tests;
