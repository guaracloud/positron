//! Positron Administration-owned governance intent.
//!
//! The implemented slice owns the semantic initial tenant, principal, policy,
//! quota, key-hash, integrity-identity, and audit intent used by Instance
//! Bootstrap. The Storage Kernel remains the sole durable publication owner.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};

mod audit;
mod identity;

pub use audit::GovernanceAuditEntry;
pub use identity::{
    AttributionFailure, AuthorizedContext, CompatibilityHints, Identity, IdentityFailure,
    IdentityReservations, PresentedCredential, RequestedIntent,
};

const GOVERNANCE_OBJECT_MAGIC: [u8; 8] = *b"POSGOV01";
const GOVERNANCE_AUDIT_MAGIC: [u8; 8] = *b"POSAUD01";

/// Administration-owned semantic proposal for the initial governance state.
pub struct InitialGovernanceIntent {
    object: Vec<u8>,
    audit: Vec<u8>,
}

pub struct InitialTenantIntent {
    instance: [u8; 16],
    tenant: TenantId,
    slug: TenantSlug,
    display_name: String,
    principal: PrincipalId,
    api_key_salt: [u8; 32],
    api_key_hash: [u8; 32],
    integrity_public_key: [u8; 32],
    integrity_key_fingerprint: [u8; 32],
    protected_integrity_key: Vec<u8>,
    tenant_key_envelope: Vec<u8>,
    retention_seconds: u64,
    quota_generation: u64,
    quota_weight: u32,
    quota_resources: [u64; 11],
}

impl InitialTenantIntent {
    #[expect(
        clippy::too_many_arguments,
        reason = "canonical tenant creation requires every jointly committed authority"
    )]
    pub fn new(
        instance: [u8; 16],
        tenant: TenantId,
        slug: TenantSlug,
        display_name: &str,
        principal: PrincipalId,
        api_key_salt: [u8; 32],
        api_key_hash: [u8; 32],
        integrity_public_key: [u8; 32],
        integrity_key_fingerprint: [u8; 32],
        protected_integrity_key: Vec<u8>,
        tenant_key_envelope: Vec<u8>,
        retention_seconds: u64,
        quota_generation: u64,
        quota_weight: u32,
        quota_resources: [u64; 11],
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
            display_name: display_name.to_owned(),
            principal,
            api_key_salt,
            api_key_hash,
            integrity_public_key,
            integrity_key_fingerprint,
            protected_integrity_key,
            tenant_key_envelope,
            retention_seconds,
            quota_generation,
            quota_weight,
            quota_resources,
        })
    }
}

impl InitialGovernanceIntent {
    pub fn create_tenant(intent: InitialTenantIntent) -> Result<Self, GovernanceIntentFailure> {
        let InitialTenantIntent {
            instance,
            tenant,
            slug,
            display_name,
            principal,
            api_key_salt,
            api_key_hash,
            integrity_public_key,
            integrity_key_fingerprint,
            protected_integrity_key,
            tenant_key_envelope,
            retention_seconds,
            quota_generation,
            quota_weight,
            quota_resources,
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
        object.push(display_length);
        object.extend_from_slice(display_bytes);
        object.extend_from_slice(&principal.to_bytes());
        object.extend_from_slice(&api_key_salt);
        object.extend_from_slice(&api_key_hash);
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
        let mut audit = Vec::with_capacity(74);
        audit.extend_from_slice(&GOVERNANCE_AUDIT_MAGIC);
        audit.extend_from_slice(&principal.to_bytes());
        audit.extend_from_slice(&tenant.to_bytes());
        audit.push(19);
        audit.extend_from_slice(b"instance.initialize");
        audit.push(9);
        audit.extend_from_slice(b"succeeded");
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

#[cfg(test)]
#[path = "tests/initial_tenant.rs"]
mod tests;
