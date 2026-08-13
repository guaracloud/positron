//! Positron Administration-owned governance intent.
//!
//! The implemented slice owns the semantic initial tenant, principal, policy,
//! quota, key-hash, integrity-identity, and audit intent used by Instance
//! Bootstrap. The Storage Kernel remains the sole durable publication owner.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};

const GOVERNANCE_OBJECT_MAGIC: [u8; 8] = *b"POSGOV01";
const GOVERNANCE_AUDIT_INTENT: &[u8] =
    b"principal=bootstrap;action=instance.initialize;target=default-tenant;outcome=succeeded";

/// Administration-owned semantic proposal for the initial governance state.
pub struct InitialGovernanceIntent {
    object: Vec<u8>,
    audit: Vec<u8>,
}

impl InitialGovernanceIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance: [u8; 16],
        tenant: TenantId,
        slug: &TenantSlug,
        principal: PrincipalId,
        api_key_salt: [u8; 32],
        api_key_hash: [u8; 32],
        integrity_public_key: [u8; 32],
        integrity_key_fingerprint: [u8; 32],
        protected_integrity_key: &[u8],
    ) -> Result<Self, GovernanceIntentFailure> {
        if protected_integrity_key.is_empty() || protected_integrity_key.len() > u16::MAX as usize {
            return Err(GovernanceIntentFailure);
        }
        let slug_bytes = slug.as_str().as_bytes();
        let slug_length = u8::try_from(slug_bytes.len()).map_err(|_| GovernanceIntentFailure)?;
        let integrity_length =
            u16::try_from(protected_integrity_key.len()).map_err(|_| GovernanceIntentFailure)?;
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
        object.extend_from_slice(&principal.to_bytes());
        object.extend_from_slice(&api_key_salt);
        object.extend_from_slice(&api_key_hash);
        object.extend_from_slice(&integrity_public_key);
        object.extend_from_slice(&integrity_key_fingerprint);
        object.extend_from_slice(&integrity_length.to_be_bytes());
        object.extend_from_slice(protected_integrity_key);
        // Active tenant, system-administration scope, policy generation 1,
        // quota generation 1, and independent local-key recovery required.
        object.extend_from_slice(&[1, 4, 0, 1, 0, 1]);
        Ok(Self {
            object,
            audit: GOVERNANCE_AUDIT_INTENT.to_vec(),
        })
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
