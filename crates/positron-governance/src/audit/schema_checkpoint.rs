use positron_domain::identity::TenantId;
use sha2::{Digest, Sha256};

use crate::{GovernanceIntentFailure, IdentityFailure};

use super::Cursor;

pub(super) const MAGIC: [u8; 8] = *b"POSSCH01";
const INTENT_BYTES: usize = MAGIC.len() + 16 + 32;

/// Typed, non-secret evidence for one rebuildable tenant schema checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaCheckpointAuditEntry {
    position: u64,
    transaction_id: [u8; 16],
    tenant: TenantId,
    checkpoint_digest: [u8; 32],
}

impl SchemaCheckpointAuditEntry {
    pub(super) fn decode_intent(
        position: u64,
        transaction_id: [u8; 16],
        intent: &[u8],
    ) -> Result<Self, IdentityFailure> {
        let mut cursor = Cursor::new(intent);
        if cursor.take_array::<8>()? != MAGIC {
            return Err(IdentityFailure);
        }
        let tenant = TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
        let checkpoint_digest = cursor.take_array()?;
        if checkpoint_digest.iter().all(|byte| *byte == 0) || !cursor.is_empty() {
            return Err(IdentityFailure);
        }
        Ok(Self {
            position,
            transaction_id,
            tenant,
            checkpoint_digest,
        })
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        self.transaction_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn checkpoint_digest(&self) -> [u8; 32] {
        self.checkpoint_digest
    }
}

/// Builds the bounded canonical audit intent for a checkpoint replacement.
pub fn schema_checkpoint_audit_intent(
    tenant: TenantId,
    checkpoint: &[u8],
) -> Result<Vec<u8>, GovernanceIntentFailure> {
    let digest: [u8; 32] = Sha256::digest(checkpoint).into();
    let mut intent = Vec::new();
    intent
        .try_reserve_exact(INTENT_BYTES)
        .map_err(|_| GovernanceIntentFailure)?;
    intent.extend_from_slice(&MAGIC);
    intent.extend_from_slice(&tenant.to_bytes());
    intent.extend_from_slice(&digest);
    Ok(intent)
}
