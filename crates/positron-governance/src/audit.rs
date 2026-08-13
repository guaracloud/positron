use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::GovernanceAuditRecord;

use crate::identity::IdentityFailure;

const MAGIC: [u8; 8] = *b"POSAUD01";

/// Administration-owned meaning reconstructed from one committed kernel audit entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceAuditEntry {
    position: u64,
    principal: PrincipalId,
    tenant: Option<TenantId>,
    action: String,
    outcome: String,
}

impl GovernanceAuditEntry {
    pub fn decode(record: &GovernanceAuditRecord) -> Result<Self, IdentityFailure> {
        Self::decode_intent(record.position(), record.intent())
    }

    fn decode_intent(position: u64, encoded: &[u8]) -> Result<Self, IdentityFailure> {
        if encoded.get(..8) != Some(MAGIC.as_slice()) {
            return Err(IdentityFailure);
        }
        let principal =
            PrincipalId::from_bytes(take_array(encoded, 8)?).map_err(|_| IdentityFailure)?;
        let tenant = TenantId::from_bytes(take_array(encoded, 24)?)
            .map(Some)
            .map_err(|_| IdentityFailure)?;
        let action_length = usize::from(*encoded.get(40).ok_or(IdentityFailure)?);
        let action_start = 41_usize;
        let action_end = action_start
            .checked_add(action_length)
            .ok_or(IdentityFailure)?;
        let action = take_text(encoded, action_start, action_end)?;
        let outcome_length = usize::from(*encoded.get(action_end).ok_or(IdentityFailure)?);
        let outcome_start = action_end.checked_add(1).ok_or(IdentityFailure)?;
        let outcome_end = outcome_start
            .checked_add(outcome_length)
            .ok_or(IdentityFailure)?;
        let outcome = take_text(encoded, outcome_start, outcome_end)?;
        if outcome_end != encoded.len() {
            return Err(IdentityFailure);
        }
        Ok(Self {
            position,
            principal,
            tenant,
            action: action.to_owned(),
            outcome: outcome.to_owned(),
        })
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant
    }

    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    #[must_use]
    pub fn outcome(&self) -> &str {
        &self.outcome
    }
}

#[cfg(test)]
#[path = "audit/tests.rs"]
mod tests;

fn take_array<const N: usize>(encoded: &[u8], start: usize) -> Result<[u8; N], IdentityFailure> {
    encoded
        .get(start..start.saturating_add(N))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(IdentityFailure)
}

fn take_text(encoded: &[u8], start: usize, end: usize) -> Result<&str, IdentityFailure> {
    encoded
        .get(start..end)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or(IdentityFailure)
}
