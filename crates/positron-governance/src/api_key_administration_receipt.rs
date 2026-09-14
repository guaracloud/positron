//! Immutable API-key lifecycle replay receipts.

use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{CatalogObject, CatalogSnapshot};

use super::*;

pub(super) const RECEIPT_MAGIC: [u8; 8] = *b"POSKRR01";
const ENCODED_BYTES: usize = 156;

#[derive(Clone, Copy)]
pub(super) struct ReceiptFields {
    pub(super) key: AdministrativeIdempotencyKey,
    pub(super) actor: PrincipalId,
    pub(super) tenant: Option<TenantId>,
    pub(super) action: ApiKeyLifecycleAction,
    pub(super) scope: u8,
    pub(super) expires_at_unix_seconds: Option<u64>,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) principal: PrincipalId,
    pub(super) target: PrincipalId,
    pub(super) audit_position: u64,
    pub(super) request_digest: [u8; 32],
}

pub(super) fn next_audit_position(
    snapshot: &CatalogSnapshot,
) -> Result<u64, ApiKeyAdministrationFailure> {
    snapshot
        .governance_audit_frontier()
        .checked_add(1)
        .ok_or(ApiKeyAdministrationFailure::CapacityExceeded)
}

pub(super) fn object(fields: ReceiptFields) -> Result<CatalogObject, ApiKeyAdministrationFailure> {
    if fields.audit_position == 0
        || fields.request_digest.iter().all(|byte| *byte == 0)
        || scope_from_code(fields.scope).is_none()
    {
        return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(ENCODED_BYTES)
        .map_err(|_| ApiKeyAdministrationFailure::CapacityExceeded)?;
    encoded.extend_from_slice(&RECEIPT_MAGIC);
    encoded.extend_from_slice(&fields.key.to_bytes());
    encoded.extend_from_slice(&fields.actor.to_bytes());
    encoded.push(u8::from(fields.tenant.is_some()));
    encoded.extend_from_slice(&fields.tenant.map_or([0; 16], TenantId::to_bytes));
    encoded.push(action_code(fields.action));
    encoded.push(fields.scope);
    encoded.push(u8::from(fields.expires_at_unix_seconds.is_some()));
    encoded.extend_from_slice(&fields.expires_at_unix_seconds.unwrap_or(0).to_be_bytes());
    encoded.extend_from_slice(&fields.expected.get().to_be_bytes());
    encoded.extend_from_slice(&fields.generation.get().to_be_bytes());
    encoded.extend_from_slice(&fields.principal.to_bytes());
    encoded.extend_from_slice(&fields.target.to_bytes());
    encoded.extend_from_slice(&fields.audit_position.to_be_bytes());
    encoded.extend_from_slice(&fields.request_digest);
    CatalogObject::new(encoded).map_err(map_catalog)
}

pub(super) fn find(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<ReceiptFields>, ApiKeyAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(&RECEIPT_MAGIC) {
            continue;
        }
        let receipt = decode(bytes)?;
        if receipt.key == key && found.replace(receipt).is_some() {
            return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

fn decode(bytes: &[u8]) -> Result<ReceiptFields, ApiKeyAdministrationFailure> {
    if bytes.len() != ENCODED_BYTES {
        return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
    }
    let array16 = |start| -> Result<[u8; 16], ApiKeyAdministrationFailure> {
        bytes
            .get(start..start + 16)
            .and_then(|value| value.try_into().ok())
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)
    };
    let long = |start| -> Result<u64, ApiKeyAdministrationFailure> {
        bytes
            .get(start..start + 8)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)
    };
    let key = AdministrativeIdempotencyKey::new(array16(8)?)
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let actor = PrincipalId::from_bytes(array16(24)?)
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let tenant = match bytes.get(40).copied() {
        Some(0) if array16(41)? == [0; 16] => None,
        Some(1) => Some(
            TenantId::from_bytes(array16(41)?)
                .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
        ),
        _ => return Err(ApiKeyAdministrationFailure::PersistenceUnavailable),
    };
    let action = action_from_code(
        bytes
            .get(57)
            .copied()
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?,
    )?;
    let scope = bytes
        .get(58)
        .copied()
        .filter(|value| scope_from_code(*value).is_some())
        .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let expires_at_unix_seconds = match bytes.get(59).copied() {
        Some(0) if long(60)? == 0 => None,
        Some(1) => Some(long(60)?),
        _ => return Err(ApiKeyAdministrationFailure::PersistenceUnavailable),
    };
    let expected = ResourceGeneration::new(long(68)?)
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let generation = ResourceGeneration::new(long(76)?)
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    if expected.get().checked_add(1) != Some(generation.get()) {
        return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
    }
    let principal = PrincipalId::from_bytes(array16(84)?)
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let target = PrincipalId::from_bytes(array16(100)?)
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let audit_position = long(116)?;
    let request_digest = bytes
        .get(124..156)
        .and_then(|value| value.try_into().ok())
        .filter(|value: &[u8; 32]| value.iter().any(|byte| *byte != 0))
        .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    if audit_position == 0 {
        return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
    }
    Ok(ReceiptFields {
        key,
        actor,
        tenant,
        action,
        scope,
        expires_at_unix_seconds,
        expected,
        generation,
        principal,
        target,
        audit_position,
        request_digest,
    })
}

const fn action_code(action: ApiKeyLifecycleAction) -> u8 {
    match action {
        ApiKeyLifecycleAction::Create => 1,
        ApiKeyLifecycleAction::Rotate => 2,
        ApiKeyLifecycleAction::Revoke => 3,
    }
}

fn action_from_code(code: u8) -> Result<ApiKeyLifecycleAction, ApiKeyAdministrationFailure> {
    match code {
        1 => Ok(ApiKeyLifecycleAction::Create),
        2 => Ok(ApiKeyLifecycleAction::Rotate),
        3 => Ok(ApiKeyLifecycleAction::Revoke),
        _ => Err(ApiKeyAdministrationFailure::PersistenceUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_receipt_rejects_truncation_and_unknown_action() {
        let mut corrupt = vec![0; ENCODED_BYTES];
        corrupt[..8].copy_from_slice(&RECEIPT_MAGIC);
        assert!(decode(&corrupt).is_err());
        corrupt[57] = 9;
        assert!(decode(&corrupt).is_err());
        for end in 0..ENCODED_BYTES {
            assert!(decode(&corrupt[..end]).is_err());
        }
    }
}
