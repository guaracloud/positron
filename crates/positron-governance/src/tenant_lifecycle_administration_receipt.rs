//! Immutable replay receipts for tenant lifecycle publications.

use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::{CatalogObject, CatalogSnapshot};

use super::*;

pub(super) const RECEIPT_MAGIC: [u8; 8] = *b"POSLRR01";
const ENCODED_BYTES: usize = 122;

#[derive(Clone, Copy)]
pub(super) struct ReceiptFields {
    pub(super) key: AdministrativeIdempotencyKey,
    pub(super) actor: PrincipalId,
    pub(super) tenant: TenantId,
    pub(super) from: TenantLifecycleState,
    pub(super) to: TenantLifecycleState,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) audit_position: u64,
    pub(super) audit_time: u64,
    pub(super) request_digest: [u8; 32],
}

pub(super) fn object(
    snapshot: &CatalogSnapshot,
    mut fields: ReceiptFields,
) -> Result<CatalogObject, TenantLifecycleAdministrationFailure> {
    fields.audit_position = snapshot
        .governance_audit_frontier()
        .checked_add(1)
        .ok_or(TenantLifecycleAdministrationFailure::CapacityExceeded)?;
    object_for_fields(fields)
}

pub(super) fn object_for_fields(
    fields: ReceiptFields,
) -> Result<CatalogObject, TenantLifecycleAdministrationFailure> {
    if fields.audit_position == 0
        || fields.audit_time == 0
        || fields.request_digest.iter().all(|byte| *byte == 0)
    {
        return Err(TenantLifecycleAdministrationFailure::PersistenceUnavailable);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(ENCODED_BYTES)
        .map_err(|_| TenantLifecycleAdministrationFailure::CapacityExceeded)?;
    encoded.extend_from_slice(&RECEIPT_MAGIC);
    encoded.extend_from_slice(&fields.key.to_bytes());
    encoded.extend_from_slice(&fields.actor.to_bytes());
    encoded.extend_from_slice(&fields.tenant.to_bytes());
    encoded.push(state_code(fields.from));
    encoded.push(state_code(fields.to));
    encoded.extend_from_slice(&fields.expected.get().to_be_bytes());
    encoded.extend_from_slice(&fields.generation.get().to_be_bytes());
    encoded.extend_from_slice(&fields.audit_position.to_be_bytes());
    encoded.extend_from_slice(&fields.audit_time.to_be_bytes());
    encoded.extend_from_slice(&fields.request_digest);
    CatalogObject::new(encoded).map_err(map_catalog)
}

pub(super) fn find(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<ReceiptFields>, TenantLifecycleAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(&RECEIPT_MAGIC) {
            continue;
        }
        let receipt = decode(bytes)?;
        if receipt.key == key && found.replace(receipt).is_some() {
            return Err(TenantLifecycleAdministrationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

fn decode(bytes: &[u8]) -> Result<ReceiptFields, TenantLifecycleAdministrationFailure> {
    if bytes.len() != ENCODED_BYTES {
        return Err(TenantLifecycleAdministrationFailure::PersistenceUnavailable);
    }
    let array16 = |start| {
        bytes
            .get(start..start + 16)
            .and_then(|value| value.try_into().ok())
            .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)
    };
    let long = |start| {
        bytes
            .get(start..start + 8)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)
    };
    let key = AdministrativeIdempotencyKey::new(array16(8)?)
        .map_err(|_| TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
    let actor = PrincipalId::from_bytes(array16(24)?)
        .map_err(|_| TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
    let tenant = TenantId::from_bytes(array16(40)?)
        .map_err(|_| TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
    let from = state_from_code(bytes.get(56).copied())?;
    let to = state_from_code(bytes.get(57).copied())?;
    let expected = ResourceGeneration::new(long(58)?)
        .map_err(|_| TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
    let generation = ResourceGeneration::new(long(66)?)
        .map_err(|_| TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
    if expected.get().checked_add(1) != Some(generation.get()) {
        return Err(TenantLifecycleAdministrationFailure::PersistenceUnavailable);
    }
    let audit_position = long(74)?;
    let audit_time = long(82)?;
    let request_digest = bytes
        .get(90..122)
        .and_then(|value| value.try_into().ok())
        .filter(|value: &[u8; 32]| value.iter().any(|byte| *byte != 0))
        .ok_or(TenantLifecycleAdministrationFailure::PersistenceUnavailable)?;
    if audit_position == 0 || audit_time == 0 {
        return Err(TenantLifecycleAdministrationFailure::PersistenceUnavailable);
    }
    Ok(ReceiptFields {
        key,
        actor,
        tenant,
        from,
        to,
        expected,
        generation,
        audit_position,
        audit_time,
        request_digest,
    })
}

const fn state_code(state: TenantLifecycleState) -> u8 {
    match state {
        TenantLifecycleState::Active => 1,
        TenantLifecycleState::ReadOnly => 2,
        TenantLifecycleState::Suspended => 3,
        TenantLifecycleState::Purging => 4,
        TenantLifecycleState::Purged => 5,
    }
}

fn state_from_code(
    code: Option<u8>,
) -> Result<TenantLifecycleState, TenantLifecycleAdministrationFailure> {
    match code {
        Some(1) => Ok(TenantLifecycleState::Active),
        Some(2) => Ok(TenantLifecycleState::ReadOnly),
        Some(3) => Ok(TenantLifecycleState::Suspended),
        Some(4) => Ok(TenantLifecycleState::Purging),
        Some(5) => Ok(TenantLifecycleState::Purged),
        _ => Err(TenantLifecycleAdministrationFailure::PersistenceUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_receipt_rejects_truncation_and_unknown_state() {
        let mut corrupt = vec![0; ENCODED_BYTES];
        corrupt[..8].copy_from_slice(&RECEIPT_MAGIC);
        assert!(decode(&corrupt).is_err());
        corrupt[56] = 9;
        assert!(decode(&corrupt).is_err());
        for end in 0..ENCODED_BYTES {
            assert!(decode(&corrupt[..end]).is_err());
        }
    }
}
