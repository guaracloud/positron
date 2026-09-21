use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{CatalogObject, CatalogSnapshot};
use sha2::{Digest, Sha256};

use super::{
    AdministrativeIdempotencyKey, PolicyAdministrationFailure, PolicyAdministrationFailureCode,
    ResourceGeneration, map_catalog,
};

const RECEIPT_MAGIC_V1: [u8; 8] = *b"POSPID01";
const RECEIPT_MAGIC: [u8; 8] = *b"POSPID02";
const AUDIT_MAGIC: [u8; 8] = *b"POSPOL02";

#[derive(Clone, Copy)]
pub(super) struct ActivationSemantics {
    pub(super) key: AdministrativeIdempotencyKey,
    pub(super) principal: PrincipalId,
    pub(super) tenant: TenantId,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) digest: [u8; 32],
    pub(super) request_digest: [u8; 32],
    pub(super) audit_position: u64,
}

pub(super) struct Receipt {
    pub(super) principal: PrincipalId,
    pub(super) tenant: TenantId,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) digest: [u8; 32],
    pub(super) request_digest: [u8; 32],
    pub(super) audit_position: u64,
}

pub(super) fn request_digest(
    key: AdministrativeIdempotencyKey,
    principal: PrincipalId,
    tenant: TenantId,
    expected: ResourceGeneration,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.ingest-policy.activate.request.v1\0");
    hash.update(key.to_bytes());
    hash.update(principal.to_bytes());
    hash.update(tenant.to_bytes());
    hash.update(expected.0.to_be_bytes());
    hash.update(generation.0.to_be_bytes());
    hash.update(digest);
    hash.finalize().into()
}

pub(super) fn encode_receipt(semantics: ActivationSemantics) -> Vec<u8> {
    let mut bytes = encode_semantics(RECEIPT_MAGIC, semantics);
    bytes.extend_from_slice(&semantics.audit_position.to_be_bytes());
    bytes
}

pub(super) fn encode_audit(semantics: ActivationSemantics) -> Vec<u8> {
    encode_semantics(AUDIT_MAGIC, semantics)
}

pub(crate) fn legacy_receipt_object(
    entry: &crate::audit::IngestPolicyActivationAuditEntry,
) -> Result<CatalogObject, PolicyAdministrationFailure> {
    if entry.position() == 0 {
        return Err(corrupt());
    }
    CatalogObject::new(encode_receipt(ActivationSemantics {
        key: entry.idempotency_key(),
        principal: entry.principal_id(),
        tenant: entry.tenant_id(),
        expected: entry.expected_generation(),
        generation: entry.generation(),
        digest: entry.digest(),
        request_digest: entry.request_digest(),
        audit_position: entry.position(),
    }))
    .map_err(map_catalog)
}

pub(crate) fn retention_terminal_key(bytes: &[u8]) -> Result<Option<[u8; 16]>, ()> {
    crate::audit::terminal_receipt_key(
        bytes,
        &[(RECEIPT_MAGIC_V1, 136, 8), (RECEIPT_MAGIC, 144, 8)],
    )
}

fn encode_semantics(magic: [u8; 8], semantics: ActivationSemantics) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(136);
    bytes.extend_from_slice(&magic);
    bytes.extend_from_slice(&semantics.key.0);
    bytes.extend_from_slice(&semantics.principal.to_bytes());
    bytes.extend_from_slice(&semantics.tenant.to_bytes());
    bytes.extend_from_slice(&semantics.expected.0.to_be_bytes());
    bytes.extend_from_slice(&semantics.generation.0.to_be_bytes());
    bytes.extend_from_slice(&semantics.digest);
    bytes.extend_from_slice(&semantics.request_digest);
    bytes
}

pub(super) fn find_receipt(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<Receipt>, PolicyAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or_else(corrupt)?;
        if !bytes.starts_with(&RECEIPT_MAGIC) && !bytes.starts_with(&RECEIPT_MAGIC_V1) {
            continue;
        }
        let receipt = decode_receipt(bytes)?;
        if bytes.get(8..24) == Some(key.0.as_slice()) && found.replace(receipt).is_some() {
            return Err(corrupt());
        }
    }
    Ok(found)
}

fn decode_receipt(bytes: &[u8]) -> Result<Receipt, PolicyAdministrationFailure> {
    let version_two = bytes.starts_with(&RECEIPT_MAGIC);
    if (!version_two && !bytes.starts_with(&RECEIPT_MAGIC_V1))
        || bytes.len() != if version_two { 144 } else { 136 }
    {
        return Err(corrupt());
    }
    let array = |start: usize| -> Result<[u8; 16], PolicyAdministrationFailure> {
        bytes
            .get(start..start + 16)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(corrupt)
    };
    let long = |start: usize| -> Result<u64, PolicyAdministrationFailure> {
        bytes
            .get(start..start + 8)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(corrupt)
    };
    let digest = |start: usize| -> Result<[u8; 32], PolicyAdministrationFailure> {
        bytes
            .get(start..start + 32)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(corrupt)
    };
    let audit_position = if version_two { long(136)? } else { 0 };
    if version_two && audit_position == 0 {
        return Err(corrupt());
    }
    Ok(Receipt {
        principal: PrincipalId::from_bytes(array(24)?).map_err(|_| corrupt())?,
        tenant: TenantId::from_bytes(array(40)?).map_err(|_| corrupt())?,
        expected: ResourceGeneration::new(long(56)?)?,
        generation: ResourceGeneration::new(long(64)?)?,
        digest: digest(72)?,
        request_digest: digest(104)?,
        audit_position,
    })
}

fn corrupt() -> PolicyAdministrationFailure {
    PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::CorruptState)
}

#[cfg(test)]
mod tests {
    use positron_domain::identity::{PrincipalId, TenantId};

    use super::*;

    #[test]
    fn canonical_activation_digest_binds_the_idempotency_key_and_principal() {
        let key = AdministrativeIdempotencyKey::new([1; 16]).expect("idempotency key");
        let principal = PrincipalId::from_bytes([2; 16]).expect("principal");
        let tenant = TenantId::from_bytes([3; 16]).expect("tenant");
        let expected = ResourceGeneration::new(7).expect("generation");
        let generation = ResourceGeneration::new(8).expect("generation");
        let digest = [4; 32];
        let canonical = request_digest(key, principal, tenant, expected, generation, digest);
        assert_ne!(
            canonical,
            request_digest(
                AdministrativeIdempotencyKey::new([5; 16]).expect("other key"),
                principal,
                tenant,
                expected,
                generation,
                digest,
            )
        );
        assert_ne!(
            canonical,
            request_digest(
                key,
                PrincipalId::from_bytes([6; 16]).expect("other principal"),
                tenant,
                expected,
                generation,
                digest,
            )
        );
    }
}
