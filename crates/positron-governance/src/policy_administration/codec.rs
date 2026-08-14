use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::CatalogSnapshot;
use sha2::{Digest, Sha256};

use super::{
    AdministrativeIdempotencyKey, PolicyAdministrationFailure, PolicyAdministrationFailureCode,
    ResourceGeneration, map_catalog,
};

const RECEIPT_MAGIC: [u8; 8] = *b"POSPID01";
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
}

pub(super) struct Receipt {
    pub(super) principal: PrincipalId,
    pub(super) tenant: TenantId,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) digest: [u8; 32],
    pub(super) request_digest: [u8; 32],
}

pub(super) fn request_digest(
    tenant: TenantId,
    expected: ResourceGeneration,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.ingest-policy.activate.request.v1\0");
    hash.update(tenant.to_bytes());
    hash.update(expected.0.to_be_bytes());
    hash.update(generation.0.to_be_bytes());
    hash.update(digest);
    hash.finalize().into()
}

pub(super) fn encode_receipt(semantics: ActivationSemantics) -> Vec<u8> {
    encode_semantics(RECEIPT_MAGIC, semantics)
}

pub(super) fn encode_audit(semantics: ActivationSemantics) -> Vec<u8> {
    encode_semantics(AUDIT_MAGIC, semantics)
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
        if !bytes.starts_with(&RECEIPT_MAGIC) {
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
    if bytes.len() != 136 {
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
    Ok(Receipt {
        principal: PrincipalId::from_bytes(array(24)?).map_err(|_| corrupt())?,
        tenant: TenantId::from_bytes(array(40)?).map_err(|_| corrupt())?,
        expected: ResourceGeneration::new(long(56)?)?,
        generation: ResourceGeneration::new(long(64)?)?,
        digest: digest(72)?,
        request_digest: digest(104)?,
    })
}

fn corrupt() -> PolicyAdministrationFailure {
    PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::CorruptState)
}
