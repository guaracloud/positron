use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::CatalogSnapshot;
use sha2::{Digest, Sha256};

use super::{TenantQuotaAdministrationFailure, corrupt, map_catalog};
use crate::{AdministrativeIdempotencyKey, ResourceGeneration};

pub(super) const RECEIPT_MAGIC: [u8; 8] = *b"POSQUR01";
pub(super) const AUDIT_MAGIC: [u8; 8] = *b"POSQUO01";

#[derive(Clone, Copy)]
pub(super) struct QuotaSemantics {
    pub(super) key: AdministrativeIdempotencyKey,
    pub(super) principal: PrincipalId,
    pub(super) tenant: TenantId,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) weight: u32,
    pub(super) resources: [u64; 11],
    pub(super) request_digest: [u8; 32],
}

pub(super) struct Receipt {
    pub(super) principal: PrincipalId,
    pub(super) tenant: TenantId,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) weight: u32,
    pub(super) resources: [u64; 11],
    pub(super) request_digest: [u8; 32],
}

pub(super) fn request_digest(
    key: AdministrativeIdempotencyKey,
    principal: PrincipalId,
    tenant: TenantId,
    expected: ResourceGeneration,
    generation: ResourceGeneration,
    weight: u32,
    resources: [u64; 11],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.tenant-quota.update.request.v1\0");
    hash.update(key.to_bytes());
    hash.update(principal.to_bytes());
    hash.update(tenant.to_bytes());
    hash.update(expected.get().to_be_bytes());
    hash.update(generation.get().to_be_bytes());
    hash.update(weight.to_be_bytes());
    for resource in resources {
        hash.update(resource.to_be_bytes());
    }
    hash.finalize().into()
}

pub(super) fn encode(magic: [u8; 8], semantics: QuotaSemantics) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(196);
    bytes.extend_from_slice(&magic);
    bytes.extend_from_slice(&semantics.key.to_bytes());
    bytes.extend_from_slice(&semantics.principal.to_bytes());
    bytes.extend_from_slice(&semantics.tenant.to_bytes());
    bytes.extend_from_slice(&semantics.expected.get().to_be_bytes());
    bytes.extend_from_slice(&semantics.generation.get().to_be_bytes());
    bytes.extend_from_slice(&semantics.weight.to_be_bytes());
    for resource in semantics.resources {
        bytes.extend_from_slice(&resource.to_be_bytes());
    }
    bytes.extend_from_slice(&semantics.request_digest);
    bytes
}

pub(super) fn find_receipt(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<Receipt>, TenantQuotaAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or_else(corrupt)?;
        if !bytes.starts_with(&RECEIPT_MAGIC) {
            continue;
        }
        let receipt = decode(bytes)?;
        if bytes.get(8..24) == Some(key.to_bytes().as_slice()) && found.replace(receipt).is_some() {
            return Err(corrupt());
        }
    }
    Ok(found)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Receipt, TenantQuotaAdministrationFailure> {
    if bytes.len() != 196 {
        return Err(corrupt());
    }
    let array = |start| {
        bytes
            .get(start..start + 16)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(corrupt)
    };
    let long = |start| {
        bytes
            .get(start..start + 8)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(corrupt)
    };
    let principal = PrincipalId::from_bytes(array(24)?).map_err(|_| corrupt())?;
    let tenant = TenantId::from_bytes(array(40)?).map_err(|_| corrupt())?;
    let expected = ResourceGeneration::new(long(56)?).map_err(|_| corrupt())?;
    let generation = ResourceGeneration::new(long(64)?).map_err(|_| corrupt())?;
    if expected.get().checked_add(1) != Some(generation.get()) {
        return Err(corrupt());
    }
    let weight = bytes
        .get(72..76)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .filter(|value| *value != 0 && *value <= u32::from(u16::MAX))
        .ok_or_else(corrupt)?;
    let mut resources = [0_u64; 11];
    for (index, resource) in resources.iter_mut().enumerate() {
        let start = 76_usize
            .checked_add(index.checked_mul(8).ok_or_else(corrupt)?)
            .ok_or_else(corrupt)?;
        *resource = long(start)?;
    }
    if resources.contains(&0) {
        return Err(corrupt());
    }
    let request_digest = bytes
        .get(164..196)
        .and_then(|value| value.try_into().ok())
        .filter(|value: &[u8; 32]| !value.iter().all(|byte| *byte == 0))
        .ok_or_else(corrupt)?;
    Ok(Receipt {
        principal,
        tenant,
        expected,
        generation,
        weight,
        resources,
        request_digest,
    })
}
