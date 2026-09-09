use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    FormatEpoch, ResourceAmounts, StorageKernelResourceAuthority, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::{AdministrativeIdempotencyKey, AuthorizedContext, Identity, ResourceGeneration};

const RECEIPT_MAGIC: [u8; 8] = *b"POSQUR01";
const AUDIT_MAGIC: [u8; 8] = *b"POSQUO01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantQuotaUpdate {
    generation: ResourceGeneration,
    audit_position: u64,
}

impl TenantQuotaUpdate {
    #[must_use]
    pub const fn resource_generation(self) -> ResourceGeneration {
        self.generation
    }

    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

pub struct TenantQuotaAdministration;

/// One bounded tenant-quota mutation request at the Administration boundary.
#[derive(Clone, Copy)]
pub struct TenantQuotaUpdateRequest {
    actor: AuthorizedContext,
    tenant: TenantId,
    expected: ResourceGeneration,
    key: AdministrativeIdempotencyKey,
    weight: u32,
    resources: [u64; 11],
}

impl TenantQuotaUpdateRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        tenant: TenantId,
        expected: ResourceGeneration,
        key: AdministrativeIdempotencyKey,
        weight: u32,
        resources: [u64; 11],
    ) -> Self {
        Self {
            actor,
            tenant,
            expected,
            key,
            weight,
            resources,
        }
    }
}

impl TenantQuotaAdministration {
    pub fn update(
        catalog: &Catalog<'_>,
        authority: &StorageKernelResourceAuthority,
        identity: &Identity,
        request: TenantQuotaUpdateRequest,
    ) -> Result<TenantQuotaUpdate, TenantQuotaAdministrationFailure> {
        let principal = identity
            .authorize_quota_update(request.actor, request.tenant)
            .map_err(|_| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::Unauthorized,
                )
            })?;
        if request.weight == 0
            || request.weight > u32::from(u16::MAX)
            || request.resources.contains(&0)
        {
            return Err(TenantQuotaAdministrationFailure::new(
                TenantQuotaAdministrationFailureCode::InvalidInput,
            ));
        }
        let generation =
            ResourceGeneration::new(request.expected.get().checked_add(1).ok_or_else(|| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::InvalidInput,
                )
            })?)
            .map_err(|_| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::InvalidInput,
                )
            })?;
        let request_digest = request_digest(
            request.key,
            principal,
            request.tenant,
            request.expected,
            generation,
            request.weight,
            request.resources,
        );
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(receipt) = find_receipt(&snapshot, request.key)? {
            if receipt.principal != principal
                || receipt.tenant != request.tenant
                || receipt.expected != request.expected
                || receipt.generation != generation
                || receipt.weight != request.weight
                || receipt.resources != request.resources
                || receipt.request_digest != request_digest
            {
                return Err(TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::IdempotencyConflict,
                ));
            }
            return Ok(TenantQuotaUpdate {
                generation,
                audit_position: audit_position(catalog, request.key)?,
            });
        }
        let (governance_id, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if governance.tenant() != request.tenant {
            return Err(TenantQuotaAdministrationFailure::new(
                TenantQuotaAdministrationFailureCode::Unauthorized,
            ));
        }
        if governance.quota_generation() != request.expected.get() {
            return Err(TenantQuotaAdministrationFailure::stale(
                ResourceGeneration::new(governance.quota_generation()).map_err(|_| corrupt())?,
            ));
        }
        let mut objects = retained_objects(&snapshot, governance_id)?;
        let successor = governance
            .with_quota(generation.get(), request.weight, request.resources)
            .map_err(map_catalog)?;
        objects.try_reserve(2).map_err(|_| {
            TenantQuotaAdministrationFailure::new(
                TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
            )
        })?;
        objects.push(CatalogObject::new(successor).map_err(map_catalog)?);
        let semantics = QuotaSemantics {
            key: request.key,
            principal,
            tenant: request.tenant,
            expected: request.expected,
            generation,
            weight: request.weight,
            resources: request.resources,
            request_digest,
        };
        objects.push(CatalogObject::new(encode(RECEIPT_MAGIC, semantics)).map_err(map_catalog)?);
        let commit = catalog
            .commit(
                snapshot.identity(),
                CatalogProposal::new(
                    TransactionId::new(request.key.to_bytes()).map_err(map_catalog)?,
                    FormatEpoch::CATALOG_V1,
                    objects,
                )
                .map_err(map_catalog)?,
                Some(AuditIntent::new(encode(AUDIT_MAGIC, semantics)).map_err(map_catalog)?),
            )
            .map_err(|failure| map_commit_failure(catalog, failure))?;
        let audit_position = commit
            .governance_audit_record()
            .ok_or_else(|| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
                )
            })?
            .position();
        authority
            .update_tenant_quota(request.tenant, ResourceAmounts::new(request.resources))
            .map_err(|_| {
                TenantQuotaAdministrationFailure::new(
                    TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
                )
            })?;
        Ok(TenantQuotaUpdate {
            generation,
            audit_position,
        })
    }
}

#[derive(Clone, Copy)]
struct QuotaSemantics {
    key: AdministrativeIdempotencyKey,
    principal: PrincipalId,
    tenant: TenantId,
    expected: ResourceGeneration,
    generation: ResourceGeneration,
    weight: u32,
    resources: [u64; 11],
    request_digest: [u8; 32],
}

struct Receipt {
    principal: PrincipalId,
    tenant: TenantId,
    expected: ResourceGeneration,
    generation: ResourceGeneration,
    weight: u32,
    resources: [u64; 11],
    request_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantQuotaAdministrationFailureCode {
    InvalidInput,
    Unauthorized,
    StaleResourceGeneration,
    IdempotencyConflict,
    PersistenceUnavailable,
    CorruptState,
}

#[derive(Debug)]
pub struct TenantQuotaAdministrationFailure {
    code: TenantQuotaAdministrationFailureCode,
    current: Option<ResourceGeneration>,
}

impl TenantQuotaAdministrationFailure {
    const fn new(code: TenantQuotaAdministrationFailureCode) -> Self {
        Self {
            code,
            current: None,
        }
    }

    const fn stale(current: ResourceGeneration) -> Self {
        Self {
            code: TenantQuotaAdministrationFailureCode::StaleResourceGeneration,
            current: Some(current),
        }
    }

    #[must_use]
    pub const fn code(&self) -> TenantQuotaAdministrationFailureCode {
        self.code
    }

    #[must_use]
    pub const fn current_generation(&self) -> Option<ResourceGeneration> {
        self.current
    }
}

impl Display for TenantQuotaAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tenant quota administration failed")
    }
}

impl Error for TenantQuotaAdministrationFailure {}

fn request_digest(
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

fn encode(magic: [u8; 8], semantics: QuotaSemantics) -> Vec<u8> {
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

fn find_receipt(
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

fn decode(bytes: &[u8]) -> Result<Receipt, TenantQuotaAdministrationFailure> {
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

fn retained_objects(
    snapshot: &CatalogSnapshot,
    governance: positron_kernel::CatalogObjectId,
) -> Result<Vec<CatalogObject>, TenantQuotaAdministrationFailure> {
    let mut objects = Vec::new();
    for identity in snapshot.object_identities() {
        if identity == governance {
            continue;
        }
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or_else(corrupt)?;
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
    }
    Ok(objects)
}

fn audit_position(
    catalog: &Catalog<'_>,
    key: AdministrativeIdempotencyKey,
) -> Result<u64, TenantQuotaAdministrationFailure> {
    let transaction = TransactionId::new(key.to_bytes()).map_err(map_catalog)?;
    catalog
        .governance_audit_records()
        .map_err(map_catalog)?
        .into_iter()
        .find(|record| record.transaction() == transaction)
        .map(|record| record.position())
        .ok_or_else(corrupt)
}

fn map_commit_failure(
    catalog: &Catalog<'_>,
    failure: positron_kernel::CatalogFailure,
) -> TenantQuotaAdministrationFailure {
    if failure.code() != CatalogFailureCode::StaleGeneration {
        return map_catalog(failure);
    }
    let current = catalog
        .pin()
        .map_err(map_catalog)
        .and_then(|snapshot| snapshot.governance_object().map_err(map_catalog));
    match current {
        Ok((_, governance)) => match ResourceGeneration::new(governance.quota_generation()) {
            Ok(generation) => TenantQuotaAdministrationFailure::stale(generation),
            Err(_) => corrupt(),
        },
        Err(failure) => failure,
    }
}

fn corrupt() -> TenantQuotaAdministrationFailure {
    TenantQuotaAdministrationFailure::new(TenantQuotaAdministrationFailureCode::CorruptState)
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> TenantQuotaAdministrationFailure {
    let code = match failure.code() {
        CatalogFailureCode::IdempotencyConflict => {
            TenantQuotaAdministrationFailureCode::IdempotencyConflict
        },
        CatalogFailureCode::IntegrityCorruption => {
            TenantQuotaAdministrationFailureCode::CorruptState
        },
        _ => TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
    };
    TenantQuotaAdministrationFailure::new(code)
}

#[cfg(test)]
mod tests {
    use positron_domain::identity::{PrincipalId, TenantId};

    use super::*;

    #[test]
    fn quota_receipt_rejects_every_truncated_persisted_encoding() {
        let semantics = QuotaSemantics {
            key: AdministrativeIdempotencyKey::new([1; 16]).expect("key"),
            principal: PrincipalId::from_bytes([2; 16]).expect("principal"),
            tenant: TenantId::from_bytes([3; 16]).expect("tenant"),
            expected: ResourceGeneration::new(1).expect("expected generation"),
            generation: ResourceGeneration::new(2).expect("generation"),
            weight: 1,
            resources: [1; 11],
            request_digest: [4; 32],
        };
        let encoded = encode(RECEIPT_MAGIC, semantics);
        assert_eq!(encoded.len(), 196);
        assert!(decode(&encoded).is_ok());
        for length in 0..encoded.len() {
            assert!(
                decode(&encoded[..length]).is_err(),
                "truncation at {length}"
            );
        }
    }
}
