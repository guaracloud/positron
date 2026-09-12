use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    ResourceAmounts, StorageKernelResourceAuthority, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, Identity, ResourceGeneration,
    TenantAdministrationFailure,
    tenant_quota_record::{TenantQuotaState, replace_tenant_quota_record, tenant_quota_state},
};

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
        let mut objects = match tenant_quota_state(&snapshot, request.tenant)
            .map_err(map_tenant_quota_record_failure)?
        {
            Some(current) => {
                if current.generation != request.expected {
                    return Err(TenantQuotaAdministrationFailure::stale(current, request));
                }
                replace_tenant_quota_record(
                    &snapshot,
                    request.tenant,
                    TenantQuotaState {
                        generation,
                        weight: request.weight,
                        resources: request.resources,
                    },
                )
                .map_err(map_tenant_quota_record_failure)?
            },
            None => default_tenant_successor(&snapshot, request, generation)?,
        };
        objects.try_reserve(1).map_err(|_| {
            TenantQuotaAdministrationFailure::new(
                TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
            )
        })?;
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
                    snapshot.format_epoch().ok_or_else(|| {
                        TenantQuotaAdministrationFailure::new(
                            TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
                        )
                    })?,
                    objects,
                )
                .map_err(map_catalog)?,
                Some(AuditIntent::new(encode(AUDIT_MAGIC, semantics)).map_err(map_catalog)?),
            )
            .map_err(|failure| map_commit_failure(catalog, request.tenant, failure))?;
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
    conflict: Option<TenantQuotaGenerationConflict>,
}

impl TenantQuotaAdministrationFailure {
    const fn new(code: TenantQuotaAdministrationFailureCode) -> Self {
        Self {
            code,
            conflict: None,
        }
    }

    fn stale(current: TenantQuotaState, request: TenantQuotaUpdateRequest) -> Self {
        Self {
            code: TenantQuotaAdministrationFailureCode::StaleResourceGeneration,
            conflict: Some(TenantQuotaGenerationConflict::between(current, request)),
        }
    }

    const fn stale_generation(current: ResourceGeneration) -> Self {
        Self {
            code: TenantQuotaAdministrationFailureCode::StaleResourceGeneration,
            conflict: Some(TenantQuotaGenerationConflict::generation_only(current)),
        }
    }

    #[must_use]
    pub const fn code(&self) -> TenantQuotaAdministrationFailureCode {
        self.code
    }

    #[must_use]
    pub fn current_generation(&self) -> Option<ResourceGeneration> {
        self.conflict
            .map(TenantQuotaGenerationConflict::current_generation)
    }

    #[must_use]
    pub const fn generation_conflict(&self) -> Option<TenantQuotaGenerationConflict> {
        self.conflict
    }
}

/// A stale quota precondition's current generation and redacted field-level
/// difference. It deliberately never includes quota values or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantQuotaGenerationConflict {
    current: ResourceGeneration,
    changed_fields: u16,
}

impl TenantQuotaGenerationConflict {
    const WEIGHT_BIT: u16 = 1;
    const RESOURCE_START_BIT: u16 = 1 << 1;
    const GENERATION_ONLY_BIT: u16 = 1 << 12;
    const RESOURCE_NAMES: [&str; 11] = [
        "memory_bytes",
        "queue_slots",
        "task_slots",
        "buffer_cache_bytes",
        "batch_items",
        "lease_slots",
        "retry_slots",
        "io_permits",
        "cpu_work_units",
        "file_descriptors",
        "disk_headroom_bytes",
    ];

    fn between(current: TenantQuotaState, request: TenantQuotaUpdateRequest) -> Self {
        Self::from_parts(current, request.weight, request.resources)
    }

    fn from_parts(
        current: TenantQuotaState,
        requested_weight: u32,
        requested_resources: [u64; 11],
    ) -> Self {
        let mut changed_fields = if current.weight == requested_weight {
            0
        } else {
            Self::WEIGHT_BIT
        };
        for (index, (current, requested)) in current
            .resources
            .into_iter()
            .zip(requested_resources)
            .enumerate()
        {
            if current != requested {
                changed_fields |= Self::RESOURCE_START_BIT << index;
            }
        }
        if changed_fields == 0 {
            changed_fields = Self::GENERATION_ONLY_BIT;
        }
        Self {
            current: current.generation,
            changed_fields,
        }
    }

    const fn generation_only(current: ResourceGeneration) -> Self {
        Self {
            current,
            changed_fields: Self::GENERATION_ONLY_BIT,
        }
    }

    #[must_use]
    pub const fn current_generation(self) -> ResourceGeneration {
        self.current
    }

    /// Renders only stable field names in canonical order; values stay
    /// inside the authorized administration boundary.
    #[must_use]
    pub fn semantic_diff(self) -> String {
        let mut rendered = String::with_capacity(192);
        if self.changed_fields & Self::WEIGHT_BIT != 0 {
            rendered.push_str("weight");
        }
        for (index, name) in Self::RESOURCE_NAMES.iter().enumerate() {
            if self.changed_fields & (Self::RESOURCE_START_BIT << index) == 0 {
                continue;
            }
            if !rendered.is_empty() {
                rendered.push(',');
            }
            rendered.push_str(name);
        }
        if rendered.is_empty() {
            rendered.push_str("resource_generation");
        }
        rendered
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

fn default_tenant_successor(
    snapshot: &CatalogSnapshot,
    request: TenantQuotaUpdateRequest,
    generation: ResourceGeneration,
) -> Result<Vec<CatalogObject>, TenantQuotaAdministrationFailure> {
    let (governance_id, governance) = snapshot.governance_object().map_err(map_catalog)?;
    if governance.tenant() != request.tenant {
        return Err(TenantQuotaAdministrationFailure::new(
            TenantQuotaAdministrationFailureCode::Unauthorized,
        ));
    }
    if governance.quota_generation() != request.expected.get() {
        return Err(TenantQuotaAdministrationFailure::stale(
            TenantQuotaState {
                generation: ResourceGeneration::new(governance.quota_generation())
                    .map_err(|_| corrupt())?,
                weight: governance.quota_weight(),
                resources: governance.quota_resources(),
            },
            request,
        ));
    }
    let mut objects = retained_objects(snapshot, governance_id)?;
    let successor = governance
        .with_quota(generation.get(), request.weight, request.resources)
        .map_err(map_catalog)?;
    objects.try_reserve(1).map_err(|_| {
        TenantQuotaAdministrationFailure::new(
            TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
        )
    })?;
    objects.push(CatalogObject::new(successor).map_err(map_catalog)?);
    Ok(objects)
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
    tenant: TenantId,
    failure: positron_kernel::CatalogFailure,
) -> TenantQuotaAdministrationFailure {
    if failure.code() != CatalogFailureCode::StaleGeneration {
        return map_catalog(failure);
    }
    let current =
        catalog.pin().map_err(map_catalog).and_then(|snapshot| {
            match tenant_quota_state(&snapshot, tenant).map_err(map_tenant_quota_record_failure)? {
                Some(state) => Ok(state.generation),
                None => {
                    let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
                    if governance.tenant() != tenant {
                        return Err(TenantQuotaAdministrationFailure::new(
                            TenantQuotaAdministrationFailureCode::Unauthorized,
                        ));
                    }
                    ResourceGeneration::new(governance.quota_generation()).map_err(|_| corrupt())
                },
            }
        });
    match current {
        Ok(generation) => TenantQuotaAdministrationFailure::stale_generation(generation),
        Err(failure) => failure,
    }
}

fn map_tenant_quota_record_failure(
    failure: TenantAdministrationFailure,
) -> TenantQuotaAdministrationFailure {
    let code = match failure {
        TenantAdministrationFailure::Unauthorized => {
            TenantQuotaAdministrationFailureCode::Unauthorized
        },
        TenantAdministrationFailure::InvalidInput
        | TenantAdministrationFailure::DuplicateTenant
        | TenantAdministrationFailure::StaleGeneration
        | TenantAdministrationFailure::IdempotencyConflict
        | TenantAdministrationFailure::PersistenceUnavailable => {
            TenantQuotaAdministrationFailureCode::CorruptState
        },
    };
    TenantQuotaAdministrationFailure::new(code)
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

    #[test]
    fn stale_quota_diff_names_only_changed_fields_in_canonical_order() {
        let current = TenantQuotaState {
            generation: ResourceGeneration::new(7).expect("generation"),
            weight: 2,
            resources: [11; 11],
        };
        let mut requested = [11; 11];
        requested[0] = 12;
        requested[10] = 13;
        let conflict = TenantQuotaGenerationConflict::from_parts(current, 3, requested);
        assert_eq!(conflict.current_generation().get(), 7);
        assert_eq!(
            conflict.semantic_diff(),
            "weight,memory_bytes,disk_headroom_bytes"
        );
        assert!(!conflict.semantic_diff().contains("11"));
        assert!(!conflict.semantic_diff().contains("12"));
        assert!(!conflict.semantic_diff().contains("13"));
    }
}
