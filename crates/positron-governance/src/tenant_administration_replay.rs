use sha2::{Digest, Sha256};

use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{Catalog, CatalogReadView, CatalogSnapshot, TransactionId};

use super::{
    AdministrativeIdempotencyKey, ResourceGeneration, TenantAdministration,
    TenantAdministrationFailure, TenantCreateCandidate, TenantCreateRequest, TenantCreation,
    generation_at, map_catalog, validate_request,
};

pub(super) const TENANT_RECEIPT_MAGIC: [u8; 8] = *b"POSTRR01";
const TENANT_AUDIT_MAGIC: [u8; 8] = *b"POSTNA01";

impl TenantAdministration {
    /// Resolves an exact committed retry from an authenticated read view before
    /// callers acquire a governor enrollment permit or the Catalog writer.
    pub fn replay_from_view(
        view: &CatalogReadView,
        administrator: PrincipalId,
        request: TenantCreateRequest,
    ) -> Result<Option<TenantCreation>, TenantAdministrationFailure> {
        validate_request(administrator, &request)?;
        let Some(replay) = replay_snapshot(view.snapshot(), &request)? else {
            return Ok(None);
        };
        let audit_position = view
            .governance_audit_records()
            .iter()
            .find(|record| {
                record.transaction().to_bytes() == request.idempotency.to_bytes()
                    && record.intent().starts_with(&TENANT_AUDIT_MAGIC)
            })
            .map(positron_kernel::GovernanceAuditRecord::position)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        Ok(Some(TenantCreation::new(
            replay.tenant_id(),
            replay.resource_generation(),
            audit_position,
        )))
    }

    /// Reads the exact verified successor of an unpublished tenant creation
    /// without publishing it. The runtime uses this only to stage the same
    /// tenant's live admission before resuming the marker publication.
    pub fn inspect_prepared(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        request: &TenantCreateRequest,
    ) -> Result<Option<TenantCreation>, TenantAdministrationFailure> {
        validate_request(administrator, request)?;
        let transaction =
            TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?;
        match catalog
            .inspect_prepared(transaction, request_digest(request))
            .map_err(map_catalog)?
        {
            positron_kernel::PreparedTransactionInspection::Absent => Ok(None),
            positron_kernel::PreparedTransactionInspection::Unavailable => {
                Err(TenantAdministrationFailure::PersistenceUnavailable)
            },
            positron_kernel::PreparedTransactionInspection::Inspected(snapshot) => {
                replay_snapshot(&snapshot, request)?
                    .map(Some)
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)
            },
        }
    }
}

pub(super) fn replay_snapshot(
    snapshot: &CatalogSnapshot,
    request: &TenantCreateRequest,
) -> Result<Option<TenantCreation>, TenantAdministrationFailure> {
    let Some(receipt) = receipt_for(snapshot, request.idempotency)? else {
        return Ok(None);
    };
    replay_receipt(
        &receipt,
        request.actor.principal_id(),
        request_digest(request),
        legacy_request_digest(request, receipt.tenant),
        retired_precondition_digest(request, receipt.tenant, receipt.expected),
    )?;
    Ok(Some(TenantCreation::new(
        receipt.tenant,
        receipt.generation,
        receipt.audit_position,
    )))
}

pub(super) fn replay_receipt(
    receipt: &Receipt,
    actor: PrincipalId,
    canonical_digest: [u8; 32],
    legacy_digest: [u8; 32],
    retired_precondition_digest: [u8; 32],
) -> Result<(), TenantAdministrationFailure> {
    if receipt.expected.get().checked_add(1) != Some(receipt.generation.get()) {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    if receipt.actor != actor
        || (receipt.digest != canonical_digest
            && receipt.digest != legacy_digest
            && receipt.digest != retired_precondition_digest)
    {
        return Err(TenantAdministrationFailure::IdempotencyConflict);
    }
    Ok(())
}
pub(super) struct Receipt {
    pub(super) actor: PrincipalId,
    pub(super) tenant: TenantId,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) digest: [u8; 32],
    pub(super) audit_position: u64,
}
pub(super) fn encode_receipt(
    candidate: &TenantCreateCandidate,
    prior_generation: ResourceGeneration,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(112);
    encoded.extend_from_slice(&TENANT_RECEIPT_MAGIC);
    encoded.extend_from_slice(&candidate.request.idempotency.to_bytes());
    encoded.extend_from_slice(&candidate.request.actor.principal_id().to_bytes());
    encoded.extend_from_slice(&candidate.tenant.to_bytes());
    encoded.extend_from_slice(&prior_generation.get().to_be_bytes());
    encoded.extend_from_slice(&generation.get().to_be_bytes());
    encoded.extend_from_slice(&digest);
    encoded.extend_from_slice(&0_u64.to_be_bytes());
    encoded
}
fn receipt_for(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<Receipt>, TenantAdministrationFailure> {
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if let Some(receipt) = decode_receipt(bytes, key)? {
            return Ok(Some(receipt));
        }
    }
    Ok(None)
}

pub(super) fn decode_receipt(
    bytes: &[u8],
    key: AdministrativeIdempotencyKey,
) -> Result<Option<Receipt>, TenantAdministrationFailure> {
    if !bytes.starts_with(&TENANT_RECEIPT_MAGIC) {
        return Ok(None);
    }
    if bytes.len() != 112 {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    if bytes.get(8..24) != Some(key.to_bytes().as_slice()) {
        return Ok(None);
    }
    let actor = principal_at(bytes, 24)?;
    let tenant = tenant_at(bytes, 40)?;
    let expected = generation_at(bytes, 56)?;
    let generation = generation_at(bytes, 64)?;
    let digest: [u8; 32] = bytes
        .get(72..104)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let audit_position = u64::from_be_bytes(
        bytes
            .get(104..112)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    Ok(Some(Receipt {
        actor,
        tenant,
        expected,
        generation,
        digest,
        audit_position,
    }))
}
fn principal_at(bytes: &[u8], at: usize) -> Result<PrincipalId, TenantAdministrationFailure> {
    PrincipalId::from_bytes(
        bytes
            .get(at..at + 16)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}
fn tenant_at(bytes: &[u8], at: usize) -> Result<TenantId, TenantAdministrationFailure> {
    TenantId::from_bytes(
        bytes
            .get(at..at + 16)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}
pub(super) fn request_digest(request: &TenantCreateRequest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(request.actor.principal_id().to_bytes());
    hasher.update(request.slug.as_str().as_bytes());
    hasher.update(request.display_name.as_bytes());
    hasher.update(request.retention_seconds.to_be_bytes());
    hasher.update(request.weight.to_be_bytes());
    for resource in request.resources {
        hasher.update(resource.to_be_bytes());
    }
    hasher.update(request.idempotency.to_bytes());
    hasher.finalize().into()
}

/// Verifies receipts and prepared transactions created by the retired
/// creation precondition without making that precondition part of the current
/// request contract.
pub(super) fn legacy_request_digest(request: &TenantCreateRequest, tenant: TenantId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(request.actor.principal_id().to_bytes());
    hasher.update(tenant.to_bytes());
    hasher.update(request.slug.as_str().as_bytes());
    hasher.update(request.display_name.as_bytes());
    hasher.update(request.retention_seconds.to_be_bytes());
    hasher.update(request.weight.to_be_bytes());
    for resource in request.resources {
        hasher.update(resource.to_be_bytes());
    }
    hasher.update(request.idempotency.to_bytes());
    hasher.finalize().into()
}

pub(super) fn retired_precondition_digest(
    request: &TenantCreateRequest,
    tenant: TenantId,
    expected: ResourceGeneration,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(request.actor.principal_id().to_bytes());
    hasher.update(tenant.to_bytes());
    hasher.update(request.slug.as_str().as_bytes());
    hasher.update(request.display_name.as_bytes());
    hasher.update(request.retention_seconds.to_be_bytes());
    hasher.update(request.weight.to_be_bytes());
    for resource in request.resources {
        hasher.update(resource.to_be_bytes());
    }
    hasher.update(expected.get().to_be_bytes());
    hasher.update(request.idempotency.to_bytes());
    hasher.finalize().into()
}
