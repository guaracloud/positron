use std::error::Error;
use std::fmt::{Display, Formatter};
use std::num::NonZeroU64;

use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    GovernanceAuditRecord, PreparedTransactionResolution, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::tenant_quota_record::{
    TenantProfileState, replace_tenant_profile_record, tenant_profile_state,
};
use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, Identity, ResourceGeneration,
    TenantAdministrationFailure,
};

const AUDIT_MAGIC: [u8; 8] = *b"POSTRT01";
const RECEIPT_MAGIC: [u8; 8] = *b"POSTTR01";
const RECEIPT_BYTES: usize = 120;

/// Redacted outcome of one confirmed retention successor publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantRetentionUpdate {
    tenant: TenantId,
    generation: ResourceGeneration,
    audit_position: u64,
    audit_ingest_time_unix_seconds: u64,
}

impl TenantRetentionUpdate {
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn retention_generation(self) -> ResourceGeneration {
        self.generation
    }
    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
    #[must_use]
    pub const fn audit_ingest_time_unix_seconds(self) -> u64 {
        self.audit_ingest_time_unix_seconds
    }
}

/// Runtime-verified confirmation for one destructive retention change.
///
/// The runtime computes this only from its complete read-only, generation-pinned
/// impact aggregate. Its bytes are opaque to callers and audit records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionImpactConfirmation([u8; 32]);

impl RetentionImpactConfirmation {
    /// Accepts a digest recomputed by the trusted runtime preview boundary.
    /// A zero digest is never a confirmation.
    pub fn from_runtime_digest(
        digest: [u8; 32],
    ) -> Result<Self, TenantRetentionAdministrationFailure> {
        if digest.iter().all(|byte| *byte == 0) {
            return Err(TenantRetentionAdministrationFailure::InvalidConfirmation);
        }
        Ok(Self(digest))
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantRetentionGenerationConflict {
    current: ResourceGeneration,
}
impl TenantRetentionGenerationConflict {
    #[must_use]
    pub const fn current_generation(self) -> ResourceGeneration {
        self.current
    }

    /// Conflicts disclose the affected setting without disclosing either
    /// retention value or impact estimate.
    #[must_use]
    pub const fn semantic_diff(self) -> &'static str {
        "retention_seconds"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantRetentionAdministrationFailure {
    InvalidInput,
    InvalidConfirmation,
    Unauthorized,
    UnknownTenant,
    StaleGeneration(TenantRetentionGenerationConflict),
    IdempotencyConflict,
    CapacityExceeded,
    TimeUnavailable,
    PersistenceUnavailable,
}
impl Display for TenantRetentionAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tenant retention administration failed")
    }
}
impl Error for TenantRetentionAdministrationFailure {}

/// One authenticated tenant retention mutation. Reductions carry the trusted
/// preview confirmation; expansions intentionally do not require one.
#[derive(Clone, Copy, Debug)]
pub struct TenantRetentionUpdateRequest {
    actor: AuthorizedContext,
    tenant: TenantId,
    proposed_seconds: NonZeroU64,
    expected: ResourceGeneration,
    confirmation: Option<RetentionImpactConfirmation>,
    idempotency: AdministrativeIdempotencyKey,
}
impl TenantRetentionUpdateRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        tenant: TenantId,
        proposed_seconds: NonZeroU64,
        expected: ResourceGeneration,
        confirmation: Option<RetentionImpactConfirmation>,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            tenant,
            proposed_seconds,
            expected,
            confirmation,
            idempotency,
        }
    }
}

pub struct TenantRetentionAdministration;

impl TenantRetentionAdministration {
    /// Resolves an exact historical receipt before callers validate a fresh
    /// reduction preview or current generation.
    pub fn replay_existing(
        catalog: &Catalog<'_>,
        identity: &Identity,
        request: TenantRetentionUpdateRequest,
    ) -> Result<Option<TenantRetentionUpdate>, TenantRetentionAdministrationFailure> {
        let principal = identity
            .authorize_policy_activation(request.actor, request.tenant)
            .map_err(|_| TenantRetentionAdministrationFailure::Unauthorized)?;
        if let Some(replay) = replay(catalog, principal, request)? {
            return Ok(Some(replay));
        }
        resume_prepared(catalog, principal, request)
    }

    /// Resolves an exact transaction-owned prepared retention mutation before
    /// rebuilding a fresh identity view. The context was authenticated before
    /// the original request; this path can only resume the same request digest
    /// against the same Catalog instance and predecessor.
    pub fn resume_prepared_existing(
        catalog: &Catalog<'_>,
        authority: [u8; 16],
        request: TenantRetentionUpdateRequest,
    ) -> Result<Option<TenantRetentionUpdate>, TenantRetentionAdministrationFailure> {
        let principal = request
            .actor
            .authorize_prepared_retention_resume(authority, request.tenant)
            .map_err(|_| TenantRetentionAdministrationFailure::Unauthorized)?;
        if let Some(replay) = replay(catalog, principal, request)? {
            return Ok(Some(replay));
        }
        resume_prepared(catalog, principal, request)
    }

    pub fn update<F>(
        catalog: &Catalog<'_>,
        identity: &Identity,
        request: TenantRetentionUpdateRequest,
        audit_time: F,
    ) -> Result<TenantRetentionUpdate, TenantRetentionAdministrationFailure>
    where
        F: FnOnce() -> Result<u64, TenantRetentionAdministrationFailure>,
    {
        let principal = identity
            .authorize_policy_activation(request.actor, request.tenant)
            .map_err(|_| TenantRetentionAdministrationFailure::Unauthorized)?;
        if let Some(replay) = Self::replay_existing(catalog, identity, request)? {
            return Ok(replay);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let (current_seconds, current_generation, objects) =
            if request.tenant == governance.tenant() {
                let current = ResourceGeneration::new(governance.retention_generation())
                    .map_err(|_| TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
                (governance.retention_seconds(), current, None)
            } else {
                let profile = tenant_profile_state(&snapshot, request.tenant)
                    .map_err(map_record)?
                    .ok_or(TenantRetentionAdministrationFailure::UnknownTenant)?;
                (
                    profile.retention_seconds,
                    profile.retention_generation,
                    Some(profile),
                )
            };
        if current_generation != request.expected {
            return Err(TenantRetentionAdministrationFailure::StaleGeneration(
                TenantRetentionGenerationConflict {
                    current: current_generation,
                },
            ));
        }
        if request.proposed_seconds.get() < current_seconds && request.confirmation.is_none() {
            return Err(TenantRetentionAdministrationFailure::InvalidConfirmation);
        }
        if request.proposed_seconds.get() >= current_seconds && request.confirmation.is_some() {
            return Err(TenantRetentionAdministrationFailure::InvalidConfirmation);
        }
        let generation = request
            .expected
            .get()
            .checked_add(1)
            .and_then(|value| ResourceGeneration::new(value).ok())
            .ok_or(TenantRetentionAdministrationFailure::CapacityExceeded)?;
        let mut replacement = if let Some(profile) = objects {
            replace_tenant_profile_record(
                &snapshot,
                request.tenant,
                &TenantProfileState {
                    display_name: profile.display_name,
                    display_generation: profile.display_generation,
                    retention_seconds: request.proposed_seconds.get(),
                    retention_generation: generation,
                },
            )
            .map_err(map_record)?
        } else {
            replacement_default(
                &snapshot,
                governance
                    .with_retention_seconds(request.proposed_seconds.get(), generation.get())
                    .map_err(map_catalog)?,
            )?
        };
        let time = audit_time()?;
        if time == 0 {
            return Err(TenantRetentionAdministrationFailure::PersistenceUnavailable);
        }
        let digest = request_digest(principal, request, generation);
        let audit = encode_audit(time, principal, request, generation, digest)?;
        let audit_position = snapshot
            .governance_audit_frontier()
            .checked_add(1)
            .ok_or(TenantRetentionAdministrationFailure::CapacityExceeded)?;
        replacement
            .try_reserve(1)
            .map_err(|_| TenantRetentionAdministrationFailure::CapacityExceeded)?;
        replacement.push(receipt_object(
            request,
            principal,
            generation,
            time,
            audit_position,
            digest,
        )?);
        let commit = catalog
            .commit_prepared(
                snapshot.identity(),
                CatalogProposal::new(
                    TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?,
                    snapshot
                        .format_epoch()
                        .ok_or(TenantRetentionAdministrationFailure::PersistenceUnavailable)?,
                    replacement,
                )
                .map_err(map_catalog)?,
                AuditIntent::new(audit).map_err(map_catalog)?,
                digest,
            )
            .map_err(map_catalog)?;
        let record = commit
            .governance_audit_record()
            .ok_or(TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
        if record.position() != audit_position {
            return Err(TenantRetentionAdministrationFailure::PersistenceUnavailable);
        }
        Ok(TenantRetentionUpdate {
            tenant: request.tenant,
            generation,
            audit_position: record.position(),
            audit_ingest_time_unix_seconds: time,
        })
    }
}

fn resume_prepared(
    catalog: &Catalog<'_>,
    principal: PrincipalId,
    request: TenantRetentionUpdateRequest,
) -> Result<Option<TenantRetentionUpdate>, TenantRetentionAdministrationFailure> {
    let generation = successor_generation(request.expected)?;
    let digest = request_digest(principal, request, generation);
    let transaction = TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?;
    let resolution = catalog
        .resume_prepared(transaction, digest)
        .map_err(map_catalog)?;
    match resolution {
        PreparedTransactionResolution::Absent => Ok(None),
        PreparedTransactionResolution::Unavailable => {
            Err(TenantRetentionAdministrationFailure::PersistenceUnavailable)
        },
        PreparedTransactionResolution::Resumed(_) => replay(catalog, principal, request)?
            .ok_or(TenantRetentionAdministrationFailure::PersistenceUnavailable)
            .map(Some),
    }
}

fn successor_generation(
    expected: ResourceGeneration,
) -> Result<ResourceGeneration, TenantRetentionAdministrationFailure> {
    expected
        .get()
        .checked_add(1)
        .and_then(|value| ResourceGeneration::new(value).ok())
        .ok_or(TenantRetentionAdministrationFailure::CapacityExceeded)
}

fn replay(
    catalog: &Catalog<'_>,
    principal: PrincipalId,
    request: TenantRetentionUpdateRequest,
) -> Result<Option<TenantRetentionUpdate>, TenantRetentionAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    if let Some(replay) = replay_receipt(&snapshot, principal, request)? {
        return Ok(Some(replay));
    }
    for record in catalog.governance_audit_records().map_err(map_catalog)? {
        if record.transaction().to_bytes() == request.idempotency.to_bytes() {
            return decode_replay(&record, principal, request).map(Some);
        }
    }
    Ok(None)
}

fn replay_receipt(
    snapshot: &CatalogSnapshot,
    principal: PrincipalId,
    request: TenantRetentionUpdateRequest,
) -> Result<Option<TenantRetentionUpdate>, TenantRetentionAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(&RECEIPT_MAGIC) {
            continue;
        }
        let receipt = decode_receipt(bytes)?;
        if receipt.key == request.idempotency && found.replace(receipt).is_some() {
            return Err(TenantRetentionAdministrationFailure::PersistenceUnavailable);
        }
    }
    let Some(receipt) = found else {
        return Ok(None);
    };
    let expected_generation = successor_generation(request.expected)?;
    if receipt.actor != principal
        || receipt.tenant != request.tenant
        || receipt.expected != request.expected
        || receipt.generation != expected_generation
        || receipt.digest != request_digest(principal, request, expected_generation)
    {
        return Err(TenantRetentionAdministrationFailure::IdempotencyConflict);
    }
    Ok(Some(TenantRetentionUpdate {
        tenant: receipt.tenant,
        generation: receipt.generation,
        audit_position: receipt.audit_position,
        audit_ingest_time_unix_seconds: receipt.time,
    }))
}

#[derive(Clone, Copy)]
struct RetentionReceipt {
    key: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    tenant: TenantId,
    expected: ResourceGeneration,
    generation: ResourceGeneration,
    time: u64,
    audit_position: u64,
    digest: [u8; 32],
}

fn receipt_object(
    request: TenantRetentionUpdateRequest,
    actor: PrincipalId,
    generation: ResourceGeneration,
    time: u64,
    audit_position: u64,
    digest: [u8; 32],
) -> Result<CatalogObject, TenantRetentionAdministrationFailure> {
    if time == 0 || audit_position == 0 {
        return Err(TenantRetentionAdministrationFailure::PersistenceUnavailable);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(RECEIPT_BYTES)
        .map_err(|_| TenantRetentionAdministrationFailure::CapacityExceeded)?;
    bytes.extend_from_slice(&RECEIPT_MAGIC);
    bytes.extend_from_slice(&request.idempotency.to_bytes());
    bytes.extend_from_slice(&actor.to_bytes());
    bytes.extend_from_slice(&request.tenant.to_bytes());
    bytes.extend_from_slice(&request.expected.get().to_be_bytes());
    bytes.extend_from_slice(&generation.get().to_be_bytes());
    bytes.extend_from_slice(&time.to_be_bytes());
    bytes.extend_from_slice(&audit_position.to_be_bytes());
    bytes.extend_from_slice(&digest);
    CatalogObject::new(bytes).map_err(map_catalog)
}

pub(crate) fn legacy_receipt_object(
    entry: &crate::audit::TenantRetentionUpdateAuditEntry,
) -> Result<CatalogObject, TenantRetentionAdministrationFailure> {
    if entry.ingest_time_unix_seconds() == 0
        || entry.position() == 0
        || entry.expected_generation().get().checked_add(1) != Some(entry.generation().get())
        || entry.request_digest().iter().all(|byte| *byte == 0)
    {
        return Err(TenantRetentionAdministrationFailure::PersistenceUnavailable);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(RECEIPT_BYTES)
        .map_err(|_| TenantRetentionAdministrationFailure::CapacityExceeded)?;
    bytes.extend_from_slice(&RECEIPT_MAGIC);
    bytes.extend_from_slice(&entry.idempotency_key().to_bytes());
    bytes.extend_from_slice(&entry.actor_id().to_bytes());
    bytes.extend_from_slice(&entry.tenant_id().to_bytes());
    bytes.extend_from_slice(&entry.expected_generation().get().to_be_bytes());
    bytes.extend_from_slice(&entry.generation().get().to_be_bytes());
    bytes.extend_from_slice(&entry.ingest_time_unix_seconds().to_be_bytes());
    bytes.extend_from_slice(&entry.position().to_be_bytes());
    bytes.extend_from_slice(&entry.request_digest());
    CatalogObject::new(bytes).map_err(map_catalog)
}

fn decode_receipt(bytes: &[u8]) -> Result<RetentionReceipt, TenantRetentionAdministrationFailure> {
    if bytes.len() != RECEIPT_BYTES {
        return Err(TenantRetentionAdministrationFailure::PersistenceUnavailable);
    }
    let array = |start| {
        bytes
            .get(start..start + 16)
            .and_then(|value| value.try_into().ok())
            .ok_or(TenantRetentionAdministrationFailure::PersistenceUnavailable)
    };
    let long = |start| {
        bytes
            .get(start..start + 8)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(TenantRetentionAdministrationFailure::PersistenceUnavailable)
    };
    let key = AdministrativeIdempotencyKey::new(array(8)?)
        .map_err(|_| TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
    let actor = PrincipalId::from_bytes(array(24)?)
        .map_err(|_| TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
    let tenant = TenantId::from_bytes(array(40)?)
        .map_err(|_| TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
    let expected = ResourceGeneration::new(long(56)?)
        .map_err(|_| TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
    let generation = ResourceGeneration::new(long(64)?)
        .map_err(|_| TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
    let time = long(72)?;
    let audit_position = long(80)?;
    let digest = bytes
        .get(88..120)
        .and_then(|value| value.try_into().ok())
        .filter(|value: &[u8; 32]| value.iter().any(|byte| *byte != 0))
        .ok_or(TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
    if time == 0 || audit_position == 0 || expected.get().checked_add(1) != Some(generation.get()) {
        return Err(TenantRetentionAdministrationFailure::PersistenceUnavailable);
    }
    Ok(RetentionReceipt {
        key,
        actor,
        tenant,
        expected,
        generation,
        time,
        audit_position,
        digest,
    })
}

fn decode_replay(
    record: &GovernanceAuditRecord,
    principal: PrincipalId,
    request: TenantRetentionUpdateRequest,
) -> Result<TenantRetentionUpdate, TenantRetentionAdministrationFailure> {
    let bytes = record.intent();
    if bytes.len() != 120 || !bytes.starts_with(&AUDIT_MAGIC) {
        return Err(TenantRetentionAdministrationFailure::IdempotencyConflict);
    }
    let time = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?,
    );
    let actor = PrincipalId::from_bytes(
        bytes[32..48]
            .try_into()
            .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?,
    )
    .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?;
    let tenant = TenantId::from_bytes(
        bytes[48..64]
            .try_into()
            .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?,
    )
    .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?;
    let expected = ResourceGeneration::new(u64::from_be_bytes(
        bytes[64..72]
            .try_into()
            .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?,
    ))
    .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?;
    let generation = ResourceGeneration::new(u64::from_be_bytes(
        bytes[72..80]
            .try_into()
            .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?,
    ))
    .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?;
    let digest: [u8; 32] = bytes[88..120]
        .try_into()
        .map_err(|_| TenantRetentionAdministrationFailure::IdempotencyConflict)?;
    if time == 0
        || actor != principal
        || tenant != request.tenant
        || expected != request.expected
        || generation.get() != expected.get().saturating_add(1)
        || digest != request_digest(principal, request, generation)
    {
        return Err(TenantRetentionAdministrationFailure::IdempotencyConflict);
    }
    Ok(TenantRetentionUpdate {
        tenant,
        generation,
        audit_position: record.position(),
        audit_ingest_time_unix_seconds: time,
    })
}

fn request_digest(
    principal: PrincipalId,
    request: TenantRetentionUpdateRequest,
    generation: ResourceGeneration,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.tenant-retention.update.request.v1\0");
    hash.update(request.idempotency.to_bytes());
    hash.update(principal.to_bytes());
    hash.update(request.tenant.to_bytes());
    hash.update(request.proposed_seconds.get().to_be_bytes());
    hash.update(request.expected.get().to_be_bytes());
    hash.update(generation.get().to_be_bytes());
    hash.update(
        request
            .confirmation
            .map_or([0; 32], RetentionImpactConfirmation::digest),
    );
    hash.finalize().into()
}

fn encode_audit(
    time: u64,
    principal: PrincipalId,
    request: TenantRetentionUpdateRequest,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> Result<Vec<u8>, TenantRetentionAdministrationFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(120)
        .map_err(|_| TenantRetentionAdministrationFailure::CapacityExceeded)?;
    bytes.extend_from_slice(&AUDIT_MAGIC);
    bytes.extend_from_slice(&time.to_be_bytes());
    bytes.extend_from_slice(&request.idempotency.to_bytes());
    bytes.extend_from_slice(&principal.to_bytes());
    bytes.extend_from_slice(&request.tenant.to_bytes());
    bytes.extend_from_slice(&request.expected.get().to_be_bytes());
    bytes.extend_from_slice(&generation.get().to_be_bytes());
    bytes.extend_from_slice(&request.proposed_seconds.get().to_be_bytes());
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn replacement_default(
    snapshot: &CatalogSnapshot,
    replacement: Vec<u8>,
) -> Result<Vec<CatalogObject>, TenantRetentionAdministrationFailure> {
    let mut objects = Vec::new();
    for id in snapshot.object_identities() {
        let bytes = snapshot
            .object(id)
            .map_err(map_catalog)?
            .ok_or(TenantRetentionAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(b"POSGOV") {
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
        }
    }
    objects.push(CatalogObject::new(replacement).map_err(map_catalog)?);
    Ok(objects)
}

fn map_record(failure: TenantAdministrationFailure) -> TenantRetentionAdministrationFailure {
    match failure {
        TenantAdministrationFailure::Unauthorized => {
            TenantRetentionAdministrationFailure::UnknownTenant
        },
        TenantAdministrationFailure::InvalidInput => {
            TenantRetentionAdministrationFailure::InvalidInput
        },
        _ => TenantRetentionAdministrationFailure::PersistenceUnavailable,
    }
}
fn map_catalog(failure: positron_kernel::CatalogFailure) -> TenantRetentionAdministrationFailure {
    if failure.code() == CatalogFailureCode::IdempotencyConflict {
        TenantRetentionAdministrationFailure::IdempotencyConflict
    } else {
        TenantRetentionAdministrationFailure::PersistenceUnavailable
    }
}
