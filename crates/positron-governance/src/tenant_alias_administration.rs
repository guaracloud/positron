use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, Scope, TenantId};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogReadView,
    CatalogSnapshot, GovernanceAuditRecord, PreparedTransactionResolution, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::tenant_quota_record::{
    TenantAliasRecord, replace_tenant_alias_record, tenant_alias_record,
};
use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, ResourceGeneration, TenantAdministration,
    TenantAdministrationFailure,
};

const RECEIPT_MAGIC_V2: [u8; 8] = *b"POSALR02";
const AUDIT_MAGIC: [u8; 8] = *b"POSALI01";
const RECEIPT_V2_BYTES: usize = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantAliasBinding {
    tenant: TenantId,
    generation: ResourceGeneration,
    audit_position: u64,
    audit_ingest_time_unix_seconds: u64,
}

impl TenantAliasBinding {
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn alias_generation(self) -> ResourceGeneration {
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

#[derive(Clone, Debug)]
pub struct TenantAliasBindRequest {
    actor: AuthorizedContext,
    tenant: TenantId,
    alias: ExternalTenantAlias,
    expected: ResourceGeneration,
    idempotency: AdministrativeIdempotencyKey,
}

impl TenantAliasBindRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        tenant: TenantId,
        alias: ExternalTenantAlias,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            tenant,
            alias,
            expected,
            idempotency,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantAliasGenerationConflict {
    current: ResourceGeneration,
}
impl TenantAliasGenerationConflict {
    #[must_use]
    pub const fn current_generation(self) -> ResourceGeneration {
        self.current
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantAliasAdministrationFailure {
    Unauthorized,
    UnknownTenant,
    AliasAlreadyBound,
    AliasConflict,
    StaleGeneration(TenantAliasGenerationConflict),
    IdempotencyConflict,
    CapacityExceeded,
    TimeUnavailable,
    PersistenceUnavailable,
}
impl Display for TenantAliasAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tenant alias administration failed")
    }
}
impl Error for TenantAliasAdministrationFailure {}

pub struct TenantAliasAdministration;

impl TenantAliasAdministration {
    pub fn replay_from_view(
        view: &CatalogReadView,
        administrator: PrincipalId,
        request: TenantAliasBindRequest,
    ) -> Result<Option<TenantAliasBinding>, TenantAliasAdministrationFailure> {
        validate_snapshot(view.snapshot().clone(), administrator, &request)?;
        if let Some(replay) = replay_receipt(view.snapshot(), &request)? {
            return Ok(Some(replay));
        }
        replay_records(view.governance_audit_records(), &request)
    }

    pub fn bind<F>(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        request: TenantAliasBindRequest,
        audit_time: F,
    ) -> Result<TenantAliasBinding, TenantAliasAdministrationFailure>
    where
        F: FnOnce() -> Result<u64, TenantAliasAdministrationFailure>,
    {
        let snapshot = validate_request(catalog, administrator, &request)?;
        if let Some(replay) = replay(catalog, &snapshot, &request)? {
            return Ok(replay);
        }
        let digest = request_digest(&request);
        let transaction =
            TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?;
        match catalog
            .resume_prepared(transaction, digest)
            .map_err(map_catalog)?
        {
            PreparedTransactionResolution::Absent => {},
            PreparedTransactionResolution::Unavailable => {
                return Err(TenantAliasAdministrationFailure::PersistenceUnavailable);
            },
            PreparedTransactionResolution::Resumed(commit) => {
                let record = commit
                    .governance_audit_record()
                    .ok_or(TenantAliasAdministrationFailure::PersistenceUnavailable)?;
                return replay_records(std::slice::from_ref(record), &request)?
                    .ok_or(TenantAliasAdministrationFailure::PersistenceUnavailable);
            },
        }
        let audit_ingest_time_unix_seconds = audit_time()?;
        if audit_ingest_time_unix_seconds == 0 {
            return Err(TenantAliasAdministrationFailure::PersistenceUnavailable);
        }
        let generation = request
            .expected
            .get()
            .checked_add(1)
            .and_then(|value| ResourceGeneration::new(value).ok())
            .ok_or(TenantAliasAdministrationFailure::CapacityExceeded)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let objects = if request.tenant == governance.tenant() {
            if governance.alias_generation() != request.expected.get() {
                return Err(TenantAliasAdministrationFailure::StaleGeneration(
                    TenantAliasGenerationConflict {
                        current: ResourceGeneration::new(governance.alias_generation()).map_err(
                            |_| TenantAliasAdministrationFailure::PersistenceUnavailable,
                        )?,
                    },
                ));
            }
            if governance.alias_generation() > 1 {
                return Err(TenantAliasAdministrationFailure::AliasAlreadyBound);
            }
            if alias_exists(&snapshot, request.tenant, &request.alias)? {
                return Err(TenantAliasAdministrationFailure::AliasConflict);
            }
            replacement_default(
                &snapshot,
                governance
                    .with_external_tenant_alias(request.alias.clone(), generation.get())
                    .map_err(map_catalog)?,
            )?
        } else {
            let current = tenant_alias_record(&snapshot, request.tenant)
                .map_err(map_tenant_record)?
                .ok_or(TenantAliasAdministrationFailure::UnknownTenant)?;
            if current.generation != request.expected {
                return Err(TenantAliasAdministrationFailure::StaleGeneration(
                    TenantAliasGenerationConflict {
                        current: current.generation,
                    },
                ));
            }
            if current.alias.is_some() {
                return Err(TenantAliasAdministrationFailure::AliasAlreadyBound);
            }
            if alias_exists(&snapshot, request.tenant, &request.alias)? {
                return Err(TenantAliasAdministrationFailure::AliasConflict);
            }
            replace_tenant_alias_record(
                &snapshot,
                request.tenant,
                TenantAliasRecord {
                    generation,
                    alias: Some(request.alias.clone()),
                },
            )
            .map_err(map_tenant_record)?
        };
        let audit = encode_audit(audit_ingest_time_unix_seconds, &request, generation, digest)?;
        let audit_position = snapshot
            .governance_audit_frontier()
            .checked_add(1)
            .ok_or(TenantAliasAdministrationFailure::CapacityExceeded)?;
        let receipt = CatalogObject::new(encode_receipt(
            audit_ingest_time_unix_seconds,
            &request,
            generation,
            audit_position,
            digest,
        )?)
        .map_err(map_catalog)?;
        let mut objects = objects;
        objects
            .try_reserve(1)
            .map_err(|_| TenantAliasAdministrationFailure::CapacityExceeded)?;
        objects.push(receipt);
        let proposal = CatalogProposal::new(
            transaction,
            snapshot
                .format_epoch()
                .ok_or(TenantAliasAdministrationFailure::PersistenceUnavailable)?,
            objects,
        )
        .map_err(map_catalog)?;
        let commit = match catalog.commit_prepared(
            snapshot.identity(),
            proposal,
            AuditIntent::new(audit).map_err(map_catalog)?,
            digest,
        ) {
            Ok(commit) => commit,
            Err(failure) if failure.code() == CatalogFailureCode::IdempotencyConflict => {
                let replayed = catalog.pin().map_err(map_catalog)?;
                return replay(catalog, &replayed, &request)?
                    .ok_or(TenantAliasAdministrationFailure::IdempotencyConflict);
            },
            Err(failure) => return Err(map_catalog(failure)),
        };
        let record = commit
            .governance_audit_record()
            .ok_or(TenantAliasAdministrationFailure::PersistenceUnavailable)?;
        if record.position() != audit_position {
            return Err(TenantAliasAdministrationFailure::PersistenceUnavailable);
        }
        Ok(TenantAliasBinding {
            tenant: request.tenant,
            generation,
            audit_position: record.position(),
            audit_ingest_time_unix_seconds,
        })
    }
}

fn validate_request(
    catalog: &Catalog<'_>,
    administrator: PrincipalId,
    request: &TenantAliasBindRequest,
) -> Result<CatalogSnapshot, TenantAliasAdministrationFailure> {
    validate_snapshot(catalog.pin().map_err(map_catalog)?, administrator, request)
}
fn validate_snapshot(
    snapshot: CatalogSnapshot,
    administrator: PrincipalId,
    request: &TenantAliasBindRequest,
) -> Result<CatalogSnapshot, TenantAliasAdministrationFailure> {
    if request.actor.principal_id() != administrator
        || request.actor.scope() != Scope::SystemAdministration
        || request.actor.tenant_attribution().is_some()
    {
        return Err(TenantAliasAdministrationFailure::Unauthorized);
    }
    let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
    if request.tenant != governance.tenant()
        && !TenantAdministration::registered_tenant_ids(&snapshot)
            .map_err(map_tenant_record)?
            .contains(&request.tenant)
    {
        return Err(TenantAliasAdministrationFailure::UnknownTenant);
    }
    Ok(snapshot)
}

fn replacement_default(
    snapshot: &CatalogSnapshot,
    replacement: Vec<u8>,
) -> Result<Vec<CatalogObject>, TenantAliasAdministrationFailure> {
    let mut objects = Vec::new();
    for id in snapshot.object_identities() {
        let bytes = snapshot
            .object(id)
            .map_err(map_catalog)?
            .ok_or(TenantAliasAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(b"POSGOV") {
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
        }
    }
    objects.push(CatalogObject::new(replacement).map_err(map_catalog)?);
    Ok(objects)
}

fn alias_exists(
    snapshot: &CatalogSnapshot,
    excluded: TenantId,
    alias: &ExternalTenantAlias,
) -> Result<bool, TenantAliasAdministrationFailure> {
    let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
    if governance.tenant() != excluded && governance.external_tenant_alias().as_ref() == Some(alias)
    {
        return Ok(true);
    }
    for tenant in
        TenantAdministration::registered_tenant_ids(snapshot).map_err(map_tenant_record)?
    {
        if tenant != excluded
            && tenant_alias_record(snapshot, tenant)
                .map_err(map_tenant_record)?
                .and_then(|record| record.alias)
                .as_ref()
                == Some(alias)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn request_digest(request: &TenantAliasBindRequest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"positron-tenant-alias-bind-v1\0");
    hasher.update(request.idempotency.to_bytes());
    hasher.update(request.actor.principal_id().to_bytes());
    hasher.update(request.tenant.to_bytes());
    hasher.update(request.alias.as_str().as_bytes());
    hasher.update(request.expected.get().to_be_bytes());
    hasher.finalize().into()
}

fn encode_audit(
    time: u64,
    request: &TenantAliasBindRequest,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> Result<Vec<u8>, TenantAliasAdministrationFailure> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(112)
        .map_err(|_| TenantAliasAdministrationFailure::CapacityExceeded)?;
    encoded.extend_from_slice(&AUDIT_MAGIC);
    encoded.extend_from_slice(&time.to_be_bytes());
    encoded.extend_from_slice(&request.idempotency.to_bytes());
    encoded.extend_from_slice(&request.actor.principal_id().to_bytes());
    encoded.extend_from_slice(&request.tenant.to_bytes());
    encoded.extend_from_slice(&request.expected.get().to_be_bytes());
    encoded.extend_from_slice(&generation.get().to_be_bytes());
    encoded.extend_from_slice(&digest);
    Ok(encoded)
}

fn encode_receipt(
    time: u64,
    request: &TenantAliasBindRequest,
    generation: ResourceGeneration,
    audit_position: u64,
    digest: [u8; 32],
) -> Result<Vec<u8>, TenantAliasAdministrationFailure> {
    if time == 0 || audit_position == 0 {
        return Err(TenantAliasAdministrationFailure::PersistenceUnavailable);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(RECEIPT_V2_BYTES)
        .map_err(|_| TenantAliasAdministrationFailure::CapacityExceeded)?;
    encoded.extend_from_slice(&RECEIPT_MAGIC_V2);
    encoded.extend_from_slice(&time.to_be_bytes());
    encoded.extend_from_slice(&request.idempotency.to_bytes());
    encoded.extend_from_slice(&request.actor.principal_id().to_bytes());
    encoded.extend_from_slice(&request.tenant.to_bytes());
    encoded.extend_from_slice(&request.expected.get().to_be_bytes());
    encoded.extend_from_slice(&generation.get().to_be_bytes());
    encoded.extend_from_slice(&audit_position.to_be_bytes());
    encoded.extend_from_slice(&digest);
    Ok(encoded)
}

pub(crate) fn legacy_receipt_object(
    entry: &crate::audit::TenantAliasBindingAuditEntry,
) -> Result<CatalogObject, TenantAliasAdministrationFailure> {
    if entry.ingest_time_unix_seconds() == 0
        || entry.position() == 0
        || entry.expected_generation().get().checked_add(1) != Some(entry.generation().get())
        || entry.request_digest().iter().all(|byte| *byte == 0)
    {
        return Err(TenantAliasAdministrationFailure::PersistenceUnavailable);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(RECEIPT_V2_BYTES)
        .map_err(|_| TenantAliasAdministrationFailure::CapacityExceeded)?;
    encoded.extend_from_slice(&RECEIPT_MAGIC_V2);
    encoded.extend_from_slice(&entry.ingest_time_unix_seconds().to_be_bytes());
    encoded.extend_from_slice(&entry.idempotency_key().to_bytes());
    encoded.extend_from_slice(&entry.actor_id().to_bytes());
    encoded.extend_from_slice(&entry.tenant_id().to_bytes());
    encoded.extend_from_slice(&entry.expected_generation().get().to_be_bytes());
    encoded.extend_from_slice(&entry.generation().get().to_be_bytes());
    encoded.extend_from_slice(&entry.position().to_be_bytes());
    encoded.extend_from_slice(&entry.request_digest());
    CatalogObject::new(encoded).map_err(map_catalog)
}

pub(crate) fn retention_terminal_key(bytes: &[u8]) -> Result<Option<[u8; 16]>, ()> {
    crate::audit::terminal_receipt_key(bytes, &[(RECEIPT_MAGIC_V2, RECEIPT_V2_BYTES, 16)])
}

fn replay(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    request: &TenantAliasBindRequest,
) -> Result<Option<TenantAliasBinding>, TenantAliasAdministrationFailure> {
    if let Some(replay) = replay_receipt(snapshot, request)? {
        return Ok(Some(replay));
    }
    replay_records(
        &catalog.governance_audit_records().map_err(map_catalog)?,
        request,
    )
}

fn replay_receipt(
    snapshot: &CatalogSnapshot,
    request: &TenantAliasBindRequest,
) -> Result<Option<TenantAliasBinding>, TenantAliasAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(TenantAliasAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(&RECEIPT_MAGIC_V2) {
            continue;
        }
        let receipt = decode_receipt(bytes)?;
        if receipt.key == request.idempotency && found.replace(receipt).is_some() {
            return Err(TenantAliasAdministrationFailure::PersistenceUnavailable);
        }
    }
    let Some(receipt) = found else {
        return Ok(None);
    };
    if receipt.actor != request.actor.principal_id()
        || receipt.tenant != request.tenant
        || receipt.expected != request.expected
        || receipt.digest != request_digest(request)
    {
        return Err(TenantAliasAdministrationFailure::IdempotencyConflict);
    }
    Ok(Some(TenantAliasBinding {
        tenant: receipt.tenant,
        generation: receipt.generation,
        audit_position: receipt.audit_position,
        audit_ingest_time_unix_seconds: receipt.time,
    }))
}

#[derive(Clone, Copy)]
struct AliasReceipt {
    key: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    tenant: TenantId,
    expected: ResourceGeneration,
    generation: ResourceGeneration,
    audit_position: u64,
    time: u64,
    digest: [u8; 32],
}

fn decode_receipt(bytes: &[u8]) -> Result<AliasReceipt, TenantAliasAdministrationFailure> {
    if bytes.len() != RECEIPT_V2_BYTES {
        return Err(TenantAliasAdministrationFailure::PersistenceUnavailable);
    }
    let array = |start| {
        bytes
            .get(start..start + 16)
            .and_then(|value| value.try_into().ok())
            .ok_or(TenantAliasAdministrationFailure::PersistenceUnavailable)
    };
    let long = |start| {
        bytes
            .get(start..start + 8)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(TenantAliasAdministrationFailure::PersistenceUnavailable)
    };
    let key = AdministrativeIdempotencyKey::new(array(16)?)
        .map_err(|_| TenantAliasAdministrationFailure::PersistenceUnavailable)?;
    let actor = PrincipalId::from_bytes(array(32)?)
        .map_err(|_| TenantAliasAdministrationFailure::PersistenceUnavailable)?;
    let tenant = TenantId::from_bytes(array(48)?)
        .map_err(|_| TenantAliasAdministrationFailure::PersistenceUnavailable)?;
    let expected = ResourceGeneration::new(long(64)?)
        .map_err(|_| TenantAliasAdministrationFailure::PersistenceUnavailable)?;
    let generation = ResourceGeneration::new(long(72)?)
        .map_err(|_| TenantAliasAdministrationFailure::PersistenceUnavailable)?;
    let audit_position = long(80)?;
    let digest = bytes
        .get(88..120)
        .and_then(|value| value.try_into().ok())
        .filter(|value: &[u8; 32]| value.iter().any(|byte| *byte != 0))
        .ok_or(TenantAliasAdministrationFailure::PersistenceUnavailable)?;
    let time = long(8)?;
    if time == 0 || audit_position == 0 || expected.get().checked_add(1) != Some(generation.get()) {
        return Err(TenantAliasAdministrationFailure::PersistenceUnavailable);
    }
    Ok(AliasReceipt {
        key,
        actor,
        tenant,
        expected,
        generation,
        audit_position,
        time,
        digest,
    })
}

fn replay_records(
    records: &[GovernanceAuditRecord],
    request: &TenantAliasBindRequest,
) -> Result<Option<TenantAliasBinding>, TenantAliasAdministrationFailure> {
    for record in records {
        if record.transaction().to_bytes() != request.idempotency.to_bytes() {
            continue;
        }
        let bytes = record.intent();
        if bytes.len() != 112 || !bytes.starts_with(&AUDIT_MAGIC) {
            return Err(TenantAliasAdministrationFailure::IdempotencyConflict);
        }
        let time = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?,
        );
        let actor = PrincipalId::from_bytes(
            bytes[32..48]
                .try_into()
                .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?,
        )
        .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?;
        let tenant = TenantId::from_bytes(
            bytes[48..64]
                .try_into()
                .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?,
        )
        .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?;
        let expected = ResourceGeneration::new(u64::from_be_bytes(
            bytes[64..72]
                .try_into()
                .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?,
        ))
        .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?;
        let generation = ResourceGeneration::new(u64::from_be_bytes(
            bytes[72..80]
                .try_into()
                .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?,
        ))
        .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?;
        let digest: [u8; 32] = bytes[80..112]
            .try_into()
            .map_err(|_| TenantAliasAdministrationFailure::IdempotencyConflict)?;
        if time == 0
            || actor != request.actor.principal_id()
            || tenant != request.tenant
            || expected != request.expected
            || digest != request_digest(request)
        {
            return Err(TenantAliasAdministrationFailure::IdempotencyConflict);
        }
        return Ok(Some(TenantAliasBinding {
            tenant,
            generation,
            audit_position: record.position(),
            audit_ingest_time_unix_seconds: time,
        }));
    }
    Ok(None)
}

fn map_tenant_record(failure: TenantAdministrationFailure) -> TenantAliasAdministrationFailure {
    match failure {
        TenantAdministrationFailure::Unauthorized => {
            TenantAliasAdministrationFailure::UnknownTenant
        },
        TenantAdministrationFailure::InvalidInput
        | TenantAdministrationFailure::DuplicateTenant
        | TenantAdministrationFailure::StaleGeneration
        | TenantAdministrationFailure::IdempotencyConflict
        | TenantAdministrationFailure::PersistenceUnavailable => {
            TenantAliasAdministrationFailure::PersistenceUnavailable
        },
    }
}
fn map_catalog(failure: positron_kernel::CatalogFailure) -> TenantAliasAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::IdempotencyConflict => {
            TenantAliasAdministrationFailure::IdempotencyConflict
        },
        CatalogFailureCode::LimitExceeded | CatalogFailureCode::ResourceAdmissionRefused => {
            TenantAliasAdministrationFailure::CapacityExceeded
        },
        CatalogFailureCode::StaleGeneration
        | CatalogFailureCode::StorageUnavailable
        | CatalogFailureCode::ConcurrentWriter
        | CatalogFailureCode::InvalidInput
        | CatalogFailureCode::IntegrityCorruption
        | CatalogFailureCode::AuthenticationFailed
        | CatalogFailureCode::UnsupportedFormat => {
            TenantAliasAdministrationFailure::PersistenceUnavailable
        },
    }
}
