//! Authenticated, replay-safe acceptance of one observed lifecycle-clock discontinuity.

use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_kernel::{
    AuditIntent, Catalog, CatalogCommit, CatalogFailureCode, CatalogObject, CatalogProposal,
    CatalogSnapshot, FormatEpoch, PreparedLifecycleClockAcceptance, PreparedTransactionResolution,
    TransactionId, validate_catalog_anchor_record,
};
use sha2::{Digest, Sha256};

use crate::audit::LifecycleClockAcceptanceAuditIntent;
use crate::{AdministrativeIdempotencyKey, AuthorizedContext, Identity};

const REQUEST_DOMAIN: &[u8] = b"positron.lifecycle-clock.acceptance.v1\0";

#[derive(Clone, Copy)]
pub struct LifecycleClockAcceptanceRequest {
    actor: AuthorizedContext,
    expected_catalog: positron_kernel::CatalogGenerationId,
    idempotency_key: AdministrativeIdempotencyKey,
}

impl LifecycleClockAcceptanceRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        expected_catalog: positron_kernel::CatalogGenerationId,
        idempotency_key: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            expected_catalog,
            idempotency_key,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleClockAcceptanceUpdate {
    audit_position: u64,
}

impl LifecycleClockAcceptanceUpdate {
    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleClockAcceptanceAdministrationFailure {
    Unauthorized,
    StaleCatalog,
    IdempotencyConflict,
    PersistenceUnavailable,
    CapacityExceeded,
}

impl Display for LifecycleClockAcceptanceAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("lifecycle clock discontinuity acceptance failed")
    }
}

impl Error for LifecycleClockAcceptanceAdministrationFailure {}

pub enum LifecycleClockAcceptanceAdministration {}

impl LifecycleClockAcceptanceAdministration {
    pub fn accept(
        catalog: &Catalog<'_>,
        identity: &Identity,
        request: LifecycleClockAcceptanceRequest,
        acceptance: &PreparedLifecycleClockAcceptance<'_>,
    ) -> Result<
        (LifecycleClockAcceptanceUpdate, CatalogCommit),
        LifecycleClockAcceptanceAdministrationFailure,
    > {
        let actor = identity
            .authorize_system_audit_retention(request.actor)
            .map_err(|_| LifecycleClockAcceptanceAdministrationFailure::Unauthorized)?;
        let digest = request_digest(actor, request, acceptance);
        let transaction =
            TransactionId::new(request.idempotency_key.to_bytes()).map_err(map_catalog)?;
        // Resolve any authenticated pre-publication before considering a new
        // generation. A visible transaction is resolved by commit_prepared
        // before its generation CAS, so acknowledgement-lost retries can
        // install the same kernel-derived correction.
        match catalog
            .resume_prepared(transaction, digest)
            .map_err(map_catalog)?
        {
            PreparedTransactionResolution::Resumed(commit) => {
                return update_from_commit(commit, actor, request, acceptance, digest);
            },
            PreparedTransactionResolution::Unavailable => {
                let commit = catalog
                    .committed_transaction(transaction)
                    .map_err(map_catalog)?
                    .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
                return update_from_commit(commit, actor, request, acceptance, digest);
            },
            PreparedTransactionResolution::Absent => {},
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let mut objects = retained_objects(&snapshot)?;
        objects
            .try_reserve(1)
            .map_err(|_| LifecycleClockAcceptanceAdministrationFailure::CapacityExceeded)?;
        objects.push(
            CatalogObject::new(acceptance.accepted_catalog_anchor().to_vec())
                .map_err(map_catalog)?,
        );
        let audit = LifecycleClockAcceptanceAuditIntent {
            idempotency_key: request.idempotency_key,
            actor,
            expected_catalog: request.expected_catalog.to_bytes(),
            safe_anchor: acceptance.safe_anchor(),
            observed_wall_clock: acceptance.observed_wall_clock(),
            observed_offset_nanoseconds: acceptance.observed_offset_nanoseconds(),
            request_digest: digest,
        }
        .encode();
        let commit = catalog
            .commit_prepared(
                request.expected_catalog,
                CatalogProposal::new(
                    transaction,
                    snapshot.format_epoch().unwrap_or(FormatEpoch::CATALOG_V1),
                    objects,
                )
                .map_err(map_catalog)?,
                AuditIntent::new(audit).map_err(map_catalog)?,
                digest,
            )
            .map_err(map_catalog)?;
        update_from_commit(commit, actor, request, acceptance, digest)
    }
}

fn update_from_commit(
    commit: CatalogCommit,
    actor: positron_domain::identity::PrincipalId,
    request: LifecycleClockAcceptanceRequest,
    acceptance: &PreparedLifecycleClockAcceptance<'_>,
    digest: [u8; 32],
) -> Result<
    (LifecycleClockAcceptanceUpdate, CatalogCommit),
    LifecycleClockAcceptanceAdministrationFailure,
> {
    let record = commit
        .governance_audit_record()
        .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
    let entry = crate::GovernanceAuditEntry::decode(record)
        .map_err(|_| LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
    let acceptance_audit = entry
        .as_lifecycle_clock_acceptance()
        .ok_or(LifecycleClockAcceptanceAdministrationFailure::IdempotencyConflict)?;
    if acceptance_audit.idempotency_key() != request.idempotency_key
        || acceptance_audit.actor_id() != actor
        || acceptance_audit.expected_catalog() != request.expected_catalog.to_bytes()
        || acceptance_audit.safe_anchor() != acceptance.safe_anchor()
        || acceptance_audit.observed_wall_clock() != acceptance.observed_wall_clock()
        || acceptance_audit.observed_offset_nanoseconds()
            != acceptance.observed_offset_nanoseconds()
        || acceptance_audit.request_digest() != digest
    {
        return Err(LifecycleClockAcceptanceAdministrationFailure::IdempotencyConflict);
    }
    Ok((
        LifecycleClockAcceptanceUpdate {
            audit_position: record.position(),
        },
        commit,
    ))
}

fn retained_objects(
    snapshot: &CatalogSnapshot,
) -> Result<Vec<CatalogObject>, LifecycleClockAcceptanceAdministrationFailure> {
    let mut objects = Vec::new();
    let mut lifecycle_anchor_seen = false;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
        if validate_catalog_anchor_record(bytes)
            .map_err(|_| LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?
        {
            if lifecycle_anchor_seen {
                return Err(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable);
            }
            lifecycle_anchor_seen = true;
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
    }
    Ok(objects)
}

fn request_digest(
    actor: positron_domain::identity::PrincipalId,
    request: LifecycleClockAcceptanceRequest,
    acceptance: &PreparedLifecycleClockAcceptance<'_>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REQUEST_DOMAIN);
    digest.update(actor.to_bytes());
    digest.update(request.expected_catalog.to_bytes());
    digest.update(request.idempotency_key.to_bytes());
    digest.update(acceptance.safe_anchor().value().to_be_bytes());
    digest.update(acceptance.observed_wall_clock().value().to_be_bytes());
    digest.update(acceptance.observed_offset_nanoseconds().to_be_bytes());
    digest.finalize().into()
}

fn map_catalog(
    failure: positron_kernel::CatalogFailure,
) -> LifecycleClockAcceptanceAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::StaleGeneration => {
            LifecycleClockAcceptanceAdministrationFailure::StaleCatalog
        },
        CatalogFailureCode::IdempotencyConflict => {
            LifecycleClockAcceptanceAdministrationFailure::IdempotencyConflict
        },
        CatalogFailureCode::LimitExceeded | CatalogFailureCode::ResourceAdmissionRefused => {
            LifecycleClockAcceptanceAdministrationFailure::CapacityExceeded
        },
        CatalogFailureCode::StorageUnavailable
        | CatalogFailureCode::ConcurrentWriter
        | CatalogFailureCode::InvalidInput
        | CatalogFailureCode::IntegrityCorruption
        | CatalogFailureCode::AuthenticationFailed
        | CatalogFailureCode::UnsupportedFormat => {
            LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable
        },
    }
}

const RETENTION_RECEIPT_MAGIC: [u8; 8] = *b"POSLCR01";
const RETENTION_RECEIPT_BYTES: usize = 128;

pub(crate) fn legacy_receipt_object(
    entry: &crate::audit::LifecycleClockAcceptanceAuditEntry,
) -> Result<CatalogObject, LifecycleClockAcceptanceAdministrationFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(RETENTION_RECEIPT_BYTES)
        .map_err(|_| LifecycleClockAcceptanceAdministrationFailure::CapacityExceeded)?;
    bytes.extend_from_slice(&RETENTION_RECEIPT_MAGIC);
    bytes.extend_from_slice(&entry.idempotency_key().to_bytes());
    bytes.extend_from_slice(&entry.actor_id().to_bytes());
    bytes.extend_from_slice(&entry.expected_catalog());
    bytes.extend_from_slice(&entry.safe_anchor().value().to_be_bytes());
    bytes.extend_from_slice(&entry.observed_wall_clock().value().to_be_bytes());
    bytes.extend_from_slice(&entry.observed_offset_nanoseconds().to_be_bytes());
    bytes.extend_from_slice(&entry.request_digest());
    CatalogObject::new(bytes).map_err(map_catalog)
}

pub(crate) fn retention_terminal_key(bytes: &[u8]) -> Result<Option<[u8; 16]>, ()> {
    crate::audit::terminal_receipt_key(
        bytes,
        &[(RETENTION_RECEIPT_MAGIC, RETENTION_RECEIPT_BYTES, 8)],
    )
}
