//! Authenticated, replay-safe acceptance of one observed lifecycle-clock discontinuity.

use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_kernel::{
    AuditIntent, Catalog, CatalogCommit, CatalogFailureCode, CatalogObject, CatalogProposal,
    CatalogSnapshot, FormatEpoch, PreparedLifecycleClockAcceptance, PreparedTransactionResolution,
    TransactionId, catalog_anchor_matches_accepted_discontinuity, validate_catalog_anchor_record,
    validate_catalog_anchor_singleton,
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
    /// Resolves a compact terminal receipt retained after its corresponding
    /// governance audit entry has been reclaimed.
    pub fn replay_retained(
        catalog: &Catalog<'_>,
        identity: &Identity,
        request: LifecycleClockAcceptanceRequest,
        expected_safe_anchor: positron_domain::time::UnixNanoseconds,
    ) -> Result<
        Option<(LifecycleClockAcceptanceUpdate, CatalogSnapshot)>,
        LifecycleClockAcceptanceAdministrationFailure,
    > {
        let actor = identity
            .authorize_system_audit_retention(request.actor)
            .map_err(|_| LifecycleClockAcceptanceAdministrationFailure::Unauthorized)?;
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let Some(receipt) = find_retained_receipt(&snapshot, request.idempotency_key)? else {
            return Ok(None);
        };
        if receipt.actor != actor
            || receipt.expected_catalog != request.expected_catalog.to_bytes()
            || receipt.safe_anchor != expected_safe_anchor
            || receipt.request_digest
                != request_digest_fields(
                    actor,
                    request.expected_catalog.to_bytes(),
                    request.idempotency_key,
                    receipt.safe_anchor,
                    receipt.observed_wall_clock,
                    receipt.observed_offset_nanoseconds,
                )
        {
            return Err(LifecycleClockAcceptanceAdministrationFailure::IdempotencyConflict);
        }
        let mut anchor_seen = false;
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
            if !validate_catalog_anchor_singleton(bytes, &mut anchor_seen).map_err(|_| {
                LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable
            })? {
                continue;
            }
            if !catalog_anchor_matches_accepted_discontinuity(
                bytes,
                receipt.safe_anchor,
                receipt.observed_wall_clock,
                receipt.observed_offset_nanoseconds,
            )
            .map_err(|_| LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?
            {
                return Err(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable);
            }
        }
        if !anchor_seen {
            return Err(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable);
        }
        Ok(Some((
            LifecycleClockAcceptanceUpdate {
                audit_position: receipt.audit_position,
            },
            snapshot,
        )))
    }

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
    request_digest_fields(
        actor,
        request.expected_catalog.to_bytes(),
        request.idempotency_key,
        acceptance.safe_anchor(),
        acceptance.observed_wall_clock(),
        acceptance.observed_offset_nanoseconds(),
    )
}

fn request_digest_fields(
    actor: positron_domain::identity::PrincipalId,
    expected_catalog: [u8; 32],
    idempotency_key: AdministrativeIdempotencyKey,
    safe_anchor: positron_domain::time::UnixNanoseconds,
    observed_wall_clock: positron_domain::time::UnixNanoseconds,
    observed_offset_nanoseconds: i64,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REQUEST_DOMAIN);
    digest.update(actor.to_bytes());
    digest.update(expected_catalog);
    digest.update(idempotency_key.to_bytes());
    digest.update(safe_anchor.value().to_be_bytes());
    digest.update(observed_wall_clock.value().to_be_bytes());
    digest.update(observed_offset_nanoseconds.to_be_bytes());
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

const RETENTION_RECEIPT_MAGIC_V1: [u8; 8] = *b"POSLCR01";
const RETENTION_RECEIPT_MAGIC: [u8; 8] = *b"POSLCR02";
const RETENTION_RECEIPT_V1_BYTES: usize = 128;
const RETENTION_RECEIPT_BYTES: usize = RETENTION_RECEIPT_V1_BYTES + 8;

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
    bytes.extend_from_slice(&entry.position().to_be_bytes());
    CatalogObject::new(bytes).map_err(map_catalog)
}

pub(crate) fn retention_terminal_key(bytes: &[u8]) -> Result<Option<[u8; 16]>, ()> {
    crate::audit::terminal_receipt_key(
        bytes,
        &[
            (RETENTION_RECEIPT_MAGIC_V1, RETENTION_RECEIPT_V1_BYTES, 8),
            (RETENTION_RECEIPT_MAGIC, RETENTION_RECEIPT_BYTES, 8),
        ],
    )
}

#[derive(Clone, Copy)]
struct RetainedReceipt {
    actor: positron_domain::identity::PrincipalId,
    expected_catalog: [u8; 32],
    safe_anchor: positron_domain::time::UnixNanoseconds,
    observed_wall_clock: positron_domain::time::UnixNanoseconds,
    observed_offset_nanoseconds: i64,
    request_digest: [u8; 32],
    audit_position: u64,
}

fn find_retained_receipt(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<RetainedReceipt>, LifecycleClockAcceptanceAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
        let Some((stored_key, receipt)) = decode_retained_receipt(bytes)? else {
            continue;
        };
        if stored_key == key && found.replace(receipt).is_some() {
            return Err(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

fn decode_retained_receipt(
    bytes: &[u8],
) -> Result<
    Option<(AdministrativeIdempotencyKey, RetainedReceipt)>,
    LifecycleClockAcceptanceAdministrationFailure,
> {
    let has_v1_magic = bytes.starts_with(&RETENTION_RECEIPT_MAGIC_V1);
    let has_v2_magic = bytes.starts_with(&RETENTION_RECEIPT_MAGIC);
    if !has_v1_magic && !has_v2_magic {
        return Ok(None);
    }
    let expected_bytes = if has_v2_magic {
        RETENTION_RECEIPT_BYTES
    } else {
        RETENTION_RECEIPT_V1_BYTES
    };
    if bytes.len() != expected_bytes {
        return Err(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable);
    }
    let array = |start| {
        bytes
            .get(start..start + 16)
            .and_then(|value| value.try_into().ok())
            .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)
    };
    let long = |start| {
        bytes
            .get(start..start + 8)
            .and_then(|value| value.try_into().ok())
            .map(i64::from_be_bytes)
            .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)
    };
    let key = AdministrativeIdempotencyKey::new(array(8)?)
        .map_err(|_| LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
    let actor = positron_domain::identity::PrincipalId::from_bytes(array(24)?)
        .map_err(|_| LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
    let expected_catalog = bytes
        .get(40..72)
        .and_then(|value| value.try_into().ok())
        .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
    let request_digest = bytes
        .get(96..128)
        .and_then(|value| value.try_into().ok())
        .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?;
    let audit_position = if has_v2_magic {
        bytes
            .get(128..136)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .filter(|position| *position != 0)
            .ok_or(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)?
    } else {
        0
    };
    Ok(Some((
        key,
        RetainedReceipt {
            actor,
            expected_catalog,
            safe_anchor: positron_domain::time::UnixNanoseconds::new(long(72)?),
            observed_wall_clock: positron_domain::time::UnixNanoseconds::new(long(80)?),
            observed_offset_nanoseconds: long(88)?,
            request_digest,
            audit_position,
        },
    )))
}

#[cfg(test)]
mod receipt_tests {
    use super::*;

    #[test]
    fn legacy_receipt_v1_has_exact_bounds_and_preserves_its_known_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = AdministrativeIdempotencyKey::new([0x31; 16])?;
        let actor = positron_domain::identity::PrincipalId::from_bytes([0x32; 16])?;
        let expected_catalog = [0x33; 32];
        let safe_anchor = positron_domain::time::UnixNanoseconds::new(400);
        let observed_wall_clock = positron_domain::time::UnixNanoseconds::new(500);
        let observed_offset_nanoseconds = 100;
        let digest = request_digest_fields(
            actor,
            expected_catalog,
            key,
            safe_anchor,
            observed_wall_clock,
            observed_offset_nanoseconds,
        );
        let mut receipt = Vec::with_capacity(RETENTION_RECEIPT_V1_BYTES);
        receipt.extend_from_slice(&RETENTION_RECEIPT_MAGIC_V1);
        receipt.extend_from_slice(&key.to_bytes());
        receipt.extend_from_slice(&actor.to_bytes());
        receipt.extend_from_slice(&expected_catalog);
        receipt.extend_from_slice(&safe_anchor.value().to_be_bytes());
        receipt.extend_from_slice(&observed_wall_clock.value().to_be_bytes());
        receipt.extend_from_slice(&observed_offset_nanoseconds.to_be_bytes());
        receipt.extend_from_slice(&digest);
        let (decoded_key, decoded) =
            decode_retained_receipt(&receipt)?.ok_or("legacy receipt was not decoded")?;
        assert_eq!(decoded_key, key);
        assert_eq!(decoded.actor, actor);
        assert_eq!(decoded.expected_catalog, expected_catalog);
        assert_eq!(decoded.safe_anchor, safe_anchor);
        assert_eq!(decoded.observed_wall_clock, observed_wall_clock);
        assert_eq!(
            decoded.observed_offset_nanoseconds,
            observed_offset_nanoseconds
        );
        assert_eq!(decoded.request_digest, digest);
        assert_eq!(decoded.audit_position, 0);

        for invalid_length in [
            RETENTION_RECEIPT_V1_BYTES - 1,
            RETENTION_RECEIPT_V1_BYTES + 1,
        ] {
            let mut malformed = receipt.clone();
            malformed.truncate(invalid_length);
            if invalid_length > RETENTION_RECEIPT_V1_BYTES {
                malformed.push(0);
            }
            assert!(matches!(
                decode_retained_receipt(&malformed),
                Err(LifecycleClockAcceptanceAdministrationFailure::PersistenceUnavailable)
            ));
        }
        Ok(())
    }
}
