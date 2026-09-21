use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogReadView,
    CatalogSnapshot, FormatEpoch, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, TenantAdministration,
    tenant_administration::is_registry,
};

const FORMAT_MIGRATION_AUDIT_MAGIC: [u8; 8] = *b"POSFMT01";
const FORMAT_MIGRATION_RECEIPT_MAGIC: [u8; 8] = *b"POSFMR01";
const FORMAT_MIGRATION_RECEIPT_BYTES: usize = 96;

/// Redacted result of the one-way V1-to-V2 Catalog format publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogFormatMigration {
    from: FormatEpoch,
    to: FormatEpoch,
    audit_position: u64,
}

impl CatalogFormatMigration {
    #[must_use]
    pub const fn from(self) -> FormatEpoch {
        self.from
    }

    #[must_use]
    pub const fn to(self) -> FormatEpoch {
        self.to
    }

    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogFormatMigrationFailure {
    Unauthorized,
    InvalidState,
    IdempotencyConflict,
    PersistenceUnavailable,
}

impl Display for CatalogFormatMigrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("catalog format migration failed")
    }
}

impl Error for CatalogFormatMigrationFailure {}

/// Administration builds the complete V2 successor; the caller must hold its
/// data-admission drain while this authority publishes the sole visibility point.
pub struct CatalogFormatMigrationAdministration;

impl CatalogFormatMigrationAdministration {
    /// Resolves an authenticated exact committed V2 retry before callers close
    /// data-plane admission.
    pub fn replay_from_view(
        view: &CatalogReadView,
        administrator: PrincipalId,
        actor: AuthorizedContext,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<Option<CatalogFormatMigration>, CatalogFormatMigrationFailure> {
        validate_actor(administrator, actor)?;
        match view.snapshot().format_epoch() {
            Some(FormatEpoch::CATALOG_V1) => Ok(None),
            Some(FormatEpoch::CATALOG_V2) => {
                if let Some(receipt) = find_receipt(view.snapshot(), idempotency)? {
                    return replay_receipt(receipt, administrator, idempotency).map(Some);
                }
                replay_epoch_two_records(
                    view.governance_audit_records(),
                    administrator,
                    idempotency,
                )
                .map(Some)
            },
            None | Some(_) => Err(CatalogFormatMigrationFailure::InvalidState),
        }
    }

    /// Validates the V1 migration candidate from an immutable Catalog view
    /// before callers close data-plane admission.
    pub fn preflight_from_view(
        view: &CatalogReadView,
        administrator: PrincipalId,
        actor: AuthorizedContext,
    ) -> Result<(), CatalogFormatMigrationFailure> {
        validate_actor(administrator, actor)?;
        match view.snapshot().format_epoch() {
            Some(FormatEpoch::CATALOG_V1) => view
                .snapshot()
                .governance_object()
                .map(|_| ())
                .map_err(map_catalog),
            None | Some(_) => Err(CatalogFormatMigrationFailure::InvalidState),
        }
    }

    pub fn migrate_to_epoch_two(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        actor: AuthorizedContext,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<CatalogFormatMigration, CatalogFormatMigrationFailure> {
        validate_actor(administrator, actor)?;
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let transaction = TransactionId::new(idempotency.to_bytes()).map_err(map_catalog)?;
        match snapshot.format_epoch() {
            Some(FormatEpoch::CATALOG_V1) => {
                let _ = snapshot.governance_object().map_err(map_catalog)?;
                let mut objects = Vec::new();
                for identity in snapshot.object_identities() {
                    let bytes = snapshot
                        .object(identity)
                        .map_err(map_catalog)?
                        .ok_or(CatalogFormatMigrationFailure::PersistenceUnavailable)?;
                    if is_registry(bytes) {
                        continue;
                    }
                    objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
                }
                objects.push(
                    TenantAdministration::epoch_two_registry(&snapshot)
                        .map_err(|_| CatalogFormatMigrationFailure::InvalidState)?,
                );
                let audit_position = snapshot
                    .governance_audit_frontier()
                    .checked_add(1)
                    .ok_or(CatalogFormatMigrationFailure::PersistenceUnavailable)?;
                objects.push(
                    CatalogObject::new(encode_receipt(administrator, idempotency, audit_position))
                        .map_err(map_catalog)?,
                );
                let audit = encode_audit(administrator, idempotency);
                let commit = catalog
                    .commit(
                        snapshot.identity(),
                        CatalogProposal::new(transaction, FormatEpoch::CATALOG_V2, objects)
                            .map_err(map_catalog)?,
                        Some(AuditIntent::new(audit).map_err(map_catalog)?),
                    )
                    .map_err(map_catalog)?;
                let position = commit
                    .governance_audit_record()
                    .ok_or(CatalogFormatMigrationFailure::PersistenceUnavailable)?
                    .position();
                if position != audit_position {
                    return Err(CatalogFormatMigrationFailure::PersistenceUnavailable);
                }
                Ok(CatalogFormatMigration {
                    from: FormatEpoch::CATALOG_V1,
                    to: FormatEpoch::CATALOG_V2,
                    audit_position: position,
                })
            },
            Some(FormatEpoch::CATALOG_V2) => replay_epoch_two(catalog, administrator, idempotency),
            None | Some(_) => Err(CatalogFormatMigrationFailure::InvalidState),
        }
    }
}

fn validate_actor(
    administrator: PrincipalId,
    actor: AuthorizedContext,
) -> Result<(), CatalogFormatMigrationFailure> {
    if actor.principal_id() != administrator
        || actor.scope() != Scope::SystemAdministration
        || actor.tenant_attribution().is_some()
    {
        return Err(CatalogFormatMigrationFailure::Unauthorized);
    }
    Ok(())
}

fn replay_epoch_two(
    catalog: &Catalog<'_>,
    administrator: PrincipalId,
    idempotency: AdministrativeIdempotencyKey,
) -> Result<CatalogFormatMigration, CatalogFormatMigrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    if let Some(receipt) = find_receipt(&snapshot, idempotency)? {
        return replay_receipt(receipt, administrator, idempotency);
    }
    replay_epoch_two_records(
        &catalog.governance_audit_records().map_err(map_catalog)?,
        administrator,
        idempotency,
    )
}

#[derive(Clone, Copy)]
struct Receipt {
    administrator: PrincipalId,
    audit_position: u64,
    request_digest: [u8; 32],
}

fn find_receipt(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<Receipt>, CatalogFormatMigrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(CatalogFormatMigrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(&FORMAT_MIGRATION_RECEIPT_MAGIC) {
            continue;
        }
        if bytes.len() != FORMAT_MIGRATION_RECEIPT_BYTES {
            return Err(CatalogFormatMigrationFailure::PersistenceUnavailable);
        }
        if bytes.get(8..24) != Some(key.to_bytes().as_slice()) {
            continue;
        }
        let administrator = PrincipalId::from_bytes(
            bytes
                .get(24..40)
                .ok_or(CatalogFormatMigrationFailure::PersistenceUnavailable)?
                .try_into()
                .map_err(|_| CatalogFormatMigrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| CatalogFormatMigrationFailure::PersistenceUnavailable)?;
        let from = u64::from_be_bytes(
            bytes
                .get(40..48)
                .ok_or(CatalogFormatMigrationFailure::PersistenceUnavailable)?
                .try_into()
                .map_err(|_| CatalogFormatMigrationFailure::PersistenceUnavailable)?,
        );
        let to = u64::from_be_bytes(
            bytes
                .get(48..56)
                .ok_or(CatalogFormatMigrationFailure::PersistenceUnavailable)?
                .try_into()
                .map_err(|_| CatalogFormatMigrationFailure::PersistenceUnavailable)?,
        );
        let audit_position = u64::from_be_bytes(
            bytes
                .get(56..64)
                .ok_or(CatalogFormatMigrationFailure::PersistenceUnavailable)?
                .try_into()
                .map_err(|_| CatalogFormatMigrationFailure::PersistenceUnavailable)?,
        );
        let request_digest: [u8; 32] = bytes
            .get(64..96)
            .ok_or(CatalogFormatMigrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| CatalogFormatMigrationFailure::PersistenceUnavailable)?;
        if from != u64::from(FormatEpoch::CATALOG_V1.value())
            || to != u64::from(FormatEpoch::CATALOG_V2.value())
            || audit_position == 0
            || request_digest != receipt_digest(key, administrator)
        {
            return Err(CatalogFormatMigrationFailure::PersistenceUnavailable);
        }
        if found
            .replace(Receipt {
                administrator,
                audit_position,
                request_digest,
            })
            .is_some()
        {
            return Err(CatalogFormatMigrationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

fn replay_receipt(
    receipt: Receipt,
    administrator: PrincipalId,
    key: AdministrativeIdempotencyKey,
) -> Result<CatalogFormatMigration, CatalogFormatMigrationFailure> {
    if receipt.administrator != administrator
        || receipt.request_digest != receipt_digest(key, administrator)
    {
        return Err(CatalogFormatMigrationFailure::IdempotencyConflict);
    }
    Ok(CatalogFormatMigration {
        from: FormatEpoch::CATALOG_V1,
        to: FormatEpoch::CATALOG_V2,
        audit_position: receipt.audit_position,
    })
}

pub(crate) fn legacy_receipt_object(
    entry: &crate::audit::CatalogFormatMigrationAuditEntry,
) -> Result<CatalogObject, CatalogFormatMigrationFailure> {
    if entry.from() != FormatEpoch::CATALOG_V1.value()
        || entry.to() != FormatEpoch::CATALOG_V2.value()
        || entry.position() == 0
    {
        return Err(CatalogFormatMigrationFailure::PersistenceUnavailable);
    }
    CatalogObject::new(encode_receipt(
        entry.actor_id(),
        entry.idempotency_key(),
        entry.position(),
    ))
    .map_err(map_catalog)
}

pub(crate) fn retention_terminal_key(bytes: &[u8]) -> Result<Option<[u8; 16]>, ()> {
    crate::audit::terminal_receipt_key(
        bytes,
        &[(
            FORMAT_MIGRATION_RECEIPT_MAGIC,
            FORMAT_MIGRATION_RECEIPT_BYTES,
            8,
        )],
    )
}

fn encode_receipt(
    administrator: PrincipalId,
    key: AdministrativeIdempotencyKey,
    audit_position: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FORMAT_MIGRATION_RECEIPT_BYTES);
    bytes.extend_from_slice(&FORMAT_MIGRATION_RECEIPT_MAGIC);
    bytes.extend_from_slice(&key.to_bytes());
    bytes.extend_from_slice(&administrator.to_bytes());
    bytes.extend_from_slice(&u64::from(FormatEpoch::CATALOG_V1.value()).to_be_bytes());
    bytes.extend_from_slice(&u64::from(FormatEpoch::CATALOG_V2.value()).to_be_bytes());
    bytes.extend_from_slice(&audit_position.to_be_bytes());
    bytes.extend_from_slice(&receipt_digest(key, administrator));
    bytes
}

fn receipt_digest(key: AdministrativeIdempotencyKey, administrator: PrincipalId) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"positron.catalog-format-migration.receipt.v1\0");
    digest.update(key.to_bytes());
    digest.update(administrator.to_bytes());
    digest.update(FormatEpoch::CATALOG_V1.value().to_be_bytes());
    digest.update(FormatEpoch::CATALOG_V2.value().to_be_bytes());
    digest.finalize().into()
}

fn replay_epoch_two_records(
    records: &[positron_kernel::GovernanceAuditRecord],
    administrator: PrincipalId,
    idempotency: AdministrativeIdempotencyKey,
) -> Result<CatalogFormatMigration, CatalogFormatMigrationFailure> {
    let record = records
        .iter()
        .find(|record| record.transaction().to_bytes() == idempotency.to_bytes())
        .ok_or(CatalogFormatMigrationFailure::InvalidState)?;
    if record.intent() != encode_audit(administrator, idempotency) {
        return Err(CatalogFormatMigrationFailure::IdempotencyConflict);
    }
    Ok(CatalogFormatMigration {
        from: FormatEpoch::CATALOG_V1,
        to: FormatEpoch::CATALOG_V2,
        audit_position: record.position(),
    })
}

fn encode_audit(administrator: PrincipalId, idempotency: AdministrativeIdempotencyKey) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(48);
    encoded.extend_from_slice(&FORMAT_MIGRATION_AUDIT_MAGIC);
    encoded.extend_from_slice(&idempotency.to_bytes());
    encoded.extend_from_slice(&administrator.to_bytes());
    encoded.extend_from_slice(&FormatEpoch::CATALOG_V1.value().to_be_bytes());
    encoded.extend_from_slice(&FormatEpoch::CATALOG_V2.value().to_be_bytes());
    encoded
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> CatalogFormatMigrationFailure {
    match failure.code() {
        CatalogFailureCode::IdempotencyConflict => {
            CatalogFormatMigrationFailure::IdempotencyConflict
        },
        CatalogFailureCode::AuthenticationFailed
        | CatalogFailureCode::IntegrityCorruption
        | CatalogFailureCode::InvalidInput
        | CatalogFailureCode::UnsupportedFormat => CatalogFormatMigrationFailure::InvalidState,
        CatalogFailureCode::ConcurrentWriter
        | CatalogFailureCode::StaleGeneration
        | CatalogFailureCode::StorageUnavailable
        | CatalogFailureCode::ResourceAdmissionRefused
        | CatalogFailureCode::LimitExceeded => {
            CatalogFormatMigrationFailure::PersistenceUnavailable
        },
    }
}
