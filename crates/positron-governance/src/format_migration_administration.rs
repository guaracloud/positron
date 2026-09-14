use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, FormatEpoch,
    TransactionId,
};

use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, TenantAdministration,
    tenant_administration::is_registry,
};

const FORMAT_MIGRATION_AUDIT_MAGIC: [u8; 8] = *b"POSFMT01";

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
    let record = catalog
        .governance_audit_records()
        .map_err(map_catalog)?
        .into_iter()
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
