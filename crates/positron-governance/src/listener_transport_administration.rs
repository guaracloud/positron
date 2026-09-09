use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    FormatEpoch, InstanceId, TransactionId,
};

use crate::GovernanceAuditEntry;
use crate::audit::plaintext_api_transport_audit_intent;

/// Administration-owned activation of the explicitly selected public
/// plaintext API transport profile.
pub enum ListenerTransportAdministration {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerTransportActivation {
    audit_position: u64,
}

impl ListenerTransportActivation {
    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerTransportAdministrationFailure {
    PersistenceUnavailable,
    CorruptState,
}

impl Display for ListenerTransportAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("listener transport administration failed")
    }
}

impl Error for ListenerTransportAdministrationFailure {}

impl ListenerTransportAdministration {
    /// Records the active explicit opt-out exactly once for this instance.
    pub fn activate_public_plaintext_api(
        catalog: &Catalog<'_>,
        instance: InstanceId,
    ) -> Result<ListenerTransportActivation, ListenerTransportAdministrationFailure> {
        let transaction = TransactionId::new(instance.to_bytes()).map_err(map_catalog)?;
        let mut existing = None;
        for record in catalog.governance_audit_records().map_err(map_catalog)? {
            let entry = GovernanceAuditEntry::decode(&record)
                .map_err(|_| ListenerTransportAdministrationFailure::CorruptState)?;
            let Some(transport) = entry.as_listener_transport() else {
                continue;
            };
            if transport.instance_id() != instance.to_bytes() {
                continue;
            }
            if existing.replace(transport.position()).is_some() {
                return Err(ListenerTransportAdministrationFailure::CorruptState);
            }
        }
        if let Some(audit_position) = existing {
            return Ok(ListenerTransportActivation { audit_position });
        }

        let snapshot = catalog.pin().map_err(map_catalog)?;
        let objects = retained_objects(&snapshot)?;
        let audit = AuditIntent::new(plaintext_api_transport_audit_intent(instance.to_bytes()))
            .map_err(map_catalog)?;
        let commit = catalog
            .commit(
                snapshot.identity(),
                CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)
                    .map_err(map_catalog)?,
                Some(audit),
            )
            .map_err(map_catalog)?;
        let record = commit
            .governance_audit_record()
            .ok_or(ListenerTransportAdministrationFailure::PersistenceUnavailable)?;
        let entry = GovernanceAuditEntry::decode(record)
            .map_err(|_| ListenerTransportAdministrationFailure::CorruptState)?;
        if entry.as_listener_transport().is_some() && record.transaction() == transaction {
            Ok(ListenerTransportActivation {
                audit_position: record.position(),
            })
        } else {
            Err(ListenerTransportAdministrationFailure::CorruptState)
        }
    }
}

fn retained_objects(
    snapshot: &CatalogSnapshot,
) -> Result<Vec<CatalogObject>, ListenerTransportAdministrationFailure> {
    let mut objects = Vec::new();
    for identity in snapshot.object_identities() {
        let object = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(ListenerTransportAdministrationFailure::PersistenceUnavailable)?;
        objects.push(CatalogObject::new(object.to_vec()).map_err(map_catalog)?);
    }
    Ok(objects)
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> ListenerTransportAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::IntegrityCorruption | CatalogFailureCode::AuthenticationFailed => {
            ListenerTransportAdministrationFailure::CorruptState
        },
        CatalogFailureCode::StorageUnavailable
        | CatalogFailureCode::ConcurrentWriter
        | CatalogFailureCode::StaleGeneration
        | CatalogFailureCode::IdempotencyConflict
        | CatalogFailureCode::InvalidInput
        | CatalogFailureCode::UnsupportedFormat
        | CatalogFailureCode::LimitExceeded
        | CatalogFailureCode::ResourceAdmissionRefused => {
            ListenerTransportAdministrationFailure::PersistenceUnavailable
        },
    }
}
