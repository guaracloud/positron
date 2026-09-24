use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    InstanceId, TransactionId,
};

use crate::audit::plaintext_listener_transport_audit_intent_v3;
use crate::{GovernanceAuditEntry, ListenerTransportAuditRequest, ListenerTransportRole};

const RECEIPT_MAGIC: [u8; 8] = *b"POSLTR01";
const RECEIPT_BYTES: usize = 80;

/// Administration-owned activation of an explicitly selected plaintext
/// listener transport profile.
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
    /// Records one exact configured plaintext opt-out intent. Legacy records
    /// remain readable and API receipts remain resolvable through their
    /// historical request identity.
    pub fn activate_plaintext_listener(
        catalog: &Catalog<'_>,
        instance: InstanceId,
        request: ListenerTransportAuditRequest,
    ) -> Result<ListenerTransportActivation, ListenerTransportAdministrationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(audit_position) = find_receipt(&snapshot, instance, request)? {
            return Ok(ListenerTransportActivation { audit_position });
        }
        let mut existing = None;
        for record in catalog.governance_audit_records().map_err(map_catalog)? {
            let entry = GovernanceAuditEntry::decode(&record)
                .map_err(|_| ListenerTransportAdministrationFailure::CorruptState)?;
            if let Some(configuration) = entry.as_configuration()
                && configuration
                    .plaintext_listener_opt_outs()
                    .iter()
                    .any(|receipt| receipt.matches_request(instance.to_bytes(), request))
            {
                if existing.replace(configuration.position()).is_some() {
                    return Err(ListenerTransportAdministrationFailure::CorruptState);
                }
                continue;
            }
            let Some(transport) = entry.as_listener_transport() else {
                continue;
            };
            if !transport.matches_request(instance.to_bytes(), request) {
                continue;
            }
            if existing.replace(transport.position()).is_some() {
                return Err(ListenerTransportAdministrationFailure::CorruptState);
            }
        }
        if let Some(audit_position) = existing {
            return Ok(ListenerTransportActivation { audit_position });
        }

        let objects = retained_objects(&snapshot)?;
        let audit_position = snapshot
            .governance_audit_frontier()
            .checked_add(1)
            .ok_or(ListenerTransportAdministrationFailure::PersistenceUnavailable)?;
        let mut objects = objects;
        let request_digest = request.digest_for(instance.to_bytes());
        let transaction = TransactionId::new(request.transaction_id_for(instance.to_bytes()))
            .map_err(map_catalog)?;
        objects.push(
            CatalogObject::new(encode_receipt(
                instance,
                transaction,
                request_digest,
                audit_position,
            ))
            .map_err(map_catalog)?,
        );
        let audit = AuditIntent::new(plaintext_listener_transport_audit_intent_v3(
            instance.to_bytes(),
            request,
        ))
        .map_err(map_catalog)?;
        let commit = catalog
            .commit(
                snapshot.identity(),
                CatalogProposal::new(
                    transaction,
                    snapshot
                        .format_epoch()
                        .ok_or(ListenerTransportAdministrationFailure::CorruptState)?,
                    objects,
                )
                .map_err(map_catalog)?,
                Some(audit),
            )
            .map_err(map_catalog)?;
        let record = commit
            .governance_audit_record()
            .ok_or(ListenerTransportAdministrationFailure::PersistenceUnavailable)?;
        let entry = GovernanceAuditEntry::decode(record)
            .map_err(|_| ListenerTransportAdministrationFailure::CorruptState)?;
        if entry.as_listener_transport().is_some_and(|transport| {
            transport.instance_id() == instance.to_bytes()
                && transport.request_digest() == Some(request_digest)
                && transport.request_id() == Some(transaction.to_bytes())
        }) && record.transaction() == transaction
            && record.position() == audit_position
        {
            Ok(ListenerTransportActivation {
                audit_position: record.position(),
            })
        } else {
            Err(ListenerTransportAdministrationFailure::CorruptState)
        }
    }

    /// Compatibility entry point for callers that explicitly select the API
    /// listener. New runtime composition should use `activate_plaintext_listener`.
    pub fn activate_public_plaintext_api(
        catalog: &Catalog<'_>,
        instance: InstanceId,
        request: ListenerTransportAuditRequest,
    ) -> Result<ListenerTransportActivation, ListenerTransportAdministrationFailure> {
        Self::activate_plaintext_listener(catalog, instance, request)
    }
}

fn find_receipt(
    snapshot: &CatalogSnapshot,
    instance: InstanceId,
    request: ListenerTransportAuditRequest,
) -> Result<Option<u64>, ListenerTransportAdministrationFailure> {
    let transaction = request.transaction_id_for(instance.to_bytes());
    let request_digest = request.digest_for(instance.to_bytes());
    let legacy = (request.listener_role() == ListenerTransportRole::Api).then(|| {
        (
            request.legacy_transaction_id_for(instance.to_bytes()),
            request.legacy_digest_for(instance.to_bytes()),
        )
    });
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(ListenerTransportAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(&RECEIPT_MAGIC) {
            continue;
        }
        if bytes.len() != RECEIPT_BYTES {
            return Err(ListenerTransportAdministrationFailure::CorruptState);
        }
        let stored_transaction: [u8; 16] = bytes
            .get(8..24)
            .ok_or(ListenerTransportAdministrationFailure::CorruptState)?
            .try_into()
            .map_err(|_| ListenerTransportAdministrationFailure::CorruptState)?;
        let expected_digest = if stored_transaction == transaction {
            request_digest
        } else {
            match legacy {
                Some((legacy_transaction, legacy_digest))
                    if stored_transaction == legacy_transaction =>
                {
                    legacy_digest
                },
                _ => continue,
            }
        };
        let stored_instance: [u8; 16] = bytes
            .get(24..40)
            .ok_or(ListenerTransportAdministrationFailure::CorruptState)?
            .try_into()
            .map_err(|_| ListenerTransportAdministrationFailure::CorruptState)?;
        let stored_digest: [u8; 32] = bytes
            .get(40..72)
            .ok_or(ListenerTransportAdministrationFailure::CorruptState)?
            .try_into()
            .map_err(|_| ListenerTransportAdministrationFailure::CorruptState)?;
        let audit_position = u64::from_be_bytes(
            bytes
                .get(72..80)
                .ok_or(ListenerTransportAdministrationFailure::CorruptState)?
                .try_into()
                .map_err(|_| ListenerTransportAdministrationFailure::CorruptState)?,
        );
        if stored_instance != instance.to_bytes()
            || stored_digest != expected_digest
            || audit_position == 0
        {
            return Err(ListenerTransportAdministrationFailure::CorruptState);
        }
        if found.replace(audit_position).is_some() {
            return Err(ListenerTransportAdministrationFailure::CorruptState);
        }
    }
    Ok(found)
}

fn encode_receipt(
    instance: InstanceId,
    transaction: TransactionId,
    request_digest: [u8; 32],
    audit_position: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RECEIPT_BYTES);
    bytes.extend_from_slice(&RECEIPT_MAGIC);
    bytes.extend_from_slice(&transaction.to_bytes());
    bytes.extend_from_slice(&instance.to_bytes());
    bytes.extend_from_slice(&request_digest);
    bytes.extend_from_slice(&audit_position.to_be_bytes());
    bytes
}

/// Builds one receipt object for a role record carried by another joint audit
/// transaction. The caller owns the enclosing Catalog proposal and supplies
/// its one shared audit position.
pub fn plaintext_listener_transport_receipt_object(
    instance: InstanceId,
    transaction: TransactionId,
    request: ListenerTransportAuditRequest,
    audit_position: u64,
) -> Result<CatalogObject, ListenerTransportAdministrationFailure> {
    if audit_position == 0 {
        return Err(ListenerTransportAdministrationFailure::PersistenceUnavailable);
    }
    CatalogObject::new(encode_receipt(
        instance,
        transaction,
        request.digest_for(instance.to_bytes()),
        audit_position,
    ))
    .map_err(map_catalog)
}

pub(crate) fn legacy_receipt_object(
    entry: &crate::audit::ListenerTransportAuditEntry,
) -> Result<CatalogObject, ListenerTransportAdministrationFailure> {
    let request_id = entry
        .request_id()
        .ok_or(ListenerTransportAdministrationFailure::CorruptState)?;
    let request_digest = entry
        .request_digest()
        .filter(|digest| digest.iter().any(|byte| *byte != 0))
        .ok_or(ListenerTransportAdministrationFailure::CorruptState)?;
    if entry.position() == 0 {
        return Err(ListenerTransportAdministrationFailure::CorruptState);
    }
    let transaction = TransactionId::new(request_id).map_err(map_catalog)?;
    CatalogObject::new(encode_receipt(
        InstanceId::new(entry.instance_id()).map_err(map_catalog)?,
        transaction,
        request_digest,
        entry.position(),
    ))
    .map_err(map_catalog)
}

pub(crate) fn retention_terminal_key(bytes: &[u8]) -> Result<Option<[u8; 16]>, ()> {
    crate::audit::terminal_receipt_key(bytes, &[(RECEIPT_MAGIC, RECEIPT_BYTES, 8)])
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
