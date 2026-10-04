//! Catalog task-record encoding and authenticated recovery helpers.

use super::super::*;
use super::*;
use crate::{AuditIntent, Catalog, CatalogObject, CatalogProposal, TransactionId};

pub(super) fn durable_retention_publication_pair_exists(
    catalog: &Catalog<'_>,
    before: &TaskState,
) -> Result<bool, MaintenanceFailure> {
    let snapshot = catalog.pin().map_err(map_catalog_failure)?;
    let reclamation_identity = retention_reclamation_identity(&before.task)?;
    let mut identities = BTreeSet::new();
    let mut publication = None;
    let mut reclamation = None;
    for bytes in snapshot.plaintext_objects() {
        let Some(identity) = record::record_identity(bytes)? else {
            continue;
        };
        if !identities.insert(identity) {
            return Err(MaintenanceFailure::CatalogUnavailable);
        }
        let candidate = decode_record(bytes)?;
        if identity == before.task.identity {
            if publication.replace(candidate).is_some() {
                return Err(MaintenanceFailure::CatalogUnavailable);
            }
        } else if identity == reclamation_identity && reclamation.replace(candidate).is_some() {
            return Err(MaintenanceFailure::CatalogUnavailable);
        }
    }
    match (publication, reclamation) {
        (Some(publication), None) if durable_running_publication_matches(before, &publication) => {
            Ok(false)
        },
        (Some(publication), Some(reclamation)) => {
            if canonical_retention_publication_pair(before, &publication, &reclamation)? {
                Ok(true)
            } else {
                Err(MaintenanceFailure::PreconditionFailed)
            }
        },
        _ => Err(MaintenanceFailure::CatalogUnavailable),
    }
}

pub(super) fn durable_compaction_completion_exists(
    catalog: &Catalog<'_>,
    before: &TaskState,
    terminal_order: u64,
) -> Result<bool, MaintenanceFailure> {
    let snapshot = catalog.pin().map_err(map_catalog_failure)?;
    let mut durable = None;
    for bytes in snapshot.plaintext_objects() {
        if record::record_identity(bytes)? != Some(before.task.identity) {
            continue;
        }
        if durable.replace(bytes).is_some() {
            return Err(MaintenanceFailure::CatalogUnavailable);
        }
    }
    let Some(durable) = durable else {
        return Err(MaintenanceFailure::CatalogUnavailable);
    };
    if encode_record(before)?.as_bytes() == durable {
        return Ok(false);
    }
    let mut succeeded = before.clone();
    succeeded.phase = MaintenanceTaskPhase::Succeeded;
    succeeded.cancellation_requested = false;
    succeeded.active_dispatch = None;
    succeeded.terminal_order = Some(terminal_order);
    if encode_record(&succeeded)?.as_bytes() == durable {
        return Ok(true);
    }
    Err(MaintenanceFailure::PreconditionFailed)
}

pub(super) fn durable_running_publication_matches(before: &TaskState, durable: &TaskState) -> bool {
    durable.task == before.task
        && durable.phase == MaintenanceTaskPhase::Running
        && durable.submitted_at == before.submitted_at
        && durable.checkpoint == before.checkpoint
        && durable.pause_until == before.pause_until
        && durable.cancellation_requested == before.cancellation_requested
        && durable.dispatches == before.dispatches
}

pub(super) fn canonical_retention_publication_pair(
    before: &TaskState,
    publication: &TaskState,
    reclamation: &TaskState,
) -> Result<bool, MaintenanceFailure> {
    Ok(publication.task == before.task
        && publication.phase == MaintenanceTaskPhase::Succeeded
        && publication.submitted_at == before.submitted_at
        && publication.pause_until == before.pause_until
        && publication.dispatches == before.dispatches
        && publication.checkpoint == before.checkpoint
        && !publication.cancellation_requested
        && reclamation.task.identity == retention_reclamation_identity(&before.task)?
        && reclamation.task.class == MaintenanceTaskClass::RetentionReclamation
        && reclamation.phase == MaintenanceTaskPhase::Queued
        && reclamation.task.scope == before.task.scope
        && matches!(
            reclamation.task.trigger,
            MaintenanceTrigger::Event | MaintenanceTrigger::AgeDerived
        )
        && reclamation.task.preconditions == before.task.preconditions
        && reclamation.task.inputs == before.task.outputs
        && reclamation.task.outputs.is_empty()
        && reclamation.task.reservations == before.task.reservations
        && reclamation.task.not_before == 0
        && reclamation.checkpoint.is_none()
        && reclamation.pause_until.is_none()
        && !reclamation.cancellation_requested
        && reclamation.dispatches == 0
        && reclamation.submitted_at == before.submitted_at)
}

pub(super) fn retention_reclamation_identity(
    publication: &MaintenanceTask,
) -> Result<MaintenanceTaskId, MaintenanceFailure> {
    let binding = publication
        .outputs
        .first()
        .ok_or(MaintenanceFailure::PreconditionFailed)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(
        binding
            .to_bytes()
            .get(..16)
            .ok_or(MaintenanceFailure::PreconditionFailed)?,
    );
    bytes[0] ^= 0xa5;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    MaintenanceTaskId::new(bytes)
}

pub(super) fn persist_task_state(
    catalog: &Catalog<'_>,
    task: &TaskState,
    removed: Option<MaintenanceTaskId>,
) -> Result<(), MaintenanceFailure> {
    persist_task_state_inner(catalog, task, removed, None, None)
}

pub(super) fn persist_task_state_audited(
    catalog: &Catalog<'_>,
    task: &TaskState,
    audit: AuditIntent,
) -> Result<(), MaintenanceFailure> {
    persist_task_state_inner(catalog, task, None, None, Some(audit))
}

pub(super) fn persist_task_state_admitted(
    catalog: &Catalog<'_>,
    task: &TaskState,
    removed: Option<MaintenanceTaskId>,
    execution: &MaintenanceExecution<'_>,
) -> Result<(), MaintenanceFailure> {
    persist_task_state_inner(catalog, task, removed, Some(execution), None)
}

pub(super) fn persist_task_state_inner(
    catalog: &Catalog<'_>,
    task: &TaskState,
    removed: Option<MaintenanceTaskId>,
    execution: Option<&MaintenanceExecution<'_>>,
    audit: Option<AuditIntent>,
) -> Result<(), MaintenanceFailure> {
    let record = encode_record(task)?;
    let snapshot = catalog.pin().map_err(map_catalog_failure)?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(snapshot.object_count())
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    let mut same_record_is_current = false;
    let mut identities = BTreeSet::new();
    for bytes in snapshot.plaintext_objects() {
        match record::record_identity(bytes).map_err(|_| MaintenanceFailure::CatalogUnavailable)? {
            Some(identity) => {
                if !identities.insert(identity) {
                    return Err(MaintenanceFailure::CatalogUnavailable);
                }
                if identity == task.task.identity || Some(identity) == removed {
                    if identity == task.task.identity && bytes == record.as_bytes() {
                        same_record_is_current = true;
                    }
                } else {
                    objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?);
                }
            },
            None => objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?),
        }
    }
    if same_record_is_current && removed.is_none() {
        return Ok(());
    }
    let record_object = record.catalog_object()?;
    let transaction = record_transaction(
        snapshot.identity().to_bytes(),
        record_object.identity().to_bytes(),
    )?;
    objects.push(record_object);
    let epoch = snapshot
        .format_epoch()
        .ok_or(MaintenanceFailure::CatalogUnavailable)?;
    let proposal =
        CatalogProposal::new(transaction, epoch, objects).map_err(map_catalog_failure)?;
    match execution {
        Some(execution) => {
            catalog.commit_admitted_maintenance_task_state(snapshot.identity(), proposal, execution)
        },
        None => catalog.commit(snapshot.identity(), proposal, audit),
    }
    .map_err(map_catalog_failure)?;
    Ok(())
}

pub(super) fn persist_window(
    catalog: &Catalog<'_>,
    window: &MaintenanceWindow,
) -> Result<(), MaintenanceFailure> {
    let encoded = record::encode_window(window)?;
    let snapshot = catalog.pin().map_err(map_catalog_failure)?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(snapshot.object_count())
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    let mut same_window_is_current = false;
    let mut identities = BTreeSet::new();
    let mut saw_window = false;
    for bytes in snapshot.plaintext_objects() {
        if let Some(identity) =
            record::record_identity(bytes).map_err(|_| MaintenanceFailure::CatalogUnavailable)?
        {
            if !identities.insert(identity) {
                return Err(MaintenanceFailure::CatalogUnavailable);
            }
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?);
            continue;
        }
        if record::window_record(bytes)
            .map_err(|_| MaintenanceFailure::CatalogUnavailable)?
            .is_some()
        {
            if saw_window {
                return Err(MaintenanceFailure::CatalogUnavailable);
            }
            saw_window = true;
            same_window_is_current |= bytes == encoded;
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?);
    }
    if same_window_is_current {
        return Ok(());
    }
    let object = CatalogObject::new(encoded).map_err(map_catalog_failure)?;
    let transaction =
        record_transaction(snapshot.identity().to_bytes(), object.identity().to_bytes())?;
    objects.push(object);
    let epoch = snapshot
        .format_epoch()
        .ok_or(MaintenanceFailure::CatalogUnavailable)?;
    let proposal =
        CatalogProposal::new(transaction, epoch, objects).map_err(map_catalog_failure)?;
    catalog
        .commit(snapshot.identity(), proposal, None)
        .map_err(map_catalog_failure)?;
    Ok(())
}

pub(super) fn record_transaction(
    predecessor: [u8; 32],
    identity: [u8; 32],
) -> Result<TransactionId, MaintenanceFailure> {
    let mut material = Vec::new();
    material
        .try_reserve_exact(77)
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    material.extend_from_slice(b"maintenance-transaction-v1");
    material.extend_from_slice(&predecessor);
    material.extend_from_slice(&identity);
    let transaction_identity = CatalogObject::new(material)
        .map_err(map_catalog_failure)?
        .identity()
        .to_bytes();
    let mut transaction = [0; 16];
    transaction.copy_from_slice(
        transaction_identity
            .get(..16)
            .ok_or(MaintenanceFailure::CatalogUnavailable)?,
    );
    if transaction.iter().all(|byte| *byte == 0) {
        transaction[0] = 1;
    }
    TransactionId::new(transaction).map_err(map_catalog_failure)
}

pub(super) fn map_catalog_failure(_: crate::CatalogFailure) -> MaintenanceFailure {
    MaintenanceFailure::CatalogUnavailable
}
