use std::mem::size_of;

use super::super::{LedgerFailure, LedgerFailureCode};
use super::map_maintenance_failure;
use crate::{CatalogObject, MaintenanceCoordinator, MaintenanceTaskId, ResourceAmounts};

const RETENTION_PUBLICATION_BATCH_ITEMS: u64 = 16;
const MAX_RETENTION_PUBLICATION_SEGMENTS: usize = 16;
const COMPLETION_RECORD_COPIES: usize = 4;
const COMPLETION_BINDING_VECTORS: usize = 13;
const COMPLETION_CHECKPOINT_COPIES: usize = 3;

pub(crate) fn retention_publication_claim() -> Result<ResourceAmounts, LedgerFailure> {
    let scanned_metadata = crate::catalog::MAX_CATALOG_OBJECTS
        .checked_mul(size_of::<super::super::format::SegmentMetadata>())
        .and_then(|bytes| bytes.checked_mul(2));
    let proposed_catalog = crate::catalog::MAX_CATALOG_OBJECTS
        .checked_mul(size_of::<CatalogObject>())
        .and_then(|objects| {
            crate::catalog::MAX_CATALOG_OBJECTS
                .checked_mul(size_of::<super::super::format::SegmentMetadata>())
                .and_then(|metadata| objects.checked_add(metadata))
        });
    // The submitted Publication and its execution copy, planning bindings,
    // completion's before/after states, the Reclamation input, and the plan's
    // input/output pairs leave thirteen bounded binding vectors live. The
    // two encoded records and their CatalogObject clones peak at four copies;
    // submitted and completion states hold three checkpoint vectors.
    let bindings = MAX_RETENTION_PUBLICATION_SEGMENTS
        .checked_mul(size_of::<crate::MaintenanceObjectId>())
        .and_then(|objects| objects.checked_mul(COMPLETION_BINDING_VECTORS));
    let record_bytes = crate::maintenance::retention_publication_record_bytes_bound()
        .map_err(map_maintenance_failure)?;
    let completion_records = record_bytes
        .checked_mul(COMPLETION_RECORD_COPIES)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let completion_checkpoints = crate::maintenance::MAX_CHECKPOINT_BYTES
        .checked_mul(COMPLETION_CHECKPOINT_COPIES)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let memory = crate::catalog::MAX_CATALOG_TOTAL_BYTES
        .checked_add(
            scanned_metadata
                .zip(proposed_catalog)
                .map(|(scan, proposal)| scan.max(proposal))
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        )
        .and_then(|bytes| bytes.checked_add(bindings?))
        .and_then(|bytes| bytes.checked_add(completion_records))
        .and_then(|bytes| bytes.checked_add(completion_checkpoints))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    Ok(ResourceAmounts::new([
        u64::try_from(memory).map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        1,
        1,
        0,
        RETENTION_PUBLICATION_BATCH_ITEMS,
        0,
        1,
        1,
        1,
        1,
        0,
    ]))
}

pub(super) fn retention_publication_frontier_bound(
    coordinator: &MaintenanceCoordinator,
    identity: MaintenanceTaskId,
) -> Result<crate::IngestTime, LedgerFailure> {
    let status = coordinator
        .status(identity)
        .map_err(map_maintenance_failure)?;
    crate::maintenance::retention_publication_frontier(status.checkpoint())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))
}

pub(super) fn durable_task_record(
    basis: &crate::CatalogSnapshot,
    identity: MaintenanceTaskId,
) -> Result<&[u8], LedgerFailure> {
    let mut record = None;
    for bytes in basis.plaintext_objects() {
        if crate::maintenance::durable_task_record_identity(bytes)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
            == Some(identity)
            && record.replace(bytes).is_some()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
    }
    record.ok_or_else(|| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))
}
