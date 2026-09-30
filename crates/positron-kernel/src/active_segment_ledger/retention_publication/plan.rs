use super::super::format::SegmentState;
use super::super::{ActiveSegmentLedger, LedgerFailure, LedgerFailureCode, SegmentRetention};
use crate::{CatalogObject, MaintenanceObjectId, MaintenanceTaskId};

pub(super) const MAX_RETENTION_PUBLICATION_SEGMENTS: usize = 16;

pub(super) struct RetentionPublicationPlan {
    pub(super) metadata: Vec<super::super::format::SegmentMetadata>,
    pub(super) retired: Vec<(MaintenanceObjectId, MaintenanceObjectId)>,
    pub(super) frontier: crate::IngestTime,
}

pub(super) fn retention_publication_plan(
    ledger: &ActiveSegmentLedger<'_, '_>,
    basis: &crate::CatalogSnapshot,
    state: &super::super::state::LedgerState<'_>,
    frontier: crate::IngestTime,
) -> Result<RetentionPublicationPlan, LedgerFailure> {
    let policy = basis.retention_policy(ledger.scope.signal)?;
    if policy.instance() != ledger.catalog.instance()
        || policy.tenant() != ledger.scope.tenant
        || policy.signal_kind() != ledger.scope.signal
    {
        return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
    }
    let duration_nanos = policy
        .retention_seconds()
        .get()
        .checked_mul(1_000_000_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let cutoff = frontier
        .instant()
        .value()
        .checked_sub(duration_nanos)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut metadata = ledger.storage.catalog_segments(basis, ledger.scope)?;
    let mut retired = Vec::new();
    retired
        .try_reserve_exact(metadata.len().min(MAX_RETENTION_PUBLICATION_SEGMENTS))
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    for candidate in metadata
        .iter_mut()
        .filter(|candidate| candidate.state == SegmentState::Sealed)
    {
        if retired.len() == MAX_RETENTION_PUBLICATION_SEGMENTS {
            break;
        }
        let input = metadata_binding(&ledger.storage, *candidate)?;
        let mut latest: Option<crate::IngestTime> = None;
        let mut last_position: Option<positron_domain::routing::CommitPosition> = None;
        let mut has_blocks = false;
        for block in state
            .blocks
            .iter()
            .filter(|block| block.segment == candidate.id)
        {
            has_blocks = true;
            match block.block_retention {
                SegmentRetention::Complete(instant) => {
                    latest = Some(latest.map_or(instant, |current| current.max(instant)));
                    last_position = Some(
                        last_position
                            .map_or(block.position(), |current| current.max(block.position())),
                    );
                },
                SegmentRetention::Empty | SegmentRetention::Unavailable => {
                    return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
                },
            }
        }
        if has_blocks && latest.is_none_or(|instant| instant.instant().value() > cutoff) {
            continue;
        }
        if let Some(position) = last_position {
            candidate.base_position = position;
        }
        candidate.state = SegmentState::Retired;
        let output = metadata_binding(&ledger.storage, *candidate)?;
        retired.push((input, output));
    }
    retired.sort_unstable_by_key(|(input, _)| *input);
    Ok(RetentionPublicationPlan {
        metadata,
        retired,
        frontier,
    })
}

pub(super) fn task_bindings(
    retired: &[(MaintenanceObjectId, MaintenanceObjectId)],
) -> Result<(Vec<MaintenanceObjectId>, Vec<MaintenanceObjectId>), LedgerFailure> {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    inputs
        .try_reserve_exact(retired.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    outputs
        .try_reserve_exact(retired.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    for (input, output) in retired {
        inputs.push(*input);
        outputs.push(*output);
    }
    inputs.sort_unstable();
    outputs.sort_unstable();
    Ok((inputs, outputs))
}

pub(in crate::active_segment_ledger) fn metadata_binding(
    storage: &super::super::LedgerStorage,
    metadata: super::super::format::SegmentMetadata,
) -> Result<MaintenanceObjectId, LedgerFailure> {
    MaintenanceObjectId::new(
        CatalogObject::new(storage.metadata_object(metadata))?
            .identity()
            .to_bytes(),
    )
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}

pub(super) fn task_identity(
    binding: MaintenanceObjectId,
    discriminator: u8,
) -> Result<MaintenanceTaskId, LedgerFailure> {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(
        binding
            .to_bytes()
            .get(..16)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
    );
    bytes[0] ^= discriminator;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    MaintenanceTaskId::new(bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}
