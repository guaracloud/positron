use super::storage::{FRAME_OVERHEAD_BYTES, MAX_GENERATIONS};
use super::{
    AuditIntent, CatalogFailure, CatalogFailureCode, CatalogProposal, MAX_RECOVERY_ITEMS,
    MAX_RECOVERY_MEMORY_BYTES, MAX_RETAINED_HISTORY_BYTES,
};
use crate::ResourceAmounts;

pub(super) fn retained_artifact_bytes(plaintext_bytes: usize) -> Result<usize, CatalogFailure> {
    plaintext_bytes
        .checked_add(FRAME_OVERHEAD_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))
}

pub(super) fn reserve_history(
    retained: usize,
    additional: usize,
    generation_number: u64,
) -> Result<usize, CatalogFailure> {
    let generation_count = usize::try_from(generation_number)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    if generation_count > MAX_GENERATIONS {
        return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
    }
    retained
        .checked_add(additional)
        .filter(|total| *total <= MAX_RETAINED_HISTORY_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))
}

pub(super) fn recovery_resource_claim() -> ResourceAmounts {
    ResourceAmounts::new([
        MAX_RECOVERY_MEMORY_BYTES,
        1,
        1,
        MAX_RECOVERY_MEMORY_BYTES,
        MAX_RECOVERY_ITEMS,
        0,
        1,
        1,
        1,
        8,
        0,
    ])
}

pub(super) fn commit_resource_claim(
    proposal: &CatalogProposal,
    audit: Option<&AuditIntent>,
) -> Result<ResourceAmounts, CatalogFailure> {
    let object_bytes = proposal
        .objects
        .iter()
        .try_fold(0_usize, |total, object| {
            total.checked_add(object.plaintext.len())
        })
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let artifact_count = proposal
        .objects
        .len()
        .checked_add(2)
        .and_then(|count| count.checked_add(usize::from(audit.is_some())))
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let durable_bytes = object_bytes
        .checked_add(audit.map_or(0, |intent| intent.0.len()))
        .and_then(|bytes| bytes.checked_add(artifact_count.saturating_mul(512)))
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let memory_bytes = durable_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1_048_576))
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let publication = ResourceAmounts::new([
        u64::try_from(memory_bytes)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
        1,
        1,
        u64::try_from(memory_bytes)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
        u64::try_from(artifact_count)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
        0,
        1,
        1,
        1,
        8,
        u64::try_from(durable_bytes)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?,
    ]);
    Ok(publication.maximum(recovery_resource_claim()))
}
