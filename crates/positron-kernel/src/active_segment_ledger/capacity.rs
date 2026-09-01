use crate::ResourceAmounts;

use super::{LedgerFailure, LedgerFailureCode};

pub(super) fn recovery_claim() -> ResourceAmounts {
    ResourceAmounts::new([2_500_000, 1, 1, 2_500_000, 1_024, 0, 1, 1, 1, 6, 0])
}

pub(super) fn retention_claim(
    block_bytes: usize,
    blocks: usize,
) -> Result<ResourceAmounts, LedgerFailure> {
    let bytes = u64::try_from(block_bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let items =
        u64::try_from(blocks).map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let memory = bytes
        .checked_add(
            items
                .checked_mul(128)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        )
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    Ok(ResourceAmounts::new([
        memory, 1, 1, bytes, items, 0, 1, 1, 1, 6, bytes,
    ]))
}

pub(super) fn compaction_claim(
    block_bytes: usize,
    blocks: usize,
) -> Result<ResourceAmounts, LedgerFailure> {
    // Compaction is copy-on-write. At the write peak, additional Log Store
    // inputs, contiguous-run copies, current plaintext/frame, and committed
    // output copies can coexist with the separately retained source snapshot.
    // Reserve every bounded copy plus fixed segment/frontier metadata before
    // the first caller allocation.
    const COPY_MULTIPLIER: usize = 5;
    const BLOCK_OVERHEAD: usize = 256;
    const FRAME_OVERHEAD: usize = 384;
    const SEGMENT_OVERHEAD: usize = 1_024;
    let staged_bytes = block_bytes
        .checked_mul(COPY_MULTIPLIER)
        .and_then(|bytes| bytes.checked_add(blocks.checked_mul(BLOCK_OVERHEAD)?))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let staged_blocks = blocks
        .checked_mul(4)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let persistent_bytes = block_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(blocks.checked_mul(FRAME_OVERHEAD)?))
        .and_then(|bytes| bytes.checked_add(blocks.checked_mul(SEGMENT_OVERHEAD)?))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let files = blocks
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let memory = u64::try_from(staged_bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let persistent = u64::try_from(persistent_bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let items = u64::try_from(staged_blocks)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let files =
        u64::try_from(files).map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    Ok(ResourceAmounts::new([
        memory, 1, 1, persistent, items, 0, 1, 1, items, files, persistent,
    ]))
}

pub(super) fn append_claim(block_bytes: usize) -> Result<ResourceAmounts, LedgerFailure> {
    let bytes = u64::try_from(block_bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let frame = bytes
        .checked_add(384)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    Ok(ResourceAmounts::new([
        frame, 1, 1, frame, 1, 0, 1, 1, 1, 4, frame,
    ]))
}

pub(super) fn retained_claim(
    bytes: usize,
    blocks: usize,
) -> Result<ResourceAmounts, LedgerFailure> {
    let memory = retained_memory(bytes, blocks)?;
    let items = u64::try_from(blocks)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    Ok(ResourceAmounts::new([
        memory, 0, 0, 0, items, 0, 0, 0, 0, 0, 0,
    ]))
}

/// Capacity retained for the lifetime of an immutable snapshot. Snapshot
/// construction CPU belongs to the caller's already-admitted task and must not
/// remain pinned after construction completes.
pub(super) fn snapshot_retained_claim(
    bytes: usize,
    blocks: usize,
) -> Result<ResourceAmounts, LedgerFailure> {
    Ok(ResourceAmounts::new([
        retained_memory(bytes, blocks)?,
        1,
        1,
        1,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ]))
}

pub(super) fn snapshot_resume_claim(
    working_bytes: usize,
    encoded_bytes: usize,
    decoded_items: usize,
    segment_count: usize,
) -> Result<ResourceAmounts, LedgerFailure> {
    let bytes = u64::try_from(working_bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let encoded = u64::try_from(encoded_bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let items = u64::try_from(decoded_items)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let memory = bytes
        .checked_add(
            items
                .checked_mul(128)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        )
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let work = items
        .checked_add(255)
        .and_then(|value| value.checked_div(256))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let files = u64::try_from(segment_count)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    Ok(ResourceAmounts::new([
        memory, 1, 1, encoded, work, 0, 1, 1, work, files, 0,
    ]))
}

pub(super) fn lease_claim(encoded_bytes: usize) -> Result<ResourceAmounts, LedgerFailure> {
    let memory = u64::try_from(encoded_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(64))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    Ok(ResourceAmounts::new([memory, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0]))
}

fn retained_memory(bytes: usize, blocks: usize) -> Result<u64, LedgerFailure> {
    // 96 bytes cover the immutable block owner; the cached plaintext digest
    // adds one more 32-byte retained field per snapshot-visible block.
    u64::try_from(bytes)
        .ok()
        .and_then(|value| value.checked_add(u64::try_from(blocks).ok()?.checked_mul(128)?))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_overflow_is_a_closed_capacity_refusal() {
        for failure in [
            append_claim(usize::MAX).expect_err("frame arithmetic overflow"),
            retained_claim(usize::MAX, usize::MAX).expect_err("retained arithmetic overflow"),
            snapshot_retained_claim(usize::MAX, usize::MAX)
                .expect_err("snapshot arithmetic overflow"),
            lease_claim(usize::MAX).expect_err("lease arithmetic overflow"),
            retention_claim(usize::MAX, usize::MAX).expect_err("retention arithmetic overflow"),
            compaction_claim(usize::MAX, 1).expect_err("compaction byte arithmetic overflow"),
            compaction_claim(1, usize::MAX).expect_err("compaction block arithmetic overflow"),
        ] {
            assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
        }
    }
}
