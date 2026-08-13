use crate::ResourceAmounts;

use super::{LedgerFailure, LedgerFailureCode};

pub(super) fn recovery_claim() -> ResourceAmounts {
    ResourceAmounts::new([2_500_000, 1, 1, 2_500_000, 1_024, 0, 1, 1, 1, 6, 0])
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

pub(super) fn snapshot_claim(
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
        1,
        0,
        0,
    ]))
}

fn retained_memory(bytes: usize, blocks: usize) -> Result<u64, LedgerFailure> {
    u64::try_from(bytes)
        .ok()
        .and_then(|value| value.checked_add(u64::try_from(blocks).ok()?.checked_mul(96)?))
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
            snapshot_claim(usize::MAX, usize::MAX).expect_err("snapshot arithmetic overflow"),
        ] {
            assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
        }
    }
}
