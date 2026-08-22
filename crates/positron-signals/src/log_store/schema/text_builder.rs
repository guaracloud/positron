use super::failure::SchemaFailure;
use super::text_index::{MAX_TEXT_TRIGRAMS, TextBlockSummary};
use crate::log_store::{ScanObservationFailureCode, ScanObserver};

const TRIGRAM_BYTES: usize = 3;
pub(crate) const WORK_QUANTUM_OPERATIONS: usize = 128;
const MAX_BINARY_COMPARISONS: usize = 13;

/// Failure returned when observed physical text evidence cannot finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TextSummaryFailure {
    Schema(SchemaFailure),
    Observation(ScanObservationFailureCode),
}

impl From<SchemaFailure> for TextSummaryFailure {
    fn from(failure: SchemaFailure) -> Self {
        Self::Schema(failure)
    }
}

/// Conservative CPU work bound for building one text summary from body bytes.
///
/// One unit covers at most `WORK_QUANTUM_OPERATIONS` body-window, sort, or
/// canonicalization operations. Collection is capped before canonicalization;
/// a cap hit returns an incomplete summary and therefore cannot prune.
pub(crate) fn work_units(body_bytes: usize) -> Option<u64> {
    let windows = body_bytes.saturating_sub(TRIGRAM_BYTES - 1);
    if windows > MAX_TEXT_TRIGRAMS {
        return u64::try_from(ceil_units(MAX_TEXT_TRIGRAMS + 1)?).ok();
    }
    let traversal = ceil_units(windows)?;
    let collected = windows.min(MAX_TEXT_TRIGRAMS);
    let canonical_operations = collected.checked_mul(MAX_BINARY_COMPARISONS + 1)?;
    let canonicalization = ceil_units(canonical_operations)?;
    let encoding = ceil_units(collected)?;
    u64::try_from(
        traversal
            .checked_add(canonicalization)?
            .checked_add(encoding)?,
    )
    .ok()
}

pub(crate) fn from_bodies<'a>(
    bodies: impl IntoIterator<Item = Option<&'a str>>,
    observer: Option<&dyn ScanObserver>,
) -> Result<TextBlockSummary, TextSummaryFailure> {
    let mut trigrams = Vec::new();
    let mut complete = true;
    let mut traversed = 0_usize;
    'bodies: for body in bodies {
        let Some(body) = body else { continue };
        let windows = body.len().saturating_sub(TRIGRAM_BYTES - 1);
        let additional = MAX_TEXT_TRIGRAMS
            .saturating_sub(trigrams.len())
            .min(windows);
        if additional > 0 {
            trigrams
                .try_reserve_exact(additional)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        }
        for window in body.as_bytes().windows(TRIGRAM_BYTES) {
            if traversed.is_multiple_of(WORK_QUANTUM_OPERATIONS) {
                observe(observer, 1)?;
            }
            traversed += 1;
            if trigrams.len() == MAX_TEXT_TRIGRAMS {
                complete = false;
                break 'bodies;
            }
            let trigram = window.try_into().map_err(|_| SchemaFailure::InvalidValue)?;
            trigrams.push(trigram);
        }
    }
    if !complete {
        trigrams.clear();
        trigrams.shrink_to_fit();
        return Ok(TextBlockSummary { complete, trigrams });
    }
    let canonical_operations = trigrams
        .len()
        .checked_mul(MAX_BINARY_COMPARISONS + 1)
        .ok_or(SchemaFailure::LimitExceeded)?;
    observe(
        observer,
        ceil_units(canonical_operations).ok_or(SchemaFailure::LimitExceeded)?,
    )?;
    trigrams.sort_unstable();
    trigrams.dedup();
    trigrams.shrink_to_fit();
    Ok(TextBlockSummary { complete, trigrams })
}

fn observe(observer: Option<&dyn ScanObserver>, units: usize) -> Result<(), TextSummaryFailure> {
    if units == 0 {
        return Ok(());
    }
    if let Some(observer) = observer {
        observer
            .observe_work(
                u64::try_from(units)
                    .map_err(|_| TextSummaryFailure::Schema(SchemaFailure::LimitExceeded))?,
            )
            .map_err(TextSummaryFailure::Observation)?;
    }
    Ok(())
}

const fn ceil_units(operations: usize) -> Option<usize> {
    match operations.checked_add(WORK_QUANTUM_OPERATIONS - 1) {
        Some(value) => Some(value / WORK_QUANTUM_OPERATIONS),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{TextSummaryFailure, ceil_units, from_bodies};
    use crate::log_store::schema::SchemaFailure;

    #[test]
    fn arithmetic_bounds_and_schema_failures_are_typed() {
        assert!(ceil_units(usize::MAX).is_none());
        assert_eq!(
            TextSummaryFailure::from(SchemaFailure::LimitExceeded),
            TextSummaryFailure::Schema(SchemaFailure::LimitExceeded)
        );
    }

    #[test]
    fn empty_body_set_is_a_complete_zero_work_summary() {
        let summary = from_bodies([Some("")], None).expect("empty body summary");
        assert!(summary.complete);
        assert!(summary.trigrams.is_empty());
    }
}
