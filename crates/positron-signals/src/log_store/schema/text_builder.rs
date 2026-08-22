use super::failure::SchemaFailure;
use super::text_index::{MAX_TEXT_TRIGRAMS, TextBlockSummary};
use crate::log_store::{ScanObservationFailureCode, ScanObserver};

const TRIGRAM_BYTES: usize = 3;
pub(crate) const WORK_QUANTUM_OPERATIONS: usize = 64;
const MAX_BINARY_COMPARISONS: usize = 13;
// Recovery reserves a 12-unit CPU slice for this optional
// sidecar. Larger summaries conservatively fall back to authenticated scans.
pub(crate) const MAX_ADMITTED_WORK_UNITS: u64 = 12;

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
/// One unit covers at most `WORK_QUANTUM_OPERATIONS` byte, comparison, or
/// insertion-movement operations. The bound deliberately reserves the worst
/// sorted insertion movement for the capped summary, while the builder charges
/// only the movement it actually performs.
pub(crate) fn work_units(body_bytes: usize) -> Option<u64> {
    let windows = body_bytes.saturating_sub(TRIGRAM_BYTES - 1);
    let insertions = windows.min(MAX_TEXT_TRIGRAMS);
    let traversal = ceil_units(windows)?;
    let comparisons = ceil_units(windows.checked_mul(MAX_BINARY_COMPARISONS)?)?;
    let insertion_operations = insertions
        .checked_mul(insertions.saturating_sub(1))?
        .checked_div(2)?;
    let insertion_movement = ceil_units(insertion_operations)?;
    let encoding = ceil_units(MAX_TEXT_TRIGRAMS)?;
    u64::try_from(
        traversal
            .checked_add(comparisons)?
            .checked_add(insertion_movement)?
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
    'bodies: for body in bodies {
        let Some(body) = body else { continue };
        let windows = body.len().saturating_sub(TRIGRAM_BYTES - 1);
        observe(
            observer,
            ceil_units(windows).ok_or(SchemaFailure::LimitExceeded)?,
        )?;
        for window in body.as_bytes().windows(TRIGRAM_BYTES) {
            let trigram = [window[0], window[1], window[2]];
            let position = observed_search(&trigrams, trigram, observer)?;
            let Err(position) = position else { continue };
            let movement = trigrams.len().saturating_sub(position);
            observe(
                observer,
                ceil_units(movement).ok_or(SchemaFailure::LimitExceeded)?,
            )?;
            if trigrams.len() >= MAX_TEXT_TRIGRAMS {
                complete = false;
                break 'bodies;
            }
            trigrams
                .try_reserve_exact(1)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            trigrams.insert(position, trigram);
        }
    }
    observe(
        observer,
        ceil_units(trigrams.len()).ok_or(SchemaFailure::LimitExceeded)?,
    )?;
    trigrams.shrink_to_fit();
    Ok(TextBlockSummary { complete, trigrams })
}

fn observed_search(
    trigrams: &[[u8; TRIGRAM_BYTES]],
    needle: [u8; TRIGRAM_BYTES],
    observer: Option<&dyn ScanObserver>,
) -> Result<Result<usize, usize>, TextSummaryFailure> {
    let mut low = 0;
    let mut high = trigrams.len();
    let mut comparisons = 0_usize;
    while low < high {
        if comparisons.is_multiple_of(WORK_QUANTUM_OPERATIONS) {
            observe(observer, 1)?;
        }
        comparisons += 1;
        let middle = low + (high - low) / 2;
        let value = trigrams.get(middle).ok_or(SchemaFailure::InvalidValue)?;
        match value.cmp(&needle) {
            std::cmp::Ordering::Less => low = middle + 1,
            std::cmp::Ordering::Equal => return Ok(Ok(middle)),
            std::cmp::Ordering::Greater => high = middle,
        }
    }
    Ok(Err(low))
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
    use super::{TextSummaryFailure, ceil_units};
    use crate::log_store::schema::SchemaFailure;

    #[test]
    fn arithmetic_bounds_and_schema_failures_are_typed() {
        assert!(ceil_units(usize::MAX).is_none());
        assert_eq!(
            TextSummaryFailure::from(SchemaFailure::LimitExceeded),
            TextSummaryFailure::Schema(SchemaFailure::LimitExceeded)
        );
    }
}
