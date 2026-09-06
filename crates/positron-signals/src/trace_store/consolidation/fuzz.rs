use crate::{ScanCancellation, ScanObservationFailureCode, ScanObserver};
use positron_domain::value::ValueLimitProfile;

use super::super::failure::TraceStoreFailure;
use super::super::scan::ScannedSpanObservation;
use super::ConsolidationContext;
use super::entries::{
    entries_with_semantic_keys, group_observations, interruptible_sort, observed_semantic_key_sizes,
};

pub(super) fn fuzz_group_observations(
    observations: Vec<ScannedSpanObservation>,
) -> Result<(), TraceStoreFailure> {
    let expected =
        u64::try_from(observations.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    let profile = ValueLimitProfile::release_1_system_maximum();
    let context = ConsolidationContext {
        profile: &profile,
        cancellation: &FuzzNeverCancelled,
        observer: &FuzzUnobserved,
    };
    let semantic_sizes = observed_semantic_key_sizes(&observations, &context)?;
    let entries = entries_with_semantic_keys(observations, semantic_sizes, &context)?;
    let entries = interruptible_sort(entries, &context)?;
    let spans = group_observations(entries, &context)?;
    let counted = spans.iter().try_fold(0_u64, |total, span| {
        if span.structural_representative().is_none()
            || span.variants().iter().any(|variant| {
                variant.observation_count() == 0
                    || variant.observation().observation().trace_id() != span.trace_id()
                    || variant.observation().observation().span_id() != span.span_id()
            })
        {
            return Err(TraceStoreFailure::invalid_input());
        }
        total
            .checked_add(span.observation_count())
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    })?;
    if counted == expected {
        Ok(())
    } else {
        Err(TraceStoreFailure::invalid_input())
    }
}

struct FuzzNeverCancelled;

impl ScanCancellation for FuzzNeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct FuzzUnobserved;

impl ScanObserver for FuzzUnobserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}
