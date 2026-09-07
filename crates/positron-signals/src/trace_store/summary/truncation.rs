use super::super::{SpanAttributeSet, SpanObservation, TraceStoreFailure};
use crate::{ScanCancellation, ScanObserver};
use positron_domain::value::NativeValueObserver;

pub(super) fn observation_is_truncated(
    observation: &SpanObservation,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<bool, TraceStoreFailure> {
    let mut traversal = SummaryTraversalObserver {
        cancellation,
        observer,
    };
    Ok(
        attribute_occurrences_are_truncated(observation.attributes(), &mut traversal)?
            || attribute_sets_are_truncated(
                observation
                    .details()
                    .events()
                    .iter()
                    .map(|event| event.attributes()),
                &mut traversal,
            )?
            || attribute_sets_are_truncated(
                observation
                    .details()
                    .links()
                    .iter()
                    .map(|link| link.attributes()),
                &mut traversal,
            )?,
    )
}

struct SummaryTraversalObserver<'a> {
    cancellation: &'a dyn ScanCancellation,
    observer: &'a dyn ScanObserver,
}

impl NativeValueObserver for SummaryTraversalObserver<'_> {
    type Error = TraceStoreFailure;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        super::super::scan::check_cancel(self.cancellation)?;
        self.observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        self.observe_structure()
    }
}

fn attribute_occurrences_are_truncated(
    attribute_sets: &[positron_domain::value::AttributeOccurrenceSet],
    observer: &mut SummaryTraversalObserver<'_>,
) -> Result<bool, TraceStoreFailure> {
    for attribute in attribute_sets {
        for index in 0..attribute.len() {
            let value = attribute
                .occurrence(index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            if value
                .contains_truncation_observed(observer)
                .map_err(super::super::details::observed_value_failure)?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn attribute_sets_are_truncated<'a>(
    attribute_sets: impl Iterator<Item = &'a [SpanAttributeSet]>,
    observer: &mut SummaryTraversalObserver<'_>,
) -> Result<bool, TraceStoreFailure> {
    for attribute_sets in attribute_sets {
        for attribute in attribute_sets {
            for index in 0..attribute.len() {
                let value = attribute
                    .occurrence(index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                if value
                    .contains_truncation_observed(observer)
                    .map_err(super::super::details::observed_value_failure)?
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
