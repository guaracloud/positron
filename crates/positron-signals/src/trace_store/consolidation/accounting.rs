use positron_domain::value::NativeValueObserver;

use super::super::failure::TraceStoreFailure;
use super::{
    ConsolidationContext, LogicalSpan, SpanObservationVariant, observe_consolidation_unit,
    vector_slots_bytes,
};

pub(super) struct ObservedRetainedSize<'a, 'context> {
    pub(super) context: &'a ConsolidationContext<'context>,
}

impl NativeValueObserver for ObservedRetainedSize<'_, '_> {
    type Error = TraceStoreFailure;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        observe_consolidation_unit(self.context)
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        observe_consolidation_unit(self.context)
    }
}

pub(super) fn logical_retained_size(
    spans: &[LogicalSpan],
    span_capacity: usize,
    observer: &mut impl NativeValueObserver<Error = TraceStoreFailure>,
) -> Result<u64, TraceStoreFailure> {
    observer.observe_structure()?;
    let span_slots = vector_slots_bytes::<LogicalSpan>(span_capacity)?;
    spans.iter().try_fold(span_slots, |total, span| {
        observer.observe_structure()?;
        let variant_slots = vector_slots_bytes::<SpanObservationVariant>(span.variants.capacity())?;
        let variants = span
            .variants
            .iter()
            .try_fold(variant_slots, |size, variant| {
                observer.observe_structure()?;
                let dynamic = u64::try_from(
                    variant
                        .observation()
                        .observation()
                        .retained_heap_bytes_observed(observer)?,
                )
                .map_err(|_| TraceStoreFailure::limit_exceeded())?;
                size.checked_add(dynamic)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)
            })?;
        total
            .checked_add(variants)
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    })
}
