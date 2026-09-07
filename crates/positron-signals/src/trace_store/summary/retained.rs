use super::{SpanSummary, TraceSummary};
use crate::{ScanCancellation, ScanObserver};

use super::super::TraceStoreFailure;

pub(super) fn summary_capacity_bytes(
    summary: &TraceSummary,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<u64, TraceStoreFailure> {
    let mut bytes = u64::try_from(std::mem::size_of::<TraceSummary>())
        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
    bytes = bytes
        .checked_add(checked_bytes(
            summary.spans.capacity(),
            std::mem::size_of::<SpanSummary>(),
        )?)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    for span in &summary.spans {
        super::super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        bytes = bytes
            .checked_add(checked_bytes(
                span.variants.capacity(),
                std::mem::size_of::<Vec<u8>>(),
            )?)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        for variant in &span.variants {
            super::super::scan::check_cancel(cancellation)?;
            observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
            bytes = bytes
                .checked_add(
                    u64::try_from(variant.capacity())
                        .map_err(|_| TraceStoreFailure::limit_exceeded())?,
                )
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        }
    }
    Ok(bytes)
}

pub(super) fn checked_bytes(
    capacity: usize,
    element_bytes: usize,
) -> Result<u64, TraceStoreFailure> {
    u64::try_from(capacity)
        .ok()
        .zip(u64::try_from(element_bytes).ok())
        .and_then(|(capacity, element_bytes)| capacity.checked_mul(element_bytes))
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}
