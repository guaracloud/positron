use super::failure::TraceStoreFailure;
use super::scan::ScannedSpanObservation;

/// Computes the complete retained heap charge for one scan result.
///
/// The fixed result slot includes the owned stored observation and its receipt
/// metadata. Native observations then contribute their owned strings, vectors,
/// nested values, and policy rule identities through the domain-owned value
/// accounting helper.
pub(super) fn scan_result_bytes(
    output_capacity: usize,
    observations: &[ScannedSpanObservation],
) -> Result<u64, TraceStoreFailure> {
    const RESULT_SLOT_BYTES: u64 = 512;
    let slots = u64::try_from(output_capacity)
        .map_err(|_| TraceStoreFailure::limit_exceeded())?
        .checked_mul(RESULT_SLOT_BYTES)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    observations.iter().try_fold(slots, |total, observation| {
        let native = observation.observation();
        let dynamic = u64::try_from(native.retained_heap_bytes()?)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        total
            .checked_add(dynamic)
            .and_then(|size| {
                size.checked_add(u64::try_from(std::mem::size_of::<ScannedSpanObservation>()).ok()?)
            })
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    })
}
