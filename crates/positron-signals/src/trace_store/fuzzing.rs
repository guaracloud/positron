use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, RecordOrdinal};
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{FixedLifecycleClockSource, LifecycleClock};

use super::codec;
use super::scan::ScannedSpanObservation;
use super::types::StoredSpanObservation;

const MAX_STORE_BLOCK_BYTES: usize = 1_048_576;

/// Exercises the bounded Trace Store Block decoder with untrusted bytes.
#[doc(hidden)]
pub fn fuzz_trace_store_block(data: &[u8]) {
    let bounded_end = data.len().min(MAX_STORE_BLOCK_BYTES.saturating_add(1));
    let bounded = data.get(..bounded_end).unwrap_or_default();
    let Ok(tenant) = TenantId::from_bytes([0x41; 16]) else {
        return;
    };
    let cancellation = NeverCancelled;
    let observer = Unobserved;
    let Ok(_) = codec::decoded_memory_bound(tenant, bounded, &cancellation, &observer) else {
        return;
    };
    let Ok(mut decoder) = codec::BlockDecode::observed(tenant, bounded, &cancellation, &observer)
    else {
        return;
    };
    let Ok(()) = validate(&mut decoder) else {
        return;
    };
}

fn validate(decoder: &mut codec::BlockDecode<'_>) -> Result<(), super::TraceStoreFailure> {
    // No CommittedBlock is available in a raw-byte fuzz target. The decoder's
    // structural path still validates all native values and framing.
    let version = decoder.version();
    let record_count = decoder.record_count();
    let mut tail = decoder.input.remaining_input();
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(record_count)
        .map_err(|_| super::TraceStoreFailure::resource_exhausted())?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));
    let position = CommitPosition::origin()
        .next()
        .map_err(super::TraceStoreFailure::domain)?;
    for index in 0..record_count {
        let (observation, _) = super::codec::decode_observation_version(&mut tail, version)?;
        let ordinal = u16::try_from(index)
            .ok()
            .and_then(|value| RecordOrdinal::new(value).ok())
            .ok_or_else(super::TraceStoreFailure::malformed_block)?;
        let ingest_time = clock
            .assign_ingest_time()
            .map_err(|_| super::TraceStoreFailure::rejected_clock())?;
        observations.push(ScannedSpanObservation::new(
            StoredSpanObservation::new(observation, ingest_time),
            position,
            ordinal,
        ));
    }
    if tail.is_empty() {
        super::consolidation::fuzz_group_observations(observations)
    } else {
        Err(super::TraceStoreFailure::malformed_block())
    }
}

struct NeverCancelled;

impl crate::ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct Unobserved;

impl crate::ScanObserver for Unobserved {
    fn observe_work(&self, _units: u64) -> Result<(), crate::ScanObservationFailureCode> {
        Ok(())
    }
}
