use positron_domain::identity::TenantId;

use super::codec;

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
    let mut tail = decoder.input.remaining_input();
    for _ in 0..decoder.record_count() {
        let _ = super::codec::decode_observation(&mut tail)?;
    }
    if tail.is_empty() {
        Ok(())
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
