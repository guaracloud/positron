use positron_domain::value::ValueLimitProfile;
use positron_kernel::{IngestTime, PreparedStoreBlock};

use super::failure::TraceStoreFailure;
use super::observation::SpanObservation;

/// The one Release 1 native Trace profile used by admission and decode.
pub(super) struct TraceLimits {
    pub(super) attribute_sets: usize,
    pub(super) occurrences_per_namespace: usize,
    pub(super) key_path_bytes: usize,
    pub(super) value_bytes: usize,
    pub(super) nesting_depth: u8,
    pub(super) array_entries: usize,
    pub(super) key_value_list_entries: usize,
    pub(super) encoded_bytes: usize,
    pub(super) decoded_bytes: usize,
}

pub(super) fn limits_for(profile: &ValueLimitProfile) -> Result<TraceLimits, TraceStoreFailure> {
    let profile = profile.effective_limits();
    let dynamic = profile.dynamic_value();
    Ok(TraceLimits {
        attribute_sets: usize::try_from(
            dynamic
                .attributes_per_namespace()
                .value()
                .checked_mul(3)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?,
        )
        .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        occurrences_per_namespace: usize::try_from(dynamic.attributes_per_namespace().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        key_path_bytes: usize::try_from(dynamic.key_path_bytes().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        value_bytes: usize::try_from(dynamic.individual_value_bytes().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        nesting_depth: u8::try_from(dynamic.nesting_depth().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        array_entries: usize::try_from(dynamic.array_entries().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        key_value_list_entries: usize::try_from(dynamic.key_value_list_entries().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        encoded_bytes: usize::try_from(profile.record().encoded_bytes().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        decoded_bytes: usize::try_from(profile.record().decoded_bytes().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
    })
}

/// One immutable observation after the kernel assigned Ingest Time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSpanObservation {
    observation: SpanObservation,
    ingest_time: IngestTime,
}

impl StoredSpanObservation {
    pub(super) const fn new(observation: SpanObservation, ingest_time: IngestTime) -> Self {
        Self {
            observation,
            ingest_time,
        }
    }

    #[must_use]
    pub const fn observation(&self) -> &SpanObservation {
        &self.observation
    }

    #[must_use]
    pub const fn trace_id(&self) -> [u8; 16] {
        self.observation.trace_id()
    }

    #[must_use]
    pub const fn span_id(&self) -> [u8; 8] {
        self.observation.span_id()
    }

    #[must_use]
    pub const fn ingest_time(&self) -> IngestTime {
        self.ingest_time
    }
}

/// Opaque checked Trace Store output accepted by the Storage Kernel ledger.
pub struct PreparedTraceBlock<'capacity> {
    pub(super) block: PreparedStoreBlock<'capacity>,
}

impl<'capacity> PreparedTraceBlock<'capacity> {
    pub(super) const fn new(block: PreparedStoreBlock<'capacity>) -> Self {
        Self { block }
    }

    /// Transfers the prepared block to the Storage Kernel for commit.
    #[must_use]
    pub fn into_store_block(self) -> PreparedStoreBlock<'capacity> {
        self.block
    }
}
