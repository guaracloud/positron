//! Native Trace Signal Store.

mod codec;
mod details;
mod failure;
#[cfg(fuzzing)]
mod fuzzing;
mod observation;
mod retained;
mod scan;
mod types;

#[cfg(test)]
mod tests;

pub use details::{
    SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails, SpanResourceMetadata,
    SpanScopeMetadata, SpanStatus, SpanStatusCode,
};
pub use failure::{TraceStoreFailure, TraceStoreFailureCode};
pub use observation::{SamplingDecision, SpanKind, SpanObservation};
pub use scan::{ScannedSpanObservation, TraceIncompleteness, TraceScan, TraceScanResult};
pub use types::{PreparedTraceBlock, StoredSpanObservation};

#[cfg(fuzzing)]
#[doc(hidden)]
pub use fuzzing::fuzz_trace_store_block;

/// The concrete Release 1 Trace Signal Store adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct TraceStore;

impl TraceStore {
    /// Constructs the stateless Trace Store adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the Release 1 native value profile used by span attributes.
    pub const fn value_limit_profile() -> positron_domain::value::ValueLimitProfile {
        positron_domain::value::ValueLimitProfile::release_1_system_maximum()
    }

    /// Prepares canonical Trace Store bytes under a kernel-issued Ingest Time.
    pub fn prepare<'capacity>(
        &self,
        preparation: positron_kernel::StoreBlockPreparation<'capacity>,
        observations: Vec<SpanObservation>,
    ) -> Result<PreparedTraceBlock<'capacity>, TraceStoreFailure> {
        let profile = Self::value_limit_profile();
        self.prepare_with_profile(&profile, preparation, observations)
    }

    /// Prepares canonical bytes under one pinned effective value profile.
    pub fn prepare_with_profile<'capacity>(
        &self,
        profile: &positron_domain::value::ValueLimitProfile,
        preparation: positron_kernel::StoreBlockPreparation<'capacity>,
        observations: Vec<SpanObservation>,
    ) -> Result<PreparedTraceBlock<'capacity>, TraceStoreFailure> {
        if preparation.scope().signal_kind() != positron_domain::routing::SignalKind::Traces {
            return Err(TraceStoreFailure::physical_scope_mismatch());
        }
        if observations.is_empty() {
            return Err(TraceStoreFailure::invalid_input());
        }
        if observations.len() > codec::MAX_RECORDS {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        let ingest_time = preparation.ingest_time();
        let mut stored = Vec::new();
        stored
            .try_reserve_exact(observations.len())
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for observation in observations {
            stored.push(StoredSpanObservation::new(observation, ingest_time));
        }
        let bytes =
            codec::encode_block_with_profile(profile, preparation.scope().tenant_id(), &stored)?;
        let block = preparation
            .finish(bytes)
            .map_err(TraceStoreFailure::kernel)?;
        Ok(PreparedTraceBlock::new(block))
    }

    /// Prepares a retention-ineligible block for deterministic store tests.
    #[cfg(any(test, fuzzing))]
    #[doc(hidden)]
    pub fn prepare_unretained_for_test<'capacity, S: positron_kernel::LifecycleClockSource>(
        &self,
        capacity: positron_kernel::ResourceReservation<'capacity>,
        clock: &positron_kernel::LifecycleClock<S>,
        tenant: positron_domain::identity::TenantId,
        shard: positron_domain::routing::VirtualShardId,
        identity: positron_kernel::StoreBlockIdentity,
        observations: Vec<SpanObservation>,
    ) -> Result<PreparedTraceBlock<'capacity>, TraceStoreFailure> {
        if observations.is_empty() {
            return Err(TraceStoreFailure::invalid_input());
        }
        if observations.len() > codec::MAX_RECORDS {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        if !capacity.authorizes_ingest_preparation(tenant, 1_048_576) {
            return Err(TraceStoreFailure::resource_admission_refused());
        }
        let mut stored = Vec::new();
        stored
            .try_reserve_exact(observations.len())
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for observation in observations {
            let ingest_time = clock
                .assign_ingest_time()
                .map_err(|_| TraceStoreFailure::rejected_clock())?;
            stored.push(StoredSpanObservation::new(observation, ingest_time));
        }
        let bytes = codec::encode_block(tenant, &stored)?;
        let scope = positron_kernel::SegmentScope::new(
            tenant,
            positron_domain::routing::SignalKind::Traces,
            shard,
        );
        let block = positron_kernel::PreparedStoreBlock::new_with_preparation_capacity(
            scope, identity, bytes, capacity,
        )
        .map_err(TraceStoreFailure::kernel)?;
        Ok(PreparedTraceBlock::new(block))
    }
}
