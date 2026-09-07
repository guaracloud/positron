//! Incremental, bounded trace-summary maintenance over committed observations.

use super::{ScannedSpanObservation, TraceIncompleteness, TraceStore, TraceStoreFailure};
use crate::{ScanCancellation, ScanLimit, ScanObserver};
use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, RecordOrdinal};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{
    IngestTime, LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor,
    ResourceReservation, WorkClaim, WorkKind,
};

/// A configured ingest-time interval after which a trace is quiescent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceQuietPeriod(u64);

impl TraceQuietPeriod {
    /// Creates a non-zero quiet period in nanoseconds.
    pub fn new(nanoseconds: u64) -> Result<Self, TraceStoreFailure> {
        if nanoseconds == 0 {
            return Err(TraceStoreFailure::invalid_input());
        }
        Ok(Self(nanoseconds))
    }

    #[must_use]
    pub const fn nanoseconds(self) -> u64 {
        self.0
    }
}

/// The only time provenance permitted in a Trace Summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceSummaryTimeProvenance {
    /// Both summary bounds came from Storage Kernel assigned ingest time.
    IngestTime,
}

#[derive(Clone, Debug)]
struct SpanSummary {
    span_id: [u8; 8],
    variants: Vec<Vec<u8>>,
}

struct SummaryUpdate {
    index: usize,
    prior: Option<TraceSummary>,
    updated: TraceSummary,
}

/// A derived, non-authoritative summary for one tenant-scoped trace.
#[derive(Clone, Debug)]
pub struct TraceSummary {
    trace_id: [u8; 16],
    first_seen: IngestTime,
    last_seen: IngestTime,
    observation_count: u64,
    spans: Vec<SpanSummary>,
    quiescent: bool,
}

impl TraceSummary {
    #[must_use]
    pub const fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }
    #[must_use]
    pub const fn first_seen(&self) -> IngestTime {
        self.first_seen
    }
    #[must_use]
    pub const fn last_seen(&self) -> IngestTime {
        self.last_seen
    }
    #[must_use]
    pub const fn observation_count(&self) -> u64 {
        self.observation_count
    }
    #[must_use]
    pub fn logical_span_count(&self) -> usize {
        self.spans.len()
    }
    #[must_use]
    pub fn conflicted_span_count(&self) -> usize {
        self.spans
            .iter()
            .filter(|span| span.variants.len() > 1)
            .count()
    }
    #[must_use]
    pub const fn quiescent(&self) -> bool {
        self.quiescent
    }
    #[must_use]
    pub const fn time_provenance(&self) -> TraceSummaryTimeProvenance {
        TraceSummaryTimeProvenance::IngestTime
    }
}

/// Result of one bounded summary-maintenance handler invocation.
pub struct TraceSummaryMaintenance<'a, 'kernel> {
    maintainer: &'a TraceSummaryMaintainer<'kernel>,
    applied_observations: u64,
    complete: bool,
    incompleteness: TraceIncompleteness,
}

impl TraceSummaryMaintenance<'_, '_> {
    #[must_use]
    pub const fn applied_observations(&self) -> u64 {
        self.applied_observations
    }
    /// Whether this invocation reached the snapshot frontier.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }
    /// Returns why this invocation stopped before its authenticated snapshot frontier.
    #[must_use]
    pub const fn incompleteness(&self) -> TraceIncompleteness {
        self.incompleteness
    }
    /// Returns a summary only when the committed snapshot contained that trace.
    #[must_use]
    pub fn summary(&self, trace_id: [u8; 16]) -> Option<&TraceSummary> {
        self.maintainer
            .find(trace_id)
            .ok()
            .map(|index| &self.maintainer.summaries[index])
    }
}

/// Trace Store-owned handler state for the future kernel Maintenance Coordinator.
///
/// It has no worker, queue, timer, or catalog authority.  Each invocation is
/// idempotent at its physical-record cursor and can be rebuilt by replaying an
/// authenticated snapshot after restart.
pub struct TraceSummaryMaintainer<'kernel> {
    governor: ResourceGovernor<'kernel>,
    tenant: TenantId,
    quiet_period: TraceQuietPeriod,
    limit: ScanLimit,
    summaries: Vec<TraceSummary>,
    cursor: Option<(CommitPosition, RecordOrdinal)>,
    capacity: ResourceReservation<'kernel>,
}

impl<'kernel> TraceSummaryMaintainer<'kernel> {
    pub fn new(
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        quiet_period: TraceQuietPeriod,
        limit: ScanLimit,
    ) -> Result<Self, TraceStoreFailure> {
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        let claim = WorkClaim::tenant(tenant, WorkKind::OrdinaryMaintenanceBackup, amounts)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        let capacity = governor
            .reserve(claim)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())?;
        Ok(Self {
            governor,
            tenant,
            quiet_period,
            limit,
            summaries: Vec::new(),
            cursor: None,
            capacity,
        })
    }

    pub fn maintain<'a>(
        &'a mut self,
        store: &TraceStore,
        snapshot: &LedgerSnapshot<'_>,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
        lifecycle_now: UnixNanoseconds,
    ) -> Result<TraceSummaryMaintenance<'a, 'kernel>, TraceStoreFailure> {
        let scan = match self.cursor {
            Some((position, ordinal)) => {
                super::TraceScan::after_cursor(self.limit, position, ordinal)
            },
            None => super::TraceScan::all(self.limit),
        };
        let result = store.scan_physical_observed(
            self.governor,
            self.tenant,
            snapshot,
            scan,
            cancellation,
            observer,
        )?;
        let complete = result.complete();
        let incompleteness = result.incompleteness();
        let mut applied = 0_u64;
        for observation in result.observations() {
            super::scan::check_cancel(cancellation)?;
            observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
            self.apply(observation, cancellation, observer)?;
            self.cursor = Some((observation.commit_position(), observation.record_ordinal()));
            applied = applied
                .checked_add(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        }
        if complete {
            self.refresh_quiescence(lifecycle_now);
        }
        Ok(TraceSummaryMaintenance {
            maintainer: self,
            applied_observations: applied,
            complete,
            incompleteness,
        })
    }

    fn apply(
        &mut self,
        scanned: &ScannedSpanObservation,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<(), TraceStoreFailure> {
        let observation = scanned.observation();
        let expected = super::codec::encoded_record_bytes_with_profile(
            &ValueLimitProfile::release_1_system_maximum(),
            observation,
        )?
        .checked_sub(8)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
        let semantic = super::codec::encode_semantic_observation_with_profile_observed(
            &ValueLimitProfile::release_1_system_maximum(),
            observation,
            expected,
            cancellation,
            observer,
        )?;
        let update = stage_summary_update(
            &self.summaries,
            observation.trace_id(),
            observation.span_id(),
            scanned.ingest_time(),
            semantic,
        )?;
        if update.prior.is_some() {
            let slot = self
                .summaries
                .get_mut(update.index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            *slot = update.updated;
        } else {
            self.summaries
                .try_reserve_exact(1)
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            self.summaries.insert(update.index, update.updated);
        }
        if let Err(failure) = self.resize_capacity() {
            if let Some(prior) = update.prior {
                let slot = self
                    .summaries
                    .get_mut(update.index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                *slot = prior;
            } else if update.index < self.summaries.len() {
                self.summaries.remove(update.index);
            } else {
                return Err(TraceStoreFailure::invalid_input());
            }
            return Err(failure);
        }
        Ok(())
    }

    fn refresh_quiescence(&mut self, lifecycle_now: UnixNanoseconds) {
        for summary in &mut self.summaries {
            let elapsed = lifecycle_now
                .value()
                .saturating_sub(summary.last_seen.instant().value());
            summary.quiescent = u64::try_from(elapsed)
                .is_ok_and(|elapsed| elapsed >= self.quiet_period.nanoseconds());
        }
    }

    fn find(&self, trace_id: [u8; 16]) -> Result<usize, usize> {
        find_summary(&self.summaries, trace_id)
    }

    fn resize_capacity(&mut self) -> Result<(), TraceStoreFailure> {
        let bytes = self
            .summaries
            .iter()
            .try_fold(0_u64, |total, summary| {
                let variants = summary
                    .spans
                    .iter()
                    .try_fold(0_u64, |variant_total, span| {
                        span.variants
                            .iter()
                            .try_fold(variant_total, |bytes, variant| {
                                bytes.checked_add(u64::try_from(variant.len()).ok()?)
                            })
                    })?;
                total
                    .checked_add(u64::try_from(std::mem::size_of::<TraceSummary>()).ok()?)
                    .and_then(|bytes| {
                        bytes.checked_add(
                            u64::try_from(summary.spans.len()).ok()?.checked_mul(
                                u64::try_from(std::mem::size_of::<SpanSummary>()).ok()?,
                            )?,
                        )
                    })
                    .and_then(|bytes| bytes.checked_add(variants))
            })
            .ok_or_else(TraceStoreFailure::limit_exceeded)?
            .max(1);
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        self.capacity
            .try_resize_preserving_capacity(amounts)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())
            .map(|_| ())
    }
}

fn stage_summary_update(
    summaries: &[TraceSummary],
    trace_id: [u8; 16],
    span_id: [u8; 8],
    ingest_time: IngestTime,
    semantic: Vec<u8>,
) -> Result<SummaryUpdate, TraceStoreFailure> {
    let (index, prior) = match find_summary(summaries, trace_id) {
        Ok(index) => (
            index,
            Some(
                summaries
                    .get(index)
                    .cloned()
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
            ),
        ),
        Err(index) => (index, None),
    };
    let mut updated = match prior.clone() {
        Some(existing) => existing,
        None => TraceSummary {
            trace_id,
            first_seen: ingest_time,
            last_seen: ingest_time,
            observation_count: 0,
            spans: Vec::new(),
            quiescent: false,
        },
    };
    updated.first_seen = updated.first_seen.min(ingest_time);
    updated.last_seen = updated.last_seen.max(ingest_time);
    updated.observation_count = updated
        .observation_count
        .checked_add(1)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    updated.quiescent = false;
    let span_index = match updated
        .spans
        .binary_search_by_key(&span_id, |span| span.span_id)
    {
        Ok(index) => index,
        Err(index) => {
            updated
                .spans
                .try_reserve_exact(1)
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            updated.spans.insert(
                index,
                SpanSummary {
                    span_id,
                    variants: Vec::new(),
                },
            );
            index
        },
    };
    let variants = &mut updated
        .spans
        .get_mut(span_index)
        .ok_or_else(TraceStoreFailure::invalid_input)?
        .variants;
    if !variants.iter().any(|variant| variant == &semantic) {
        variants
            .try_reserve_exact(1)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        variants.push(semantic);
    }
    Ok(SummaryUpdate {
        index,
        prior,
        updated,
    })
}

fn find_summary(summaries: &[TraceSummary], trace_id: [u8; 16]) -> Result<usize, usize> {
    summaries.binary_search_by_key(&trace_id, |summary| summary.trace_id)
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_trace_summary_state(data: &[u8]) {
    let mut summaries = Vec::new();
    let clock = positron_kernel::LifecycleClock::new(
        positron_kernel::FixedLifecycleClockSource::new(UnixNanoseconds::new(1)),
    );
    for chunk in data.chunks(40).take(256) {
        let mut trace_id = [0_u8; 16];
        let mut span_id = [0_u8; 8];
        trace_id[..chunk.len().min(16)].copy_from_slice(&chunk[..chunk.len().min(16)]);
        let span_start = 16.min(chunk.len());
        let span_end = (span_start + 8).min(chunk.len());
        span_id[..span_end.saturating_sub(span_start)]
            .copy_from_slice(&chunk[span_start..span_end]);
        let semantic = chunk.get(24..).unwrap_or_default().to_vec();
        let Ok(ingest_time) = clock.assign_ingest_time() else {
            return;
        };
        let Ok(update) = stage_summary_update(&summaries, trace_id, span_id, ingest_time, semantic)
        else {
            return;
        };
        if update.prior.is_some() {
            if let Some(slot) = summaries.get_mut(update.index) {
                *slot = update.updated;
            } else {
                return;
            }
        } else if update.index <= summaries.len() {
            summaries.insert(update.index, update.updated);
        } else {
            return;
        }
    }
    for summary in &summaries {
        if !summary
            .spans
            .windows(2)
            .all(|pair| pair[0].span_id < pair[1].span_id)
        {
            return;
        }
    }
}
