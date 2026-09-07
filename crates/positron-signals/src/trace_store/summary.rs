//! Incremental, bounded trace-summary maintenance over committed observations.

use super::{ScannedSpanObservation, TraceIncompleteness, TraceStore, TraceStoreFailure};
#[cfg(fuzzing)]
use crate::ScanObservationFailureCode;
use crate::{ScanCancellation, ScanLimit, ScanObserver};
use positron_domain::routing::{CommitPosition, RecordOrdinal, SignalKind};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{
    IngestTime, LedgerSnapshot, LifecycleClock, LifecycleClockSource, ResourceAmounts,
    ResourceDimension, ResourceGovernor, ResourceReservation, SegmentScope, WorkClaim, WorkKind,
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
    scope: SegmentScope,
    quiet_period: TraceQuietPeriod,
    limit: ScanLimit,
    summaries: Vec<TraceSummary>,
    cursor: Option<(CommitPosition, RecordOrdinal)>,
    catalog_identity: Option<positron_kernel::CatalogGenerationId>,
    capacity: ResourceReservation<'kernel>,
}

impl<'kernel> TraceSummaryMaintainer<'kernel> {
    pub fn new(
        governor: ResourceGovernor<'kernel>,
        scope: SegmentScope,
        quiet_period: TraceQuietPeriod,
        limit: ScanLimit,
    ) -> Result<Self, TraceStoreFailure> {
        if scope.signal_kind() != SignalKind::Traces {
            return Err(TraceStoreFailure::physical_scope_mismatch());
        }
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        let claim = WorkClaim::tenant(
            scope.tenant_id(),
            WorkKind::OrdinaryMaintenanceBackup,
            amounts,
        )
        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        let capacity = governor
            .reserve(claim)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())?;
        Ok(Self {
            governor,
            scope,
            quiet_period,
            limit,
            summaries: Vec::new(),
            cursor: None,
            catalog_identity: None,
            capacity,
        })
    }

    pub fn maintain<'a, S: LifecycleClockSource>(
        &'a mut self,
        store: &TraceStore,
        snapshot: &LedgerSnapshot<'_>,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
        lifecycle_clock: &LifecycleClock<S>,
    ) -> Result<TraceSummaryMaintenance<'a, 'kernel>, TraceStoreFailure> {
        self.validate_snapshot(snapshot)?;
        let scan = match self.cursor {
            Some((position, ordinal)) => {
                super::TraceScan::after_cursor(self.limit, position, ordinal)
            },
            None => super::TraceScan::all(self.limit),
        };
        let result = store.scan_physical_observed(
            self.governor,
            self.scope.tenant_id(),
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
            let lifecycle_now = lifecycle_clock
                .assign_ingest_time()
                .map_err(|_| TraceStoreFailure::rejected_clock())?;
            self.refresh_quiescence(lifecycle_now.instant(), cancellation, observer)?;
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
        let expected = super::codec::encoded_record_bytes_with_profile_observed(
            &ValueLimitProfile::release_1_system_maximum(),
            observation,
            cancellation,
            observer,
        )?
        .checked_sub(8)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
        self.reserve_staged_update(expected)?;
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
            cancellation,
            observer,
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
        if let Err(failure) = self.resize_capacity(cancellation, observer) {
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

    fn refresh_quiescence(
        &mut self,
        lifecycle_now: positron_domain::time::UnixNanoseconds,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<(), TraceStoreFailure> {
        for summary in &mut self.summaries {
            super::scan::check_cancel(cancellation)?;
            observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
            let elapsed = lifecycle_now
                .value()
                .saturating_sub(summary.last_seen.instant().value());
            summary.quiescent = u64::try_from(elapsed)
                .is_ok_and(|elapsed| elapsed >= self.quiet_period.nanoseconds());
        }
        Ok(())
    }

    fn validate_snapshot(
        &mut self,
        snapshot: &LedgerSnapshot<'_>,
    ) -> Result<(), TraceStoreFailure> {
        if snapshot.scope() != self.scope {
            return Err(TraceStoreFailure::physical_scope_mismatch());
        }
        if self
            .cursor
            .is_some_and(|(position, _)| snapshot.frontier() < position)
        {
            return Err(TraceStoreFailure::stale_generation());
        }
        match self.catalog_identity {
            Some(identity) if identity != snapshot.catalog_identity() => {
                Err(TraceStoreFailure::stale_generation())
            },
            Some(_) => Ok(()),
            None => {
                self.catalog_identity = Some(snapshot.catalog_identity());
                Ok(())
            },
        }
    }

    fn find(&self, trace_id: [u8; 16]) -> Result<usize, usize> {
        find_summary(&self.summaries, trace_id)
    }

    fn resize_capacity(
        &mut self,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<(), TraceStoreFailure> {
        let mut bytes = checked_bytes(
            self.summaries.capacity(),
            std::mem::size_of::<TraceSummary>(),
        )?;
        for summary in &self.summaries {
            super::scan::check_cancel(cancellation)?;
            observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
            bytes = bytes
                .checked_add(checked_bytes(
                    summary.spans.capacity(),
                    std::mem::size_of::<SpanSummary>(),
                )?)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            for span in &summary.spans {
                super::scan::check_cancel(cancellation)?;
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
                    super::scan::check_cancel(cancellation)?;
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
        }
        let bytes = bytes.max(1);
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        self.capacity
            .try_resize_preserving_capacity(amounts)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())
            .map(|_| ())
    }

    fn reserve_staged_update(&mut self, semantic_capacity: usize) -> Result<(), TraceStoreFailure> {
        let current = self.capacity.granted().get(ResourceDimension::MemoryBytes);
        let staged = checked_bytes(semantic_capacity, 1)?
            .checked_add(checked_bytes(1, std::mem::size_of::<TraceSummary>())?)
            .and_then(|bytes| {
                bytes.checked_add(u64::try_from(std::mem::size_of::<SpanSummary>()).ok()?)
            })
            .and_then(|bytes| {
                bytes.checked_add(u64::try_from(std::mem::size_of::<Vec<u8>>()).ok()?)
            })
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let required = current
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(staged))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, required)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        self.capacity
            .try_resize_preserving_capacity(amounts)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())
            .map(|_| ())
    }
}

fn checked_bytes(capacity: usize, element_bytes: usize) -> Result<u64, TraceStoreFailure> {
    u64::try_from(capacity)
        .ok()
        .zip(u64::try_from(element_bytes).ok())
        .and_then(|(capacity, element_bytes)| capacity.checked_mul(element_bytes))
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}

fn stage_summary_update(
    summaries: &[TraceSummary],
    trace_id: [u8; 16],
    span_id: [u8; 8],
    ingest_time: IngestTime,
    semantic: Vec<u8>,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<SummaryUpdate, TraceStoreFailure> {
    let (index, prior) = match find_summary_observed(summaries, trace_id, cancellation, observer)? {
        Ok(index) => (
            index,
            Some(clone_summary_observed(
                summaries
                    .get(index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
                cancellation,
                observer,
            )?),
        ),
        Err(index) => (index, None),
    };
    let mut updated = match &prior {
        Some(existing) => clone_summary_observed(existing, cancellation, observer)?,
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
    let span_index = match find_span_observed(&updated.spans, span_id, cancellation, observer)? {
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
    let mut duplicate = false;
    for variant in variants.iter() {
        super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        if semantic_equal_observed(variant, &semantic, cancellation, observer)? {
            duplicate = true;
            break;
        }
    }
    if !duplicate {
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

fn clone_summary_observed(
    summary: &TraceSummary,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<TraceSummary, TraceStoreFailure> {
    let mut spans = Vec::new();
    spans
        .try_reserve_exact(summary.spans.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for span in &summary.spans {
        super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(span.variants.len())
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for variant in &span.variants {
            super::scan::check_cancel(cancellation)?;
            observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
            let mut copy = Vec::new();
            copy.try_reserve_exact(variant.len())
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            for chunk in variant.chunks(4_096) {
                super::scan::check_cancel(cancellation)?;
                observer
                    .observe_work(1)
                    .map_err(TraceStoreFailure::observation)?;
                copy.extend_from_slice(chunk);
            }
            variants.push(copy);
        }
        spans.push(SpanSummary {
            span_id: span.span_id,
            variants,
        });
    }
    Ok(TraceSummary {
        trace_id: summary.trace_id,
        first_seen: summary.first_seen,
        last_seen: summary.last_seen,
        observation_count: summary.observation_count,
        spans,
        quiescent: summary.quiescent,
    })
}

fn find_summary(summaries: &[TraceSummary], trace_id: [u8; 16]) -> Result<usize, usize> {
    summaries.binary_search_by_key(&trace_id, |summary| summary.trace_id)
}

fn find_summary_observed(
    summaries: &[TraceSummary],
    trace_id: [u8; 16],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<Result<usize, usize>, TraceStoreFailure> {
    find_sorted_observed(
        summaries,
        trace_id,
        |summary| summary.trace_id,
        cancellation,
        observer,
    )
}

fn find_span_observed(
    spans: &[SpanSummary],
    span_id: [u8; 8],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<Result<usize, usize>, TraceStoreFailure> {
    find_sorted_observed(spans, span_id, |span| span.span_id, cancellation, observer)
}

fn find_sorted_observed<T, K: Ord + Copy>(
    values: &[T],
    key: K,
    item_key: impl Fn(&T) -> K,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<Result<usize, usize>, TraceStoreFailure> {
    for (index, value) in values.iter().enumerate() {
        super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        match key.cmp(&item_key(value)) {
            std::cmp::Ordering::Less => return Ok(Err(index)),
            std::cmp::Ordering::Equal => return Ok(Ok(index)),
            std::cmp::Ordering::Greater => {},
        }
    }
    Ok(Err(values.len()))
}

fn semantic_equal_observed(
    left: &[u8],
    right: &[u8],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<bool, TraceStoreFailure> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.chunks(4_096).zip(right.chunks(4_096)) {
        super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(fuzzing)]
struct FuzzCancellation;

#[cfg(fuzzing)]
impl ScanCancellation for FuzzCancellation {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[cfg(fuzzing)]
struct FuzzObserver;

#[cfg(fuzzing)]
impl ScanObserver for FuzzObserver {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_trace_summary_state(data: &[u8]) {
    let mut summaries = Vec::new();
    let cancellation = FuzzCancellation;
    let observer = FuzzObserver;
    let clock =
        positron_kernel::LifecycleClock::new(positron_kernel::FixedLifecycleClockSource::new(
            positron_domain::time::UnixNanoseconds::new(1),
        ));
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
        let Ok(update) = stage_summary_update(
            &summaries,
            trace_id,
            span_id,
            ingest_time,
            semantic,
            &cancellation,
            &observer,
        ) else {
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
