//! Incremental, bounded trace-summary maintenance over committed observations.

mod index;
mod retained;
mod truncation;

use super::{ScannedSpanObservation, TraceIncompleteness, TraceStore, TraceStoreFailure};
use crate::{ScanCancellation, ScanLimit, ScanObserver};
use positron_domain::routing::{CommitPosition, RecordOrdinal, SignalKind};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{
    IngestTime, LedgerSnapshot, LifecycleClock, LifecycleClockSource, ResourceAmounts,
    ResourceDimension, ResourceGovernor, ResourceReservation, SegmentScope, WorkClaim, WorkKind,
};

use index::{Lookup, SummaryIndex};
use retained::{checked_bytes, summary_capacity_bytes};

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
    slot: usize,
    prior: Option<TraceSummary>,
    updated: TraceSummary,
}

struct StagedObservation {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    ingest_time: IngestTime,
    semantic: Vec<u8>,
    truncated: bool,
}

/// A derived, non-authoritative summary for one tenant-scoped trace.
#[derive(Clone, Debug)]
pub struct TraceSummary {
    trace_id: [u8; 16],
    first_seen: IngestTime,
    last_seen: IngestTime,
    observation_count: u64,
    spans: Vec<SpanSummary>,
    truncated: bool,
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
    /// Whether any committed observation retained an explicit truncation marker.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
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
            .and_then(|index| self.maintainer.summaries.get(index))
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
    summary_capacities: Vec<u64>,
    summary_bytes: u64,
    index: SummaryIndex,
    cursor: Option<(CommitPosition, RecordOrdinal)>,
    catalog_generation: Option<u64>,
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
            summary_capacities: Vec::new(),
            summary_bytes: 0,
            index: SummaryIndex::new(),
            cursor: None,
            catalog_generation: None,
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
        let result = store.scan_physical_observed_for_maintenance(
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
        let capacity_before = self.capacity.granted();
        match self.apply_staged(scanned, cancellation, observer) {
            Ok(()) => Ok(()),
            Err(failure) => {
                self.capacity
                    .try_resize_preserving_capacity(capacity_before)
                    .map_err(|_| TraceStoreFailure::resource_admission_refused())?;
                Err(failure)
            },
        }
    }

    fn apply_staged(
        &mut self,
        scanned: &ScannedSpanObservation,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<(), TraceStoreFailure> {
        let observation = scanned.observation();
        let truncated = truncation::observation_is_truncated(observation, cancellation, observer)?;
        let expected = super::codec::encoded_record_bytes_with_profile_observed(
            &ValueLimitProfile::release_1_system_maximum(),
            observation,
            cancellation,
            observer,
        )?
        .checked_sub(8)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
        let trace_id = observation.trace_id();
        let lookup = self
            .index
            .lookup_observed(trace_id, cancellation, observer)?;
        let (slot, vacant_bucket, index_growth) = match lookup {
            Lookup::Present(slot) => (slot, None, None),
            Lookup::Vacant(bucket) => (
                self.summaries.len(),
                Some(bucket),
                self.index.growth_bytes_for_insert()?,
            ),
        };
        self.reserve_staged_update(expected, index_growth.unwrap_or(0))?;
        let semantic = super::codec::encode_semantic_observation_with_profile_observed(
            &ValueLimitProfile::release_1_system_maximum(),
            observation,
            expected,
            cancellation,
            observer,
        )?;
        let update = stage_summary_update(
            self.summaries.get(slot),
            slot,
            StagedObservation {
                trace_id,
                span_id: observation.span_id(),
                ingest_time: scanned.ingest_time(),
                semantic,
                truncated,
            },
            cancellation,
            observer,
        )?;
        let updated_bytes = summary_capacity_bytes(&update.updated, cancellation, observer)?;
        let prior_bytes = if update.prior.is_some() {
            *self
                .summary_capacities
                .get(update.slot)
                .ok_or_else(TraceStoreFailure::invalid_input)?
        } else {
            0
        };
        let staged_index = if update.prior.is_none() && index_growth.is_some() {
            Some(
                self.index
                    .staged_with_insert(trace_id, update.slot, cancellation, observer)?,
            )
        } else {
            None
        };
        if update.prior.is_none() {
            self.summaries
                .try_reserve_exact(1)
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            self.summary_capacities
                .try_reserve_exact(1)
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        }
        let prior_index = staged_index.map(|staged| std::mem::replace(&mut self.index, staged));
        let inserted_bucket = if update.prior.is_none() && prior_index.is_none() {
            let bucket = vacant_bucket.ok_or_else(TraceStoreFailure::invalid_input)?;
            self.index.insert_at(bucket, trace_id, update.slot)?;
            Some(bucket)
        } else {
            None
        };
        if update.prior.is_some() {
            let slot = self
                .summaries
                .get_mut(update.slot)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            *slot = update.updated;
        } else {
            self.summaries.push(update.updated);
            self.summary_capacities.push(updated_bytes);
        }
        if update.prior.is_some() {
            let slot = self
                .summary_capacities
                .get_mut(update.slot)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            *slot = updated_bytes;
        }
        if let Err(failure) = self.resize_capacity(
            prior_bytes,
            updated_bytes,
            update.prior.as_ref(),
            cancellation,
            observer,
        ) {
            if let Some(prior) = update.prior {
                let slot = self
                    .summaries
                    .get_mut(update.slot)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                *slot = prior;
                let capacity = self
                    .summary_capacities
                    .get_mut(update.slot)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                *capacity = prior_bytes;
            } else if update.slot.checked_add(1) == Some(self.summaries.len()) {
                self.summaries.pop();
                self.summary_capacities.pop();
            } else {
                return Err(TraceStoreFailure::invalid_input());
            }
            if let Some(index) = prior_index {
                self.index = index;
            } else if let Some(bucket) = inserted_bucket {
                self.index.remove_inserted(bucket, trace_id, update.slot)?;
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
        if self
            .catalog_generation
            .is_some_and(|generation| snapshot.catalog_generation() < generation)
        {
            return Err(TraceStoreFailure::stale_generation());
        }
        self.catalog_generation = Some(snapshot.catalog_generation());
        Ok(())
    }

    fn find(&self, trace_id: [u8; 16]) -> Option<usize> {
        self.index.slot(trace_id)
    }

    fn resize_capacity(
        &mut self,
        prior_bytes: u64,
        updated_bytes: u64,
        rollback: Option<&TraceSummary>,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<(), TraceStoreFailure> {
        let summary_bytes = self
            .summary_bytes
            .checked_sub(prior_bytes)
            .and_then(|bytes| bytes.checked_add(updated_bytes))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let index_bytes = self.index.retained_bytes()?;
        let mut bytes = checked_bytes(
            self.summaries.capacity(),
            std::mem::size_of::<TraceSummary>(),
        )?
        .checked_add(checked_bytes(
            self.summary_capacities.capacity(),
            std::mem::size_of::<u64>(),
        )?)
        .and_then(|bytes| bytes.checked_add(index_bytes))
        .and_then(|bytes| bytes.checked_add(summary_bytes))
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        if let Some(rollback) = rollback {
            bytes = bytes
                .checked_add(summary_capacity_bytes(rollback, cancellation, observer)?)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        }
        let bytes = bytes.max(1);
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        self.capacity
            .try_resize_preserving_capacity(amounts)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())
            .map(|_| {
                self.summary_bytes = summary_bytes;
            })
    }

    fn reserve_staged_update(
        &mut self,
        semantic_capacity: usize,
        index_growth_bytes: u64,
    ) -> Result<(), TraceStoreFailure> {
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
            .and_then(|bytes| bytes.checked_add(index_growth_bytes))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, required)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        self.capacity
            .try_resize_preserving_capacity(amounts)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())
            .map(|_| ())
    }
}

fn stage_summary_update(
    existing: Option<&TraceSummary>,
    slot: usize,
    observation: StagedObservation,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<SummaryUpdate, TraceStoreFailure> {
    let prior = existing
        .map(|summary| clone_summary_observed(summary, cancellation, observer))
        .transpose()?;
    let mut updated = match &prior {
        Some(existing) => clone_summary_observed(existing, cancellation, observer)?,
        None => TraceSummary {
            trace_id: observation.trace_id,
            first_seen: observation.ingest_time,
            last_seen: observation.ingest_time,
            observation_count: 0,
            spans: Vec::new(),
            truncated: false,
            quiescent: false,
        },
    };
    updated.first_seen = updated.first_seen.min(observation.ingest_time);
    updated.last_seen = updated.last_seen.max(observation.ingest_time);
    updated.observation_count = updated
        .observation_count
        .checked_add(1)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    updated.quiescent = false;
    updated.truncated |= observation.truncated;
    let span_index =
        match find_span_observed(&updated.spans, observation.span_id, cancellation, observer)? {
            Ok(index) => index,
            Err(index) => {
                updated
                    .spans
                    .try_reserve_exact(1)
                    .map_err(|_| TraceStoreFailure::resource_exhausted())?;
                updated.spans.insert(
                    index,
                    SpanSummary {
                        span_id: observation.span_id,
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
        if semantic_equal_observed(variant, &observation.semantic, cancellation, observer)? {
            duplicate = true;
            break;
        }
    }
    if !duplicate {
        variants
            .try_reserve_exact(1)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        variants.push(observation.semantic);
    }
    Ok(SummaryUpdate {
        slot,
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
        truncated: summary.truncated,
        quiescent: summary.quiescent,
    })
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
    let mut lower = 0_usize;
    let mut upper = values.len();
    while lower < upper {
        super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        let middle = lower
            .checked_add(upper - lower)
            .and_then(|sum| sum.checked_div(2))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let value = values
            .get(middle)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        match key.cmp(&item_key(value)) {
            std::cmp::Ordering::Less => upper = middle,
            std::cmp::Ordering::Equal => return Ok(Ok(middle)),
            std::cmp::Ordering::Greater => {
                lower = middle
                    .checked_add(1)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            },
        }
    }
    Ok(Err(lower))
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
