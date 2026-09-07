//! Incremental, bounded trace-summary maintenance over committed observations.

mod index;
mod retained;
mod transition;
mod truncation;

use super::{ScannedSpanObservation, TraceIncompleteness, TraceStore, TraceStoreFailure};
use crate::{ScanCancellation, ScanLimit, ScanObserver};
use positron_domain::routing::{CommitPosition, RecordOrdinal, SignalKind};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{
    CatalogGenerationId, IngestTime, LedgerSnapshot, LifecycleClock, LifecycleClockSource,
    ResourceAmounts, ResourceDimension, ResourceGovernor, ResourceReservation, SegmentScope,
    WorkClaim, WorkKind,
};

use index::{Lookup, SummaryIndex};
use retained::{checked_bytes, summary_capacity_bytes};
use transition::{StagedObservation, stage_summary_update};

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

/// Immutable authenticated coverage for one trace-summary maintenance result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceSummaryCoverage {
    scope: SegmentScope,
    catalog_generation: u64,
    catalog_identity: CatalogGenerationId,
    frontier: CommitPosition,
    applied_cursor: Option<(CommitPosition, RecordOrdinal)>,
    physical_complete: bool,
    quiescence_complete: bool,
    quiescence_checked_at: Option<IngestTime>,
}

impl TraceSummaryCoverage {
    #[must_use]
    pub const fn scope(self) -> SegmentScope {
        self.scope
    }
    #[must_use]
    pub const fn catalog_generation(self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub const fn catalog_identity(self) -> CatalogGenerationId {
        self.catalog_identity
    }
    #[must_use]
    pub const fn frontier(self) -> CommitPosition {
        self.frontier
    }
    #[must_use]
    pub const fn applied_cursor(self) -> Option<(CommitPosition, RecordOrdinal)> {
        self.applied_cursor
    }
    #[must_use]
    pub const fn physical_complete(self) -> bool {
        self.physical_complete
    }
    #[must_use]
    pub const fn quiescence_complete(self) -> bool {
        self.quiescence_complete
    }
    #[must_use]
    pub const fn quiescence_checked_at(self) -> Option<IngestTime> {
        self.quiescence_checked_at
    }
}

#[derive(Clone, Debug)]
struct SpanSummary {
    span_id: [u8; 8],
    variants: Vec<Vec<u8>>,
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
    coverage: TraceSummaryCoverage,
    applied_observations: u64,
    complete: bool,
    quiescence_complete: bool,
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
    /// Whether every retained summary was refreshed at one ingest-time instant.
    #[must_use]
    pub const fn quiescence_complete(&self) -> bool {
        self.quiescence_complete
    }
    /// Returns the authenticated snapshot and cursor this result covers.
    #[must_use]
    pub const fn coverage(&self) -> TraceSummaryCoverage {
        self.coverage
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
    catalog_identity: Option<CatalogGenerationId>,
    quiescence_basis: Option<(CatalogGenerationId, CommitPosition, u64)>,
    quiescence_target: Option<IngestTime>,
    quiescence_cursor: usize,
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
            catalog_identity: None,
            quiescence_basis: None,
            quiescence_target: None,
            quiescence_cursor: 0,
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
        let mut quiescence_complete = false;
        if complete {
            let lifecycle_now = lifecycle_clock
                .assign_ingest_time()
                .map_err(|_| TraceStoreFailure::rejected_clock())?;
            quiescence_complete = self.refresh_quiescence(
                snapshot.frontier(),
                snapshot.catalog_generation(),
                lifecycle_now,
                cancellation,
                observer,
            )?;
        }
        Ok(TraceSummaryMaintenance {
            maintainer: self,
            coverage: TraceSummaryCoverage {
                scope: snapshot.scope(),
                catalog_generation: snapshot.catalog_generation(),
                catalog_identity: snapshot.catalog_identity(),
                frontier: snapshot.frontier(),
                applied_cursor: self.cursor,
                physical_complete: complete,
                quiescence_complete,
                quiescence_checked_at: if complete {
                    self.quiescence_target
                } else {
                    None
                },
            },
            applied_observations: applied,
            complete,
            quiescence_complete,
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
                self.restore_failure_capacity(capacity_before)?;
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
        let (slot, vacant_bucket, index_growth, appending) = match lookup {
            Lookup::Present(slot) => (slot, None, None, false),
            Lookup::Vacant(bucket) => (
                self.summaries.len(),
                Some(bucket),
                self.index.growth_bytes_for_insert()?,
                true,
            ),
        };
        let outer_growth = if appending {
            self.outer_growth_bytes_for_append()?
        } else {
            0
        };
        self.reserve_staged_update(expected, index_growth.unwrap_or(0), outer_growth)?;
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
            self.reserve_outer_slots()?;
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
            prior_index.as_ref(),
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
        frontier: CommitPosition,
        catalog_generation: u64,
        lifecycle_now: IngestTime,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<bool, TraceStoreFailure> {
        let basis = (
            self.catalog_identity
                .ok_or_else(TraceStoreFailure::invalid_input)?,
            frontier,
            catalog_generation,
        );
        if self.quiescence_basis != Some(basis) || self.quiescence_cursor >= self.summaries.len() {
            self.quiescence_basis = Some(basis);
            self.quiescence_target = Some(lifecycle_now);
            self.quiescence_cursor = 0;
        }
        let target = self
            .quiescence_target
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let mut refreshed = 0_usize;
        while refreshed < self.limit.value() && self.quiescence_cursor < self.summaries.len() {
            super::scan::check_cancel(cancellation)?;
            observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
            let summary = self
                .summaries
                .get_mut(self.quiescence_cursor)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            let elapsed = target
                .instant()
                .value()
                .saturating_sub(summary.last_seen.instant().value());
            summary.quiescent = u64::try_from(elapsed)
                .is_ok_and(|elapsed| elapsed >= self.quiet_period.nanoseconds());
            refreshed = refreshed
                .checked_add(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            self.quiescence_cursor = self
                .quiescence_cursor
                .checked_add(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        }
        Ok(self.quiescence_cursor >= self.summaries.len())
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
        if self.catalog_generation == Some(snapshot.catalog_generation())
            && self
                .catalog_identity
                .is_some_and(|identity| identity != snapshot.catalog_identity())
        {
            return Err(TraceStoreFailure::stale_generation());
        }
        self.catalog_generation = Some(snapshot.catalog_generation());
        self.catalog_identity = Some(snapshot.catalog_identity());
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
        rollback_index: Option<&SummaryIndex>,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<(), TraceStoreFailure> {
        let summary_bytes = self
            .summary_bytes
            .checked_sub(prior_bytes)
            .and_then(|bytes| bytes.checked_add(updated_bytes))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let mut bytes = self.retained_capacity_bytes(summary_bytes)?;
        if let Some(rollback) = rollback {
            bytes = bytes
                .checked_add(summary_capacity_bytes(rollback, cancellation, observer)?)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        }
        if let Some(rollback_index) = rollback_index {
            bytes = bytes
                .checked_add(rollback_index.retained_bytes()?)
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

    fn restore_failure_capacity(
        &mut self,
        capacity_before: ResourceAmounts,
    ) -> Result<(), TraceStoreFailure> {
        let retained = self.retained_capacity_bytes(self.summary_bytes)?.max(1);
        let required = ResourceAmounts::only(
            ResourceDimension::MemoryBytes,
            capacity_before
                .get(ResourceDimension::MemoryBytes)
                .max(retained),
        )
        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        self.capacity
            .try_resize_preserving_capacity(required)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())
            .map(|_| ())
    }

    fn retained_capacity_bytes(&self, summary_bytes: u64) -> Result<u64, TraceStoreFailure> {
        let index_bytes = self.index.retained_bytes()?;
        checked_bytes(
            self.summaries.capacity(),
            std::mem::size_of::<TraceSummary>(),
        )?
        .checked_add(checked_bytes(
            self.summary_capacities.capacity(),
            std::mem::size_of::<u64>(),
        )?)
        .and_then(|bytes| bytes.checked_add(index_bytes))
        .and_then(|bytes| bytes.checked_add(summary_bytes))
        .ok_or_else(TraceStoreFailure::limit_exceeded)
    }

    fn reserve_staged_update(
        &mut self,
        semantic_capacity: usize,
        index_growth_bytes: u64,
        outer_growth_bytes: u64,
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
            .and_then(|bytes| bytes.checked_add(outer_growth_bytes))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, required)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        self.capacity
            .try_resize_preserving_capacity(amounts)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())
            .map(|_| ())
    }

    fn outer_growth_bytes_for_append(&self) -> Result<u64, TraceStoreFailure> {
        let summary_capacity =
            retained::append_capacity(self.summaries.len(), self.summaries.capacity())?;
        let capacity_cache = retained::append_capacity(
            self.summary_capacities.len(),
            self.summary_capacities.capacity(),
        )?;
        let summary_bytes = if summary_capacity > self.summaries.capacity() {
            checked_bytes(summary_capacity, std::mem::size_of::<TraceSummary>())?
        } else {
            0
        };
        let cache_bytes = if capacity_cache > self.summary_capacities.capacity() {
            checked_bytes(capacity_cache, std::mem::size_of::<u64>())?
        } else {
            0
        };
        summary_bytes
            .checked_add(cache_bytes)
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    }

    fn reserve_outer_slots(&mut self) -> Result<(), TraceStoreFailure> {
        let summaries = retained::append_capacity(self.summaries.len(), self.summaries.capacity())?;
        let capacities = retained::append_capacity(
            self.summary_capacities.len(),
            self.summary_capacities.capacity(),
        )?;
        self.summaries
            .try_reserve_exact(
                summaries
                    .checked_sub(self.summaries.len())
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?,
            )
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        self.summary_capacities
            .try_reserve_exact(
                capacities
                    .checked_sub(self.summary_capacities.len())
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?,
            )
            .map_err(|_| TraceStoreFailure::resource_exhausted())
    }
}
