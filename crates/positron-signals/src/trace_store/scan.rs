use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, RecordOrdinal, SignalKind};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{
    LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor, ResourceReservation,
    WorkClaim, WorkKind,
};

use super::codec;
use super::failure::TraceStoreFailure;
use super::types::StoredSpanObservation;
use crate::{ScanCancellation, ScanLimit, ScanObservationFailureCode, ScanObserver};

const SPAN_RESULT_SLOT_BYTES: u64 = codec::DECODED_RECORD_SLOT_BYTES;

/// A bounded native Trace Store scan over one authenticated snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceScan {
    limit: ScanLimit,
    after: Option<CommitPosition>,
    after_record: Option<(CommitPosition, RecordOrdinal)>,
    frontier: Option<CommitPosition>,
    scanned_bytes: Option<u64>,
}

impl TraceScan {
    #[must_use]
    pub const fn all(limit: ScanLimit) -> Self {
        Self {
            limit,
            after: None,
            after_record: None,
            frontier: None,
            scanned_bytes: None,
        }
    }

    #[must_use]
    pub const fn through(limit: ScanLimit, frontier: CommitPosition) -> Self {
        Self {
            limit,
            after: None,
            after_record: None,
            frontier: Some(frontier),
            scanned_bytes: None,
        }
    }

    #[must_use]
    pub const fn after(limit: ScanLimit, position: CommitPosition) -> Self {
        Self {
            limit,
            after: Some(position),
            after_record: None,
            frontier: None,
            scanned_bytes: None,
        }
    }

    /// Returns committed records strictly after one physical record cursor.
    #[must_use]
    pub const fn after_cursor(
        limit: ScanLimit,
        position: CommitPosition,
        ordinal: RecordOrdinal,
    ) -> Self {
        Self {
            limit,
            after: None,
            after_record: Some((position, ordinal)),
            frontier: None,
            scanned_bytes: None,
        }
    }

    #[must_use]
    pub const fn between(
        limit: ScanLimit,
        after: CommitPosition,
        frontier: CommitPosition,
    ) -> Self {
        Self {
            limit,
            after: Some(after),
            after_record: None,
            frontier: Some(frontier),
            scanned_bytes: None,
        }
    }

    #[must_use]
    pub const fn between_record(
        limit: ScanLimit,
        position: CommitPosition,
        ordinal: RecordOrdinal,
        frontier: CommitPosition,
    ) -> Self {
        Self {
            limit,
            after: None,
            after_record: Some((position, ordinal)),
            frontier: Some(frontier),
            scanned_bytes: None,
        }
    }

    #[must_use]
    pub const fn limit(self) -> ScanLimit {
        self.limit
    }

    #[must_use]
    pub const fn frontier(self) -> Option<CommitPosition> {
        self.frontier
    }

    #[must_use]
    pub const fn after_position(self) -> Option<CommitPosition> {
        self.after
    }

    #[must_use]
    pub const fn after_record(self) -> Option<(CommitPosition, RecordOrdinal)> {
        self.after_record
    }

    #[must_use]
    pub const fn with_scanned_bytes(self, limit: u64) -> Self {
        Self {
            limit: self.limit,
            after: self.after,
            after_record: self.after_record,
            frontier: self.frontier,
            scanned_bytes: Some(limit),
        }
    }

    #[must_use]
    pub const fn scanned_bytes_limit(self) -> Option<u64> {
        self.scanned_bytes
    }
}

/// Why a trace scan result is explicitly incomplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceIncompleteness {
    /// Every selected block and observation was visited.
    None,
    /// The caller's finite result limit stopped the scan.
    ResultLimit,
    /// The caller's cumulative raw-byte limit stopped the scan.
    ScannedBytesLimit,
}

/// A bounded scan result retaining only authenticated observations.
#[derive(Debug)]
pub struct TraceScanResult<'kernel> {
    observations: Vec<ScannedSpanObservation>,
    decoded_observations: u64,
    complete: bool,
    scanned_bytes: u64,
    scanned_bytes_limited: bool,
    retained_size_bytes: u64,
    _capacity: ResourceReservation<'kernel>,
}

impl<'kernel> TraceScanResult<'kernel> {
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn new(
        observations: Vec<ScannedSpanObservation>,
        decoded_observations: u64,
        complete: bool,
        scanned_bytes: u64,
        scanned_bytes_limited: bool,
        retained_size_bytes: u64,
        capacity: ResourceReservation<'_>,
    ) -> TraceScanResult<'_> {
        TraceScanResult {
            observations,
            decoded_observations,
            complete,
            scanned_bytes,
            scanned_bytes_limited,
            retained_size_bytes,
            _capacity: capacity,
        }
    }

    #[must_use]
    pub fn observations(&self) -> &[ScannedSpanObservation] {
        &self.observations
    }

    #[must_use]
    pub const fn decoded_observations(&self) -> u64 {
        self.decoded_observations
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }

    #[must_use]
    pub const fn scanned_bytes_limited(&self) -> bool {
        self.scanned_bytes_limited
    }

    #[must_use]
    pub const fn incompleteness(&self) -> TraceIncompleteness {
        if self.complete {
            TraceIncompleteness::None
        } else if self.scanned_bytes_limited {
            TraceIncompleteness::ScannedBytesLimit
        } else {
            TraceIncompleteness::ResultLimit
        }
    }

    #[must_use]
    pub const fn retained_size_bytes(&self) -> u64 {
        self.retained_size_bytes
    }

    /// Consolidates this bounded physical scan into logical spans while
    /// retaining the caller's cancellation and work-accounting capabilities.
    fn into_logical_spans(
        self,
        profile: &ValueLimitProfile,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<super::LogicalTraceScanResult<'kernel>, TraceStoreFailure> {
        let Self {
            observations,
            complete,
            scanned_bytes,
            scanned_bytes_limited,
            retained_size_bytes,
            _capacity,
            ..
        } = self;
        super::consolidation::consolidate(
            observations,
            complete,
            scanned_bytes,
            scanned_bytes_limited,
            retained_size_bytes,
            _capacity,
            super::consolidation::ConsolidationContext {
                profile,
                cancellation,
                observer,
            },
        )
    }

    fn into_trace_by_id(
        self,
        trace_id: [u8; 16],
        search: &super::TraceSearch,
        profile: &ValueLimitProfile,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<super::TraceByIdResult<'kernel>, TraceStoreFailure> {
        let mut logical = self.into_matching_logical(search, profile, cancellation, observer)?;
        retain_trace_id(&mut logical.spans, trace_id, cancellation, observer)?;
        Ok(super::TraceByIdResult::from_logical(trace_id, logical))
    }

    fn into_matching_logical(
        self,
        search: &super::TraceSearch,
        profile: &ValueLimitProfile,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<super::LogicalTraceScanResult<'kernel>, TraceStoreFailure> {
        let mut logical = self.into_logical_spans(profile, cancellation, observer)?;
        retain_matching_spans(&mut logical.spans, search, cancellation, observer)?;
        Ok(logical)
    }
}

fn retain_trace_id(
    spans: &mut Vec<super::LogicalSpan>,
    trace_id: [u8; 16],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    let mut index = 0_usize;
    while index < spans.len() {
        observe_selection(cancellation, observer)?;
        let span = spans
            .get(index)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        if span.trace_id() == trace_id {
            index = index
                .checked_add(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        } else {
            spans.remove(index);
        }
    }
    Ok(())
}

fn retain_matching_spans(
    spans: &mut Vec<super::LogicalSpan>,
    search: &super::TraceSearch,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    let mut index = 0_usize;
    while index < spans.len() {
        observe_selection(cancellation, observer)?;
        let span = spans
            .get(index)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let mut matched = false;
        for variant in span.variants() {
            observe_selection(cancellation, observer)?;
            if search.matches(variant.observation().observation(), cancellation, observer)? {
                matched = true;
                break;
            }
        }
        if matched {
            index = index
                .checked_add(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        } else {
            spans.remove(index);
        }
    }
    Ok(())
}

fn observe_selection(
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    check_cancel(cancellation)?;
    observer
        .observe_work(1)
        .map_err(TraceStoreFailure::observation)
}

/// One authenticated observation with its stable physical commit identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannedSpanObservation {
    observation: StoredSpanObservation,
    commit_position: CommitPosition,
    record_ordinal: RecordOrdinal,
}

impl ScannedSpanObservation {
    pub(super) const fn new(
        observation: StoredSpanObservation,
        commit_position: CommitPosition,
        record_ordinal: RecordOrdinal,
    ) -> Self {
        Self {
            observation,
            commit_position,
            record_ordinal,
        }
    }

    #[must_use]
    pub const fn stored(&self) -> &StoredSpanObservation {
        &self.observation
    }

    #[must_use]
    pub const fn observation(&self) -> &super::observation::SpanObservation {
        self.observation.observation()
    }

    #[must_use]
    pub const fn commit_position(&self) -> CommitPosition {
        self.commit_position
    }

    #[must_use]
    pub const fn record_ordinal(&self) -> RecordOrdinal {
        self.record_ordinal
    }
}

impl std::ops::Deref for ScannedSpanObservation {
    type Target = StoredSpanObservation;

    fn deref(&self) -> &Self::Target {
        &self.observation
    }
}

impl super::TraceStore {
    /// Searches the normal consolidated Trace Store view for one authenticated snapshot.
    ///
    /// The logical result is ordered by trace and span identity and retains all
    /// conflicting span variants; its completion state discloses finite scan
    /// boundaries instead of presenting a partial result as exhaustive.
    pub fn search<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        search: super::TraceSearch,
    ) -> Result<super::LogicalTraceScanResult<'kernel>, TraceStoreFailure> {
        self.search_observed(
            governor,
            tenant,
            snapshot,
            search,
            &NeverCancelled,
            &Unobserved,
        )
    }

    /// Searches with caller-owned cancellation and cumulative budget observation.
    #[allow(clippy::too_many_arguments)]
    pub fn search_observed<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        search: super::TraceSearch,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<super::LogicalTraceScanResult<'kernel>, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        self.scan_physical_observed_with_profile(
            &profile,
            governor,
            tenant,
            snapshot,
            search.scan(),
            cancellation,
            observer,
        )?
        .into_matching_logical(&search, &profile, cancellation, observer)
    }

    /// Retrieves one tenant-scoped trace from one authenticated snapshot.
    ///
    /// The result remains explicitly incomplete when its finite physical scan
    /// boundary is reached before the snapshot frontier, so an empty response
    /// never fabricates trace absence.
    pub fn trace_by_id<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        trace_id: [u8; 16],
        search: super::TraceSearch,
    ) -> Result<super::TraceByIdResult<'kernel>, TraceStoreFailure> {
        self.trace_by_id_observed(
            governor,
            tenant,
            snapshot,
            trace_id,
            search,
            &NeverCancelled,
            &Unobserved,
        )
    }

    /// Retrieves one trace with caller-owned cancellation and cumulative budget observation.
    #[allow(clippy::too_many_arguments)]
    pub fn trace_by_id_observed<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        trace_id: [u8; 16],
        search: super::TraceSearch,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<super::TraceByIdResult<'kernel>, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        self.scan_physical_observed_with_profile(
            &profile,
            governor,
            tenant,
            snapshot,
            search.scan(),
            cancellation,
            observer,
        )?
        .into_trace_by_id(trace_id, &search, &profile, cancellation, observer)
    }

    /// Scans the normal consolidated Trace Store view for one authenticated snapshot.
    pub fn scan<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
    ) -> Result<super::LogicalTraceScanResult<'kernel>, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        self.scan_observed_with_profile(
            &profile,
            governor,
            tenant,
            snapshot,
            scan,
            &NeverCancelled,
            &Unobserved,
        )
    }

    /// Scans raw authenticated observations for diagnostic expansion.
    pub fn scan_physical<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
    ) -> Result<TraceScanResult<'kernel>, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        self.scan_physical_observed_with_profile(
            &profile,
            governor,
            tenant,
            snapshot,
            scan,
            &NeverCancelled,
            &Unobserved,
        )
    }

    /// Scans the normal consolidated view with caller-owned cancellation and work budgets.
    #[allow(clippy::too_many_arguments)]
    pub fn scan_observed<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<super::LogicalTraceScanResult<'kernel>, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        self.scan_observed_with_profile(
            &profile,
            governor,
            tenant,
            snapshot,
            scan,
            cancellation,
            observer,
        )
    }

    /// Scans raw observations with cooperative cancellation and caller-owned work observation.
    pub fn scan_physical_observed<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<TraceScanResult<'kernel>, TraceStoreFailure> {
        let profile = ValueLimitProfile::release_1_system_maximum();
        self.scan_physical_observed_with_profile(
            &profile,
            governor,
            tenant,
            snapshot,
            scan,
            cancellation,
            observer,
        )
    }

    /// Scans the normal consolidated view using one pinned effective value profile.
    #[allow(clippy::too_many_arguments)]
    pub fn scan_observed_with_profile<'kernel>(
        &self,
        profile: &ValueLimitProfile,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<super::LogicalTraceScanResult<'kernel>, TraceStoreFailure> {
        self.scan_physical_observed_with_profile(
            profile,
            governor,
            tenant,
            snapshot,
            scan,
            cancellation,
            observer,
        )?
        .into_logical_spans(profile, cancellation, observer)
    }

    /// Scans raw observations using one pinned effective value profile.
    #[allow(clippy::too_many_arguments)]
    pub fn scan_physical_observed_with_profile<'kernel>(
        &self,
        profile: &ValueLimitProfile,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<TraceScanResult<'kernel>, TraceStoreFailure> {
        self.scan_physical_observed_with_profile_and_work_kind(
            profile,
            governor,
            tenant,
            snapshot,
            scan,
            cancellation,
            observer,
            WorkKind::InteractiveQueryTail,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn scan_physical_observed_for_maintenance<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<TraceScanResult<'kernel>, TraceStoreFailure> {
        self.scan_physical_observed_with_profile_and_work_kind(
            &ValueLimitProfile::release_1_system_maximum(),
            governor,
            tenant,
            snapshot,
            scan,
            cancellation,
            observer,
            WorkKind::OrdinaryMaintenanceBackup,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_physical_observed_with_profile_and_work_kind<'kernel>(
        &self,
        profile: &ValueLimitProfile,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
        work_kind: WorkKind,
    ) -> Result<TraceScanResult<'kernel>, TraceStoreFailure> {
        let scope = snapshot.scope();
        if scope.tenant_id() != tenant || scope.signal_kind() != SignalKind::Traces {
            return Err(TraceStoreFailure::physical_scope_mismatch());
        }
        check_cancel(cancellation)?;
        let output_memory = u64::try_from(scan.limit().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?
            .checked_mul(SPAN_RESULT_SLOT_BYTES)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let memory = output_memory.max(1);
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, memory)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        let claim = WorkClaim::tenant(tenant, work_kind, amounts)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        let mut capacity = governor
            .reserve(claim)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())?;
        check_cancel(cancellation)?;
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(scan.limit().value())
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        let mut retained_size_bytes = output_memory;
        let mut scanned_bytes = 0_u64;
        let mut complete = true;
        let mut scanned_bytes_limited = false;
        for block in snapshot.blocks() {
            check_cancel(cancellation)?;
            if !includes_block(scan, block.position()) {
                continue;
            }
            let remaining = scan.limit().value().saturating_sub(observations.len());
            if remaining == 0 {
                complete = false;
                break;
            }
            let block_bytes = u64::try_from(block.payload().len())
                .map_err(|_| TraceStoreFailure::limit_exceeded())?;
            let next_scanned = scanned_bytes
                .checked_add(block_bytes)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            if scan
                .scanned_bytes_limit()
                .is_some_and(|limit| next_scanned > limit)
            {
                complete = false;
                scanned_bytes_limited = true;
                break;
            }
            observer
                .observe_scanned_bytes(block_bytes)
                .map_err(TraceStoreFailure::observation)?;
            scanned_bytes = next_scanned;
            let staged_memory = retained_size_bytes
                .checked_add(block_bytes)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?
                .max(1);
            resize_capacity(&mut capacity, staged_memory)?;
            let decoded_memory = codec::decoded_memory_bound_with_profile(
                tenant,
                block.payload(),
                cancellation,
                observer,
                profile,
            )?;
            let admitted_memory = retained_size_bytes
                .checked_add(block_bytes)
                .and_then(|memory| memory.checked_add(decoded_memory))
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            resize_capacity(&mut capacity, admitted_memory)?;
            let decoder = codec::BlockDecode::observed_with_profile(
                profile,
                tenant,
                block.payload(),
                cancellation,
                observer,
            )?;
            let skipped = skipped_records(scan, block.position());
            let available = decoder.record_count().saturating_sub(skipped);
            let decoded = decoder.decode_after_with_profile(
                block,
                skipped,
                remaining,
                cancellation,
                profile,
            )?;
            let first = skipped;
            for (offset, observation) in decoded.observations.into_iter().enumerate() {
                let ordinal = first
                    .checked_add(offset)
                    .and_then(|value| u16::try_from(value).ok())
                    .and_then(|value| RecordOrdinal::new(value).ok())
                    .ok_or_else(TraceStoreFailure::malformed_block)?;
                observations.push(ScannedSpanObservation::new(
                    observation,
                    block.position(),
                    ordinal,
                ));
            }
            if available > remaining {
                complete = false;
                break;
            }
            retained_size_bytes =
                super::retained::scan_result_bytes(observations.capacity(), &observations)?;
            resize_capacity(&mut capacity, retained_size_bytes.max(1))?;
        }
        check_cancel(cancellation)?;
        retained_size_bytes =
            super::retained::scan_result_bytes(observations.capacity(), &observations)?;
        resize_capacity(&mut capacity, retained_size_bytes.max(1))?;
        let decoded_observations =
            u64::try_from(observations.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?;
        Ok(TraceScanResult::new(
            observations,
            decoded_observations,
            complete,
            scanned_bytes,
            scanned_bytes_limited,
            retained_size_bytes,
            capacity,
        ))
    }
}

pub(super) fn resize_capacity(
    capacity: &mut ResourceReservation<'_>,
    memory: u64,
) -> Result<(), TraceStoreFailure> {
    let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, memory)
        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
    capacity
        .try_resize(amounts)
        .map_err(|_| TraceStoreFailure::resource_admission_refused())
        .map(|_| ())
}

struct NeverCancelled;

impl ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct Unobserved;

impl ScanObserver for Unobserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

fn includes_block(scan: TraceScan, position: CommitPosition) -> bool {
    (if let Some((after, _)) = scan.after_record() {
        position >= after
    } else {
        scan.after_position().is_none_or(|after| position > after)
    }) && scan.frontier().is_none_or(|frontier| position <= frontier)
}

fn skipped_records(scan: TraceScan, position: CommitPosition) -> usize {
    scan.after_record()
        .filter(|(after, _)| *after == position)
        .and_then(|(_, ordinal)| usize::from(ordinal.value()).checked_add(1))
        .unwrap_or(0)
}

pub(super) fn check_cancel(cancellation: &dyn ScanCancellation) -> Result<(), TraceStoreFailure> {
    if cancellation.is_cancelled() {
        Err(TraceStoreFailure::cancelled())
    } else {
        Ok(())
    }
}
