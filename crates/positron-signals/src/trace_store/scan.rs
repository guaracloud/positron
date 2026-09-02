use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, RecordOrdinal, SignalKind};
use positron_kernel::{
    LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor, ResourceReservation,
    WorkClaim, WorkKind,
};

use super::codec;
use super::failure::TraceStoreFailure;
use super::types::StoredSpanObservation;
use crate::{ScanCancellation, ScanLimit, ScanObservationFailureCode, ScanObserver};

const SPAN_RESULT_SLOT_BYTES: u64 = 512;

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

impl TraceScanResult<'_> {
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
    pub fn into_observations(self) -> Vec<ScannedSpanObservation> {
        self.observations
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
    pub const fn observation(&self) -> &super::types::SpanObservation {
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
    /// Scans authenticated committed observations from active and sealed segments.
    pub fn scan<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
    ) -> Result<TraceScanResult<'kernel>, TraceStoreFailure> {
        self.scan_observed(
            governor,
            tenant,
            snapshot,
            scan,
            &NeverCancelled,
            &Unobserved,
        )
    }

    /// Scans with cooperative cancellation and caller-owned bounded work observation.
    pub fn scan_observed<'kernel>(
        &self,
        governor: ResourceGovernor<'kernel>,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        scan: TraceScan,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<TraceScanResult<'kernel>, TraceStoreFailure> {
        let scope = snapshot.scope();
        if scope.tenant_id() != tenant || scope.signal_kind() != SignalKind::Traces {
            return Err(TraceStoreFailure::physical_scope_mismatch());
        }
        check_cancel(cancellation)?;
        let mut encoded_bytes = 0_u64;
        for block in snapshot.blocks() {
            check_cancel(cancellation)?;
            if includes_block(scan, block.position()) {
                encoded_bytes = encoded_bytes
                    .checked_add(
                        u64::try_from(block.payload().len())
                            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
                    )
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            }
        }
        let output_memory = u64::try_from(scan.limit().value())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?
            .checked_mul(SPAN_RESULT_SLOT_BYTES)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let memory = encoded_bytes
            .checked_add(output_memory)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?
            .max(1);
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, memory)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        let claim = WorkClaim::tenant(tenant, WorkKind::InteractiveQueryTail, amounts)
            .map_err(|_| TraceStoreFailure::limit_exceeded())?;
        let capacity = governor
            .reserve(claim)
            .map_err(|_| TraceStoreFailure::resource_admission_refused())?;
        check_cancel(cancellation)?;
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(scan.limit().value())
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
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
            let decoder =
                codec::BlockDecode::observed(tenant, block.payload(), cancellation, observer)?;
            let skipped = skipped_records(scan, block.position());
            let available = decoder.record_count().saturating_sub(skipped);
            let decoded = decoder.decode_after(block, skipped, remaining, cancellation)?;
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
        }
        check_cancel(cancellation)?;
        let retained_size_bytes = retained_size(&observations)?;
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

fn check_cancel(cancellation: &dyn ScanCancellation) -> Result<(), TraceStoreFailure> {
    if cancellation.is_cancelled() {
        Err(TraceStoreFailure::cancelled())
    } else {
        Ok(())
    }
}

fn retained_size(observations: &[ScannedSpanObservation]) -> Result<u64, TraceStoreFailure> {
    let slots = u64::try_from(observations.len())
        .map_err(|_| TraceStoreFailure::limit_exceeded())?
        .checked_mul(SPAN_RESULT_SLOT_BYTES)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    observations.iter().try_fold(slots, |total, observation| {
        let dynamic =
            observation
                .observation()
                .attributes()
                .iter()
                .try_fold(0_u64, |bytes, attribute| {
                    (0..attribute.len()).try_fold(bytes, |bytes, index| {
                        let value = attribute
                            .occurrence(index)
                            .ok_or_else(TraceStoreFailure::invalid_input)?;
                        let retained = u64::try_from(
                            value
                                .retained_heap_bytes()
                                .map_err(TraceStoreFailure::domain)?,
                        )
                        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
                        bytes
                            .checked_add(retained)
                            .ok_or_else(TraceStoreFailure::limit_exceeded)
                    })
                })?;
        total
            .checked_add(dynamic)
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    })
}
