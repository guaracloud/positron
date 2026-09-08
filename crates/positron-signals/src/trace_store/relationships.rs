use std::{
    cmp::Ordering,
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hash, Hasher},
    mem::size_of,
};

use positron_domain::{
    routing::{CommitPosition, RecordOrdinal},
    value::{AttributeNamespace, MarkerAction},
};
use positron_kernel::{CatalogGenerationId, LedgerSnapshot, ResourceReservation, SegmentScope};

use crate::{ScanCancellation, ScanObserver};

use super::{
    LogicalSpan, LogicalTraceScanResult, SamplingDecision, TraceByIdSummary, TraceIncompleteness,
    TraceScan, TraceStoreFailure,
};

/// The authenticated identity state of one service endpoint field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceServiceIdentity<'span> {
    Missing,
    Exact(&'span str),
    Ambiguous,
    Removed,
    Redacted,
    Truncated,
    Invalid,
}

impl<'span> TraceServiceIdentity<'span> {
    const fn exact(self) -> Option<&'span str> {
        if let Self::Exact(value) = self {
            Some(value)
        } else {
            None
        }
    }

    const fn is_present_and_not_exact(self) -> bool {
        !matches!(self, Self::Missing | Self::Exact(_))
    }
}

/// One direct parent-to-child service edge visible in an authenticated trace snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceServiceRelationship<'span> {
    parent_span_id: [u8; 8],
    child_span_id: [u8; 8],
    parent_service: Option<&'span str>,
    child_service: Option<&'span str>,
    parent_service_namespace: Option<&'span str>,
    child_service_namespace: Option<&'span str>,
    parent_sampling: SamplingDecision,
    child_sampling: SamplingDecision,
    parent_identity: TraceServiceIdentity<'span>,
    child_identity: TraceServiceIdentity<'span>,
    parent_namespace_identity: TraceServiceIdentity<'span>,
    child_namespace_identity: TraceServiceIdentity<'span>,
}

impl TraceServiceRelationship<'_> {
    #[must_use]
    pub const fn parent_span_id(&self) -> [u8; 8] {
        self.parent_span_id
    }
    #[must_use]
    pub const fn child_span_id(&self) -> [u8; 8] {
        self.child_span_id
    }
    #[must_use]
    pub const fn parent_service(&self) -> Option<&str> {
        self.parent_service
    }
    #[must_use]
    pub const fn child_service(&self) -> Option<&str> {
        self.child_service
    }
    #[must_use]
    pub const fn parent_service_namespace(&self) -> Option<&str> {
        self.parent_service_namespace
    }
    #[must_use]
    pub const fn child_service_namespace(&self) -> Option<&str> {
        self.child_service_namespace
    }
    #[must_use]
    pub const fn parent_sampling(&self) -> SamplingDecision {
        self.parent_sampling
    }
    #[must_use]
    pub const fn child_sampling(&self) -> SamplingDecision {
        self.child_sampling
    }
    #[must_use]
    pub const fn parent_identity(&self) -> TraceServiceIdentity<'_> {
        self.parent_identity
    }
    #[must_use]
    pub const fn child_identity(&self) -> TraceServiceIdentity<'_> {
        self.child_identity
    }
    #[must_use]
    pub const fn parent_service_namespace_identity(&self) -> TraceServiceIdentity<'_> {
        self.parent_namespace_identity
    }
    #[must_use]
    pub const fn child_service_namespace_identity(&self) -> TraceServiceIdentity<'_> {
        self.child_namespace_identity
    }
}

/// Direct service edges and whether their identities and structural evidence are complete.
#[derive(Debug)]
pub struct TraceServiceRelationships<'span> {
    edges: Vec<TraceServiceRelationship<'span>>,
    complete: bool,
}

/// The non-payload identity state retained for an endpoint in a snapshot-wide pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TraceServiceIdentityState {
    Missing,
    Exact,
    Ambiguous,
    Removed,
    Redacted,
    Truncated,
    Invalid,
}

/// One aggregate of matching direct service evidence from an authenticated snapshot.
///
/// `edge_count` counts logical direct parent-to-child edges. Retries and
/// conflicting variants remain within each logical edge and never inflate this
/// count; `trace_ids` records every trace which contributed one or more edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceServiceRelationshipPair {
    parent_service: Option<String>,
    child_service: Option<String>,
    parent_service_namespace: Option<String>,
    child_service_namespace: Option<String>,
    parent_identity: TraceServiceIdentityState,
    child_identity: TraceServiceIdentityState,
    parent_namespace_identity: TraceServiceIdentityState,
    child_namespace_identity: TraceServiceIdentityState,
    parent_sampling_counts: [u64; 3],
    child_sampling_counts: [u64; 3],
    edge_count: u64,
    trace_ids: Vec<[u8; 16]>,
}

impl TraceServiceRelationshipPair {
    #[must_use]
    pub fn parent_service(&self) -> Option<&str> {
        self.parent_service.as_deref()
    }
    #[must_use]
    pub fn child_service(&self) -> Option<&str> {
        self.child_service.as_deref()
    }
    #[must_use]
    pub fn parent_service_namespace(&self) -> Option<&str> {
        self.parent_service_namespace.as_deref()
    }
    #[must_use]
    pub fn child_service_namespace(&self) -> Option<&str> {
        self.child_service_namespace.as_deref()
    }
    #[must_use]
    pub const fn parent_identity(&self) -> TraceServiceIdentityState {
        self.parent_identity
    }
    #[must_use]
    pub const fn child_identity(&self) -> TraceServiceIdentityState {
        self.child_identity
    }
    #[must_use]
    pub const fn parent_service_namespace_identity(&self) -> TraceServiceIdentityState {
        self.parent_namespace_identity
    }
    #[must_use]
    pub const fn child_service_namespace_identity(&self) -> TraceServiceIdentityState {
        self.child_namespace_identity
    }
    #[must_use]
    pub const fn parent_sampling_count(&self, sampling: SamplingDecision) -> u64 {
        self.parent_sampling_counts[sampling_key(sampling) as usize]
    }
    #[must_use]
    pub const fn child_sampling_count(&self, sampling: SamplingDecision) -> u64 {
        self.child_sampling_counts[sampling_key(sampling) as usize]
    }
    #[must_use]
    pub const fn edge_count(&self) -> u64 {
        self.edge_count
    }
    #[must_use]
    pub fn trace_ids(&self) -> &[[u8; 16]] {
        &self.trace_ids
    }
}

/// Structural reasons one contributing trace cannot establish complete direct evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceServiceRelationshipTraceIncompleteness {
    trace_id: [u8; 16],
    missing_parents: u64,
    conflicts: u64,
    cycle_members: u64,
    invalid_durations: u64,
    temporal_inconsistencies: u64,
    ambiguous_roots: bool,
}

impl TraceServiceRelationshipTraceIncompleteness {
    #[must_use]
    pub const fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }
    #[must_use]
    pub const fn missing_parents(&self) -> u64 {
        self.missing_parents
    }
    #[must_use]
    pub const fn conflicts(&self) -> u64 {
        self.conflicts
    }
    #[must_use]
    pub const fn cycle_members(&self) -> u64 {
        self.cycle_members
    }
    #[must_use]
    pub const fn invalid_durations(&self) -> u64 {
        self.invalid_durations
    }
    #[must_use]
    pub const fn temporal_inconsistencies(&self) -> u64 {
        self.temporal_inconsistencies
    }
    #[must_use]
    pub const fn ambiguous_roots(&self) -> bool {
        self.ambiguous_roots
    }
}

/// Snapshot and trace-local limits that prevent a complete relationship answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceServiceRelationshipIncompleteness {
    scan: TraceIncompleteness,
    traces: Vec<TraceServiceRelationshipTraceIncompleteness>,
}

/// The exact physical bounds selected for one relationship derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceServiceRelationshipSelection {
    after_position: Option<CommitPosition>,
    after_record: Option<(CommitPosition, RecordOrdinal)>,
    frontier: CommitPosition,
}

impl TraceServiceRelationshipSelection {
    #[must_use]
    pub const fn after_position(&self) -> Option<CommitPosition> {
        self.after_position
    }

    #[must_use]
    pub const fn after_record(&self) -> Option<(CommitPosition, RecordOrdinal)> {
        self.after_record
    }

    /// Returns the inclusive selected upper frontier, resolved against the snapshot.
    #[must_use]
    pub const fn frontier(&self) -> CommitPosition {
        self.frontier
    }

    fn covers_snapshot(&self, snapshot_frontier: CommitPosition) -> bool {
        self.after_position.is_none()
            && self.after_record.is_none()
            && self.frontier == snapshot_frontier
    }
}

/// The explicit reason a relationship result cannot represent its whole snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceServiceRelationshipSnapshotLimitation {
    ResultLimit,
    ScannedBytesLimit,
    SelectedRange,
}

impl TraceServiceRelationshipIncompleteness {
    #[must_use]
    pub const fn scan(&self) -> TraceIncompleteness {
        self.scan
    }
    #[must_use]
    pub fn traces(&self) -> &[TraceServiceRelationshipTraceIncompleteness] {
        &self.traces
    }
}

/// One bounded native service-relationship derivation over one authenticated snapshot.
#[derive(Debug)]
pub struct TraceServiceRelationshipSnapshot<'kernel> {
    pairs: Vec<TraceServiceRelationshipPair>,
    selected_range_complete: bool,
    snapshot_complete: bool,
    relationships_complete: bool,
    selection: TraceServiceRelationshipSelection,
    snapshot_limitation: Option<TraceServiceRelationshipSnapshotLimitation>,
    incompleteness: TraceServiceRelationshipIncompleteness,
    scanned_bytes: u64,
    decoded_observations: u64,
    scope: SegmentScope,
    catalog_generation: u64,
    catalog_identity: CatalogGenerationId,
    frontier: CommitPosition,
    _capacity: ResourceReservation<'kernel>,
}

#[derive(Clone, Copy)]
struct PairIndexSlot {
    hash: u64,
    pair_index: usize,
}

impl TraceServiceRelationshipSnapshot<'_> {
    /// Whether the bounded scan exhausted its explicit physical selection.
    #[must_use]
    pub const fn selected_range_complete(&self) -> bool {
        self.selected_range_complete
    }

    /// Whether the bounded scan exhausted this snapshot's complete physical range.
    ///
    /// A successful `after`, `through`, or `between` selection remains false:
    /// it is complete for its selected range but cannot establish whole-snapshot
    /// relationship evidence.
    /// This makes no claim that any trace is complete.
    #[must_use]
    pub const fn snapshot_complete(&self) -> bool {
        self.snapshot_complete
    }
    /// Whether the complete snapshot scan and every contributing trace's
    /// direct structural evidence are sufficient for a complete relationship answer.
    #[must_use]
    pub const fn relationships_complete(&self) -> bool {
        self.relationships_complete
    }
    #[must_use]
    pub const fn selection(&self) -> TraceServiceRelationshipSelection {
        self.selection
    }
    /// Returns why the result cannot establish whole-snapshot evidence.
    #[must_use]
    pub const fn snapshot_limitation(&self) -> Option<TraceServiceRelationshipSnapshotLimitation> {
        self.snapshot_limitation
    }
    #[must_use]
    pub fn pairs(&self) -> &[TraceServiceRelationshipPair] {
        &self.pairs
    }
    #[must_use]
    pub const fn incompleteness(&self) -> &TraceServiceRelationshipIncompleteness {
        &self.incompleteness
    }
    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }
    #[must_use]
    pub const fn decoded_observations(&self) -> u64 {
        self.decoded_observations
    }
    /// Returns the authenticated physical tenant, signal, and shard scope.
    #[must_use]
    pub const fn scope(&self) -> SegmentScope {
        self.scope
    }
    /// Returns the immutable catalog generation selected by this snapshot.
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }
    /// Returns the immutable catalog identity selected by this snapshot.
    #[must_use]
    pub const fn catalog_identity(&self) -> CatalogGenerationId {
        self.catalog_identity
    }
    /// Returns the authenticated Durability Frontier selected by this snapshot.
    #[must_use]
    pub const fn frontier(&self) -> CommitPosition {
        self.frontier
    }
}

pub(super) fn aggregate<'kernel>(
    logical: LogicalTraceScanResult<'kernel>,
    snapshot: &LedgerSnapshot<'_>,
    scan: TraceScan,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<TraceServiceRelationshipSnapshot<'kernel>, TraceStoreFailure> {
    let LogicalTraceScanResult {
        spans,
        complete,
        scanned_bytes,
        scanned_bytes_limited,
        decoded_observations,
        retained_size_bytes,
        mut _capacity,
        ..
    } = logical;
    let scan_incompleteness = if complete {
        TraceIncompleteness::None
    } else if scanned_bytes_limited {
        TraceIncompleteness::ScannedBytesLimit
    } else {
        TraceIncompleteness::ResultLimit
    };
    let pair_slots = vector_slots_bytes::<TraceServiceRelationshipPair>(spans.len())?;
    let incomplete_slots =
        vector_slots_bytes::<TraceServiceRelationshipTraceIncompleteness>(spans.len())?;
    let index_slots = pair_index_slots(spans.len())?;
    let index_bytes = vector_slots_bytes::<Option<PairIndexSlot>>(index_slots)?;
    let mut aggregate_retained_size = retained_size_bytes
        .checked_add(pair_slots)
        .and_then(|bytes| bytes.checked_add(incomplete_slots))
        .and_then(|bytes| bytes.checked_add(index_bytes))
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    super::scan::resize_capacity(&mut _capacity, aggregate_retained_size.max(1))?;
    let mut pairs = Vec::new();
    pairs
        .try_reserve_exact(spans.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    let mut incomplete_traces = Vec::new();
    incomplete_traces
        .try_reserve_exact(spans.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    let mut index = Vec::new();
    index
        .try_reserve_exact(index_slots)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    index.resize(index_slots, None);
    let hasher = RandomState::new();
    let mut start = 0_usize;
    while start < spans.len() {
        observe(cancellation, observer)?;
        let trace_id = spans
            .get(start)
            .ok_or_else(TraceStoreFailure::invalid_input)?
            .trace_id();
        let mut end = start;
        while end < spans.len()
            && spans
                .get(end)
                .is_some_and(|span| span.trace_id() == trace_id)
        {
            observe(cancellation, observer)?;
            end = end
                .checked_add(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        }
        let group = spans
            .get(start..end)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let summary = TraceByIdSummary::no_maintenance();
        let structure = super::structural::analyze(
            super::structural::StructuralInput {
                spans: group,
                summary: &summary,
                scan: scan_incompleteness,
                filtered: false,
                retained_size_bytes: aggregate_retained_size,
            },
            cancellation,
            observer,
            &mut _capacity,
        )?;
        let facts = structure.incompleteness();
        if !structure.service_relationships().complete() {
            incomplete_traces.push(TraceServiceRelationshipTraceIncompleteness {
                trace_id,
                missing_parents: facts.missing_parents(),
                conflicts: facts.conflicts(),
                cycle_members: facts.cycle_members(),
                invalid_durations: facts.invalid_durations(),
                temporal_inconsistencies: facts.temporal_inconsistencies(),
                ambiguous_roots: facts.ambiguous_roots(),
            });
        }
        for edge in structure.service_relationships().edges() {
            observe(cancellation, observer)?;
            let hash = edge_hash(&hasher, edge);
            let lookup = find_pair(&index, &pairs, edge, hash, cancellation, observer)?;
            if let Some(index) = lookup.pair_index {
                let pair = pairs
                    .get_mut(index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                pair.edge_count = pair
                    .edge_count
                    .checked_add(1)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
                if pair.trace_ids.last().copied() != Some(trace_id) {
                    if pair.trace_ids.len() == pair.trace_ids.capacity() {
                        reserve_aggregate_growth(
                            &mut _capacity,
                            u64::try_from(size_of::<[u8; 16]>())
                                .map_err(|_| TraceStoreFailure::limit_exceeded())?,
                        )?;
                        aggregate_retained_size = aggregate_retained_size
                            .checked_add(
                                u64::try_from(size_of::<[u8; 16]>())
                                    .map_err(|_| TraceStoreFailure::limit_exceeded())?,
                            )
                            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
                        pair.trace_ids
                            .try_reserve_exact(1)
                            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
                    }
                    pair.trace_ids.push(trace_id);
                }
                pair.record_sampling(edge)?;
            } else {
                let additional = TraceServiceRelationshipPair::owned_heap_bytes(edge)?
                    .checked_add(
                        u64::try_from(size_of::<[u8; 16]>())
                            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
                    )
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
                reserve_aggregate_growth(&mut _capacity, additional)?;
                aggregate_retained_size = aggregate_retained_size
                    .checked_add(additional)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
                let pair_index = pairs.len();
                pairs.push(TraceServiceRelationshipPair::from_edge(edge, trace_id)?);
                let slot = index
                    .get_mut(lookup.slot_index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                *slot = Some(PairIndexSlot { hash, pair_index });
            }
        }
        start = end;
    }
    drop(index);
    aggregate_retained_size = aggregate_retained_size
        .checked_sub(index_bytes)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    super::scan::resize_capacity(&mut _capacity, aggregate_retained_size.max(1))?;
    sort_pairs_observed(&mut pairs, cancellation, observer)?;
    let selection = TraceServiceRelationshipSelection {
        after_position: scan.after_position(),
        after_record: scan.after_record(),
        frontier: scan.frontier().unwrap_or(snapshot.frontier()),
    };
    let snapshot_complete = complete && selection.covers_snapshot(snapshot.frontier());
    let snapshot_limitation = if !complete {
        Some(if scanned_bytes_limited {
            TraceServiceRelationshipSnapshotLimitation::ScannedBytesLimit
        } else {
            TraceServiceRelationshipSnapshotLimitation::ResultLimit
        })
    } else if !snapshot_complete {
        Some(TraceServiceRelationshipSnapshotLimitation::SelectedRange)
    } else {
        None
    };
    let relationships_complete = snapshot_complete && incomplete_traces.is_empty();
    Ok(TraceServiceRelationshipSnapshot {
        pairs,
        selected_range_complete: complete,
        snapshot_complete,
        relationships_complete,
        selection,
        snapshot_limitation,
        incompleteness: TraceServiceRelationshipIncompleteness {
            scan: scan_incompleteness,
            traces: incomplete_traces,
        },
        scanned_bytes,
        decoded_observations,
        scope: snapshot.scope(),
        catalog_generation: snapshot.catalog_generation(),
        catalog_identity: snapshot.catalog_identity(),
        frontier: snapshot.frontier(),
        _capacity,
    })
}

impl TraceServiceRelationshipPair {
    fn from_edge(
        edge: &TraceServiceRelationship<'_>,
        trace_id: [u8; 16],
    ) -> Result<Self, TraceStoreFailure> {
        Ok(Self {
            parent_service: clone_identity(edge.parent_service())?,
            child_service: clone_identity(edge.child_service())?,
            parent_service_namespace: clone_identity(edge.parent_service_namespace())?,
            child_service_namespace: clone_identity(edge.child_service_namespace())?,
            parent_identity: identity_state(edge.parent_identity()),
            child_identity: identity_state(edge.child_identity()),
            parent_namespace_identity: identity_state(edge.parent_service_namespace_identity()),
            child_namespace_identity: identity_state(edge.child_service_namespace_identity()),
            parent_sampling_counts: sampling_counts(edge.parent_sampling()),
            child_sampling_counts: sampling_counts(edge.child_sampling()),
            edge_count: 1,
            trace_ids: trace_ids(trace_id)?,
        })
    }

    fn owned_heap_bytes(edge: &TraceServiceRelationship<'_>) -> Result<u64, TraceStoreFailure> {
        [
            edge.parent_service(),
            edge.child_service(),
            edge.parent_service_namespace(),
            edge.child_service_namespace(),
        ]
        .into_iter()
        .flatten()
        .try_fold(0_u64, |bytes, identity| {
            bytes
                .checked_add(
                    u64::try_from(identity.len())
                        .map_err(|_| TraceStoreFailure::limit_exceeded())?,
                )
                .ok_or_else(TraceStoreFailure::limit_exceeded)
        })
    }

    fn compare_edge(&self, edge: &TraceServiceRelationship<'_>) -> Ordering {
        self.parent_service
            .as_deref()
            .cmp(&edge.parent_service())
            .then_with(|| self.child_service.as_deref().cmp(&edge.child_service()))
            .then_with(|| {
                self.parent_service_namespace
                    .as_deref()
                    .cmp(&edge.parent_service_namespace())
            })
            .then_with(|| {
                self.child_service_namespace
                    .as_deref()
                    .cmp(&edge.child_service_namespace())
            })
            .then_with(|| {
                self.parent_identity
                    .cmp(&identity_state(edge.parent_identity()))
            })
            .then_with(|| {
                self.child_identity
                    .cmp(&identity_state(edge.child_identity()))
            })
            .then_with(|| {
                self.parent_namespace_identity
                    .cmp(&identity_state(edge.parent_service_namespace_identity()))
            })
            .then_with(|| {
                self.child_namespace_identity
                    .cmp(&identity_state(edge.child_service_namespace_identity()))
            })
    }

    fn compare_pair(&self, other: &Self) -> Ordering {
        self.parent_service
            .cmp(&other.parent_service)
            .then_with(|| self.child_service.cmp(&other.child_service))
            .then_with(|| {
                self.parent_service_namespace
                    .cmp(&other.parent_service_namespace)
            })
            .then_with(|| {
                self.child_service_namespace
                    .cmp(&other.child_service_namespace)
            })
            .then_with(|| self.parent_identity.cmp(&other.parent_identity))
            .then_with(|| self.child_identity.cmp(&other.child_identity))
            .then_with(|| {
                self.parent_namespace_identity
                    .cmp(&other.parent_namespace_identity)
            })
            .then_with(|| {
                self.child_namespace_identity
                    .cmp(&other.child_namespace_identity)
            })
    }

    fn record_sampling(
        &mut self,
        edge: &TraceServiceRelationship<'_>,
    ) -> Result<(), TraceStoreFailure> {
        record_sampling(&mut self.parent_sampling_counts, edge.parent_sampling())?;
        record_sampling(&mut self.child_sampling_counts, edge.child_sampling())
    }
}

fn vector_slots_bytes<T>(capacity: usize) -> Result<u64, TraceStoreFailure> {
    u64::try_from(capacity)
        .map_err(|_| TraceStoreFailure::limit_exceeded())?
        .checked_mul(
            u64::try_from(size_of::<T>()).map_err(|_| TraceStoreFailure::limit_exceeded())?,
        )
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}

struct PairLookup {
    pair_index: Option<usize>,
    slot_index: usize,
}

fn pair_index_slots(pair_count: usize) -> Result<usize, TraceStoreFailure> {
    if pair_count == 0 {
        Ok(1)
    } else {
        pair_count
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    }
}

fn edge_hash(hasher: &RandomState, edge: &TraceServiceRelationship<'_>) -> u64 {
    let mut state = hasher.build_hasher();
    edge.parent_service().hash(&mut state);
    edge.child_service().hash(&mut state);
    edge.parent_service_namespace().hash(&mut state);
    edge.child_service_namespace().hash(&mut state);
    identity_state(edge.parent_identity()).hash(&mut state);
    identity_state(edge.child_identity()).hash(&mut state);
    identity_state(edge.parent_service_namespace_identity()).hash(&mut state);
    identity_state(edge.child_service_namespace_identity()).hash(&mut state);
    state.finish()
}

fn find_pair(
    index: &[Option<PairIndexSlot>],
    pairs: &[TraceServiceRelationshipPair],
    edge: &TraceServiceRelationship<'_>,
    hash: u64,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<PairLookup, TraceStoreFailure> {
    let mask = index
        .len()
        .checked_sub(1)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    let mut slot_index =
        usize::try_from(hash).map_err(|_| TraceStoreFailure::limit_exceeded())? & mask;
    for _ in 0..index.len() {
        observe(cancellation, observer)?;
        let slot = index
            .get(slot_index)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let Some(slot) = slot else {
            return Ok(PairLookup {
                pair_index: None,
                slot_index,
            });
        };
        if slot.hash == hash
            && pairs
                .get(slot.pair_index)
                .ok_or_else(TraceStoreFailure::invalid_input)?
                .compare_edge(edge)
                .is_eq()
        {
            return Ok(PairLookup {
                pair_index: Some(slot.pair_index),
                slot_index,
            });
        }
        slot_index = slot_index
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?
            & mask;
    }
    Err(TraceStoreFailure::limit_exceeded())
}

fn sort_pairs_observed(
    pairs: &mut [TraceServiceRelationshipPair],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    let length = pairs.len();
    let mut root = length / 2;
    while root > 0 {
        root = root
            .checked_sub(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        sift_pair_down(pairs, root, length, cancellation, observer)?;
    }
    let mut end = length;
    while end > 1 {
        observe(cancellation, observer)?;
        end = end
            .checked_sub(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        pairs.swap(0, end);
        sift_pair_down(pairs, 0, end, cancellation, observer)?;
    }
    Ok(())
}

fn sift_pair_down(
    pairs: &mut [TraceServiceRelationshipPair],
    mut root: usize,
    end: usize,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    loop {
        observe(cancellation, observer)?;
        let left = root
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        if left >= end {
            return Ok(());
        }
        let right = left
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let child = if right < end && compare_pairs(pairs, left, right)?.is_lt() {
            right
        } else {
            left
        };
        if !compare_pairs(pairs, root, child)?.is_lt() {
            return Ok(());
        }
        pairs.swap(root, child);
        root = child;
    }
}

fn compare_pairs(
    pairs: &[TraceServiceRelationshipPair],
    left: usize,
    right: usize,
) -> Result<Ordering, TraceStoreFailure> {
    let left = pairs
        .get(left)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    let right = pairs
        .get(right)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    Ok(left.compare_pair(right))
}

fn reserve_aggregate_growth(
    capacity: &mut ResourceReservation<'_>,
    additional: u64,
) -> Result<(), TraceStoreFailure> {
    let next = capacity
        .granted()
        .get(positron_kernel::ResourceDimension::MemoryBytes)
        .checked_add(additional)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    super::scan::resize_capacity(capacity, next.max(1))
}

fn clone_identity(identity: Option<&str>) -> Result<Option<String>, TraceStoreFailure> {
    identity
        .map(|identity| {
            let mut owned = String::new();
            owned
                .try_reserve_exact(identity.len())
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            owned.push_str(identity);
            Ok(owned)
        })
        .transpose()
}

fn trace_ids(trace_id: [u8; 16]) -> Result<Vec<[u8; 16]>, TraceStoreFailure> {
    let mut trace_ids = Vec::new();
    trace_ids
        .try_reserve_exact(1)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    trace_ids.push(trace_id);
    Ok(trace_ids)
}

fn identity_state(identity: TraceServiceIdentity<'_>) -> TraceServiceIdentityState {
    match identity {
        TraceServiceIdentity::Missing => TraceServiceIdentityState::Missing,
        TraceServiceIdentity::Exact(_) => TraceServiceIdentityState::Exact,
        TraceServiceIdentity::Ambiguous => TraceServiceIdentityState::Ambiguous,
        TraceServiceIdentity::Removed => TraceServiceIdentityState::Removed,
        TraceServiceIdentity::Redacted => TraceServiceIdentityState::Redacted,
        TraceServiceIdentity::Truncated => TraceServiceIdentityState::Truncated,
        TraceServiceIdentity::Invalid => TraceServiceIdentityState::Invalid,
    }
}

const fn sampling_key(sampling: SamplingDecision) -> u8 {
    match sampling {
        SamplingDecision::Unknown => 0,
        SamplingDecision::NotSampled => 1,
        SamplingDecision::Sampled => 2,
    }
}

const fn sampling_counts(sampling: SamplingDecision) -> [u64; 3] {
    let mut counts = [0; 3];
    counts[sampling_key(sampling) as usize] = 1;
    counts
}

fn record_sampling(
    counts: &mut [u64; 3],
    sampling: SamplingDecision,
) -> Result<(), TraceStoreFailure> {
    let slot = counts
        .get_mut(sampling_key(sampling) as usize)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    *slot = slot
        .checked_add(1)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    Ok(())
}

impl<'span> TraceServiceRelationships<'span> {
    #[must_use]
    pub fn edges(&self) -> &[TraceServiceRelationship<'span>] {
        &self.edges
    }
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }
}

pub(super) fn collect<'span>(
    spans: &'span [LogicalSpan],
    parent_indexes: &[Option<usize>],
    structurally_complete: bool,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<TraceServiceRelationships<'span>, TraceStoreFailure> {
    if parent_indexes.len() != spans.len() {
        return Err(TraceStoreFailure::invalid_input());
    }
    let mut edges = Vec::new();
    edges
        .try_reserve_exact(spans.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    let mut complete = structurally_complete;
    for (child_index, child) in spans.iter().enumerate() {
        observe(cancellation, observer)?;
        let Some(parent_index) = parent_indexes
            .get(child_index)
            .copied()
            .ok_or_else(TraceStoreFailure::invalid_input)?
        else {
            continue;
        };
        let parent = spans
            .get(parent_index)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let parent_observation = representative(parent)?;
        let child_observation = representative(child)?;
        let parent_identity =
            resource_identity(parent_observation, "service.name", cancellation, observer)?;
        let child_identity =
            resource_identity(child_observation, "service.name", cancellation, observer)?;
        let parent_namespace_identity = resource_identity(
            parent_observation,
            "service.namespace",
            cancellation,
            observer,
        )?;
        let child_namespace_identity = resource_identity(
            child_observation,
            "service.namespace",
            cancellation,
            observer,
        )?;
        if parent_identity.exact().is_none()
            || child_identity.exact().is_none()
            || parent_namespace_identity.is_present_and_not_exact()
            || child_namespace_identity.is_present_and_not_exact()
            || parent_observation.sampling() != SamplingDecision::Sampled
            || child_observation.sampling() != SamplingDecision::Sampled
        {
            complete = false;
        }
        edges.push(TraceServiceRelationship {
            parent_span_id: parent.span_id(),
            child_span_id: child.span_id(),
            parent_service: parent_identity.exact(),
            child_service: child_identity.exact(),
            parent_service_namespace: parent_namespace_identity.exact(),
            child_service_namespace: child_namespace_identity.exact(),
            parent_sampling: parent_observation.sampling(),
            child_sampling: child_observation.sampling(),
            parent_identity,
            child_identity,
            parent_namespace_identity,
            child_namespace_identity,
        });
    }
    Ok(TraceServiceRelationships { edges, complete })
}

fn resource_identity<'span>(
    observation: &'span super::SpanObservation,
    key: &str,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<TraceServiceIdentity<'span>, TraceStoreFailure> {
    let mut result = TraceServiceIdentity::Missing;
    for attribute in observation.attributes() {
        observe(cancellation, observer)?;
        if attribute.namespace() != AttributeNamespace::Resource || attribute.key() != key {
            continue;
        }
        if !matches!(result, TraceServiceIdentity::Missing) || attribute.len() != 1 {
            return Ok(TraceServiceIdentity::Ambiguous);
        }
        let Some(value) = attribute.occurrence(0) else {
            return Ok(TraceServiceIdentity::Invalid);
        };
        if let Some(action) = value.marker_action() {
            return Ok(match action {
                MarkerAction::Removed => TraceServiceIdentity::Removed,
                MarkerAction::Redacted => TraceServiceIdentity::Redacted,
                MarkerAction::TruncatedBytes | MarkerAction::TruncatedElements => {
                    TraceServiceIdentity::Truncated
                },
            });
        }
        if value.truncation_action().is_some() {
            return Ok(TraceServiceIdentity::Truncated);
        }
        let Some(value) = value.as_str() else {
            return Ok(TraceServiceIdentity::Invalid);
        };
        result = TraceServiceIdentity::Exact(value);
    }
    Ok(result)
}

fn representative(span: &LogicalSpan) -> Result<&super::SpanObservation, TraceStoreFailure> {
    span.structural_representative()
        .map(|representative| representative.observation())
        .ok_or_else(TraceStoreFailure::invalid_input)
}

fn observe(
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    super::scan::check_cancel(cancellation)?;
    observer
        .observe_work(1)
        .map_err(TraceStoreFailure::observation)?;
    super::scan::check_cancel(cancellation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceStoreFailureCode;

    struct AlreadyCancelled;

    impl ScanCancellation for AlreadyCancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    struct Unobserved;

    impl ScanObserver for Unobserved {
        fn observe_work(&self, _units: u64) -> Result<(), crate::ScanObservationFailureCode> {
            Ok(())
        }
    }

    fn pair(parent_service: &str) -> TraceServiceRelationshipPair {
        TraceServiceRelationshipPair {
            parent_service: Some(parent_service.to_owned()),
            child_service: None,
            parent_service_namespace: None,
            child_service_namespace: None,
            parent_identity: TraceServiceIdentityState::Exact,
            child_identity: TraceServiceIdentityState::Missing,
            parent_namespace_identity: TraceServiceIdentityState::Missing,
            child_namespace_identity: TraceServiceIdentityState::Missing,
            parent_sampling_counts: [0; 3],
            child_sampling_counts: [0; 3],
            edge_count: 0,
            trace_ids: Vec::new(),
        }
    }

    #[test]
    fn cancelled_pair_ordering_returns_before_rearranging_pairs() {
        let mut pairs = vec![pair("zulu"), pair("alpha"), pair("middle")];
        let failure = sort_pairs_observed(&mut pairs, &AlreadyCancelled, &Unobserved)
            .expect_err("cancellation must stop ordering before pair mutation");
        assert_eq!(failure.code(), TraceStoreFailureCode::Cancelled);
        assert_eq!(
            pairs
                .iter()
                .map(|pair| pair.parent_service())
                .collect::<Vec<_>>(),
            vec![Some("zulu"), Some("alpha"), Some("middle")]
        );
    }
}
