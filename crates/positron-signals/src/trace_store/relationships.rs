use std::collections::BTreeMap;
use std::mem::size_of;

use positron_domain::value::AttributeNamespace;
use positron_kernel::ResourceReservation;

use crate::{ScanCancellation, ScanObserver};

use super::{
    LogicalSpan, LogicalTraceScanResult, SamplingDecision, TraceByIdSummary, TraceIncompleteness,
    TraceStoreFailure,
};

/// The authenticated identity state of one service endpoint field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceServiceIdentity<'span> {
    Missing,
    Exact(&'span str),
    Ambiguous,
    Transformed,
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
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TraceServiceIdentityState {
    Missing,
    Exact,
    Ambiguous,
    Transformed,
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
    snapshot_complete: bool,
    relationships_complete: bool,
    incompleteness: TraceServiceRelationshipIncompleteness,
    scanned_bytes: u64,
    decoded_observations: u64,
    _capacity: ResourceReservation<'kernel>,
}

impl TraceServiceRelationshipSnapshot<'_> {
    /// Whether the bounded scan reached this snapshot's selected frontier.
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
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct PairKey {
    parent_service: Option<String>,
    child_service: Option<String>,
    parent_service_namespace: Option<String>,
    child_service_namespace: Option<String>,
    parent_identity: TraceServiceIdentityState,
    child_identity: TraceServiceIdentityState,
    parent_namespace_identity: TraceServiceIdentityState,
    child_namespace_identity: TraceServiceIdentityState,
}

pub(super) fn aggregate<'kernel>(
    logical: LogicalTraceScanResult<'kernel>,
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
    let scan = if complete {
        TraceIncompleteness::None
    } else if scanned_bytes_limited {
        TraceIncompleteness::ScannedBytesLimit
    } else {
        TraceIncompleteness::ResultLimit
    };
    let structural_overhead = u64::try_from(spans.len())
        .map_err(|_| TraceStoreFailure::limit_exceeded())?
        .checked_mul(
            u64::try_from(size_of::<TraceServiceRelationshipPair>())
                .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        )
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    super::scan::resize_capacity(
        &mut _capacity,
        retained_size_bytes
            .checked_add(structural_overhead)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?
            .max(1),
    )?;
    let mut pairs = BTreeMap::<PairKey, TraceServiceRelationshipPair>::new();
    let mut incomplete_traces = Vec::new();
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
                scan,
                filtered: false,
                retained_size_bytes,
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
            let key = PairKey::from_edge(edge);
            if let Some(pair) = pairs.get_mut(&key) {
                pair.edge_count = pair
                    .edge_count
                    .checked_add(1)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
                if pair.trace_ids.last().copied() != Some(trace_id) {
                    pair.trace_ids.push(trace_id);
                }
                pair.record_sampling(edge)?;
            } else {
                pairs.insert(
                    key,
                    TraceServiceRelationshipPair::from_edge(edge, trace_id)?,
                );
            }
        }
        start = end;
    }
    let pairs = pairs.into_values().collect::<Vec<_>>();
    let relationships_complete = complete && incomplete_traces.is_empty();
    Ok(TraceServiceRelationshipSnapshot {
        pairs,
        snapshot_complete: complete,
        relationships_complete,
        incompleteness: TraceServiceRelationshipIncompleteness {
            scan,
            traces: incomplete_traces,
        },
        scanned_bytes,
        decoded_observations,
        _capacity,
    })
}

impl PairKey {
    fn from_edge(edge: &TraceServiceRelationship<'_>) -> Self {
        Self {
            parent_service: edge.parent_service().map(str::to_owned),
            child_service: edge.child_service().map(str::to_owned),
            parent_service_namespace: edge.parent_service_namespace().map(str::to_owned),
            child_service_namespace: edge.child_service_namespace().map(str::to_owned),
            parent_identity: identity_state(edge.parent_identity()),
            child_identity: identity_state(edge.child_identity()),
            parent_namespace_identity: identity_state(edge.parent_service_namespace_identity()),
            child_namespace_identity: identity_state(edge.child_service_namespace_identity()),
        }
    }
}

impl TraceServiceRelationshipPair {
    fn from_edge(
        edge: &TraceServiceRelationship<'_>,
        trace_id: [u8; 16],
    ) -> Result<Self, TraceStoreFailure> {
        Ok(Self {
            parent_service: edge.parent_service().map(str::to_owned),
            child_service: edge.child_service().map(str::to_owned),
            parent_service_namespace: edge.parent_service_namespace().map(str::to_owned),
            child_service_namespace: edge.child_service_namespace().map(str::to_owned),
            parent_identity: identity_state(edge.parent_identity()),
            child_identity: identity_state(edge.child_identity()),
            parent_namespace_identity: identity_state(edge.parent_service_namespace_identity()),
            child_namespace_identity: identity_state(edge.child_service_namespace_identity()),
            parent_sampling_counts: sampling_counts(edge.parent_sampling()),
            child_sampling_counts: sampling_counts(edge.child_sampling()),
            edge_count: 1,
            trace_ids: vec![trace_id],
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

fn identity_state(identity: TraceServiceIdentity<'_>) -> TraceServiceIdentityState {
    match identity {
        TraceServiceIdentity::Missing => TraceServiceIdentityState::Missing,
        TraceServiceIdentity::Exact(_) => TraceServiceIdentityState::Exact,
        TraceServiceIdentity::Ambiguous => TraceServiceIdentityState::Ambiguous,
        TraceServiceIdentity::Transformed => TraceServiceIdentityState::Transformed,
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
        if value.is_marker() || value.truncation_action().is_some() {
            return Ok(TraceServiceIdentity::Transformed);
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
