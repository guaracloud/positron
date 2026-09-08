use std::mem::size_of;

use positron_domain::time::{SourceTimeQuality, UnixNanoseconds};
use positron_kernel::ResourceReservation;

use crate::{ScanCancellation, ScanObserver};

use super::{
    LogicalSpan, SamplingDecision, TraceByIdSummary, TraceIncompleteness, TraceStoreFailure,
};

/// The direct parent relationship established from a logical span's earliest
/// committed observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceParentRelation {
    /// The span supplied no parent identity.
    Root,
    /// The referenced parent is visible in this authenticated snapshot.
    Child,
    /// The referenced parent is absent from this authenticated snapshot.
    Orphan,
}

/// One logical span's structural facts without discarding its conflicting variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceStructureSpan {
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    relation: TraceParentRelation,
    sampling: SamplingDecision,
    conflicted: bool,
    cycle_member: bool,
}

impl TraceStructureSpan {
    #[must_use]
    pub const fn span_id(self) -> [u8; 8] {
        self.span_id
    }
    #[must_use]
    pub const fn parent_span_id(self) -> Option<[u8; 8]> {
        self.parent_span_id
    }
    #[must_use]
    pub const fn relation(self) -> TraceParentRelation {
        self.relation
    }
    #[must_use]
    pub const fn sampling(self) -> SamplingDecision {
        self.sampling
    }
    #[must_use]
    pub const fn conflicted(self) -> bool {
        self.conflicted
    }
    #[must_use]
    pub const fn cycle_member(self) -> bool {
        self.cycle_member
    }
}

/// Every reason a snapshot graph cannot support a complete structural answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceStructureIncompleteness {
    scan: TraceIncompleteness,
    filtered: bool,
    missing_parents: u64,
    conflicts: u64,
    cycle_members: u64,
    invalid_durations: u64,
    temporal_inconsistencies: u64,
    ambiguous_roots: bool,
}

impl TraceStructureIncompleteness {
    #[must_use]
    pub const fn scan(self) -> TraceIncompleteness {
        self.scan
    }
    /// Whether the trace-by-ID request omitted spans using an attribute
    /// predicate, so this visible graph cannot prove trace-wide structure.
    #[must_use]
    pub const fn filtered(self) -> bool {
        self.filtered
    }
    #[must_use]
    pub const fn missing_parents(self) -> u64 {
        self.missing_parents
    }
    #[must_use]
    pub const fn conflicts(self) -> u64 {
        self.conflicts
    }
    #[must_use]
    pub const fn cycle_members(self) -> u64 {
        self.cycle_members
    }
    #[must_use]
    pub const fn invalid_durations(self) -> u64 {
        self.invalid_durations
    }
    #[must_use]
    pub const fn temporal_inconsistencies(self) -> u64 {
        self.temporal_inconsistencies
    }
    #[must_use]
    pub const fn ambiguous_roots(self) -> bool {
        self.ambiguous_roots
    }

    const fn complete(self) -> bool {
        matches!(self.scan, TraceIncompleteness::None)
            && self.missing_parents == 0
            && self.conflicts == 0
            && self.cycle_members == 0
            && self.invalid_durations == 0
            && self.temporal_inconsistencies == 0
            && !self.filtered
            && !self.ambiguous_roots
    }
}

/// One exact, non-overlapping critical-path interval attributed to a span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceCriticalPathFragment {
    span_id: [u8; 8],
    start: UnixNanoseconds,
    end: UnixNanoseconds,
}

impl TraceCriticalPathFragment {
    #[must_use]
    pub const fn span_id(self) -> [u8; 8] {
        self.span_id
    }
    #[must_use]
    pub const fn start(self) -> UnixNanoseconds {
        self.start
    }
    #[must_use]
    pub const fn end(self) -> UnixNanoseconds {
        self.end
    }
    #[must_use]
    pub fn duration_nanos(self) -> Option<u64> {
        u64::try_from(i128::from(self.end.value()) - i128::from(self.start.value())).ok()
    }
}

/// The deterministic temporal critical path, fragmented at child spawn and
/// return boundaries. Fragment durations are disjoint and sum to observed
/// wall-clock latency without double-counting nested spans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceCriticalPath {
    fragments: Vec<TraceCriticalPathFragment>,
    duration_nanos: u64,
}

impl TraceCriticalPath {
    #[must_use]
    pub fn fragments(&self) -> &[TraceCriticalPathFragment] {
        &self.fragments
    }
    #[must_use]
    pub const fn duration_nanos(&self) -> u64 {
        self.duration_nanos
    }
}

/// Bounded structural facts derived from a snapshot-stable trace-by-ID result.
///
/// The result borrows the trace result's exact-snapshot summary while that
/// query's reservation accounts for both the logical span view and this
/// derived graph. `complete` concerns only the visible snapshot graph; traces
/// remain incremental and may reopen.
#[derive(Debug)]
pub struct TraceStructure<'summary> {
    summary: &'summary TraceByIdSummary,
    spans: Vec<TraceStructureSpan>,
    roots: Vec<[u8; 8]>,
    orphans: Vec<[u8; 8]>,
    cycles: Vec<[u8; 8]>,
    incompleteness: TraceStructureIncompleteness,
    critical_path: Option<TraceCriticalPath>,
}

impl TraceStructure<'_> {
    /// Whether the authenticated snapshot graph is complete enough for
    /// structural and critical-path conclusions. This never means the trace is
    /// complete.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.incompleteness.complete()
    }
    #[must_use]
    pub fn spans(&self) -> &[TraceStructureSpan] {
        &self.spans
    }
    #[must_use]
    pub fn roots(&self) -> &[[u8; 8]] {
        &self.roots
    }
    #[must_use]
    pub fn orphans(&self) -> &[[u8; 8]] {
        &self.orphans
    }
    #[must_use]
    pub fn cycles(&self) -> &[[u8; 8]] {
        &self.cycles
    }
    #[must_use]
    pub const fn incompleteness(&self) -> TraceStructureIncompleteness {
        self.incompleteness
    }

    /// Returns a path only when every dependency and duration needed to prove
    /// it is present and unambiguous. It follows the latest-returning direct
    /// child, then earlier non-overlapping children, and attributes the gaps
    /// to their parent. This is the CRISP fragment model without clock-skew
    /// correction: inconsistent intervals make the result unavailable.
    #[must_use]
    pub fn critical_path(&self) -> Option<&TraceCriticalPath> {
        self.critical_path.as_ref()
    }

    /// Exposes summary facts and exact-snapshot provenance without treating a
    /// quiescent trace as complete.
    #[must_use]
    pub const fn summary(&self) -> &TraceByIdSummary {
        self.summary
    }
}

pub(super) struct StructuralInput<'spans, 'summary> {
    pub(super) spans: &'spans [LogicalSpan],
    pub(super) summary: &'summary TraceByIdSummary,
    pub(super) scan: TraceIncompleteness,
    pub(super) filtered: bool,
    pub(super) retained_size_bytes: u64,
}

#[derive(Clone, Copy)]
struct SpanIndexEntry {
    span_id: [u8; 8],
    parent_index: Option<usize>,
}

struct SpanIndex {
    entries: Vec<SpanIndexEntry>,
}

impl SpanIndex {
    fn build(
        spans: &[LogicalSpan],
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<Self, TraceStoreFailure> {
        let mut entries = reserve(Vec::new(), spans.len())?;
        let mut previous = None;
        for span in spans {
            observe(cancellation, observer)?;
            if previous.is_some_and(|id| id >= span.span_id()) {
                return Err(TraceStoreFailure::invalid_input());
            }
            previous = Some(span.span_id());
            entries.push(SpanIndexEntry {
                span_id: span.span_id(),
                parent_index: None,
            });
        }
        let mut index = Self { entries };
        for (span_index, span) in spans.iter().enumerate() {
            observe(cancellation, observer)?;
            let parent_span_id = representative(span)?.observation().parent_span_id();
            let parent_index = parent_span_id
                .map(|parent| index.find(parent, cancellation, observer))
                .transpose()?
                .flatten();
            let entry = index
                .entries
                .get_mut(span_index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            entry.parent_index = parent_index;
        }
        Ok(index)
    }

    fn find(
        &self,
        span_id: [u8; 8],
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<Option<usize>, TraceStoreFailure> {
        let mut low = 0_usize;
        let mut high = self.entries.len();
        while low < high {
            observe(cancellation, observer)?;
            let middle = low
                .checked_add(high.saturating_sub(low) / 2)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            let entry = self
                .entries
                .get(middle)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            match entry.span_id.cmp(&span_id) {
                std::cmp::Ordering::Less => {
                    low = middle
                        .checked_add(1)
                        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
                },
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Ok(Some(middle)),
            }
        }
        Ok(None)
    }

    fn parent_index(&self, index: usize) -> Result<Option<usize>, TraceStoreFailure> {
        self.entries
            .get(index)
            .map(|entry| entry.parent_index)
            .ok_or_else(TraceStoreFailure::invalid_input)
    }
}

#[derive(Clone, Copy)]
struct ChildRange {
    start: usize,
    end: usize,
    next: usize,
}

struct ChildAdjacency {
    children: Vec<usize>,
    ranges: Vec<ChildRange>,
}

impl ChildAdjacency {
    fn build(
        spans: &[LogicalSpan],
        index: &SpanIndex,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<Self, TraceStoreFailure> {
        let mut ranges = reserve(Vec::new(), spans.len())?;
        for _ in spans {
            observe(cancellation, observer)?;
            ranges.push(ChildRange {
                start: 0,
                end: 0,
                next: 0,
            });
        }
        for span_index in 0..spans.len() {
            observe(cancellation, observer)?;
            if let Some(parent_index) = index.parent_index(span_index)? {
                let range = ranges
                    .get_mut(parent_index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                range.end = range
                    .end
                    .checked_add(1)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            }
        }
        let mut child_count = 0_usize;
        for range in &mut ranges {
            observe(cancellation, observer)?;
            let count = range.end;
            range.start = child_count;
            child_count = child_count
                .checked_add(count)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            range.end = child_count;
            range.next = range.start;
        }
        let mut children = reserve(Vec::new(), child_count)?;
        for _ in 0..child_count {
            observe(cancellation, observer)?;
            children.push(usize::MAX);
        }
        for span_index in 0..spans.len() {
            observe(cancellation, observer)?;
            if let Some(parent_index) = index.parent_index(span_index)? {
                let range = ranges
                    .get_mut(parent_index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                let position = range.next;
                let slot = children
                    .get_mut(position)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                *slot = span_index;
                range.next = range
                    .next
                    .checked_add(1)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            }
        }
        for range in &mut ranges {
            observe(cancellation, observer)?;
            if range.next != range.end {
                return Err(TraceStoreFailure::invalid_input());
            }
            let ordered = children
                .get_mut(range.start..range.end)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            order_children(ordered, spans, cancellation, observer)?;
            range.next = range.start;
        }
        Ok(Self { children, ranges })
    }

    fn next_child(
        &self,
        parent_index: usize,
        next: &mut usize,
        cursor: UnixNanoseconds,
        spans: &[LogicalSpan],
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<Option<usize>, TraceStoreFailure> {
        let range = self
            .ranges
            .get(parent_index)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        while *next < range.end {
            observe(cancellation, observer)?;
            let position = *next;
            *next = next
                .checked_add(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            let child_index = *self
                .children
                .get(position)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            let child = spans
                .get(child_index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            let (start, end) = span_interval(representative(child)?)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            if start < cursor && end <= cursor {
                return Ok(Some(child_index));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CycleState {
    Unseen,
    Visiting,
    Acyclic,
    Cycle,
}

pub(super) fn analyze<'summary>(
    input: StructuralInput<'_, 'summary>,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
    capacity: &mut ResourceReservation<'_>,
) -> Result<TraceStructure<'summary>, TraceStoreFailure> {
    let StructuralInput {
        spans,
        summary,
        scan,
        filtered,
        retained_size_bytes,
    } = input;
    let count = u64::try_from(spans.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    let span_bytes = u64::try_from(size_of::<TraceStructureSpan>())
        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
    let per_span_bytes = span_bytes
        .checked_add(
            u64::try_from(3 * size_of::<[u8; 8]>())
                .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        )
        .and_then(|bytes| {
            bytes.checked_add(u64::try_from(2 * size_of::<TraceCriticalPathFragment>()).ok()?)
        })
        .and_then(|bytes| bytes.checked_add(u64::try_from(size_of::<CriticalPathFrame>()).ok()?))
        .and_then(|bytes| bytes.checked_add(u64::try_from(size_of::<SpanIndexEntry>()).ok()?))
        .and_then(|bytes| bytes.checked_add(u64::try_from(size_of::<CycleState>()).ok()?))
        .and_then(|bytes| bytes.checked_add(u64::try_from(size_of::<ChildRange>()).ok()?))
        .and_then(|bytes| bytes.checked_add(u64::try_from(size_of::<usize>()).ok()?))
        .and_then(|bytes| bytes.checked_add(u64::try_from(size_of::<usize>()).ok()?))
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    let structural_bytes = count
        .checked_mul(per_span_bytes)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    super::scan::resize_capacity(
        capacity,
        retained_size_bytes
            .checked_add(structural_bytes)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?
            .max(1),
    )?;

    let mut result_spans = reserve(Vec::new(), spans.len())?;
    let mut roots = reserve(Vec::new(), spans.len())?;
    let mut orphans = reserve(Vec::new(), spans.len())?;
    let mut cycles = reserve(Vec::new(), spans.len())?;
    let index = SpanIndex::build(spans, cancellation, observer)?;
    let cycle_states = classify_cycles(&index, cancellation, observer)?;
    let mut incompleteness = TraceStructureIncompleteness {
        scan,
        filtered,
        missing_parents: 0,
        conflicts: 0,
        cycle_members: 0,
        invalid_durations: 0,
        temporal_inconsistencies: 0,
        ambiguous_roots: false,
    };

    for (span_index, span) in spans.iter().enumerate() {
        observe(cancellation, observer)?;
        let observation = representative(span)?;
        let parent_span_id = observation.observation().parent_span_id();
        let (relation, parent_index) = match parent_span_id {
            None => {
                roots.push(span.span_id());
                (TraceParentRelation::Root, None)
            },
            Some(_) => match index.parent_index(span_index)? {
                Some(parent_index) => (TraceParentRelation::Child, Some(parent_index)),
                None => {
                    incompleteness.missing_parents = increment(incompleteness.missing_parents)?;
                    orphans.push(span.span_id());
                    (TraceParentRelation::Orphan, None)
                },
            },
        };
        let cycle_member = relation == TraceParentRelation::Child
            && cycle_states
                .get(span_index)
                .is_some_and(|state| *state == CycleState::Cycle);
        if cycle_member {
            incompleteness.cycle_members = increment(incompleteness.cycle_members)?;
            cycles.push(span.span_id());
        }
        if span.conflicted() {
            incompleteness.conflicts = increment(incompleteness.conflicts)?;
        }
        if span_duration(observation).is_none() {
            incompleteness.invalid_durations = increment(incompleteness.invalid_durations)?;
        }
        if let Some(parent_index) = parent_index
            && let (Some(parent), Some(child)) = (
                span_interval(representative(
                    spans
                        .get(parent_index)
                        .ok_or_else(TraceStoreFailure::invalid_input)?,
                )?),
                span_interval(observation),
            )
            && (child.0 < parent.0 || child.1 > parent.1)
        {
            incompleteness.temporal_inconsistencies =
                increment(incompleteness.temporal_inconsistencies)?;
        }
        result_spans.push(TraceStructureSpan {
            span_id: span.span_id(),
            parent_span_id,
            relation,
            sampling: observation.observation().sampling(),
            conflicted: span.conflicted(),
            cycle_member,
        });
    }

    incompleteness.ambiguous_roots = roots.len() > 1;

    let critical_path = if incompleteness.complete() {
        critical_path(spans, &index, &roots, cancellation, observer)?
    } else {
        None
    };
    Ok(TraceStructure {
        summary,
        spans: result_spans,
        roots,
        orphans,
        cycles,
        incompleteness,
        critical_path,
    })
}

fn critical_path(
    spans: &[LogicalSpan],
    index: &SpanIndex,
    roots: &[[u8; 8]],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<Option<TraceCriticalPath>, TraceStoreFailure> {
    let Some(root_id) = roots.first().copied() else {
        return Ok(None);
    };
    let root = index
        .find(root_id, cancellation, observer)?
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    let children = ChildAdjacency::build(spans, index, cancellation, observer)?;
    let mut fragments = reserve(
        Vec::new(),
        spans
            .len()
            .checked_mul(2)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?,
    )?;
    let mut stack = reserve(Vec::new(), spans.len())?;
    stack.push(CriticalPathFrame::new(root, spans, &children)?);
    while !stack.is_empty() {
        let next_child = {
            let frame = stack
                .last_mut()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            observe(cancellation, observer)?;
            let parent = spans
                .get(frame.span_index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            let parent_span_id = parent.span_id();
            let child = children.next_child(
                frame.span_index,
                &mut frame.next_child,
                frame.cursor,
                spans,
                cancellation,
                observer,
            )?;
            if let Some(child_index) = child {
                let child_span = spans
                    .get(child_index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                let (child_start, child_end) = span_interval(representative(child_span)?)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                append_fragment(&mut fragments, parent_span_id, child_end, frame.cursor)?;
                frame.cursor = child_start;
            } else {
                append_fragment(&mut fragments, parent_span_id, frame.start, frame.cursor)?;
            }
            child
        };
        if let Some(child_index) = next_child {
            stack.push(CriticalPathFrame::new(child_index, spans, &children)?);
        } else {
            let _completed = stack.pop().ok_or_else(TraceStoreFailure::invalid_input)?;
        }
    }
    fragments.reverse();
    let mut duration_nanos = 0_u64;
    for fragment in &fragments {
        observe(cancellation, observer)?;
        let duration = fragment
            .duration_nanos()
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        duration_nanos = duration_nanos
            .checked_add(duration)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    }
    Ok(Some(TraceCriticalPath {
        fragments,
        duration_nanos,
    }))
}

#[derive(Clone, Copy)]
struct CriticalPathFrame {
    span_index: usize,
    start: UnixNanoseconds,
    cursor: UnixNanoseconds,
    next_child: usize,
}

impl CriticalPathFrame {
    fn new(
        span_index: usize,
        spans: &[LogicalSpan],
        children: &ChildAdjacency,
    ) -> Result<Self, TraceStoreFailure> {
        let span = spans
            .get(span_index)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let (start, end) =
            span_interval(representative(span)?).ok_or_else(TraceStoreFailure::invalid_input)?;
        Ok(Self {
            span_index,
            start,
            cursor: end,
            next_child: children
                .ranges
                .get(span_index)
                .map(|range| range.start)
                .ok_or_else(TraceStoreFailure::invalid_input)?,
        })
    }
}

fn order_children(
    children: &mut [usize],
    spans: &[LogicalSpan],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    let length = children.len();
    if length < 2 {
        return Ok(());
    }
    let first_parent = length
        .checked_sub(2)
        .ok_or_else(TraceStoreFailure::invalid_input)?
        / 2;
    for root in (0..=first_parent).rev() {
        sift_child_heap(children, root, length, spans, cancellation, observer)?;
    }
    for end in (1..length).rev() {
        observe(cancellation, observer)?;
        children.swap(0, end);
        sift_child_heap(children, 0, end, spans, cancellation, observer)?;
    }
    for index in 0..(length / 2) {
        observe(cancellation, observer)?;
        let other = length
            .checked_sub(1)
            .and_then(|last| last.checked_sub(index))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        children.swap(index, other);
    }
    Ok(())
}

fn sift_child_heap(
    children: &mut [usize],
    mut root: usize,
    end: usize,
    spans: &[LogicalSpan],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    loop {
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
        let mut highest = left;
        if right < end
            && child_precedes(
                *children
                    .get(right)
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
                *children
                    .get(left)
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
                spans,
                cancellation,
                observer,
            )?
        {
            highest = right;
        }
        if !child_precedes(
            *children
                .get(highest)
                .ok_or_else(TraceStoreFailure::invalid_input)?,
            *children
                .get(root)
                .ok_or_else(TraceStoreFailure::invalid_input)?,
            spans,
            cancellation,
            observer,
        )? {
            return Ok(());
        }
        observe(cancellation, observer)?;
        children.swap(root, highest);
        root = highest;
    }
}

fn child_precedes(
    left: usize,
    right: usize,
    spans: &[LogicalSpan],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<bool, TraceStoreFailure> {
    observe(cancellation, observer)?;
    let left_span = spans
        .get(left)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    let right_span = spans
        .get(right)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    let (_, left_end) =
        span_interval(representative(left_span)?).ok_or_else(TraceStoreFailure::invalid_input)?;
    let (_, right_end) =
        span_interval(representative(right_span)?).ok_or_else(TraceStoreFailure::invalid_input)?;
    Ok(left_end > right_end
        || (left_end == right_end && left_span.span_id() < right_span.span_id()))
}

fn append_fragment(
    fragments: &mut Vec<TraceCriticalPathFragment>,
    span_id: [u8; 8],
    start: UnixNanoseconds,
    end: UnixNanoseconds,
) -> Result<(), TraceStoreFailure> {
    if end < start {
        return Err(TraceStoreFailure::invalid_input());
    }
    if end > start {
        fragments.push(TraceCriticalPathFragment {
            span_id,
            start,
            end,
        });
    }
    Ok(())
}

fn classify_cycles(
    index: &SpanIndex,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<Vec<CycleState>, TraceStoreFailure> {
    let mut states = reserve(Vec::new(), index.entries.len())?;
    let mut trail = reserve(Vec::new(), index.entries.len())?;
    for _ in &index.entries {
        states.push(CycleState::Unseen);
    }
    for start in 0..index.entries.len() {
        observe(cancellation, observer)?;
        if states
            .get(start)
            .is_none_or(|state| *state != CycleState::Unseen)
        {
            continue;
        }
        let mut current = Some(start);
        let cycle_start = loop {
            let Some(current_index) = current else {
                break None;
            };
            observe(cancellation, observer)?;
            let state = *states
                .get(current_index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            match state {
                CycleState::Unseen => {
                    let slot = states
                        .get_mut(current_index)
                        .ok_or_else(TraceStoreFailure::invalid_input)?;
                    *slot = CycleState::Visiting;
                    trail.push(current_index);
                    current = index.parent_index(current_index)?;
                },
                CycleState::Visiting => {
                    break trail
                        .iter()
                        .position(|candidate| *candidate == current_index);
                },
                CycleState::Acyclic | CycleState::Cycle => break None,
            }
        };
        for (position, trail_index) in trail.iter().enumerate() {
            observe(cancellation, observer)?;
            let state = states
                .get_mut(*trail_index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            *state = if cycle_start.is_some_and(|start| position >= start) {
                CycleState::Cycle
            } else {
                CycleState::Acyclic
            };
        }
        trail.clear();
    }
    Ok(states)
}

fn representative(span: &LogicalSpan) -> Result<&super::ScannedSpanObservation, TraceStoreFailure> {
    span.structural_representative()
        .ok_or_else(TraceStoreFailure::invalid_input)
}

fn span_duration(observation: &super::ScannedSpanObservation) -> Option<u64> {
    let (start, end) = span_interval(observation)?;
    u64::try_from(i128::from(end.value()) - i128::from(start.value())).ok()
}

fn span_interval(
    observation: &super::ScannedSpanObservation,
) -> Option<(UnixNanoseconds, UnixNanoseconds)> {
    let observation = observation.observation();
    let start = usable_instant(observation.start_time())?;
    let end = usable_instant(observation.end_time())?;
    (end >= start).then_some((start, end))
}

fn usable_instant(time: positron_domain::time::EventTime) -> Option<UnixNanoseconds> {
    matches!(
        time.quality(),
        SourceTimeQuality::Usable | SourceTimeQuality::Outlier
    )
    .then_some(time.instant())
    .flatten()
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

fn reserve<T>(mut values: Vec<T>, capacity: usize) -> Result<Vec<T>, TraceStoreFailure> {
    values
        .try_reserve_exact(capacity)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    Ok(values)
}

fn increment(value: u64) -> Result<u64, TraceStoreFailure> {
    value
        .checked_add(1)
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}
