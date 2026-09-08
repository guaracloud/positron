#![no_main]

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, LifecycleClockFailure, LifecycleClockSource, ResourceAmounts,
    ResourceDimension, SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_policy::{IngestPolicy, NativeTraceCandidate, PolicyReceiver, TracePolicyEvaluation};
use positron_signals::{
    EvaluatedSpanObservationInput, SamplingDecision, ScanCancellation, ScanLimit,
    ScanObservationFailureCode, ScanObserver, SpanKind, SpanObservation, SpanObservationDetails,
    TraceIncompleteness, TraceParentRelation, TraceQuietPeriod, TraceSearch, TraceStore,
    TraceStoreFailureCode, TraceSummaryMaintainer,
};

#[path = "schema_discovery_query/authority.rs"]
mod authority;

const MAX_INPUT_BYTES: usize = 128;
const MAX_OPERATIONS: usize = 32;
const QUIET_PERIOD_NANOS: u64 = 5;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct FuzzRoot(PathBuf);

impl FuzzRoot {
    fn new() -> Option<Self> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "positron-trace-summary-fuzz-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).ok()?;
        Some(Self(root))
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct MutableClock(Arc<AtomicI64>);

impl LifecycleClockSource for MutableClock {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
        Ok(UnixNanoseconds::new(self.0.load(Ordering::Relaxed)))
    }
}

struct InputCancellation(bool);

impl ScanCancellation for InputCancellation {
    fn is_cancelled(&self) -> bool {
        self.0
    }
}

struct Unobserved;

impl ScanObserver for Unobserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

struct WorkBudget(Cell<u64>);

impl WorkBudget {
    const fn exact(units: u64) -> Self {
        Self(Cell::new(units))
    }
}

impl ScanObserver for WorkBudget {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let Some(remaining) = self.0.get().checked_sub(units) else {
            return Err(ScanObservationFailureCode::BudgetExhausted);
        };
        self.0.set(remaining);
        Ok(())
    }
}

struct RefusingObserver;

impl ScanObserver for RefusingObserver {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Err(ScanObservationFailureCode::ResourceExhausted)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Some(root) = FuzzRoot::new() else {
        return;
    };
    if let Err(error) = run_once(data, &root.0) {
        panic!("public Trace Summary maintenance fuzz setup failed: {error}");
    }
});

fn run_once(data: &[u8], root: &std::path::Path) -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let authority = authority::establish(root, tenant)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x51; 16])?,
        CatalogSecret::from_owned(Box::new([0x52; 32]), Box::new([0x53; 32])),
    )?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(51)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x54; 32]));
    let store = TraceStore::new();
    let policy = IngestPolicy::preserving(1)?;
    let mut ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let source = Arc::new(AtomicI64::new(100));
    let lifecycle_clock = LifecycleClock::new(MutableClock(Arc::clone(&source)));
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(QUIET_PERIOD_NANOS)?,
        ScanLimit::new(1)?,
    )?;
    let mut expected = BTreeMap::new();
    let mut expected_spans = BTreeMap::new();
    let mut expected_observations = BTreeMap::new();
    let mut next_identity = 1_u8;
    let mut next_ingest_time = 1_000_i64;

    for command in data.chunks_exact(4).take(MAX_OPERATIONS) {
        let mut reopened_trace = None;
        match command[0] % 7 {
            0 | 1 => {
                let trace = trace_id(command);
                let (observation, expected_observation) =
                    observation(&policy, trace, command[2], command[3])?;
                append(
                    &ledger,
                    &authority,
                    &store,
                    tenant,
                    scope.shard_id(),
                    next_identity,
                    observation,
                    next_ingest_time,
                )?;
                next_identity = next_identity.wrapping_add(1).max(1);
                next_ingest_time = next_ingest_time
                    .checked_add(1)
                    .ok_or("bounded ingest time overflow")?;
                let count = expected.entry(trace).or_insert(0_u64);
                *count = count
                    .checked_add(1)
                    .ok_or("bounded observation count overflow")?;
                record_expected_span(&mut expected_spans, trace, command[2])?;
                expected_observations
                    .entry(trace)
                    .or_insert_with(Vec::new)
                    .push(expected_observation);
            },
            2 => {
                if let Some(trace) = expected.keys().next().copied() {
                    let quiescent_at = next_ingest_time
                        .checked_add(i64::try_from(QUIET_PERIOD_NANOS)?)
                        .ok_or("bounded quiescence time overflow")?;
                    source.store(quiescent_at, Ordering::Relaxed);
                    maintain_until_quiescent(
                        &mut maintainer,
                        &ledger,
                        &store,
                        &lifecycle_clock,
                        &expected,
                    )?;
                    let late_ingest_time = quiescent_at
                        .checked_add(1)
                        .ok_or("bounded late ingest time overflow")?;
                    let (observation, expected_observation) =
                        observation(&policy, trace, command[2], command[3])?;
                    append(
                        &ledger,
                        &authority,
                        &store,
                        tenant,
                        scope.shard_id(),
                        next_identity,
                        observation,
                        late_ingest_time,
                    )?;
                    next_identity = next_identity.wrapping_add(1).max(1);
                    next_ingest_time = late_ingest_time
                        .checked_add(1)
                        .ok_or("bounded ingest time overflow")?;
                    let count = expected.entry(trace).or_insert(0_u64);
                    *count = count
                        .checked_add(1)
                        .ok_or("bounded observation count overflow")?;
                    record_expected_span(&mut expected_spans, trace, command[2])?;
                    expected_observations
                        .entry(trace)
                        .or_insert_with(Vec::new)
                        .push(expected_observation);
                    source.store(late_ingest_time, Ordering::Relaxed);
                    reopened_trace = Some(trace);
                }
            },
            3 => {
                source_set(&source, command[1]);
                let snapshot = ledger.snapshot()?;
                let failure = match maintainer.maintain(
                    &store,
                    &snapshot,
                    &InputCancellation(true),
                    &Unobserved,
                    &lifecycle_clock,
                ) {
                    Ok(_) => panic!("cancelled maintenance unexpectedly succeeded"),
                    Err(failure) => failure,
                };
                assert_eq!(failure.code(), TraceStoreFailureCode::Cancelled);
            },
            4 => {
                source_set(&source, command[1]);
                let snapshot = ledger.snapshot()?;
                if let Err(failure) = maintainer.maintain(
                    &store,
                    &snapshot,
                    &InputCancellation(false),
                    &WorkBudget::exact(u64::from(command[2] % 8)),
                    &lifecycle_clock,
                ) {
                    assert_eq!(failure.code(), TraceStoreFailureCode::BudgetExhausted);
                }
            },
            5 => {
                source_set(&source, command[1]);
                let snapshot = ledger.snapshot()?;
                if let Err(failure) = maintainer.maintain(
                    &store,
                    &snapshot,
                    &InputCancellation(false),
                    &RefusingObserver,
                    &lifecycle_clock,
                ) {
                    assert_eq!(failure.code(), TraceStoreFailureCode::ResourceExhausted);
                }
            },
            _ => {
                ledger.seal()?;
                ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
            },
        }

        if reopened_trace.is_none() {
            source_set(&source, command[3]);
        }
        let snapshot = ledger.snapshot()?;
        let result = maintainer.maintain(
            &store,
            &snapshot,
            &InputCancellation(false),
            &Unobserved,
            &lifecycle_clock,
        )?;
        assert_visible_summary_counts(&result, &expected);
        exercise_trace_queries(
            &store,
            &authority,
            tenant,
            &snapshot,
            &expected,
            &expected_spans,
            &expected_observations,
            command[1] & 0x80 != 0,
            command[2],
        )?;
        if let Some(trace) = reopened_trace {
            let summary = result
                .summary(trace)
                .ok_or("late trace summary is present")?;
            assert!(
                !summary.quiescent(),
                "a later span reopens a quiescent trace"
            );
            assert_eq!(
                summary.observation_count(),
                *expected
                    .get(&trace)
                    .ok_or("late trace remains in the expected state")?
            );
        }
    }

    let quiescent_at = next_ingest_time
        .checked_add(i64::try_from(QUIET_PERIOD_NANOS)?)
        .ok_or("bounded final quiescence time overflow")?;
    source.store(quiescent_at, Ordering::Relaxed);
    maintain_until_quiescent(
        &mut maintainer,
        &ledger,
        &store,
        &lifecycle_clock,
        &expected,
    )?;
    let (fixture_trace, fixture_observation_count) = exercise_structural_fixture(
        &ledger,
        &authority,
        &store,
        &policy,
        tenant,
        scope.shard_id(),
        data[0],
        next_ingest_time,
    )?;
    expected.insert(fixture_trace, fixture_observation_count);
    drop(ledger);
    replay_and_assert(&authority, &catalog, scope, key(), &store, &expected)
}

fn exercise_trace_queries(
    store: &TraceStore,
    authority: &positron_kernel::StorageKernelResourceAuthority,
    tenant: TenantId,
    snapshot: &positron_kernel::LedgerSnapshot<'_>,
    expected: &BTreeMap<[u8; 16], u64>,
    expected_spans: &BTreeMap<[u8; 16], BTreeMap<[u8; 8], u64>>,
    expected_observations: &BTreeMap<[u8; 16], Vec<ExpectedObservation>>,
    cancelled: bool,
    target_selector: u8,
) -> Result<(), Box<dyn Error>> {
    let cancellation = InputCancellation(cancelled);
    let search = store.search_observed(
        authority.governor(),
        tenant,
        snapshot,
        TraceSearch::all(ScanLimit::new(MAX_OPERATIONS)?),
        &cancellation,
        &Unobserved,
    );
    if cancelled {
        let failure = search.expect_err("cancelled trace search unexpectedly succeeded");
        assert_eq!(failure.code(), TraceStoreFailureCode::Cancelled);
        return Ok(());
    }
    let search = search?;
    assert!(search.complete());
    let actual = search
        .spans()
        .iter()
        .map(|span| (span.trace_id(), span.span_id(), span.observation_count()))
        .collect::<Vec<_>>();
    let expected_search = expected_spans
        .iter()
        .flat_map(|(trace_id, spans)| {
            spans
                .iter()
                .map(move |(span_id, count)| (*trace_id, *span_id, *count))
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected_search);
    drop(search);
    let target_index = usize::from(target_selector) % expected.len().max(1);
    let trace_id = expected
        .keys()
        .nth(target_index)
        .copied()
        .unwrap_or([0x7f; 16]);
    let mut by_id = store.trace_by_id_observed(
        authority.governor(),
        tenant,
        snapshot,
        trace_id,
        TraceSearch::all(ScanLimit::new(MAX_OPERATIONS)?),
        &InputCancellation(false),
        &Unobserved,
    )?;
    assert!(by_id.complete());
    let expected_by_id = expected_spans
        .get(&trace_id)
        .into_iter()
        .flat_map(|spans| {
            spans
                .iter()
                .map(|(span_id, count)| (trace_id, *span_id, *count))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        by_id
            .spans()
            .iter()
            .map(|span| (span.trace_id(), span.span_id(), span.observation_count()))
            .collect::<Vec<_>>(),
        expected_by_id
    );
    let by_id_complete = by_id.complete();
    let expected_structure = expected_structure(
        expected_observations
            .get(&trace_id)
            .map(Vec::as_slice)
            .unwrap_or_default(),
    );
    let structure = by_id.analyze_structure(&InputCancellation(false), &Unobserved)?;
    assert_eq!(structure.incompleteness().scan(), TraceIncompleteness::None);
    assert_eq!(structure.roots(), expected_structure.roots.as_slice());
    assert_eq!(structure.orphans(), expected_structure.orphans.as_slice());
    assert_eq!(structure.cycles(), expected_structure.cycles.as_slice());
    assert_eq!(
        structure
            .spans()
            .iter()
            .map(|span| (
                span.span_id(),
                span.parent_span_id(),
                span.relation(),
                span.sampling(),
                span.conflicted(),
                span.cycle_member(),
            ))
            .collect::<Vec<_>>(),
        expected_structure.spans
    );
    assert_eq!(
        structure.incompleteness().missing_parents(),
        expected_structure.missing_parents
    );
    assert_eq!(
        structure.incompleteness().conflicts(),
        expected_structure.conflicts
    );
    assert_eq!(
        structure.incompleteness().cycle_members(),
        expected_structure.cycles.len() as u64
    );
    assert_eq!(
        structure.incompleteness().invalid_durations(),
        expected_structure.invalid_durations
    );
    assert_eq!(
        structure.incompleteness().temporal_inconsistencies(),
        expected_structure.temporal_inconsistencies
    );
    assert_eq!(
        structure.incompleteness().ambiguous_roots(),
        expected_structure.roots.len() > 1
    );
    let expected_complete = by_id_complete
        && expected_structure.missing_parents == 0
        && expected_structure.conflicts == 0
        && expected_structure.cycles.is_empty()
        && expected_structure.invalid_durations == 0
        && expected_structure.temporal_inconsistencies == 0
        && expected_structure.roots.len() <= 1;
    assert_eq!(structure.complete(), expected_complete);
    if let Some(expected_path) = expected_critical_path(&expected_structure) {
        let actual_path = structure.critical_path().map(|path| {
            (
                path.fragments()
                    .iter()
                    .map(|fragment| (fragment.span_id(), fragment.start(), fragment.end()))
                    .collect::<Vec<_>>(),
                path.duration_nanos(),
            )
        });
        assert_eq!(actual_path, expected_path);
    }
    if expected.values().copied().sum::<u64>() > 1 {
        let incomplete = store.search_observed(
            authority.governor(),
            tenant,
            snapshot,
            TraceSearch::all(ScanLimit::new(1)?),
            &InputCancellation(false),
            &Unobserved,
        )?;
        assert!(!incomplete.complete());
    }
    Ok(())
}

struct ExpectedStructure {
    spans: Vec<ExpectedSpan>,
    nodes: BTreeMap<[u8; 8], ExpectedNode>,
    roots: Vec<[u8; 8]>,
    orphans: Vec<[u8; 8]>,
    cycles: Vec<[u8; 8]>,
    missing_parents: u64,
    conflicts: u64,
    invalid_durations: u64,
    temporal_inconsistencies: u64,
}

type ExpectedSpan = (
    [u8; 8],
    Option<[u8; 8]>,
    TraceParentRelation,
    SamplingDecision,
    bool,
    bool,
);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedObservation {
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    interval: Option<(UnixNanoseconds, UnixNanoseconds)>,
    sampling: SamplingDecision,
    semantic_selector: u8,
}

#[derive(Clone)]
struct ExpectedNode {
    parent_span_id: Option<[u8; 8]>,
    interval: Option<(UnixNanoseconds, UnixNanoseconds)>,
    sampling: SamplingDecision,
    conflicted: bool,
    semantic_selector: u8,
}

fn expected_structure(observations: &[ExpectedObservation]) -> ExpectedStructure {
    let mut nodes = BTreeMap::new();
    for observation in observations {
        nodes
            .entry(observation.span_id)
            .and_modify(|node: &mut ExpectedNode| {
                node.conflicted |= node.parent_span_id != observation.parent_span_id
                    || node.interval != observation.interval
                    || node.sampling != observation.sampling
                    || node.semantic_selector != observation.semantic_selector;
            })
            .or_insert_with(|| ExpectedNode {
                parent_span_id: observation.parent_span_id,
                interval: observation.interval,
                sampling: observation.sampling,
                conflicted: false,
                semantic_selector: observation.semantic_selector,
            });
    }
    let mut expected = ExpectedStructure {
        spans: Vec::new(),
        nodes: BTreeMap::new(),
        roots: Vec::new(),
        orphans: Vec::new(),
        cycles: Vec::new(),
        missing_parents: 0,
        conflicts: 0,
        invalid_durations: 0,
        temporal_inconsistencies: 0,
    };
    let cycles = cycle_members(&nodes);
    for (span_id, node) in &nodes {
        let relation = match node.parent_span_id {
            None => {
                expected.roots.push(*span_id);
                TraceParentRelation::Root
            },
            Some(parent) if nodes.contains_key(&parent) => TraceParentRelation::Child,
            Some(_) => {
                expected.orphans.push(*span_id);
                expected.missing_parents = expected.missing_parents.saturating_add(1);
                TraceParentRelation::Orphan
            },
        };
        let cycle_member = cycles.contains(span_id);
        if node.conflicted {
            expected.conflicts = expected.conflicts.saturating_add(1);
        }
        if node.interval.is_none() {
            expected.invalid_durations = expected.invalid_durations.saturating_add(1);
        }
        if let Some(parent) = node.parent_span_id.and_then(|parent| nodes.get(&parent))
            && let (Some(parent_interval), Some(child_interval)) = (parent.interval, node.interval)
            && (child_interval.0 < parent_interval.0 || child_interval.1 > parent_interval.1)
        {
            expected.temporal_inconsistencies = expected.temporal_inconsistencies.saturating_add(1);
        }
        if cycle_member {
            expected.cycles.push(*span_id);
        }
        expected.spans.push((
            *span_id,
            node.parent_span_id,
            relation,
            node.sampling,
            node.conflicted,
            cycle_member,
        ));
    }
    expected.nodes = nodes;
    expected
}

fn cycle_members(nodes: &BTreeMap<[u8; 8], ExpectedNode>) -> BTreeSet<[u8; 8]> {
    let mut cycles = BTreeSet::new();
    for origin in nodes.keys().copied() {
        let mut trail = Vec::new();
        let mut positions = BTreeMap::new();
        let mut current = Some(origin);
        while let Some(span_id) = current {
            let Some(node) = nodes.get(&span_id) else {
                break;
            };
            if let Some(start) = positions.get(&span_id).copied() {
                cycles.extend(trail.into_iter().skip(start));
                break;
            }
            positions.insert(span_id, trail.len());
            trail.push(span_id);
            current = node.parent_span_id;
        }
    }
    cycles
}

fn expected_critical_path(
    expected: &ExpectedStructure,
) -> Option<Option<(Vec<([u8; 8], UnixNanoseconds, UnixNanoseconds)>, u64)>> {
    if expected.nodes.len() > 6 {
        return None;
    }
    if expected.missing_parents != 0
        || expected.conflicts != 0
        || !expected.cycles.is_empty()
        || expected.invalid_durations != 0
        || expected.temporal_inconsistencies != 0
        || expected.roots.len() != 1
    {
        return Some(None);
    }
    let root = expected.roots[0];
    let fragments = reference_fragments(&expected.nodes, root)?;
    let duration = fragments.iter().try_fold(0_u64, |total, (_, start, end)| {
        u64::try_from(i128::from(end.value()) - i128::from(start.value()))
            .ok()
            .and_then(|part| total.checked_add(part))
    })?;
    Some(Some((fragments, duration)))
}

// This bounded enumerator is deliberately unlike the production backwards walk:
// it enumerates compatible direct-child schedules, picks the CRISP-preferred
// schedule by its endpoint ordering, then expands it in chronological order.
fn reference_fragments(
    nodes: &BTreeMap<[u8; 8], ExpectedNode>,
    parent_id: [u8; 8],
) -> Option<Vec<([u8; 8], UnixNanoseconds, UnixNanoseconds)>> {
    let (start, end) = nodes.get(&parent_id)?.interval?;
    let schedule = preferred_schedule(nodes, parent_id, end)?;
    let mut fragments = Vec::new();
    let mut cursor = start;
    for child_id in schedule.iter().rev() {
        let (child_start, child_end) = nodes.get(child_id)?.interval?;
        if child_start > cursor {
            fragments.push((parent_id, cursor, child_start));
        }
        fragments.extend(reference_fragments(nodes, *child_id)?);
        cursor = child_end;
    }
    if end > cursor {
        fragments.push((parent_id, cursor, end));
    }
    Some(fragments)
}

fn preferred_schedule(
    nodes: &BTreeMap<[u8; 8], ExpectedNode>,
    parent_id: [u8; 8],
    cursor: UnixNanoseconds,
) -> Option<Vec<[u8; 8]>> {
    let mut schedules = vec![Vec::new()];
    for (child_id, child) in nodes {
        let (start, end) = child.interval?;
        if child.parent_span_id != Some(parent_id) || start >= cursor || end > cursor {
            continue;
        }
        for suffix in preferred_schedule_options(nodes, parent_id, start)? {
            let mut schedule = Vec::with_capacity(suffix.len().saturating_add(1));
            schedule.push(*child_id);
            schedule.extend(suffix);
            schedules.push(schedule);
        }
    }
    schedules
        .into_iter()
        .max_by(|left, right| compare_schedules(left, right, nodes))
}

fn preferred_schedule_options(
    nodes: &BTreeMap<[u8; 8], ExpectedNode>,
    parent_id: [u8; 8],
    cursor: UnixNanoseconds,
) -> Option<Vec<Vec<[u8; 8]>>> {
    let mut schedules = vec![Vec::new()];
    for (child_id, child) in nodes {
        let (start, end) = child.interval?;
        if child.parent_span_id != Some(parent_id) || start >= cursor || end > cursor {
            continue;
        }
        for suffix in preferred_schedule_options(nodes, parent_id, start)? {
            let mut schedule = Vec::with_capacity(suffix.len().saturating_add(1));
            schedule.push(*child_id);
            schedule.extend(suffix);
            schedules.push(schedule);
        }
    }
    Some(schedules)
}

fn compare_schedules(
    left: &[[u8; 8]],
    right: &[[u8; 8]],
    nodes: &BTreeMap<[u8; 8], ExpectedNode>,
) -> std::cmp::Ordering {
    for (left_id, right_id) in left.iter().zip(right) {
        let left_end = nodes
            .get(left_id)
            .and_then(|node| node.interval)
            .map(|(_, end)| end);
        let right_end = nodes
            .get(right_id)
            .and_then(|node| node.interval)
            .map(|(_, end)| end);
        match left_end.cmp(&right_end).then_with(|| right_id.cmp(left_id)) {
            std::cmp::Ordering::Equal => {},
            order => return order,
        }
    }
    left.len().cmp(&right.len())
}

fn record_expected_span(
    expected_spans: &mut BTreeMap<[u8; 16], BTreeMap<[u8; 8], u64>>,
    trace_id: [u8; 16],
    span_selector: u8,
) -> Result<(), Box<dyn Error>> {
    let spans = expected_spans.entry(trace_id).or_default();
    let count = spans.entry([span_selector.max(1); 8]).or_insert(0_u64);
    *count = count
        .checked_add(1)
        .ok_or("bounded logical span observation count overflow")?;
    Ok(())
}

fn source_set(source: &AtomicI64, input: u8) {
    let value = if input & 1 == 0 {
        i64::from(200_u16 + u16::from(input))
    } else {
        i64::from(100_u16 + u16::from(input))
    };
    source.store(value, Ordering::Relaxed);
}

fn trace_id(command: &[u8]) -> [u8; 16] {
    let state = 0xcbf2_9ce4_8422_2325_u64
        .wrapping_mul(u64::from(command.first().copied().unwrap_or_default()).wrapping_add(1));
    let mut trace_id = [0_u8; 16];
    trace_id[..8].copy_from_slice(&state.to_be_bytes());
    trace_id[8..].copy_from_slice(
        &state
            .rotate_left(29)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .to_be_bytes(),
    );
    if trace_id == [0; 16] {
        trace_id[0] = 1;
    }
    trace_id
}

fn observation(
    policy: &IngestPolicy,
    trace_id: [u8; 16],
    span_selector: u8,
    semantic_selector: u8,
) -> Result<(SpanObservation, ExpectedObservation), Box<dyn Error>> {
    let TracePolicyEvaluation::Accepted(evaluated) = policy.evaluate_trace(
        NativeTraceCandidate::new(Vec::new()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving trace policy rejected a candidate".into());
    };
    let start = i64::from(span_selector.max(2));
    let end = if semantic_selector & 0x80 == 0 {
        start.saturating_add(i64::from(semantic_selector & 0x3f))
    } else {
        start.saturating_sub(1)
    };
    let quality = source_time_quality(semantic_selector);
    let sampling = sampling_decision(semantic_selector);
    let start_time = generated_event_time(start, quality)?;
    let end_time = generated_event_time(end, quality)?;
    let interval = generated_interval(start, end, quality);
    let parent_span_id = parent_span_id(span_selector, semantic_selector);
    let observation = SpanObservation::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        EvaluatedSpanObservationInput {
            trace_id,
            span_id: [span_selector.max(1); 8],
            parent_span_id,
            name: format!("fuzz-span-{semantic_selector}"),
            start_time,
            end_time,
            kind: SpanKind::Internal,
            sampling,
            evaluated: *evaluated,
            details: SpanObservationDetails::default(),
        },
    )?;
    Ok((
        observation,
        ExpectedObservation {
            span_id: [span_selector.max(1); 8],
            parent_span_id,
            interval,
            sampling,
            semantic_selector,
        },
    ))
}

fn source_time_quality(selector: u8) -> SourceTimeQuality {
    match selector & 0x03 {
        0 => SourceTimeQuality::Usable,
        1 => SourceTimeQuality::Outlier,
        2 => SourceTimeQuality::Missing,
        _ => SourceTimeQuality::Zero,
    }
}

fn sampling_decision(selector: u8) -> SamplingDecision {
    match selector % 3 {
        0 => SamplingDecision::Unknown,
        1 => SamplingDecision::NotSampled,
        _ => SamplingDecision::Sampled,
    }
}

fn generated_event_time(
    value: i64,
    quality: SourceTimeQuality,
) -> Result<EventTime, Box<dyn Error>> {
    match quality {
        SourceTimeQuality::Missing => Ok(EventTime::missing()),
        SourceTimeQuality::Zero => Ok(EventTime::received(
            UnixNanoseconds::new(0),
            SourceTimeQuality::Zero,
        )?),
        SourceTimeQuality::Usable | SourceTimeQuality::Outlier => {
            Ok(EventTime::received(UnixNanoseconds::new(value), quality)?)
        },
        SourceTimeQuality::Contradictory => {
            Err("generated source quality is not valid for a trace observation".into())
        },
    }
}

fn generated_interval(
    start: i64,
    end: i64,
    quality: SourceTimeQuality,
) -> Option<(UnixNanoseconds, UnixNanoseconds)> {
    matches!(quality, SourceTimeQuality::Usable | SourceTimeQuality::Outlier)
        .then_some((UnixNanoseconds::new(start), UnixNanoseconds::new(end)))
        .filter(|(start, end)| end >= start)
}

#[derive(Clone, Copy)]
struct FixtureInput {
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    start: Option<i64>,
    end: Option<i64>,
    name: u8,
    sampling: SamplingDecision,
}

#[allow(clippy::too_many_arguments)]
fn exercise_structural_fixture<'kernel>(
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    authority: &'kernel positron_kernel::StorageKernelResourceAuthority,
    store: &TraceStore,
    policy: &IngestPolicy,
    tenant: TenantId,
    shard: VirtualShardId,
    selector: u8,
    ingest_time: i64,
) -> Result<([u8; 16], u64), Box<dyn Error>> {
    let case = selector % 9;
    let trace_id = [0xe0_u8.saturating_add(case); 16];
    let sampling = sampling_decision(selector);
    let usable_quality = if selector & 0x10 == 0 {
        SourceTimeQuality::Usable
    } else {
        SourceTimeQuality::Outlier
    };
    let root = [0x01; 8];
    let first = [0x02; 8];
    let second = [0x03; 8];
    let inputs = match case {
        0 => vec![
            FixtureInput { span_id: root, parent_span_id: None, start: Some(1), end: Some(101), name: 0, sampling },
            FixtureInput { span_id: first, parent_span_id: Some(root), start: Some(11), end: Some(91), name: 1, sampling },
            FixtureInput { span_id: second, parent_span_id: Some(first), start: Some(21), end: Some(81), name: 2, sampling },
        ],
        1 => vec![
            FixtureInput { span_id: root, parent_span_id: None, start: Some(1), end: Some(101), name: 0, sampling },
            FixtureInput { span_id: first, parent_span_id: Some(root), start: Some(11), end: Some(41), name: 1, sampling },
            FixtureInput { span_id: second, parent_span_id: Some(root), start: Some(51), end: Some(91), name: 2, sampling },
        ],
        2 => vec![
            FixtureInput { span_id: root, parent_span_id: None, start: Some(1), end: Some(101), name: 0, sampling },
            FixtureInput { span_id: first, parent_span_id: Some(root), start: Some(11), end: Some(61), name: 1, sampling },
            FixtureInput { span_id: second, parent_span_id: Some(root), start: Some(21), end: Some(91), name: 2, sampling },
        ],
        3 => vec![
            FixtureInput { span_id: root, parent_span_id: None, start: Some(1), end: Some(101), name: 0, sampling },
            FixtureInput { span_id: first, parent_span_id: Some(root), start: Some(11), end: Some(81), name: 1, sampling },
            FixtureInput { span_id: second, parent_span_id: Some(root), start: Some(21), end: Some(81), name: 2, sampling },
        ],
        4 => vec![FixtureInput { span_id: first, parent_span_id: Some([0x09; 8]), start: Some(10), end: Some(20), name: 0, sampling }],
        5 => vec![
            FixtureInput { span_id: first, parent_span_id: Some(second), start: Some(10), end: Some(40), name: 0, sampling },
            FixtureInput { span_id: second, parent_span_id: Some(first), start: Some(15), end: Some(35), name: 1, sampling },
        ],
        6 => vec![
            FixtureInput { span_id: root, parent_span_id: None, start: Some(1), end: Some(101), name: 0, sampling },
            FixtureInput { span_id: root, parent_span_id: None, start: Some(1), end: Some(101), name: 1, sampling: SamplingDecision::NotSampled },
        ],
        7 => vec![FixtureInput { span_id: root, parent_span_id: None, start: None, end: None, name: 0, sampling }],
        _ => vec![
            FixtureInput { span_id: root, parent_span_id: None, start: Some(1), end: Some(51), name: 0, sampling },
            FixtureInput { span_id: first, parent_span_id: Some(root), start: Some(11), end: Some(71), name: 1, sampling },
        ],
    };
    let mut observations = Vec::new();
    let mut expected_observations = Vec::new();
    for input in inputs {
        let quality = if case == 7 { SourceTimeQuality::Missing } else { usable_quality };
        let (observation, expected) = fixture_observation(policy, trace_id, input, quality)?;
        observations.push(observation);
        expected_observations.push(expected);
    }
    append_all(
        ledger,
        authority,
        store,
        tenant,
        shard,
        0xfe,
        observations,
        ingest_time,
    )?;
    let snapshot = ledger.snapshot()?;
    let mut trace = store.trace_by_id_observed(
        authority.governor(),
        tenant,
        &snapshot,
        trace_id,
        TraceSearch::all(ScanLimit::new(MAX_OPERATIONS.saturating_add(3))?),
        &InputCancellation(false),
        &Unobserved,
    )?;
    assert!(trace.complete());
    let expected = expected_structure(&expected_observations);
    let structure = trace.analyze_structure(&InputCancellation(false), &Unobserved)?;
    assert_eq!(structure.roots(), expected.roots.as_slice());
    assert_eq!(structure.orphans(), expected.orphans.as_slice());
    assert_eq!(structure.cycles(), expected.cycles.as_slice());
    assert_eq!(structure.incompleteness().missing_parents(), expected.missing_parents);
    assert_eq!(structure.incompleteness().conflicts(), expected.conflicts);
    assert_eq!(structure.incompleteness().cycle_members(), expected.cycles.len() as u64);
    assert_eq!(structure.incompleteness().invalid_durations(), expected.invalid_durations);
    assert_eq!(structure.incompleteness().temporal_inconsistencies(), expected.temporal_inconsistencies);
    assert_eq!(
        structure.spans().iter().map(|span| (
            span.span_id(), span.parent_span_id(), span.relation(), span.sampling(),
            span.conflicted(), span.cycle_member(),
        )).collect::<Vec<_>>(),
        expected.spans.as_slice(),
    );
    let literal_path = literal_fixture_path(case);
    assert_eq!(expected_critical_path(&expected), Some(literal_path.clone()));
    let actual_path = structure.critical_path().map(|path| (
        path.fragments().iter().map(|fragment| (fragment.span_id(), fragment.start(), fragment.end())).collect::<Vec<_>>(),
        path.duration_nanos(),
    ));
    assert_eq!(actual_path, literal_path);
    Ok((trace_id, u64::try_from(expected_observations.len())?))
}

fn fixture_observation(
    policy: &IngestPolicy,
    trace_id: [u8; 16],
    input: FixtureInput,
    quality: SourceTimeQuality,
) -> Result<(SpanObservation, ExpectedObservation), Box<dyn Error>> {
    let TracePolicyEvaluation::Accepted(evaluated) = policy.evaluate_trace(
        NativeTraceCandidate::new(Vec::new()),
        PolicyReceiver::OtlpGrpc,
    )? else {
        return Err("preserving trace policy rejected fixture candidate".into());
    };
    let start_time = input
        .start
        .map(|value| generated_event_time(value, quality))
        .transpose()?
        .unwrap_or_else(EventTime::missing);
    let end_time = input
        .end
        .map(|value| generated_event_time(value, quality))
        .transpose()?
        .unwrap_or_else(EventTime::missing);
    let interval = input.start.zip(input.end).and_then(|(start, end)| generated_interval(start, end, quality));
    Ok((
        SpanObservation::checked_evaluated(
            ValueLimitProfile::release_1_system_maximum(),
            EvaluatedSpanObservationInput {
                trace_id,
                span_id: input.span_id,
                parent_span_id: input.parent_span_id,
                name: format!("fixture-{}", input.name),
                start_time,
                end_time,
                kind: SpanKind::Internal,
                sampling: input.sampling,
                evaluated: *evaluated,
                details: SpanObservationDetails::default(),
            },
        )?,
        ExpectedObservation {
            span_id: input.span_id,
            parent_span_id: input.parent_span_id,
            interval,
            sampling: input.sampling,
            semantic_selector: input.name,
        },
    ))
}

fn literal_fixture_path(
    case: u8,
) -> Option<(Vec<([u8; 8], UnixNanoseconds, UnixNanoseconds)>, u64)> {
    let at = |value| UnixNanoseconds::new(value);
    let root = [0x01; 8];
    let first = [0x02; 8];
    let second = [0x03; 8];
    match case {
        0 => Some((vec![(root, at(1), at(11)), (first, at(11), at(21)), (second, at(21), at(81)), (first, at(81), at(91)), (root, at(91), at(101))], 100)),
        1 => Some((vec![(root, at(1), at(11)), (first, at(11), at(41)), (root, at(41), at(51)), (second, at(51), at(91)), (root, at(91), at(101))], 100)),
        2 => Some((vec![(root, at(1), at(21)), (second, at(21), at(91)), (root, at(91), at(101))], 100)),
        3 => Some((vec![(root, at(1), at(11)), (first, at(11), at(81)), (root, at(81), at(101))], 100)),
        _ => None,
    }
}

fn parent_span_id(span_selector: u8, semantic_selector: u8) -> Option<[u8; 8]> {
    match semantic_selector & 0x03 {
        0 => None,
        1 => Some([span_selector.max(1); 8]),
        2 => Some([semantic_selector.max(1); 8]),
        _ => Some([span_selector.wrapping_add(1).max(1); 8]),
    }
}

#[allow(clippy::too_many_arguments)]
fn append<'kernel>(
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    authority: &'kernel positron_kernel::StorageKernelResourceAuthority,
    store: &TraceStore,
    tenant: TenantId,
    shard: VirtualShardId,
    identity: u8,
    observation: SpanObservation,
    ingest_time: i64,
) -> Result<(), Box<dyn Error>> {
    append_all(
        ledger,
        authority,
        store,
        tenant,
        shard,
        identity,
        vec![observation],
        ingest_time,
    )
}

#[allow(clippy::too_many_arguments)]
fn append_all<'kernel>(
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    authority: &'kernel positron_kernel::StorageKernelResourceAuthority,
    store: &TraceStore,
    tenant: TenantId,
    shard: VirtualShardId,
    identity: u8,
    observations: Vec<SpanObservation>,
    ingest_time: i64,
) -> Result<(), Box<dyn Error>> {
    let capacity = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        ingest_time,
    )));
    ledger.append(
        store
            .prepare_unretained_for_test(
                capacity,
                &clock,
                tenant,
                shard,
                StoreBlockIdentity::new([identity; 16])?,
                observations,
            )?
            .into_store_block(),
    )?;
    Ok(())
}

fn assert_visible_summary_counts(
    result: &positron_signals::TraceSummaryMaintenance<'_, '_>,
    expected: &BTreeMap<[u8; 16], u64>,
) {
    for (trace, expected_observations) in expected {
        let Some(summary) = result.summary(*trace) else {
            continue;
        };
        assert!(summary.observation_count() <= *expected_observations);
        assert!(
            u64::try_from(summary.logical_span_count())
                .is_ok_and(|count| count <= summary.observation_count())
        );
        assert!(summary.conflicted_span_count() <= summary.logical_span_count());
    }
}

fn maintain_until_quiescent<'kernel>(
    maintainer: &mut TraceSummaryMaintainer<'kernel>,
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    store: &TraceStore,
    lifecycle_clock: &LifecycleClock<MutableClock>,
    expected: &BTreeMap<[u8; 16], u64>,
) -> Result<(), Box<dyn Error>> {
    if expected.is_empty() {
        return Ok(());
    }
    let observations = expected.values().copied().sum::<u64>();
    let summaries = u64::try_from(expected.len())?;
    let attempts = observations
        .checked_add(summaries)
        .and_then(|value| value.checked_add(summaries))
        .and_then(|value| value.checked_add(1))
        .ok_or("bounded quiescence attempts overflow")?;
    for _ in 0..attempts {
        let snapshot = ledger.snapshot()?;
        let result = maintainer.maintain(
            store,
            &snapshot,
            &InputCancellation(false),
            &Unobserved,
            lifecycle_clock,
        )?;
        assert_visible_summary_counts(&result, expected);
        let all_quiescent = expected.keys().all(|trace| {
            result
                .summary(*trace)
                .is_some_and(|summary| summary.quiescent())
        });
        if result.complete() && result.quiescence_complete() && all_quiescent {
            return Ok(());
        }
    }
    Err("bounded live maintenance did not reach physical and quiescence completion".into())
}

fn replay_and_assert(
    authority: &positron_kernel::StorageKernelResourceAuthority,
    catalog: &Catalog<'_>,
    scope: SegmentScope,
    key: SegmentProtectionKey,
    store: &TraceStore,
    expected: &BTreeMap<[u8; 16], u64>,
) -> Result<(), Box<dyn Error>> {
    let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key)?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(10_000)));
    let mut replay = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(QUIET_PERIOD_NANOS)?,
        ScanLimit::new(1)?,
    )?;
    let total = expected.values().copied().sum::<u64>();
    let mut completed = false;
    let mut quiescence_complete = false;
    for _ in 0..=total.saturating_mul(2) {
        let snapshot = ledger.snapshot()?;
        let result = replay.maintain(
            store,
            &snapshot,
            &InputCancellation(false),
            &Unobserved,
            &clock,
        )?;
        assert_visible_summary_counts(&result, expected);
        if result.complete() {
            completed = true;
            if result.quiescence_complete() {
                quiescence_complete = true;
                break;
            }
        }
    }
    assert!(
        completed,
        "bounded replay did not reach its authenticated frontier"
    );
    assert!(
        quiescence_complete,
        "bounded replay did not refresh quiescence for its authenticated frontier"
    );
    let snapshot = ledger.snapshot()?;
    let result = replay.maintain(
        store,
        &snapshot,
        &InputCancellation(false),
        &Unobserved,
        &clock,
    )?;
    for (trace, expected_observations) in expected {
        let summary = result
            .summary(*trace)
            .ok_or("replayed trace summary missing")?;
        assert_eq!(summary.observation_count(), *expected_observations);
        assert!(summary.quiescent());
    }
    Ok(())
}
