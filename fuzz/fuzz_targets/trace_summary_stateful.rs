#![no_main]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::{EventTime, UnixNanoseconds};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, LifecycleClockFailure, LifecycleClockSource, ResourceAmounts,
    ResourceDimension, SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim,
    WorkKind,
};
use positron_policy::{IngestPolicy, NativeTraceCandidate, PolicyReceiver, TracePolicyEvaluation};
use positron_signals::{
    EvaluatedSpanObservationInput, SamplingDecision, ScanCancellation, ScanLimit,
    ScanObservationFailureCode, ScanObserver, SpanKind, SpanObservation, SpanObservationDetails,
    TraceQuietPeriod, TraceSearch, TraceStore, TraceStoreFailureCode, TraceSummaryMaintainer,
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
    let mut next_identity = 1_u8;
    let mut next_ingest_time = 1_000_i64;

    for command in data.chunks_exact(4).take(MAX_OPERATIONS) {
        let mut reopened_trace = None;
        match command[0] % 7 {
            0 | 1 => {
                let trace = trace_id(command);
                let observation = observation(&policy, trace, command[2], command[3])?;
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
                *count = count.checked_add(1).ok_or("bounded observation count overflow")?;
                record_expected_span(&mut expected_spans, trace, command[2])?;
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
                    append(
                        &ledger,
                        &authority,
                        &store,
                        tenant,
                        scope.shard_id(),
                        next_identity,
                        observation(&policy, trace, command[2], command[3])?,
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
                assert_eq!(
                    failure.code(),
                    TraceStoreFailureCode::Cancelled
                );
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
            command[1] & 0x80 != 0,
            command[2],
        )?;
        if let Some(trace) = reopened_trace {
            let summary = result.summary(trace).ok_or("late trace summary is present")?;
            assert!(!summary.quiescent(), "a later span reopens a quiescent trace");
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
    let by_id = store.trace_by_id_observed(
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
    if expected.values().copied().sum::<u64>() > 1 {
        let incomplete = store.search_observed(
            authority.governor(), tenant, snapshot, TraceSearch::all(ScanLimit::new(1)?),
            &InputCancellation(false), &Unobserved,
        )?;
        assert!(!incomplete.complete());
    }
    Ok(())
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
    let mut state = 0xcbf2_9ce4_8422_2325_u64;
    for byte in command {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
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
) -> Result<SpanObservation, Box<dyn Error>> {
    let TracePolicyEvaluation::Accepted(evaluated) = policy.evaluate_trace(
        NativeTraceCandidate::new(Vec::new()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving trace policy rejected a candidate".into());
    };
    Ok(SpanObservation::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        EvaluatedSpanObservationInput {
            trace_id,
            span_id: [span_selector.max(1); 8],
            parent_span_id: None,
            name: format!("fuzz-span-{semantic_selector}"),
            start_time: EventTime::missing(),
            end_time: EventTime::missing(),
            kind: SpanKind::Internal,
            sampling: SamplingDecision::Unknown,
            evaluated: *evaluated,
            details: SpanObservationDetails::default(),
        },
    )?)
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
                vec![observation],
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
        assert!(u64::try_from(summary.logical_span_count())
            .is_ok_and(|count| count <= summary.observation_count()));
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
    assert!(completed, "bounded replay did not reach its authenticated frontier");
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
        let summary = result.summary(*trace).ok_or("replayed trace summary missing")?;
        assert_eq!(summary.observation_count(), *expected_observations);
        assert!(summary.quiescent());
    }
    Ok(())
}
