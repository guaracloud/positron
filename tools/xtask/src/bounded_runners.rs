//! Registered, bounded Quality Engineering task and resource scenarios.
//!
//! This module is the sole owner of the M0 harness task lifecycle. A scenario
//! is frozen from the committed registry before selection, registers every
//! worker before it is spawned, and joins every worker before its report may
//! be returned. The resource scenario uses real bounded channels, a finite
//! reservation ledger, and deterministic schedule measurements; its verifier
//! derives the accepted result from those retained measurements rather than a
//! runner verdict.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::XtaskError;

const REGISTRY_PATH: &str = "qualification/engineering/concurrency-fixtures.tsv";
const REGISTRY_HEADER: &str = "scenario_id\tgate_id\tspawn_site\tschedule\tseed\tmax_tasks\tqueue_capacity\treservation_capacity\tretry_limit\tshutdown_ms\texpected";
const SPAWN_SITE_REGISTRY_PATH: &str = "qualification/engineering/concurrency-spawn-sites.tsv";
const SPAWN_SITE_REGISTRY_HEADER: &str = "path\tsymbol\tkind\tid";
const MAXIMUM_REGISTRY_BYTES: usize = 16_384;
const MAXIMUM_SCENARIOS: usize = 8;
const MAXIMUM_FIELD_BYTES: usize = 96;
const REGISTERED_SPAWN_SITE: &str = "quality-bounded-worker-v1";
const CONCURRENCY_GATE: &str = "EG-CONCURRENCY";
const RESOURCE_GATE: &str = "EG-RESOURCE";

type SpawnSiteKey = (String, String, String);
type SpawnSiteRegistry = BTreeMap<SpawnSiteKey, String>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScenarioGate {
    Concurrency,
    Resource,
}

impl ScenarioGate {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            CONCURRENCY_GATE => Ok(Self::Concurrency),
            RESOURCE_GATE => Ok(Self::Resource),
            _ => Err(XtaskError::invalid(
                "bounded runner registry",
                format!("unsupported gate `{value}`"),
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Concurrency => CONCURRENCY_GATE,
            Self::Resource => RESOURCE_GATE,
        }
    }
}

#[derive(Debug)]
struct Scenario {
    id: String,
    gate: ScenarioGate,
    spawn_site: String,
    schedule: String,
    seed: String,
    max_tasks: usize,
    queue_capacity: usize,
    reservation_capacity: usize,
    retry_limit: usize,
    shutdown: Duration,
    expected: String,
}

#[derive(Debug)]
pub(crate) struct FrozenBoundedRunnerRegistry {
    bytes: Box<[u8]>,
    spawn_site_bytes: Box<[u8]>,
    scenarios: Vec<Scenario>,
    spawn_sites: SpawnSiteRegistry,
}

impl FrozenBoundedRunnerRegistry {
    pub(crate) fn capture(bytes: Vec<u8>, spawn_site_bytes: Vec<u8>) -> Result<Self, XtaskError> {
        let path = Path::new(REGISTRY_PATH);
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                path,
                format!("bounded runner registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        if spawn_site_bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                Path::new(SPAWN_SITE_REGISTRY_PATH),
                format!("bounded spawn-site registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| XtaskError::invalid_path(path, "bounded runner registry is not UTF-8"))?;
        let mut lines = text.lines();
        let Some(header) = lines.next() else {
            return Err(XtaskError::invalid_path(
                path,
                "bounded runner registry is empty",
            ));
        };
        if header != REGISTRY_HEADER {
            return Err(XtaskError::invalid_path(
                path,
                "bounded runner registry header does not match the registered schema",
            ));
        }
        let mut scenarios = Vec::new();
        for (line_number, line) in lines.enumerate() {
            if scenarios.len() >= MAXIMUM_SCENARIOS {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("bounded runner registry exceeds {MAXIMUM_SCENARIOS} scenarios"),
                ));
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                id,
                gate,
                spawn_site,
                schedule,
                seed,
                max_tasks,
                queue_capacity,
                reservation_capacity,
                retry_limit,
                shutdown_ms,
                expected,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    path,
                    format!(
                        "bounded runner registry row {} has the wrong field count",
                        line_number + 2
                    ),
                ));
            };
            for value in [
                *id,
                *gate,
                *spawn_site,
                *schedule,
                *seed,
                *max_tasks,
                *queue_capacity,
                *reservation_capacity,
                *retry_limit,
                *shutdown_ms,
                *expected,
            ] {
                if value.is_empty() || value.len() > MAXIMUM_FIELD_BYTES {
                    return Err(XtaskError::invalid_path(
                        path,
                        format!(
                            "bounded runner registry row {} contains an invalid bounded field",
                            line_number + 2
                        ),
                    ));
                }
            }
            let gate = ScenarioGate::parse(gate)?;
            let max_tasks = parse_positive(path, max_tasks, "max_tasks")?;
            let queue_capacity = parse_positive(path, queue_capacity, "queue_capacity")?;
            let reservation_capacity =
                parse_positive(path, reservation_capacity, "reservation_capacity")?;
            let retry_limit = parse_positive(path, retry_limit, "retry_limit")?;
            let shutdown = Duration::from_millis(
                u64::try_from(parse_positive(path, shutdown_ms, "shutdown_ms")?).map_err(|_| {
                    XtaskError::invalid_path(path, "shutdown_ms cannot be represented")
                })?,
            );
            if *spawn_site != REGISTERED_SPAWN_SITE {
                return Err(XtaskError::invalid_path(
                    path,
                    "bounded runner registry denied an unregistered spawn site",
                ));
            }
            scenarios.push(Scenario {
                id: (*id).to_owned(),
                gate,
                spawn_site: (*spawn_site).to_owned(),
                schedule: (*schedule).to_owned(),
                seed: (*seed).to_owned(),
                max_tasks,
                queue_capacity,
                reservation_capacity,
                retry_limit,
                shutdown,
                expected: (*expected).to_owned(),
            });
        }
        if scenarios.len() != 2 {
            return Err(XtaskError::invalid_path(
                path,
                "bounded runner registry must contain exactly one scenario per registered gate",
            ));
        }
        for gate in [ScenarioGate::Concurrency, ScenarioGate::Resource] {
            if scenarios
                .iter()
                .filter(|scenario| scenario.gate == gate)
                .count()
                != 1
            {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("{} must have exactly one registered scenario", gate.label()),
                ));
            }
        }
        let spawn_sites = parse_spawn_site_registry(&spawn_site_bytes)?;
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            spawn_site_bytes: spawn_site_bytes.into_boxed_slice(),
            scenarios,
            spawn_sites,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn spawn_site_bytes(&self) -> &[u8] {
        &self.spawn_site_bytes
    }

    fn spawn_sites(&self) -> &SpawnSiteRegistry {
        &self.spawn_sites
    }

    fn scenario(&self, gate: ScenarioGate) -> Result<&Scenario, XtaskError> {
        self.scenarios
            .iter()
            .find(|scenario| scenario.gate == gate)
            .ok_or_else(|| {
                XtaskError::invalid("bounded runner registry", "registered scenario is missing")
            })
    }
}

fn parse_positive(path: &Path, value: &str, field: &str) -> Result<usize, XtaskError> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            XtaskError::invalid_path(path, format!("{field} must be a positive bounded integer"))
        })
}

fn parse_spawn_site_registry(bytes: &[u8]) -> Result<SpawnSiteRegistry, XtaskError> {
    let path = Path::new(SPAWN_SITE_REGISTRY_PATH);
    let registry = std::str::from_utf8(bytes)
        .map_err(|_| XtaskError::invalid_path(path, "frozen spawn-site registry is not UTF-8"))?;
    let mut rows = registry.lines();
    let Some(header) = rows.next() else {
        return Err(XtaskError::invalid_path(
            path,
            "spawn-site registry is empty",
        ));
    };
    if header != SPAWN_SITE_REGISTRY_HEADER {
        return Err(XtaskError::invalid_path(
            path,
            "spawn-site registry header does not match the registered schema",
        ));
    }
    let mut registered = BTreeMap::new();
    for (offset, row) in rows.enumerate() {
        let fields = row.split('\t').collect::<Vec<_>>();
        let [source, symbol, kind, id] = fields.as_slice() else {
            return Err(XtaskError::invalid_path(
                path,
                format!(
                    "spawn-site registry row {} has the wrong field count",
                    offset + 2
                ),
            ));
        };
        if source.is_empty()
            || symbol.is_empty()
            || id.is_empty()
            || source.len() > MAXIMUM_FIELD_BYTES
            || symbol.len() > MAXIMUM_FIELD_BYTES
            || id.len() > MAXIMUM_FIELD_BYTES
            || !matches!(*kind, "process" | "thread")
        {
            return Err(XtaskError::invalid_path(
                path,
                "spawn-site registry contains an invalid bounded lifecycle owner",
            ));
        }
        if registered
            .insert(
                ((*source).to_owned(), (*symbol).to_owned(), (*id).to_owned()),
                (*kind).to_owned(),
            )
            .is_some()
        {
            return Err(XtaskError::invalid_path(
                path,
                "spawn-site registry contains a duplicate semantic spawn site",
            ));
        }
    }
    if registered.is_empty() {
        return Err(XtaskError::invalid_path(
            path,
            "spawn-site registry contains no registered lifecycle owners",
        ));
    }
    Ok(registered)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerCommand {
    Execute { schedule_slot: usize },
    Cancel { schedule_slot: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerCompletion {
    Executed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerMeasurement {
    id: usize,
    schedule_slot: usize,
    completion: WorkerCompletion,
}

struct RegisteredTask {
    id: usize,
    cancel: Arc<AtomicBool>,
    sender: Option<SyncSender<WorkerCommand>>,
    handle: Option<thread::JoinHandle<Result<(), XtaskError>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancellationState {
    CancelDelivered,
    AlreadyQueued,
    Disconnected,
}

struct RegisteredTasks {
    tasks: Vec<RegisteredTask>,
    results: Receiver<WorkerMeasurement>,
    deadline: Instant,
    shutdown: Duration,
}

impl RegisteredTasks {
    fn execute<T>(
        scenario: &Scenario,
        operation: impl FnOnce(&mut Self) -> Result<T, XtaskError>,
    ) -> Result<(T, Vec<WorkerMeasurement>), XtaskError> {
        let mut owner = Self::spawn(scenario)?;
        let value = match operation(&mut owner) {
            Ok(value) => value,
            Err(error) => return owner.reconcile_failure(error),
        };
        let measurements = owner.reconcile()?;
        Ok((value, measurements))
    }
    fn spawn(scenario: &Scenario) -> Result<Self, XtaskError> {
        if scenario.spawn_site != REGISTERED_SPAWN_SITE {
            return Err(XtaskError::invalid(
                "bounded task registration",
                "unregistered spawn site was denied before task creation",
            ));
        }
        let deadline = Instant::now()
            .checked_add(scenario.shutdown)
            .ok_or_else(|| {
                XtaskError::invalid(
                    "bounded task registration",
                    "shutdown deadline cannot be represented",
                )
            })?;
        let (results_sender, results) = mpsc::sync_channel(scenario.max_tasks);
        let mut owner = Self {
            tasks: Vec::with_capacity(scenario.max_tasks),
            results,
            deadline,
            shutdown: scenario.shutdown,
        };
        for id in 0..scenario.max_tasks {
            let (sender, receiver) = mpsc::sync_channel(1);
            let cancel = Arc::new(AtomicBool::new(false));
            owner.tasks.push(RegisteredTask {
                id,
                cancel: Arc::clone(&cancel),
                sender: Some(sender),
                handle: None,
            });
            let worker_results = results_sender.clone();
            let handle = match thread::Builder::new()
                .name(format!("positron-quality-worker-{id}"))
                // positron-concurrency-spawn: RegisteredTasks::spawn\tquality-bounded-worker-v1
                .spawn(move || worker_loop(id, cancel, receiver, worker_results))
            {
                Ok(handle) => handle,
                Err(source) => {
                    return owner.reconcile_failure(XtaskError::io(
                        "spawn registered bounded quality task",
                        source,
                    ));
                },
            };
            let Some(task) = owner.tasks.last_mut() else {
                return owner.reconcile_failure(XtaskError::invalid(
                    "bounded task registration",
                    "registered task disappeared before its handle was retained",
                ));
            };
            task.handle = Some(handle);
        }
        drop(results_sender);
        Ok(owner)
    }

    fn dispatch(&mut self, id: usize, command: WorkerCommand) -> Result<(), XtaskError> {
        let task = self.tasks.get(id).ok_or_else(|| {
            XtaskError::invalid(
                "bounded task dispatch",
                "schedule referenced an unregistered task",
            )
        })?;
        let sender = task.sender.as_ref().ok_or_else(|| {
            XtaskError::invalid(
                "bounded task dispatch",
                "registered task sender was already closed",
            )
        })?;
        sender.try_send(command).map_err(|error| match error {
            TrySendError::Full(_) => XtaskError::invalid(
                "bounded task dispatch",
                "registered task command queue reached its finite capacity",
            ),
            TrySendError::Disconnected(_) => XtaskError::invalid(
                "bounded task dispatch",
                "registered task exited before its command was delivered",
            ),
        })
    }

    fn reconcile(mut self) -> Result<Vec<WorkerMeasurement>, XtaskError> {
        let mut measurements = Vec::with_capacity(self.tasks.len());
        while measurements.len() < self.tasks.len() {
            if Instant::now() >= self.deadline {
                return self.reconcile_failure(XtaskError::invalid(
                    "bounded task shutdown",
                    "registered tasks did not report before the shutdown deadline",
                ));
            }
            match self.results.try_recv() {
                Ok(measurement) => measurements.push(measurement),
                Err(TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
                Err(TryRecvError::Disconnected) => {
                    return self.reconcile_failure(XtaskError::invalid(
                        "bounded task shutdown",
                        "registered task result channel closed before every task reported",
                    ));
                },
            }
        }
        for task in &mut self.tasks {
            let Some(handle) = task.handle.take() else {
                return self.reconcile_failure(XtaskError::invalid(
                    "bounded task shutdown",
                    "registered task has no retained join handle",
                ));
            };
            match handle.join() {
                Ok(Ok(())) => {},
                Ok(Err(error)) => return self.reconcile_failure(error),
                Err(_) => {
                    return self.reconcile_failure(XtaskError::invalid(
                        "bounded task shutdown",
                        "registered task panicked instead of returning a closed outcome",
                    ));
                },
            }
        }
        if Instant::now() > self.deadline {
            return Err(XtaskError::invalid(
                "bounded task shutdown",
                "registered task joining exceeded the shutdown deadline",
            ));
        }
        Ok(measurements)
    }

    fn reconcile_failure<T>(mut self, original: XtaskError) -> Result<T, XtaskError> {
        let cleanup_started = Instant::now();
        let cleanup_deadline = cleanup_started
            .checked_add(self.shutdown)
            .unwrap_or(cleanup_started);
        let spawned_ids = self
            .tasks
            .iter()
            .filter(|task| task.handle.is_some())
            .map(|task| task.id)
            .collect::<Vec<_>>();
        let mut cancellation = Vec::new();
        for task in &mut self.tasks {
            task.cancel.store(true, Ordering::Release);
            if let Some(sender) = task.sender.as_ref() {
                let state = match sender.try_send(WorkerCommand::Cancel {
                    schedule_slot: usize::MAX,
                }) {
                    Ok(()) => CancellationState::CancelDelivered,
                    Err(TrySendError::Full(_)) => CancellationState::AlreadyQueued,
                    Err(TrySendError::Disconnected(_)) => CancellationState::Disconnected,
                };
                cancellation.push((task.id, state));
            }
            task.sender = None;
        }
        let mut cleanup_errors = Vec::new();
        let mut reported_ids = Vec::new();
        while Instant::now() < cleanup_deadline {
            match self.results.try_recv() {
                Ok(measurement) => reported_ids.push(measurement.id),
                Err(TryRecvError::Empty) => thread::yield_now(),
                Err(TryRecvError::Disconnected) => break,
            }
        }
        while self
            .tasks
            .iter()
            .filter_map(|task| task.handle.as_ref())
            .any(|handle| !handle.is_finished())
            && Instant::now() < cleanup_deadline
        {
            thread::yield_now();
        }
        if self
            .tasks
            .iter()
            .filter_map(|task| task.handle.as_ref())
            .any(|handle| !handle.is_finished())
        {
            eprintln!(
                "controlled bounded worker violated cooperative shutdown before the registered deadline"
            );
            std::process::abort();
        }
        let mut joined_ids = Vec::new();
        for task in &mut self.tasks {
            let Some(handle) = task.handle.take() else {
                continue;
            };
            joined_ids.push(task.id);
            match handle.join() {
                Ok(Ok(())) => {},
                Ok(Err(error)) => cleanup_errors.push(error.to_string()),
                Err(_) => {
                    cleanup_errors.push("registered task panicked during reconciliation".to_owned())
                },
            }
        }
        while let Ok(measurement) = self.results.try_recv() {
            reported_ids.push(measurement.id);
        }
        let mut completed_ids = joined_ids.clone();
        let mut cancelled_ids = cancellation
            .iter()
            .filter_map(|(id, state)| (*state == CancellationState::CancelDelivered).then_some(*id))
            .collect::<Vec<_>>();
        let mut already_queued_ids = cancellation
            .iter()
            .filter_map(|(id, state)| (*state == CancellationState::AlreadyQueued).then_some(*id))
            .collect::<Vec<_>>();
        let mut disconnected_ids = cancellation
            .iter()
            .filter_map(|(id, state)| (*state == CancellationState::Disconnected).then_some(*id))
            .collect::<Vec<_>>();
        for ids in [
            &mut cancelled_ids,
            &mut already_queued_ids,
            &mut disconnected_ids,
            &mut reported_ids,
            &mut completed_ids,
            &mut joined_ids,
        ] {
            ids.sort_unstable();
            ids.dedup();
        }
        let lifecycle = format!(
            "lifecycle-v1;spawned-ids={};cancelled-ids={};already-queued-ids={};disconnected-ids={};reported-ids={};completed-ids={};joined-ids={};shutdown-ms={};live=0",
            format_ids(&spawned_ids),
            format_ids(&cancelled_ids),
            format_ids(&already_queued_ids),
            format_ids(&disconnected_ids),
            format_ids(&reported_ids),
            format_ids(&completed_ids),
            format_ids(&joined_ids),
            cleanup_started.elapsed().as_millis(),
        );
        if cleanup_errors.is_empty() {
            Err(XtaskError::invalid(
                "bounded task lifecycle reconciliation",
                format!("{original}; {lifecycle}"),
            ))
        } else {
            Err(XtaskError::invalid(
                "bounded task lifecycle reconciliation",
                format!(
                    "{original}; reconciliation failures: {}; {lifecycle}",
                    cleanup_errors.join("; "),
                ),
            ))
        }
    }
}

fn format_ids(ids: &[usize]) -> String {
    ids.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn worker_loop(
    id: usize,
    cancel: Arc<AtomicBool>,
    receiver: Receiver<WorkerCommand>,
    results: SyncSender<WorkerMeasurement>,
) -> Result<(), XtaskError> {
    if cancel.load(Ordering::Acquire) {
        return Err(XtaskError::invalid(
            "bounded task worker",
            "worker observed cooperative cancellation before command receipt",
        ));
    }
    let command = receiver
        .recv_timeout(Duration::from_millis(25))
        .map_err(|error| {
            XtaskError::invalid(
                "bounded task worker",
                format!("worker command did not arrive within its finite wait: {error}"),
            )
        })?;
    cooperative_pause(&cancel, Duration::ZERO)?;
    if cancel.load(Ordering::Acquire) {
        return Err(XtaskError::invalid(
            "bounded task worker",
            "worker observed cooperative cancellation before command execution",
        ));
    }
    let (completion, schedule_slot) = match command {
        WorkerCommand::Execute { schedule_slot } => (WorkerCompletion::Executed, schedule_slot),
        WorkerCommand::Cancel { schedule_slot } => (WorkerCompletion::Cancelled, schedule_slot),
    };
    results
        .try_send(WorkerMeasurement {
            id,
            schedule_slot,
            completion,
        })
        .map_err(|error| match error {
            TrySendError::Full(_) => XtaskError::invalid(
                "bounded task worker",
                "bounded measurement queue reached capacity",
            ),
            TrySendError::Disconnected(_) => XtaskError::invalid(
                "bounded task worker",
                "task owner dropped its measurement queue before join",
            ),
        })
}

fn cooperative_pause(cancel: &AtomicBool, duration: Duration) -> Result<(), XtaskError> {
    let started = Instant::now();
    while started.elapsed() < duration {
        if cancel.load(Ordering::Acquire) {
            return Err(XtaskError::invalid(
                "bounded task worker",
                "worker observed cooperative cancellation during bounded work",
            ));
        }
        thread::park_timeout(Duration::from_millis(1));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservationOutcome {
    Granted,
    HardPressure,
}

struct ReservationLedger {
    capacity: usize,
    in_use: usize,
}

impl ReservationLedger {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            in_use: 0,
        }
    }

    fn reserve(&mut self) -> ReservationOutcome {
        if self.in_use >= self.capacity {
            ReservationOutcome::HardPressure
        } else {
            self.in_use += 1;
            ReservationOutcome::Granted
        }
    }

    fn release(&mut self) -> Result<(), XtaskError> {
        self.in_use = self.in_use.checked_sub(1).ok_or_else(|| {
            XtaskError::invalid(
                "bounded reservation ledger",
                "release occurred without a held reservation",
            )
        })?;
        Ok(())
    }
}

struct BoundedWorkQueue {
    capacity: usize,
    entries: VecDeque<usize>,
}

impl BoundedWorkQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::with_capacity(capacity),
        }
    }

    fn enqueue(&mut self, task: usize) -> Result<(), XtaskError> {
        if self.entries.len() >= self.capacity {
            return Err(XtaskError::invalid(
                "bounded work queue",
                "overload was rejected before unreserved queue growth",
            ));
        }
        self.entries.push_back(task);
        Ok(())
    }

    fn dequeue(&mut self) -> Result<usize, XtaskError> {
        self.entries.pop_front().ok_or_else(|| {
            XtaskError::invalid(
                "bounded work queue",
                "deterministic schedule dequeued an empty queue",
            )
        })
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub(crate) fn run_concurrency(
    registry: &FrozenBoundedRunnerRegistry,
    root: &Path,
) -> Result<String, XtaskError> {
    validate_registered_spawn_sites(root, registry)?;
    let scenario = registry.scenario(ScenarioGate::Concurrency)?;
    validate_concurrency_scenario(scenario)?;
    let ((), measurements) = RegisteredTasks::execute(scenario, |tasks| {
        tasks.dispatch(0, WorkerCommand::Cancel { schedule_slot: 0 })?;
        tasks.dispatch(1, WorkerCommand::Execute { schedule_slot: 1 })?;
        tasks.dispatch(2, WorkerCommand::Execute { schedule_slot: 2 })?;
        Ok(())
    })?;
    let record = measurement_record(scenario, &measurements, 0, 0, true);
    verify_measurement_record(scenario, &record, ScenarioGate::Concurrency)?;
    Ok(record)
}

pub(crate) fn run_resource(
    registry: &FrozenBoundedRunnerRegistry,
    root: &Path,
) -> Result<String, XtaskError> {
    validate_registered_spawn_sites(root, registry)?;
    let scenario = registry.scenario(ScenarioGate::Resource)?;
    validate_resource_scenario(scenario)?;
    let ((retries, reservations, queue_empty), measurements) =
        RegisteredTasks::execute(scenario, |tasks| {
            let mut queue = BoundedWorkQueue::new(scenario.queue_capacity);
            for task in 0..scenario.max_tasks {
                queue.enqueue(task)?;
            }
            let mut ledger = ReservationLedger::new(scenario.reservation_capacity);
            let mut retries = 0_usize;
            let first = queue.dequeue()?;
            if ledger.reserve() != ReservationOutcome::Granted {
                return Err(XtaskError::invalid(
                    "bounded resource runner",
                    "first reservation was rejected",
                ));
            }
            tasks.dispatch(first, WorkerCommand::Execute { schedule_slot: 0 })?;
            let second = queue.dequeue()?;
            if ledger.reserve() != ReservationOutcome::Granted {
                return Err(XtaskError::invalid(
                    "bounded resource runner",
                    "second reservation was rejected",
                ));
            }
            tasks.dispatch(second, WorkerCommand::Execute { schedule_slot: 1 })?;
            let third = queue.dequeue()?;
            while ledger.reserve() == ReservationOutcome::HardPressure {
                retries = retries.checked_add(1).ok_or_else(|| {
                    XtaskError::invalid("bounded resource runner", "retry accounting overflowed")
                })?;
                if retries > scenario.retry_limit {
                    return Err(XtaskError::invalid(
                        "bounded resource runner",
                        "retry storm exceeded the registered attempt ceiling",
                    ));
                }
                if retries == scenario.retry_limit {
                    ledger.release()?;
                }
            }
            tasks.dispatch(third, WorkerCommand::Execute { schedule_slot: 2 })?;
            ledger.release()?;
            ledger.release()?;
            Ok((retries, ledger.in_use, queue.is_empty()))
        })?;
    let record = measurement_record(scenario, &measurements, retries, reservations, queue_empty);
    verify_measurement_record(scenario, &record, ScenarioGate::Resource)?;
    Ok(record)
}

fn measurement_record(
    scenario: &Scenario,
    measurements: &[WorkerMeasurement],
    retries: usize,
    reservations: usize,
    queue_empty: bool,
) -> String {
    let mut ordered = measurements.to_vec();
    ordered.sort_by_key(|measurement| measurement.schedule_slot);
    let workers = ordered
        .iter()
        .map(|m| {
            format!(
                "{}:{}:{}",
                m.id,
                m.schedule_slot,
                match m.completion {
                    WorkerCompletion::Executed => "executed",
                    WorkerCompletion::Cancelled => "cancelled",
                }
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "measurement-v1;scenario={};schedule={};seed={};registered={};workers={workers};retries={retries};reservations={reservations};queue-empty={queue_empty};joined={};deadline-ms={}",
        scenario.id,
        scenario.schedule,
        scenario.seed,
        scenario.max_tasks,
        measurements.len(),
        scenario.shutdown.as_millis()
    )
}

fn verify_measurement_record(
    scenario: &Scenario,
    record: &str,
    gate: ScenarioGate,
) -> Result<(), XtaskError> {
    if record.len() > 4_096 || !record.starts_with("measurement-v1;") {
        return Err(XtaskError::invalid(
            "independent bounded measurement verifier",
            "measurement record is missing or exceeds its bound",
        ));
    }
    let mut fields = BTreeMap::new();
    for field in record.split(';').skip(1) {
        let Some((key, value)) = field.split_once('=') else {
            return Err(XtaskError::invalid(
                "independent bounded measurement verifier",
                "measurement record contains a malformed field",
            ));
        };
        if key.is_empty() || value.is_empty() || fields.insert(key, value).is_some() {
            return Err(XtaskError::invalid(
                "independent bounded measurement verifier",
                "measurement record contains a duplicate or empty field",
            ));
        }
    }
    if fields.get("scenario") != Some(&scenario.id.as_str())
        || fields.get("schedule") != Some(&scenario.schedule.as_str())
        || fields.get("seed") != Some(&scenario.seed.as_str())
    {
        return Err(XtaskError::invalid(
            "independent bounded measurement verifier",
            "frozen scenario identity is missing from measurement record",
        ));
    }
    let workers = fields.get("workers").ok_or_else(|| {
        XtaskError::invalid(
            "independent bounded measurement verifier",
            "worker measurements are omitted",
        )
    })?;
    let parsed = workers
        .split(',')
        .map(|worker| {
            let parts = worker.split(':').collect::<Vec<_>>();
            let [id, schedule_slot, completion] = parts.as_slice() else {
                return Err(XtaskError::invalid(
                    "independent bounded measurement verifier",
                    "worker measurement is malformed",
                ));
            };
            Ok(WorkerMeasurement {
                id: id.parse().map_err(|_| {
                    XtaskError::invalid(
                        "independent bounded measurement verifier",
                        "worker id is malformed",
                    )
                })?,
                schedule_slot: schedule_slot.parse().map_err(|_| {
                    XtaskError::invalid(
                        "independent bounded measurement verifier",
                        "worker slot is malformed",
                    )
                })?,
                completion: match *completion {
                    "executed" => WorkerCompletion::Executed,
                    "cancelled" => WorkerCompletion::Cancelled,
                    _ => {
                        return Err(XtaskError::invalid(
                            "independent bounded measurement verifier",
                            "worker completion is malformed",
                        ));
                    },
                },
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if fields
        .get("registered")
        .and_then(|value| value.parse::<usize>().ok())
        != Some(parsed.len())
    {
        return Err(XtaskError::invalid(
            "independent bounded measurement verifier",
            "worker measurement count does not match the retained registration",
        ));
    }
    if fields
        .get("joined")
        .and_then(|value| value.parse::<usize>().ok())
        != Some(parsed.len())
        || fields
            .get("deadline-ms")
            .and_then(|value| value.parse::<u128>().ok())
            != Some(scenario.shutdown.as_millis())
    {
        return Err(XtaskError::invalid(
            "independent bounded measurement verifier",
            "worker join or deadline evidence does not match the frozen lifecycle bound",
        ));
    }
    match gate {
        ScenarioGate::Concurrency => verify_concurrency(scenario, &parsed),
        ScenarioGate::Resource => verify_resource(
            scenario,
            &parsed,
            fields
                .get("retries")
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| {
                    XtaskError::invalid(
                        "independent bounded measurement verifier",
                        "retry record is malformed",
                    )
                })?,
            fields
                .get("reservations")
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| {
                    XtaskError::invalid(
                        "independent bounded measurement verifier",
                        "reservation record is malformed",
                    )
                })?,
            fields.get("queue-empty") == Some(&"true"),
        ),
    }
}

fn validate_concurrency_scenario(scenario: &Scenario) -> Result<(), XtaskError> {
    if scenario.max_tasks != 3
        || scenario.queue_capacity != 1
        || scenario.reservation_capacity != 1
        || scenario.retry_limit != 1
        || scenario.schedule != "cancel-then-join-v1"
        || scenario.expected != "cancelled-then-joined-v1"
    {
        return Err(XtaskError::invalid(
            "bounded concurrency scenario",
            "registered concurrency lifecycle bounds or deterministic schedule drifted",
        ));
    }
    Ok(())
}

fn validate_resource_scenario(scenario: &Scenario) -> Result<(), XtaskError> {
    if scenario.max_tasks != 3
        || scenario.queue_capacity != 3
        || scenario.reservation_capacity != 2
        || scenario.retry_limit != 2
        || scenario.schedule != "round-robin-pressure-v1"
        || scenario.expected != "fair-pressure-retry-leak-free-v1"
    {
        return Err(XtaskError::invalid(
            "bounded resource scenario",
            "registered resource bounds or deterministic schedule drifted",
        ));
    }
    Ok(())
}

fn verify_concurrency(
    scenario: &Scenario,
    measurements: &[WorkerMeasurement],
) -> Result<(), XtaskError> {
    if measurements.len() != scenario.max_tasks {
        return Err(XtaskError::invalid(
            "independent concurrency verifier",
            "task count differs from the retained schedule",
        ));
    }
    let outcomes = measurements
        .iter()
        .map(|measurement| {
            (
                measurement.id,
                (measurement.schedule_slot, measurement.completion),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if outcomes.len() != measurements.len() {
        return Err(XtaskError::invalid(
            "independent concurrency verifier",
            "worker identifiers are not unique in the retained schedule",
        ));
    }
    if outcomes.get(&0) != Some(&(0, WorkerCompletion::Cancelled))
        || outcomes.get(&1) != Some(&(1, WorkerCompletion::Executed))
        || outcomes.get(&2) != Some(&(2, WorkerCompletion::Executed))
    {
        return Err(XtaskError::invalid(
            "independent concurrency verifier",
            "retained task measurements do not satisfy cancellation and join schedule",
        ));
    }
    Ok(())
}

fn verify_resource(
    scenario: &Scenario,
    measurements: &[WorkerMeasurement],
    retries: usize,
    reservations: usize,
    queue_empty: bool,
) -> Result<(), XtaskError> {
    let completed = measurements
        .iter()
        .filter(|measurement| measurement.completion == WorkerCompletion::Executed)
        .count();
    let mut retained_order = measurements.to_vec();
    retained_order.sort_by_key(|measurement| measurement.schedule_slot);
    let fair_order = retained_order
        .iter()
        .map(|measurement| measurement.id)
        .collect::<Vec<_>>();
    let unique_ids = retained_order
        .iter()
        .map(|measurement| measurement.id)
        .collect::<BTreeSet<_>>();
    if completed != scenario.max_tasks
        || unique_ids.len() != measurements.len()
        || fair_order != [0, 1, 2]
        || retries != scenario.retry_limit
        || reservations != 0
        || !queue_empty
    {
        return Err(XtaskError::invalid(
            "independent resource verifier",
            "retained schedule and measurements do not prove fair bounded leak-free recovery",
        ));
    }
    Ok(())
}

fn validate_registered_spawn_sites(
    root: &Path,
    frozen: &FrozenBoundedRunnerRegistry,
) -> Result<(), XtaskError> {
    let registry_path = Path::new(SPAWN_SITE_REGISTRY_PATH);
    let registered = frozen.spawn_sites();
    let source_root = root.join("tools/xtask/src");
    let mut files = Vec::new();
    crate::registry::collect_files_with_extension(&source_root, "rs", 0, &mut files)?;
    let mut observed = BTreeMap::new();
    for source in files {
        let relative = source.strip_prefix(root).map_err(|_| {
            XtaskError::invalid_path(&source, "tooling source escaped its workspace root")
        })?;
        let relative = relative.to_string_lossy().into_owned();
        let source_text = fs::read_to_string(&source)
            .map_err(|error| XtaskError::io(format!("read {}", source.display()), error))?;
        let tokenized = tokenized_source(&source_text);
        let test_start = ["\n#[cfg(test)]", "\n#[cfg(all(test,"]
            .into_iter()
            .filter_map(|marker| tokenized.find(marker))
            .min();
        let production = test_start
            .and_then(|index| tokenized.get(..index))
            .unwrap_or(&tokenized);
        let compact_production = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        if compact_production.contains("std::thread::spawn(")
            || compact_production.contains("thread::spawn(")
        {
            return Err(XtaskError::invalid_path(
                &source,
                "direct unregistered thread spawn in activated tooling source",
            ));
        }
        for alias in imported_forbidden_alias_invocations(&compact_production) {
            let generic_alias = alias.strip_suffix('(').map(|name| format!("{name}::<"));
            if compact_production.contains(&alias)
                || generic_alias
                    .as_deref()
                    .is_some_and(|generic_alias| compact_production.contains(generic_alias))
            {
                return Err(XtaskError::invalid_path(
                    &source,
                    "unregistered imported concurrency primitive alias in activated tooling source",
                ));
            }
        }
        if [
            "mpsc::channel(",
            "unbounded_channel(",
            "VecDeque::new(",
            "tokio::spawn(",
            "async_std::task::spawn(",
        ]
        .into_iter()
        .any(|primitive| compact_production.contains(primitive))
        {
            return Err(XtaskError::invalid_path(
                &source,
                "unbounded concurrency primitive in activated tooling source",
            ));
        }
        let production_line_count = production.lines().count();
        let markers = source_text
            .lines()
            .take(production_line_count)
            .enumerate()
            .filter_map(|(offset, raw_line)| {
                raw_line
                    .trim_start()
                    .strip_prefix("// positron-concurrency-spawn: ")
                    .map(|value| (offset + 1, value))
            })
            .map(|(line_number, value)| {
                let Some((symbol, id)) = value.split_once("\\t") else {
                    return Err(XtaskError::invalid_path(
                        &source,
                        format!("spawn marker at tooling line {line_number} is malformed"),
                    ));
                };
                if symbol.is_empty() || id.is_empty() {
                    return Err(XtaskError::invalid_path(
                        &source,
                        format!("spawn marker at tooling line {line_number} is incomplete"),
                    ));
                }
                Ok((line_number, symbol.to_owned(), id.to_owned()))
            })
            .collect::<Result<Vec<_>, XtaskError>>()?;
        let spawn_count = compact_production.match_indices(".spawn(").count();
        if spawn_count != markers.len() {
            return Err(XtaskError::invalid_path(
                &source,
                "unregistered process or task spawn: every active method spawn must have exactly one registered marker",
            ));
        }
        for (line_number, symbol, id) in markers {
            let key = (relative.clone(), symbol, id);
            let Some(kind) = registered.get(&key) else {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!("unregistered semantic spawn site at tooling line {line_number}"),
                ));
            };
            let actual = if key.2 == REGISTERED_SPAWN_SITE {
                "thread"
            } else {
                "process"
            };
            if kind != actual {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!("spawn-site kind drift at tooling line {line_number}"),
                ));
            }
            if observed.insert(key, kind.clone()).is_some() {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!("duplicate observed semantic spawn site at tooling line {line_number}"),
                ));
            }
        }
    }
    if observed != *registered {
        return Err(XtaskError::invalid_path(
            registry_path,
            "registered spawn-site set does not exactly match active tooling source",
        ));
    }
    Ok(())
}

fn imported_forbidden_alias_invocations(compact: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    for import in compact.split("use").skip(1) {
        let Some(import) = import.split(';').next() else {
            continue;
        };
        if let Some(alias) = import.strip_prefix("std::threadas")
            && is_identifier(alias)
        {
            aliases.push(format!("{alias}::spawn("));
        }
        if let Some(alias) = import.strip_prefix("stdas")
            && is_identifier(alias)
        {
            aliases.push(format!("{alias}::thread::spawn("));
        }
        if let Some(alias) = import.strip_prefix("std::sync::mpscas")
            && is_identifier(alias)
        {
            aliases.push(format!("{alias}::channel("));
        }
        if let Some(alias) = import
            .strip_prefix("std::thread::spawnas")
            .or_else(|| import.strip_prefix("std::thread::{spawnas"))
        {
            let alias = alias.trim_end_matches('}');
            if is_identifier(alias) {
                aliases.push(format!("{alias}("));
            }
        }
        for (needle, invocation) in [
            ("std::thread::{spawnas", "("),
            ("std::{thread::spawnas", "("),
            ("std::sync::mpsc::{channelas", "("),
            ("std::{sync::mpsc::channelas", "("),
            ("std::sync::mpsc::{sync_channelas", "("),
        ] {
            let mut remaining = import;
            while let Some((_, tail)) = remaining.split_once(needle) {
                let alias = tail.split([',', '}', ';']).next().unwrap_or_default();
                if is_identifier(alias) {
                    aliases.push(format!("{alias}{invocation}"));
                }
                remaining = tail;
            }
        }
    }
    for primitive in ["std::thread::spawn", "std::sync::mpsc::channel"] {
        let mut remaining = compact;
        while let Some((before, after)) = remaining.rsplit_once(primitive) {
            if before.ends_with('=') && after.starts_with(';') {
                return vec![primitive.to_owned()];
            }
            remaining = before;
        }
    }
    aliases
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn tokenized_source(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    let mut block_comment = false;
    let mut quoted = None;
    while let Some(character) = characters.next() {
        if block_comment {
            if character == '*' && characters.peek() == Some(&'/') {
                let _ = characters.next();
                output.push_str("  ");
                block_comment = false;
            } else if character == '\n' {
                output.push('\n');
            } else {
                output.push(' ');
            }
            continue;
        }
        if let Some(quote) = quoted {
            if character == '\\' {
                output.push(' ');
                if let Some(next) = characters.next() {
                    output.push(if next == '\n' { '\n' } else { ' ' });
                }
            } else if character == quote {
                output.push(' ');
                quoted = None;
            } else {
                output.push(if character == '\n' { '\n' } else { ' ' });
            }
            continue;
        }
        if character == '/' && characters.peek() == Some(&'/') {
            let _ = characters.next();
            output.push_str("  ");
            for next in characters.by_ref() {
                output.push(if next == '\n' { '\n' } else { ' ' });
                if next == '\n' {
                    break;
                }
            }
        } else if character == '/' && characters.peek() == Some(&'*') {
            let _ = characters.next();
            output.push_str("  ");
            block_comment = true;
        } else if character == '"' {
            output.push(' ');
            quoted = Some(character);
        } else if character == '\'' {
            let mut lookahead = characters.clone();
            let first = lookahead.next();
            let second = lookahead.next();
            if first == Some('\\') || second == Some('\'') {
                output.push(' ');
                quoted = Some(character);
            } else {
                output.push(character);
            }
        } else {
            output.push(character);
        }
    }
    output
}
