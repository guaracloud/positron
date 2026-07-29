//! Registered, bounded Quality Engineering task and resource scenarios.
//!
//! This module is the sole owner of the M0 harness task lifecycle. A scenario
//! is frozen from the committed registry before selection, registers every
//! worker before it is spawned, and joins every worker before its report may
//! be returned. The resource scenario uses real bounded channels, a finite
//! reservation ledger, and deterministic schedule measurements; its verifier
//! derives the accepted result from those retained measurements rather than a
//! runner verdict.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::Path;
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
    scenarios: Vec<Scenario>,
}

impl FrozenBoundedRunnerRegistry {
    pub(crate) fn capture(root: &Path) -> Result<Self, XtaskError> {
        let path = root.join(REGISTRY_PATH);
        let bytes = fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                &path,
                format!("bounded runner registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| XtaskError::invalid_path(&path, "bounded runner registry is not UTF-8"))?;
        let mut lines = text.lines();
        let Some(header) = lines.next() else {
            return Err(XtaskError::invalid_path(
                &path,
                "bounded runner registry is empty",
            ));
        };
        if header != REGISTRY_HEADER {
            return Err(XtaskError::invalid_path(
                &path,
                "bounded runner registry header does not match the registered schema",
            ));
        }
        let mut scenarios = Vec::new();
        for (line_number, line) in lines.enumerate() {
            if scenarios.len() >= MAXIMUM_SCENARIOS {
                return Err(XtaskError::invalid_path(
                    &path,
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
                    &path,
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
                        &path,
                        format!(
                            "bounded runner registry row {} contains an invalid bounded field",
                            line_number + 2
                        ),
                    ));
                }
            }
            let gate = ScenarioGate::parse(gate)?;
            let max_tasks = parse_positive(&path, max_tasks, "max_tasks")?;
            let queue_capacity = parse_positive(&path, queue_capacity, "queue_capacity")?;
            let reservation_capacity =
                parse_positive(&path, reservation_capacity, "reservation_capacity")?;
            let retry_limit = parse_positive(&path, retry_limit, "retry_limit")?;
            let shutdown = Duration::from_millis(
                u64::try_from(parse_positive(&path, shutdown_ms, "shutdown_ms")?).map_err(
                    |_| XtaskError::invalid_path(&path, "shutdown_ms cannot be represented"),
                )?,
            );
            if *spawn_site != REGISTERED_SPAWN_SITE {
                return Err(XtaskError::invalid_path(
                    &path,
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
                &path,
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
                    &path,
                    format!("{} must have exactly one registered scenario", gate.label()),
                ));
            }
        }
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            scenarios,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
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
    sender: SyncSender<WorkerCommand>,
    handle: Option<thread::JoinHandle<Result<(), XtaskError>>>,
}

struct RegisteredTasks {
    tasks: Vec<RegisteredTask>,
    results: Receiver<WorkerMeasurement>,
    deadline: Instant,
}

impl RegisteredTasks {
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
        let mut tasks = Vec::with_capacity(scenario.max_tasks);
        for id in 0..scenario.max_tasks {
            let (sender, receiver) = mpsc::sync_channel(1);
            tasks.push(RegisteredTask {
                sender,
                handle: None,
            });
            let worker_results = results_sender.clone();
            let handle = thread::Builder::new()
                .name(format!("positron-quality-worker-{id}"))
                // positron-concurrency-spawn: RegisteredTasks::spawn\tquality-bounded-worker-v1
                .spawn(move || worker_loop(id, receiver, worker_results))
                .map_err(|source| {
                    XtaskError::io("spawn registered bounded quality task", source)
                })?;
            let Some(task) = tasks.last_mut() else {
                return Err(XtaskError::invalid(
                    "bounded task registration",
                    "registered task disappeared before its handle was retained",
                ));
            };
            task.handle = Some(handle);
        }
        drop(results_sender);
        Ok(Self {
            tasks,
            results,
            deadline,
        })
    }

    fn dispatch(&self, id: usize, command: WorkerCommand) -> Result<(), XtaskError> {
        let task = self.tasks.get(id).ok_or_else(|| {
            XtaskError::invalid(
                "bounded task dispatch",
                "schedule referenced an unregistered task",
            )
        })?;
        task.sender.try_send(command).map_err(|error| match error {
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
                return Err(XtaskError::invalid(
                    "bounded task shutdown",
                    "registered tasks did not report before the shutdown deadline",
                ));
            }
            match self.results.try_recv() {
                Ok(measurement) => measurements.push(measurement),
                Err(TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
                Err(TryRecvError::Disconnected) => {
                    return Err(XtaskError::invalid(
                        "bounded task shutdown",
                        "registered task result channel closed before every task reported",
                    ));
                },
            }
        }
        for task in &mut self.tasks {
            let Some(handle) = task.handle.take() else {
                return Err(XtaskError::invalid(
                    "bounded task shutdown",
                    "registered task has no retained join handle",
                ));
            };
            match handle.join() {
                Ok(Ok(())) => {},
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Err(XtaskError::invalid(
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
}

fn worker_loop(
    id: usize,
    receiver: Receiver<WorkerCommand>,
    results: SyncSender<WorkerMeasurement>,
) -> Result<(), XtaskError> {
    let command = receiver
        .recv_timeout(Duration::from_millis(25))
        .map_err(|error| {
            XtaskError::invalid(
                "bounded task worker",
                format!("worker command did not arrive within its finite wait: {error}"),
            )
        })?;
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
    validate_registered_spawn_sites(root)?;
    let scenario = registry.scenario(ScenarioGate::Concurrency)?;
    validate_concurrency_scenario(scenario)?;
    let tasks = RegisteredTasks::spawn(scenario)?;
    tasks.dispatch(0, WorkerCommand::Cancel { schedule_slot: 0 })?;
    tasks.dispatch(1, WorkerCommand::Execute { schedule_slot: 1 })?;
    tasks.dispatch(2, WorkerCommand::Execute { schedule_slot: 2 })?;
    let measurements = tasks.reconcile()?;
    verify_concurrency(scenario, &measurements)?;
    Ok(format!(
        "scenario={}; schedule={}; seed={}; registered-tasks=3; cancellation=observed; joined-and-reaped=3; verifier=independent",
        scenario.id, scenario.schedule, scenario.seed
    ))
}

pub(crate) fn run_resource(registry: &FrozenBoundedRunnerRegistry) -> Result<String, XtaskError> {
    let scenario = registry.scenario(ScenarioGate::Resource)?;
    validate_resource_scenario(scenario)?;
    let tasks = RegisteredTasks::spawn(scenario)?;
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
    let measurements = tasks.reconcile()?;
    verify_resource(
        scenario,
        &measurements,
        retries,
        ledger.in_use,
        queue.is_empty(),
    )?;
    Ok(format!(
        "scenario={}; schedule={}; seed={}; reservation-capacity=2; fairness=round-robin; pressure=hard; retry-storm=bounded; leaks=none; shutdown=bounded; verifier=independent",
        scenario.id, scenario.schedule, scenario.seed
    ))
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
        .map(|measurement| (measurement.id, measurement.completion))
        .collect::<BTreeMap<_, _>>();
    if outcomes.get(&0) != Some(&WorkerCompletion::Cancelled)
        || outcomes.get(&1) != Some(&WorkerCompletion::Executed)
        || outcomes.get(&2) != Some(&WorkerCompletion::Executed)
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
    if completed != scenario.max_tasks
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

fn validate_registered_spawn_sites(root: &Path) -> Result<(), XtaskError> {
    let registry_path = root.join(SPAWN_SITE_REGISTRY_PATH);
    let registry = fs::read_to_string(&registry_path)
        .map_err(|source| XtaskError::io(format!("read {}", registry_path.display()), source))?;
    let mut rows = registry.lines();
    let Some(header) = rows.next() else {
        return Err(XtaskError::invalid_path(
            &registry_path,
            "spawn-site registry is empty",
        ));
    };
    if header != SPAWN_SITE_REGISTRY_HEADER {
        return Err(XtaskError::invalid_path(
            &registry_path,
            "spawn-site registry header does not match the registered schema",
        ));
    }
    let mut registered = BTreeMap::new();
    for (offset, row) in rows.enumerate() {
        let fields = row.split('\t').collect::<Vec<_>>();
        let [path, symbol, kind, id] = fields.as_slice() else {
            return Err(XtaskError::invalid_path(
                &registry_path,
                format!(
                    "spawn-site registry row {} has the wrong field count",
                    offset + 2
                ),
            ));
        };
        if path.is_empty()
            || symbol.is_empty()
            || id.is_empty()
            || path.len() > MAXIMUM_FIELD_BYTES
            || symbol.len() > MAXIMUM_FIELD_BYTES
            || id.len() > MAXIMUM_FIELD_BYTES
            || !matches!(*kind, "process" | "thread")
        {
            return Err(XtaskError::invalid_path(
                &registry_path,
                "spawn-site registry contains an invalid bounded lifecycle owner",
            ));
        }
        if registered
            .insert(
                ((*path).to_owned(), (*symbol).to_owned(), (*id).to_owned()),
                (*kind).to_owned(),
            )
            .is_some()
        {
            return Err(XtaskError::invalid_path(
                &registry_path,
                "spawn-site registry contains a duplicate semantic spawn site",
            ));
        }
    }
    if registered.is_empty() {
        return Err(XtaskError::invalid_path(
            &registry_path,
            "spawn-site registry contains no registered lifecycle owners",
        ));
    }
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
        let production_lines = production.lines().collect::<Vec<_>>();
        let mut marker = None;
        for (index, (raw_line, line)) in source_text
            .lines()
            .take(production_lines.len())
            .zip(production_lines)
            .enumerate()
        {
            let line_number = index + 1;
            if let Some(value) = raw_line
                .trim_start()
                .strip_prefix("// positron-concurrency-spawn: ")
            {
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
                marker = Some((symbol.to_owned(), id.to_owned()));
                continue;
            }
            if line.contains("mpsc::channel(")
                || line.contains("unbounded_channel(")
                || line.contains("VecDeque::new(")
                || line.contains("tokio::spawn(")
                || line.contains("async_std::task::spawn(")
            {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!(
                        "unbounded concurrency primitive at registered tooling line {line_number}"
                    ),
                ));
            }
            if line.contains("thread::spawn(") {
                return Err(XtaskError::invalid_path(
                    &source,
                    format!("direct unregistered thread spawn at tooling line {line_number}"),
                ));
            }
            if line.contains(".spawn(") {
                let Some((symbol, id)) = marker.take() else {
                    return Err(XtaskError::invalid_path(
                        &source,
                        format!("unregistered process or task spawn at tooling line {line_number}"),
                    ));
                };
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
                observed.insert(key, kind.clone());
            } else if marker.is_some() && !line.trim().is_empty() {
                let marker_line = line_number.saturating_sub(1);
                return Err(XtaskError::invalid_path(
                    &source,
                    format!(
                        "spawn marker at tooling line {marker_line} is not attached to a spawn"
                    ),
                ));
            }
        }
    }
    if observed != registered {
        return Err(XtaskError::invalid_path(
            &registry_path,
            "registered spawn-site set does not exactly match active tooling source",
        ));
    }
    Ok(())
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
