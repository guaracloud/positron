//! Registered, bounded Quality Engineering task and resource scenarios.
//!
//! This module owns the frozen scenarios, resource accounting, measurement
//! serialization, and independent verification. `registered_task_lifecycle`
//! owns worker registration, cancellation, completion, and exact join
//! observation; `concurrency_source_policy` owns spawn-site and forbidden
//! primitive resolution. The resource scenario uses real bounded channels, a
//! finite reservation ledger, and deterministic schedule measurements rather
//! than a runner verdict.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::concurrency_source_policy::SpawnSiteRegistry;
use crate::error::XtaskError;
use crate::registered_task_lifecycle::{
    LifecycleResult, RegisteredTasks, WorkerCommand, WorkerCompletion, WorkerMeasurement,
};

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
const CHILD_PROCESS_RECONCILIATION_RESERVE: Duration = Duration::from_millis(50);
const MAXIMUM_CHILD_ARGUMENT_BYTES: usize = 32_768;
const MAXIMUM_CHILD_OUTCOME_BYTES: usize = 8_192;

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

    pub(crate) fn child_arguments(
        &self,
        gate: &str,
        outcome: &Path,
    ) -> Result<Vec<OsString>, XtaskError> {
        let registry = hex_encode(&self.bytes)?;
        let spawn_sites = hex_encode(&self.spawn_site_bytes)?;
        Ok(vec![
            OsString::from("quality-bounded-runner"),
            OsString::from(gate),
            OsString::from(registry),
            OsString::from(spawn_sites),
            outcome.as_os_str().to_owned(),
        ])
    }

    pub(crate) fn retained_child_invocation_matches(
        gate: &str,
        timeout_ms: u128,
        arguments: &[&str],
    ) -> bool {
        let [
            "quality-bounded-runner",
            recorded_gate,
            registry,
            spawn_sites,
            outcome,
        ] = arguments
        else {
            return false;
        };
        if *recorded_gate != gate {
            return false;
        }
        let outcome = Path::new(outcome);
        let outcome_name_matches = outcome
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with("bounded-runner-") && name.ends_with(".out"));
        if !outcome.is_absolute() || !outcome_name_matches {
            return false;
        }
        let Ok(registry_bytes) = hex_decode(registry) else {
            return false;
        };
        let Ok(spawn_site_bytes) = hex_decode(spawn_sites) else {
            return false;
        };
        let Ok(parsed_gate) = ScenarioGate::parse(gate) else {
            return false;
        };
        FrozenBoundedRunnerRegistry::capture(registry_bytes, spawn_site_bytes)
            .and_then(|frozen| {
                frozen.scenario(parsed_gate)?;
                frozen.process_work_budget(gate)
            })
            .is_ok_and(|budget| budget.as_millis() == timeout_ms)
    }

    pub(crate) fn process_work_budget(&self, gate: &str) -> Result<Duration, XtaskError> {
        let scenario = self.scenario(ScenarioGate::parse(gate)?)?;
        scenario
            .shutdown
            .checked_sub(CHILD_PROCESS_RECONCILIATION_RESERVE)
            .ok_or_else(|| {
                XtaskError::invalid(
                    "bounded runner process lifecycle",
                    "registered shutdown bound does not reserve process reconciliation time",
                )
            })
    }

    pub(crate) fn shutdown_bound(&self, gate: &str) -> Result<Duration, XtaskError> {
        Ok(self.scenario(ScenarioGate::parse(gate)?)?.shutdown)
    }
}

fn hex_encode(bytes: &[u8]) -> Result<String, XtaskError> {
    let capacity = bytes.len().checked_mul(2).ok_or_else(|| {
        XtaskError::invalid(
            "bounded runner child arguments",
            "hex-encoded field length cannot be represented",
        )
    })?;
    if capacity > MAXIMUM_CHILD_ARGUMENT_BYTES {
        return Err(XtaskError::invalid(
            "bounded runner child arguments",
            "hex-encoded field exceeds its exact maximum",
        ));
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(capacity);
    for byte in bytes {
        encoded.push(char::from(hex_digit(HEX, byte >> 4)?));
        encoded.push(char::from(hex_digit(HEX, byte & 0x0f)?));
    }
    Ok(encoded)
}

fn hex_digit(digits: &[u8; 16], index: u8) -> Result<u8, XtaskError> {
    digits.get(usize::from(index)).copied().ok_or_else(|| {
        XtaskError::invalid(
            "bounded runner child arguments",
            "hex digit index escaped its canonical alphabet",
        )
    })
}

pub(crate) fn run_process(arguments: impl Iterator<Item = String>) -> Result<(), XtaskError> {
    let arguments = arguments.take(5).collect::<Vec<_>>();
    let [gate, registry, spawn_sites, outcome] = arguments.as_slice() else {
        return Err(XtaskError::usage(
            "quality-bounded-runner requires one gate, two frozen registries, and one outcome path",
        ));
    };
    let outcome = PathBuf::from(outcome);
    let result = (|| {
        let registry =
            FrozenBoundedRunnerRegistry::capture(hex_decode(registry)?, hex_decode(spawn_sites)?)?;
        let record = match ScenarioGate::parse(gate)? {
            ScenarioGate::Concurrency => run_concurrency_scenario(&registry)?,
            ScenarioGate::Resource => run_resource_scenario(&registry)?,
        };
        Ok(record)
    })();
    write_child_outcome(&outcome, &result)?;
    result.map(|_| ())
}

fn hex_decode(encoded: &str) -> Result<Vec<u8>, XtaskError> {
    if encoded.len() > MAXIMUM_CHILD_ARGUMENT_BYTES || !encoded.len().is_multiple_of(2) {
        return Err(XtaskError::invalid(
            "bounded runner child arguments",
            "hex-encoded field has an invalid bounded length",
        ));
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let [high, low] = pair else {
                return Err(XtaskError::invalid(
                    "bounded runner child arguments",
                    "hex-encoded field contains an incomplete byte",
                ));
            };
            let high = hex_nibble(*high)?;
            let low = hex_nibble(*low)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, XtaskError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(XtaskError::invalid(
            "bounded runner child arguments",
            "hex-encoded field contains a non-canonical digit",
        )),
    }
}

fn write_child_outcome(path: &Path, result: &Result<String, XtaskError>) -> Result<(), XtaskError> {
    let root = std::env::current_dir()
        .map_err(|source| XtaskError::io("resolve bounded runner workspace", source))?;
    let parent = path.parent().ok_or_else(|| {
        XtaskError::invalid_path(path, "bounded runner outcome path has no parent")
    })?;
    if !path.is_absolute() || !parent.starts_with(root.join("target/quality/tmp")) {
        return Err(XtaskError::invalid_path(
            path,
            "bounded runner outcome path escaped the owned quality temporary root",
        ));
    }
    let content = match result {
        Ok(record) => format!("ok\n{record}\n"),
        Err(error) => format!("error\n{error}\n"),
    };
    if content.len() > MAXIMUM_CHILD_OUTCOME_BYTES {
        return Err(XtaskError::invalid_path(
            path,
            "bounded runner outcome exceeds its exact maximum",
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| XtaskError::io("create bounded runner outcome", source))?;
    file.write_all(content.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| XtaskError::io("write bounded runner outcome", source))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| XtaskError::io("synchronize bounded runner outcome parent", source))
}

pub(crate) fn validate_source_policy(
    registry: &FrozenBoundedRunnerRegistry,
    root: &Path,
) -> Result<(), XtaskError> {
    crate::concurrency_source_policy::validate_registered_spawn_sites(
        root,
        Path::new(SPAWN_SITE_REGISTRY_PATH),
        registry.spawn_sites(),
        REGISTERED_SPAWN_SITE,
    )
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

fn run_concurrency_scenario(registry: &FrozenBoundedRunnerRegistry) -> Result<String, XtaskError> {
    let scenario = registry.scenario(ScenarioGate::Concurrency)?;
    validate_concurrency_scenario(scenario)?;
    let LifecycleResult {
        value: (),
        measurements,
        joined_ids,
    } = RegisteredTasks::execute(
        scenario.max_tasks,
        scenario.shutdown,
        &scenario.spawn_site,
        REGISTERED_SPAWN_SITE,
        |tasks| {
            tasks.dispatch(0, WorkerCommand::Cancel { schedule_slot: 0 })?;
            tasks.dispatch(1, WorkerCommand::Execute { schedule_slot: 1 })?;
            tasks.dispatch(2, WorkerCommand::Execute { schedule_slot: 2 })?;
            Ok(())
        },
    )?;
    let record = measurement_record(scenario, &measurements, &joined_ids, 0, 0, true);
    verify_measurement_record(scenario, &record, ScenarioGate::Concurrency)?;
    Ok(record)
}

fn run_resource_scenario(registry: &FrozenBoundedRunnerRegistry) -> Result<String, XtaskError> {
    let scenario = registry.scenario(ScenarioGate::Resource)?;
    validate_resource_scenario(scenario)?;
    let LifecycleResult {
        value: (retries, reservations, queue_empty),
        measurements,
        joined_ids,
    } = RegisteredTasks::execute(
        scenario.max_tasks,
        scenario.shutdown,
        &scenario.spawn_site,
        REGISTERED_SPAWN_SITE,
        |tasks| {
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
        },
    )?;
    let record = measurement_record(
        scenario,
        &measurements,
        &joined_ids,
        retries,
        reservations,
        queue_empty,
    );
    verify_measurement_record(scenario, &record, ScenarioGate::Resource)?;
    Ok(record)
}

fn measurement_record(
    scenario: &Scenario,
    measurements: &[WorkerMeasurement],
    joined_ids: &[usize],
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
    let mut joined_ids = joined_ids.to_vec();
    joined_ids.sort_unstable();
    let joined = joined_ids
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "measurement-v1;scenario={};schedule={};seed={};registered={};workers={workers};retries={retries};reservations={reservations};queue-empty={queue_empty};joined-ids={joined};deadline-ms={}",
        scenario.id,
        scenario.schedule,
        scenario.seed,
        scenario.max_tasks,
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
    let expected_identity = (0..scenario.max_tasks).collect::<BTreeSet<_>>();
    let worker_ids = parsed
        .iter()
        .map(|measurement| measurement.id)
        .collect::<BTreeSet<_>>();
    if worker_ids != expected_identity || worker_ids.len() != parsed.len() {
        return Err(XtaskError::invalid(
            "independent bounded measurement verifier",
            "worker identifiers do not exactly match the registered workers",
        ));
    }
    let schedule_slots = parsed
        .iter()
        .map(|measurement| measurement.schedule_slot)
        .collect::<BTreeSet<_>>();
    if schedule_slots != expected_identity || schedule_slots.len() != parsed.len() {
        return Err(XtaskError::invalid(
            "independent bounded measurement verifier",
            "worker schedule slots are not unique and contiguous",
        ));
    }
    let joined_ids = fields
        .get("joined-ids")
        .ok_or_else(|| {
            XtaskError::invalid(
                "independent bounded measurement verifier",
                "observed join records are omitted",
            )
        })?
        .split(',')
        .map(|id| {
            id.parse::<usize>().map_err(|_| {
                XtaskError::invalid(
                    "independent bounded measurement verifier",
                    "observed join record is malformed",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_joined_ids = (0..scenario.max_tasks).collect::<Vec<_>>();
    if joined_ids != expected_joined_ids {
        return Err(XtaskError::invalid(
            "independent bounded measurement verifier",
            "observed join records do not match the registered workers",
        ));
    }
    if fields
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
