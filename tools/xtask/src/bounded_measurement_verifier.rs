//! Parent-owned verification of bounded-runner measurement records.
//!
//! The controlled child produces a raw measurement and may diagnose its own
//! output. Only this module decides whether that child record can satisfy the
//! parent quality gate. Its inputs are the parent-captured gate descriptor and
//! frozen registry bytes, not child-produced verdict fields.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::controlled_execution::ExecutionVerdict;
use crate::error::XtaskError;
use crate::registry::Gate;

const VERIFIER_IDENTITY: &str = "parent-bounded-measurement-verifier-v1";
const VERIFIER_VERSION: &str = "1";
const VERIFIER_CONTRACT: &str = "parent-bounded-measurement-verifier-v1|exact-gate-descriptor|exact-scenario-registry|exact-spawn-registry|measurement-v1|canonical-fields|closed-semantics";
const VERIFIER_CONTRACT_SHA256: &str =
    "sha256:20a2dc38a14b0fdf864234b574144df77cfadf33b79335fe7124f68832d20be3";
const SCENARIO_HEADER: &str = "scenario_id\tgate_id\tspawn_site\tschedule\tseed\tmax_tasks\tqueue_capacity\treservation_capacity\tretry_limit\tshutdown_ms\texpected";
const SPAWN_HEADER: &str = "path\tsymbol\tkind\tid";
const MEASUREMENT_FIELDS: [&str; 10] = [
    "scenario",
    "schedule",
    "seed",
    "registered",
    "workers",
    "retries",
    "reservations",
    "queue-empty",
    "joined-ids",
    "shutdown-ms",
];
const MAXIMUM_REGISTRY_BYTES: usize = 16_384;
const MAXIMUM_MEASUREMENT_BYTES: usize = 4_096;
const MAXIMUM_FIELD_BYTES: usize = 96;

pub(crate) struct VerificationInput<'input> {
    pub(crate) gate: &'input Gate,
    pub(crate) scenario_registry: &'input [u8],
    pub(crate) spawn_registry: &'input [u8],
    pub(crate) measurement: &'input str,
    pub(crate) execution: &'input ExecutionVerdict,
}

pub(crate) struct VerifiedMeasurement {
    evidence: String,
}

impl VerifiedMeasurement {
    pub(crate) fn evidence(&self) -> &str {
        &self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateKind {
    Concurrency,
    Resource,
}

impl GateKind {
    fn from_gate(gate: &Gate) -> Result<Self, XtaskError> {
        match gate.id.as_str() {
            "EG-CONCURRENCY" => Ok(Self::Concurrency),
            "EG-RESOURCE" => Ok(Self::Resource),
            _ => closed("parent verifier received an unsupported gate descriptor"),
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Concurrency => "EG-CONCURRENCY",
            Self::Resource => "EG-RESOURCE",
        }
    }
}

#[derive(Debug)]
struct Scenario {
    id: String,
    gate: GateKind,
    spawn_site: String,
    schedule: String,
    seed: String,
    max_tasks: usize,
    queue_capacity: usize,
    reservation_capacity: usize,
    retry_limit: usize,
    shutdown_ms: usize,
    expected: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Completion {
    Executed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Worker {
    id: usize,
    slot: usize,
    completion: Completion,
}

pub(crate) fn verify(input: VerificationInput<'_>) -> Result<VerifiedMeasurement, XtaskError> {
    let verifier_digest = sha256(VERIFIER_CONTRACT.as_bytes());
    if verifier_digest != VERIFIER_CONTRACT_SHA256 {
        return closed("stable verifier contract digest does not match its registered identity");
    }
    let gate_kind = GateKind::from_gate(input.gate)?;
    validate_gate_descriptor(input.gate, gate_kind)?;
    if !input.execution.status.success() {
        return closed("controlled child did not return a successful reconciled execution verdict");
    }

    let scenarios = parse_scenarios(input.scenario_registry)?;
    validate_registered_scenarios(&scenarios)?;
    let scenario = scenarios.get(gate_kind.id()).ok_or_else(|| {
        verifier_error("parent-captured scenario registry omitted the selected gate")
    })?;
    validate_spawn_registry(input.spawn_registry, scenario)?;
    verify_measurement(input.measurement, scenario)?;

    let evidence = format!(
        "parent-measurement-verification-v1;identity={VERIFIER_IDENTITY};version={VERIFIER_VERSION};verifier-sha256={verifier_digest};verdict=passed;gate={};gate-descriptor-sha256={};scenario-registry-sha256={};spawn-registry-sha256={};measurement-sha256={};child-self-verification=diagnostic-only;process-reaped=true;live=0",
        gate_kind.id(),
        gate_descriptor_digest(input.gate),
        sha256(input.scenario_registry),
        sha256(input.spawn_registry),
        sha256(input.measurement.as_bytes()),
    );
    Ok(VerifiedMeasurement { evidence })
}

fn validate_gate_descriptor(gate: &Gate, kind: GateKind) -> Result<(), XtaskError> {
    let expected_stages = ["EXT", "PR", "QUAL"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let (coordinator, timeout_seconds, runner) = match kind {
        GateKind::Concurrency => ("Application Runtime", 900, "concurrency"),
        GateKind::Resource => ("Storage Kernel", 1_800, "resource"),
    };
    if gate.id != kind.id()
        || gate.stages != expected_stages
        || gate.coordinator != coordinator
        || gate.timeout_seconds != timeout_seconds
        || gate.memory_mib != 4_096
        || gate.exception_class != "non-waivable"
        || gate.activation != "risk"
        || gate.runner != runner
    {
        return closed("parent-captured gate descriptor does not match the frozen gate contract");
    }
    Ok(())
}

fn gate_descriptor_digest(gate: &Gate) -> String {
    let stages = gate
        .stages
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("|");
    sha256(
        format!(
            "gate-descriptor-v1\0{}\0{stages}\0{}\0{}\0{}\0{}\0{}\0{}",
            gate.id,
            gate.coordinator,
            gate.timeout_seconds,
            gate.memory_mib,
            gate.exception_class,
            gate.activation,
            gate.runner,
        )
        .as_bytes(),
    )
}

fn parse_scenarios(bytes: &[u8]) -> Result<BTreeMap<String, Scenario>, XtaskError> {
    if bytes.len() > MAXIMUM_REGISTRY_BYTES {
        return closed("parent-captured scenario registry exceeds its exact byte bound");
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| verifier_error("parent-captured scenario registry is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(SCENARIO_HEADER) {
        return closed("parent-captured scenario registry header is malformed or stale");
    }
    let mut scenarios = BTreeMap::new();
    for line in lines {
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
            return closed("parent-captured scenario registry row is malformed");
        };
        for field in &fields {
            if field.is_empty() || field.len() > MAXIMUM_FIELD_BYTES {
                return closed("parent-captured scenario registry contains an invalid field");
            }
        }
        let gate = match *gate {
            "EG-CONCURRENCY" => GateKind::Concurrency,
            "EG-RESOURCE" => GateKind::Resource,
            _ => return closed("parent-captured scenario registry contains a stale gate"),
        };
        let scenario = Scenario {
            id: (*id).to_owned(),
            gate,
            spawn_site: (*spawn_site).to_owned(),
            schedule: (*schedule).to_owned(),
            seed: (*seed).to_owned(),
            max_tasks: parse_positive(max_tasks, "scenario max_tasks")?,
            queue_capacity: parse_positive(queue_capacity, "scenario queue_capacity")?,
            reservation_capacity: parse_positive(
                reservation_capacity,
                "scenario reservation_capacity",
            )?,
            retry_limit: parse_positive(retry_limit, "scenario retry_limit")?,
            shutdown_ms: parse_positive(shutdown_ms, "scenario shutdown_ms")?,
            expected: (*expected).to_owned(),
        };
        if scenarios.insert(gate.id().to_owned(), scenario).is_some() {
            return closed("parent-captured scenario registry contains a duplicate gate");
        }
    }
    if scenarios.len() != 2 {
        return closed("parent-captured scenario registry has a missing or extra gate");
    }
    Ok(scenarios)
}

fn validate_registered_scenarios(scenarios: &BTreeMap<String, Scenario>) -> Result<(), XtaskError> {
    for kind in [GateKind::Concurrency, GateKind::Resource] {
        let scenario = scenarios.get(kind.id()).ok_or_else(|| {
            verifier_error("parent-captured scenario registry omitted a required gate")
        })?;
        let (id, schedule, seed, queue, reservations, retries, expected) = match kind {
            GateKind::Concurrency => (
                "concurrency-cancel-join",
                "cancel-then-join-v1",
                "seed-concurrency-v1",
                1,
                1,
                1,
                "cancelled-then-joined-v1",
            ),
            GateKind::Resource => (
                "resource-fair-pressure",
                "round-robin-pressure-v1",
                "seed-resource-v1",
                3,
                2,
                2,
                "fair-pressure-retry-leak-free-v1",
            ),
        };
        if scenario.id != id
            || scenario.gate != kind
            || scenario.spawn_site != "quality-bounded-worker-v1"
            || scenario.schedule != schedule
            || scenario.seed != seed
            || scenario.max_tasks != 3
            || scenario.queue_capacity != queue
            || scenario.reservation_capacity != reservations
            || scenario.retry_limit != retries
            || scenario.shutdown_ms != 100
            || scenario.expected != expected
        {
            return closed(
                "parent-captured scenario identity or capacity bounds drifted from the contract",
            );
        }
    }
    Ok(())
}

fn validate_spawn_registry(bytes: &[u8], scenario: &Scenario) -> Result<(), XtaskError> {
    if bytes.len() > MAXIMUM_REGISTRY_BYTES {
        return closed("parent-captured spawn registry exceeds its exact byte bound");
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| verifier_error("parent-captured spawn registry is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(SPAWN_HEADER) {
        return closed("parent-captured spawn registry header is malformed or stale");
    }
    let mut identities = BTreeMap::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        let [path, symbol, kind, id] = fields.as_slice() else {
            return closed("parent-captured spawn registry row is malformed");
        };
        if fields
            .iter()
            .any(|field| field.is_empty() || field.len() > MAXIMUM_FIELD_BYTES)
            || !matches!(*kind, "thread" | "process")
        {
            return closed("parent-captured spawn registry contains an invalid field");
        }
        if identities
            .insert(
                (*id).to_owned(),
                ((*path).to_owned(), (*symbol).to_owned(), (*kind).to_owned()),
            )
            .is_some()
        {
            return closed("parent-captured spawn registry contains a duplicate identity");
        }
    }
    let required = [
        (
            scenario.spawn_site.as_str(),
            "tools/xtask/src/registered_task_lifecycle.rs",
            "RegisteredTasks::spawn",
            "thread",
        ),
        (
            "controlled-command-v1",
            "tools/xtask/src/controlled_execution.rs",
            "execute_unix",
            "process",
        ),
        (
            "controlled-input-broker-v1",
            "tools/xtask/src/controlled_execution.rs",
            "InputBroker::start",
            "process",
        ),
        (
            "controlled-capture-broker-v1",
            "tools/xtask/src/controlled_execution.rs",
            "CaptureReader::start",
            "process",
        ),
        (
            "controlled-framed-stdout-broker-v1",
            "tools/xtask/src/controlled_execution.rs",
            "FramedStdoutBroker::start",
            "thread",
        ),
        (
            "fixture-writer-v1",
            "tools/xtask/src/qualification_fixtures.rs",
            "execute_state_transition",
            "process",
        ),
        (
            "fixture-recovery-v1",
            "tools/xtask/src/qualification_fixtures.rs",
            "execute_state_transition",
            "process",
        ),
        (
            "fixture-provider-v1",
            "tools/xtask/src/qualification_fixtures.rs",
            "send_to_closed_provider",
            "process",
        ),
    ];
    if identities.len() != required.len() {
        return closed(
            "parent-captured spawn registry contains a missing, extra, or stale lifecycle owner",
        );
    }
    for (id, path, symbol, kind) in required {
        if identities.get(id) != Some(&(path.to_owned(), symbol.to_owned(), kind.to_owned())) {
            return closed("parent-captured spawn registry omitted an exact lifecycle owner");
        }
    }
    Ok(())
}

fn verify_measurement(record: &str, scenario: &Scenario) -> Result<(), XtaskError> {
    if record.len() > MAXIMUM_MEASUREMENT_BYTES {
        return closed("child measurement exceeds its exact parent byte bound");
    }
    let mut tokens = record.split(';');
    if tokens.next() != Some("measurement-v1") {
        return closed("child measurement schema identity is missing or stale");
    }
    let expected_fields = MEASUREMENT_FIELDS.into_iter().collect::<BTreeSet<_>>();
    let mut fields = BTreeMap::new();
    for token in tokens {
        let Some((key, value)) = token.split_once('=') else {
            return closed("child measurement contains a malformed field");
        };
        if key.is_empty() || value.is_empty() {
            return closed("child measurement contains an empty field");
        }
        if !expected_fields.contains(key) {
            return closed("child measurement contains an extra or stale field");
        }
        if fields.insert(key, value).is_some() {
            return closed("child measurement contains a duplicate field");
        }
    }
    if fields.len() != MEASUREMENT_FIELDS.len()
        || MEASUREMENT_FIELDS
            .iter()
            .any(|field| !fields.contains_key(field))
    {
        return closed("child measurement omits a required field");
    }
    if fields.get("scenario") != Some(&scenario.id.as_str())
        || fields.get("schedule") != Some(&scenario.schedule.as_str())
        || fields.get("seed") != Some(&scenario.seed.as_str())
    {
        return closed("child measurement identity mismatches the frozen scenario");
    }

    let workers = parse_workers(required(&fields, "workers")?)?;
    let registered = parse_unsigned(required(&fields, "registered")?, "registered worker count")?;
    if registered != scenario.max_tasks || workers.len() != scenario.max_tasks {
        return closed("worker count does not exactly match the frozen scenario");
    }
    verify_worker_identity_and_schedule(&workers, scenario)?;

    let joined = parse_id_list(required(&fields, "joined-ids")?, "joined worker IDs")?;
    let expected_ids = (0..scenario.max_tasks).collect::<Vec<_>>();
    if joined != expected_ids {
        return closed("joined worker IDs do not exactly match the frozen lifecycle");
    }
    if parse_unsigned(required(&fields, "shutdown-ms")?, "shutdown bound")? != scenario.shutdown_ms
    {
        return closed("worker shutdown bound does not match the frozen lifecycle");
    }

    let retries = parse_unsigned(required(&fields, "retries")?, "retry count")?;
    let reservations = parse_unsigned(required(&fields, "reservations")?, "reservation count")?;
    let queue_empty = match required(&fields, "queue-empty")? {
        "true" => true,
        "false" => false,
        _ => return closed("queue-empty outcome is not canonical"),
    };
    match scenario.gate {
        GateKind::Concurrency => {
            if retries != 0 || reservations != 0 || !queue_empty {
                return closed("concurrency lifecycle outcome contains fabricated resource state");
            }
        },
        GateKind::Resource => {
            if retries != scenario.retry_limit || reservations != 0 || !queue_empty {
                return closed(
                    "resource retry ceiling, reservation release, or queue outcome is false",
                );
            }
        },
    }
    Ok(())
}

fn parse_workers(value: &str) -> Result<Vec<Worker>, XtaskError> {
    value
        .split(',')
        .map(|worker| {
            let parts = worker.split(':').collect::<Vec<_>>();
            let [id, slot, completion] = parts.as_slice() else {
                return closed("worker measurement is malformed");
            };
            let completion = match *completion {
                "executed" => Completion::Executed,
                "cancelled" => Completion::Cancelled,
                _ => return closed("worker completion is stale or unknown"),
            };
            Ok(Worker {
                id: parse_unsigned(id, "worker ID")?,
                slot: parse_unsigned(slot, "worker schedule slot")?,
                completion,
            })
        })
        .collect()
}

fn verify_worker_identity_and_schedule(
    workers: &[Worker],
    scenario: &Scenario,
) -> Result<(), XtaskError> {
    let expected = (0..scenario.max_tasks).collect::<BTreeSet<_>>();
    let ids = workers
        .iter()
        .map(|worker| worker.id)
        .collect::<BTreeSet<_>>();
    let slots = workers
        .iter()
        .map(|worker| worker.slot)
        .collect::<BTreeSet<_>>();
    if ids != expected || ids.len() != workers.len() {
        return closed("worker IDs do not exactly match the frozen scenario");
    }
    if slots != expected || slots.len() != workers.len() {
        return closed("worker schedule slots do not exactly match the frozen scenario");
    }
    let by_id = workers
        .iter()
        .map(|worker| (worker.id, (worker.slot, worker.completion)))
        .collect::<BTreeMap<_, _>>();
    match scenario.gate {
        GateKind::Concurrency => {
            if by_id.get(&0) != Some(&(0, Completion::Cancelled))
                || by_id.get(&1) != Some(&(1, Completion::Executed))
                || by_id.get(&2) != Some(&(2, Completion::Executed))
            {
                return closed(
                    "worker completion outcomes do not prove the frozen cancellation schedule",
                );
            }
        },
        GateKind::Resource => {
            let mut by_slot = workers.to_vec();
            by_slot.sort_by_key(|worker| worker.slot);
            if by_slot
                .iter()
                .any(|worker| worker.completion != Completion::Executed)
                || by_slot.iter().map(|worker| worker.id).collect::<Vec<_>>() != [0, 1, 2]
            {
                return closed("worker order does not prove the frozen fair resource schedule");
            }
        },
    }
    Ok(())
}

fn parse_id_list(value: &str, label: &str) -> Result<Vec<usize>, XtaskError> {
    value
        .split(',')
        .map(|id| parse_unsigned(id, label))
        .collect()
}

fn required<'fields>(
    fields: &'fields BTreeMap<&str, &str>,
    key: &str,
) -> Result<&'fields str, XtaskError> {
    fields
        .get(key)
        .copied()
        .ok_or_else(|| verifier_error(format!("child measurement omits `{key}`")))
}

fn parse_positive(value: &str, label: &str) -> Result<usize, XtaskError> {
    let parsed = parse_unsigned(value, label)?;
    if parsed == 0 {
        return closed(format!("{label} must be positive"));
    }
    Ok(parsed)
}

fn parse_unsigned(value: &str, label: &str) -> Result<usize, XtaskError> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| verifier_error(format!("{label} is not a canonical unsigned integer")))?;
    if parsed.to_string() != value {
        return closed(format!("{label} is not a canonical unsigned integer"));
    }
    Ok(parsed)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn closed<T>(detail: impl Into<String>) -> Result<T, XtaskError> {
    Err(verifier_error(detail))
}

fn verifier_error(detail: impl Into<String>) -> XtaskError {
    XtaskError::invalid("parent bounded measurement verifier", detail)
}
