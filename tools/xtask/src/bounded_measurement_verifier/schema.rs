//! Bounded parsing for parent-captured registries and child measurements.

use std::collections::BTreeMap;

use crate::error::XtaskError;

use super::{
    Completion, GateKind, MAXIMUM_FIELD_BYTES, MAXIMUM_REGISTRY_BYTES, SCENARIO_HEADER,
    SPAWN_HEADER, Scenario, Worker, closed, verifier_error,
};

pub(super) fn parse_scenarios(bytes: &[u8]) -> Result<BTreeMap<String, Scenario>, XtaskError> {
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

pub(super) fn validate_spawn_registry(bytes: &[u8], scenario: &Scenario) -> Result<(), XtaskError> {
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

pub(super) fn parse_workers(value: &str) -> Result<Vec<Worker>, XtaskError> {
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

pub(super) fn parse_id_list(value: &str, label: &str) -> Result<Vec<usize>, XtaskError> {
    value
        .split(',')
        .map(|id| parse_unsigned(id, label))
        .collect()
}

pub(super) fn required<'fields>(
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

pub(super) fn parse_unsigned(value: &str, label: &str) -> Result<usize, XtaskError> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| verifier_error(format!("{label} is not a canonical unsigned integer")))?;
    if parsed.to_string() != value {
        return closed(format!("{label} is not a canonical unsigned integer"));
    }
    Ok(parsed)
}
