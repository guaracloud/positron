//! Semantic verification against the frozen bounded-runner contract.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::XtaskError;
use crate::registry::Gate;

use super::schema::{parse_id_list, parse_unsigned, parse_workers, required};
use super::{
    Completion, GateKind, MAXIMUM_MEASUREMENT_BYTES, MEASUREMENT_FIELDS, Scenario, Worker, closed,
    sha256,
};

pub(super) fn validate_gate_descriptor(gate: &Gate, kind: GateKind) -> Result<(), XtaskError> {
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

pub(super) fn gate_descriptor_digest(gate: &Gate) -> String {
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

pub(super) fn validate_registered_scenarios(
    scenarios: &BTreeMap<String, Scenario>,
) -> Result<(), XtaskError> {
    for kind in [GateKind::Concurrency, GateKind::Resource] {
        let scenario = scenarios.get(kind.id()).ok_or_else(|| {
            super::verifier_error("parent-captured scenario registry omitted a required gate")
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

pub(super) fn verify_measurement(record: &str, scenario: &Scenario) -> Result<(), XtaskError> {
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
