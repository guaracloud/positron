//! Diagnostic child measurement generation and verification.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::XtaskError;
use crate::registered_task_lifecycle::{WorkerCompletion, WorkerMeasurement};

use super::registry::{Scenario, ScenarioGate};

pub(super) fn measurement_record(
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
        "measurement-v1;scenario={};schedule={};seed={};registered={};workers={workers};retries={retries};reservations={reservations};queue-empty={queue_empty};joined-ids={joined};shutdown-ms={}",
        scenario.id,
        scenario.schedule,
        scenario.seed,
        scenario.max_tasks,
        scenario.shutdown.as_millis()
    )
}

pub(super) fn verify_child_measurement_record(
    scenario: &Scenario,
    record: &str,
    gate: ScenarioGate,
) -> Result<(), XtaskError> {
    if record.len() > 4_096 || !record.starts_with("measurement-v1;") {
        return Err(XtaskError::invalid(
            "child diagnostic bounded measurement verifier",
            "measurement record is missing or exceeds its bound",
        ));
    }
    let mut fields = BTreeMap::new();
    for field in record.split(';').skip(1) {
        let Some((key, value)) = field.split_once('=') else {
            return Err(XtaskError::invalid(
                "child diagnostic bounded measurement verifier",
                "measurement record contains a malformed field",
            ));
        };
        if key.is_empty() || value.is_empty() || fields.insert(key, value).is_some() {
            return Err(XtaskError::invalid(
                "child diagnostic bounded measurement verifier",
                "measurement record contains a duplicate or empty field",
            ));
        }
    }
    if fields.get("scenario") != Some(&scenario.id.as_str())
        || fields.get("schedule") != Some(&scenario.schedule.as_str())
        || fields.get("seed") != Some(&scenario.seed.as_str())
    {
        return Err(XtaskError::invalid(
            "child diagnostic bounded measurement verifier",
            "frozen scenario identity is missing from measurement record",
        ));
    }
    let workers = fields.get("workers").ok_or_else(|| {
        XtaskError::invalid(
            "child diagnostic bounded measurement verifier",
            "worker measurements are omitted",
        )
    })?;
    let parsed = workers
        .split(',')
        .map(|worker| {
            let parts = worker.split(':').collect::<Vec<_>>();
            let [id, schedule_slot, completion] = parts.as_slice() else {
                return Err(XtaskError::invalid(
                    "child diagnostic bounded measurement verifier",
                    "worker measurement is malformed",
                ));
            };
            Ok(WorkerMeasurement {
                id: id.parse().map_err(|_| {
                    XtaskError::invalid(
                        "child diagnostic bounded measurement verifier",
                        "worker id is malformed",
                    )
                })?,
                schedule_slot: schedule_slot.parse().map_err(|_| {
                    XtaskError::invalid(
                        "child diagnostic bounded measurement verifier",
                        "worker slot is malformed",
                    )
                })?,
                completion: match *completion {
                    "executed" => WorkerCompletion::Executed,
                    "cancelled" => WorkerCompletion::Cancelled,
                    _ => {
                        return Err(XtaskError::invalid(
                            "child diagnostic bounded measurement verifier",
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
            "child diagnostic bounded measurement verifier",
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
            "child diagnostic bounded measurement verifier",
            "worker identifiers do not exactly match the registered workers",
        ));
    }
    let schedule_slots = parsed
        .iter()
        .map(|measurement| measurement.schedule_slot)
        .collect::<BTreeSet<_>>();
    if schedule_slots != expected_identity || schedule_slots.len() != parsed.len() {
        return Err(XtaskError::invalid(
            "child diagnostic bounded measurement verifier",
            "worker schedule slots are not unique and contiguous",
        ));
    }
    let joined_ids = fields
        .get("joined-ids")
        .ok_or_else(|| {
            XtaskError::invalid(
                "child diagnostic bounded measurement verifier",
                "observed join records are omitted",
            )
        })?
        .split(',')
        .map(|id| {
            id.parse::<usize>().map_err(|_| {
                XtaskError::invalid(
                    "child diagnostic bounded measurement verifier",
                    "observed join record is malformed",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_joined_ids = (0..scenario.max_tasks).collect::<Vec<_>>();
    if joined_ids != expected_joined_ids {
        return Err(XtaskError::invalid(
            "child diagnostic bounded measurement verifier",
            "observed join records do not match the registered workers",
        ));
    }
    if fields
        .get("shutdown-ms")
        .and_then(|value| value.parse::<u128>().ok())
        != Some(scenario.shutdown.as_millis())
    {
        return Err(XtaskError::invalid(
            "child diagnostic bounded measurement verifier",
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
                        "child diagnostic bounded measurement verifier",
                        "retry record is malformed",
                    )
                })?,
            fields
                .get("reservations")
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| {
                    XtaskError::invalid(
                        "child diagnostic bounded measurement verifier",
                        "reservation record is malformed",
                    )
                })?,
            fields.get("queue-empty") == Some(&"true"),
        ),
    }
}

pub(super) fn validate_concurrency_scenario(scenario: &Scenario) -> Result<(), XtaskError> {
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

pub(super) fn validate_resource_scenario(scenario: &Scenario) -> Result<(), XtaskError> {
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
