//! Registered scenario execution and orchestration.

use std::time::Duration;

use crate::error::XtaskError;
use crate::registered_task_lifecycle::{
    LifecycleResult, RegisteredTaskSpec, RegisteredTasks, WorkerCommand,
};

use super::measurement::{
    measurement_record, validate_concurrency_scenario, validate_resource_scenario,
    verify_child_measurement_record,
};
use super::registry::{FrozenBoundedRunnerRegistry, REGISTERED_SPAWN_SITE, ScenarioGate};
use super::resource::{BoundedWorkQueue, ReservationLedger, ReservationOutcome};

pub(super) fn run_concurrency_scenario(
    registry: &FrozenBoundedRunnerRegistry,
    execution_timeout: Duration,
) -> Result<String, XtaskError> {
    let scenario = registry.scenario(ScenarioGate::Concurrency)?;
    validate_concurrency_scenario(scenario)?;
    let LifecycleResult {
        value: (),
        measurements,
        joined_ids,
    } = RegisteredTasks::execute(
        RegisteredTaskSpec {
            max_tasks: scenario.max_tasks,
            execution_timeout,
            shutdown: scenario.shutdown,
            spawn_site: &scenario.spawn_site,
            registered_spawn_site: REGISTERED_SPAWN_SITE,
        },
        |tasks| {
            tasks.dispatch(0, WorkerCommand::Cancel { schedule_slot: 0 })?;
            tasks.dispatch(1, WorkerCommand::Execute { schedule_slot: 1 })?;
            tasks.dispatch(2, WorkerCommand::Execute { schedule_slot: 2 })?;
            Ok(())
        },
    )?;
    let record = measurement_record(scenario, &measurements, &joined_ids, 0, 0, true);
    verify_child_measurement_record(scenario, &record, ScenarioGate::Concurrency)?;
    Ok(record)
}

pub(super) fn run_resource_scenario(
    registry: &FrozenBoundedRunnerRegistry,
    execution_timeout: Duration,
) -> Result<String, XtaskError> {
    let scenario = registry.scenario(ScenarioGate::Resource)?;
    validate_resource_scenario(scenario)?;
    let LifecycleResult {
        value: (retries, reservations, queue_empty),
        measurements,
        joined_ids,
    } = RegisteredTasks::execute(
        RegisteredTaskSpec {
            max_tasks: scenario.max_tasks,
            execution_timeout,
            shutdown: scenario.shutdown,
            spawn_site: &scenario.spawn_site,
            registered_spawn_site: REGISTERED_SPAWN_SITE,
        },
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
    verify_child_measurement_record(scenario, &record, ScenarioGate::Resource)?;
    Ok(record)
}
