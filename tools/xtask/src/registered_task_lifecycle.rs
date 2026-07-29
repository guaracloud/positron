//! Registered worker lifecycle for bounded Quality Engineering scenarios.
//!
//! One owner registers every worker before spawn, retains every join handle,
//! carries one monotonic deadline from registration through reconciliation,
//! and records completion and join observations only when they actually occur.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::XtaskError;

const CANCELLATION_JOIN_RESERVE: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerCommand {
    Execute { schedule_slot: usize },
    Cancel { schedule_slot: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerCompletion {
    Executed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkerMeasurement {
    pub(crate) id: usize,
    pub(crate) schedule_slot: usize,
    pub(crate) completion: WorkerCompletion,
}

pub(crate) struct LifecycleResult<T> {
    pub(crate) value: T,
    pub(crate) measurements: Vec<WorkerMeasurement>,
    pub(crate) joined_ids: Vec<usize>,
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

pub(crate) struct RegisteredTasks {
    tasks: Vec<RegisteredTask>,
    results: Receiver<WorkerMeasurement>,
    started: Instant,
    work_deadline: Instant,
    deadline: Instant,
    shutdown: Duration,
    spawned_ids: Vec<usize>,
    joined_ids: Vec<usize>,
    completed_ids: Vec<usize>,
}

impl RegisteredTasks {
    pub(crate) fn execute<T>(
        max_tasks: usize,
        shutdown: Duration,
        spawn_site: &str,
        registered_spawn_site: &str,
        operation: impl FnOnce(&mut Self) -> Result<T, XtaskError>,
    ) -> Result<LifecycleResult<T>, XtaskError> {
        let mut owner = Self::spawn(max_tasks, shutdown, spawn_site, registered_spawn_site)?;
        let value = match operation(&mut owner) {
            Ok(value) => value,
            Err(error) => return owner.reconcile_failure(error),
        };
        let measurements = owner.reconcile()?;
        Ok(LifecycleResult {
            value,
            measurements,
            joined_ids: owner.joined_ids,
        })
    }

    fn spawn(
        max_tasks: usize,
        shutdown: Duration,
        spawn_site: &str,
        registered_spawn_site: &str,
    ) -> Result<Self, XtaskError> {
        if spawn_site != registered_spawn_site {
            return Err(XtaskError::invalid(
                "bounded task registration",
                "unregistered spawn site was denied before task creation",
            ));
        }
        let started = Instant::now();
        let deadline = started.checked_add(shutdown).ok_or_else(|| {
            XtaskError::invalid(
                "bounded task registration",
                "shutdown deadline cannot be represented",
            )
        })?;
        let work_deadline = deadline
            .checked_sub(CANCELLATION_JOIN_RESERVE)
            .ok_or_else(|| {
                XtaskError::invalid(
                    "bounded task registration",
                    "shutdown deadline does not reserve bounded cancellation and join time",
                )
            })?;
        let (results_sender, results) = mpsc::sync_channel(max_tasks);
        let mut owner = Self {
            tasks: Vec::with_capacity(max_tasks),
            results,
            started,
            work_deadline,
            deadline,
            shutdown,
            spawned_ids: Vec::with_capacity(max_tasks),
            joined_ids: Vec::with_capacity(max_tasks),
            completed_ids: Vec::with_capacity(max_tasks),
        };
        for id in 0..max_tasks {
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
                .spawn(move || worker_loop(id, cancel, deadline, receiver, worker_results))
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
            owner.spawned_ids.push(id);
        }
        drop(results_sender);
        Ok(owner)
    }

    pub(crate) fn dispatch(&mut self, id: usize, command: WorkerCommand) -> Result<(), XtaskError> {
        if Instant::now() >= self.work_deadline {
            return Err(XtaskError::invalid(
                "bounded task dispatch",
                "registered work deadline expired before command delivery",
            ));
        }
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

    fn reconcile(&mut self) -> Result<Vec<WorkerMeasurement>, XtaskError> {
        let mut measurements = Vec::with_capacity(self.tasks.len());
        while measurements.len() < self.tasks.len() {
            if Instant::now() >= self.work_deadline {
                return self.reconcile_failure(XtaskError::invalid(
                    "bounded task shutdown",
                    "registered tasks did not report before the shutdown deadline",
                ));
            }
            match self.results.try_recv() {
                Ok(measurement) => measurements.push(measurement),
                Err(TryRecvError::Empty) => thread::yield_now(),
                Err(TryRecvError::Disconnected) => {
                    return self.reconcile_failure(XtaskError::invalid(
                        "bounded task shutdown",
                        "registered task result channel closed before every task reported",
                    ));
                },
            }
        }
        while self.has_unjoined_handles() {
            if Instant::now() >= self.deadline {
                return self.reconcile_failure(XtaskError::invalid(
                    "bounded task shutdown",
                    "registered task completion was not observed before the shutdown deadline",
                ));
            }
            let join_errors = self.join_finished_tasks();
            if !join_errors.is_empty() {
                return self.reconcile_failure(XtaskError::invalid(
                    "bounded task shutdown",
                    format!("registered task failures: {}", join_errors.join("; ")),
                ));
            }
            thread::yield_now();
        }
        Ok(measurements)
    }

    fn reconcile_failure<T>(&mut self, original: XtaskError) -> Result<T, XtaskError> {
        let spawned_ids = self.spawned_ids.clone();
        let mut cancellation = Vec::new();
        for task in &mut self.tasks {
            task.cancel.store(true, Ordering::Release);
            if self.spawned_ids.contains(&task.id)
                && let Some(sender) = task.sender.as_ref()
            {
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
        let mut deadline_expired = false;
        while self.has_unjoined_handles() {
            drain_measurements(&self.results, &mut reported_ids);
            cleanup_errors.extend(self.join_finished_tasks());
            if Instant::now() >= self.deadline {
                deadline_expired = true;
            }
            thread::yield_now();
        }
        drain_measurements(&self.results, &mut reported_ids);

        if deadline_expired {
            cleanup_errors.push(
                "cooperative worker completion was not observed before the one registered deadline"
                    .to_owned(),
            );
        }

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
            &mut self.completed_ids,
            &mut self.joined_ids,
        ] {
            ids.sort_unstable();
            ids.dedup();
        }
        let lifecycle = format!(
            "lifecycle-v1;spawned-ids={};cancelled-ids={};already-queued-ids={};disconnected-ids={};reported-ids={};completed-ids={};joined-ids={};deadline-ms={};deadline-elapsed-ms={};live=0",
            format_ids(&spawned_ids),
            format_ids(&cancelled_ids),
            format_ids(&already_queued_ids),
            format_ids(&disconnected_ids),
            format_ids(&reported_ids),
            format_ids(&self.completed_ids),
            format_ids(&self.joined_ids),
            self.shutdown.as_millis(),
            self.started.elapsed().as_millis(),
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

    fn join_finished_tasks(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        for task in &mut self.tasks {
            if !task
                .handle
                .as_ref()
                .is_some_and(thread::JoinHandle::is_finished)
            {
                continue;
            }
            self.completed_ids.push(task.id);
            let Some(handle) = task.handle.take() else {
                continue;
            };
            match handle.join() {
                Ok(result) => {
                    self.joined_ids.push(task.id);
                    if let Err(error) = result {
                        errors.push(error.to_string());
                    }
                },
                Err(_) => {
                    errors.push(
                        XtaskError::invalid(
                            "bounded task shutdown",
                            "registered task panicked instead of returning a closed outcome",
                        )
                        .to_string(),
                    );
                },
            }
        }
        errors
    }

    fn has_unjoined_handles(&self) -> bool {
        self.tasks.iter().any(|task| task.handle.is_some())
    }
}

fn drain_measurements(results: &Receiver<WorkerMeasurement>, reported_ids: &mut Vec<usize>) {
    while let Ok(measurement) = results.try_recv() {
        reported_ids.push(measurement.id);
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
    deadline: Instant,
    receiver: Receiver<WorkerCommand>,
    results: SyncSender<WorkerMeasurement>,
) -> Result<(), XtaskError> {
    let command = loop {
        if cancel.load(Ordering::Acquire) {
            return Err(XtaskError::invalid(
                "bounded task worker",
                "worker observed cooperative cancellation before command receipt",
            ));
        }
        match receiver.try_recv() {
            Ok(command) => break command,
            Err(TryRecvError::Empty) if Instant::now() < deadline => thread::yield_now(),
            Err(TryRecvError::Empty) => {
                return Err(XtaskError::invalid(
                    "bounded task worker",
                    "worker command did not arrive before the registered deadline",
                ));
            },
            Err(TryRecvError::Disconnected) => {
                return Err(XtaskError::invalid(
                    "bounded task worker",
                    "worker command channel disconnected before delivery",
                ));
            },
        }
    };
    cooperative_pause(&cancel, Duration::ZERO)?;
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
        thread::yield_now();
    }
    Ok(())
}
