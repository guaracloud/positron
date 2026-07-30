//! Bounded process-group termination and direct-child reconciliation.

#![cfg(unix)]

use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use super::{
    ExecutionFailure, FailurePhase, POLL_INTERVAL, TERMINATION_GRACE, wait_for_direct_child,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminationOutcome {
    AlreadyExited,
    TerminationRequested,
}

pub(super) fn terminate_and_reap(
    child: &mut Child,
    group: &ProcessGroup,
    command: &str,
    shutdown_deadline: Instant,
) -> Result<TerminationOutcome, ExecutionFailure> {
    let direct_already_exited = child.try_wait().map_err(|source| {
        ExecutionFailure::new(
            command.to_owned(),
            FailurePhase::DirectProcess,
            source.to_string(),
        )
    })?;
    if direct_already_exited.is_some() {
        let group_exists = match group.exists(command, shutdown_deadline) {
            Ok(exists) => exists,
            Err(failure) => {
                return reconcile_after_process_control_failure(
                    child,
                    group,
                    command,
                    shutdown_deadline,
                    failure,
                );
            },
        };
        if !group_exists {
            return Ok(TerminationOutcome::AlreadyExited);
        }
    }
    if let Err(failure) = group.signal(Signal::Terminate, command, shutdown_deadline) {
        return reconcile_after_process_control_failure(
            child,
            group,
            command,
            shutdown_deadline,
            failure,
        );
    }
    let grace_deadline = Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or(shutdown_deadline)
        .min(shutdown_deadline);
    let closed_during_grace = match wait_for_group_while_reaping_direct(
        child,
        group,
        command,
        grace_deadline,
        shutdown_deadline,
    ) {
        Ok(closed) => closed,
        Err(failure) => {
            return reconcile_after_process_control_failure(
                child,
                group,
                command,
                shutdown_deadline,
                failure,
            );
        },
    };
    if !closed_during_grace {
        if let Err(failure) = group.signal(Signal::Kill, command, shutdown_deadline) {
            return reconcile_after_process_control_failure(
                child,
                group,
                command,
                shutdown_deadline,
                failure,
            );
        }
        let closed_after_kill = match wait_for_group_while_reaping_direct(
            child,
            group,
            command,
            shutdown_deadline,
            shutdown_deadline,
        ) {
            Ok(closed) => closed,
            Err(failure) => {
                return reconcile_after_process_control_failure(
                    child,
                    group,
                    command,
                    shutdown_deadline,
                    failure,
                );
            },
        };
        if !closed_after_kill {
            return Err(group.not_empty_failure(command));
        }
    }
    match wait_for_direct_child(child, command, shutdown_deadline, None, None, None) {
        Ok(_) => Ok(TerminationOutcome::TerminationRequested),
        Err(failure) => reconcile_after_process_control_failure(
            child,
            group,
            command,
            shutdown_deadline,
            failure,
        ),
    }
}

fn reconcile_after_process_control_failure(
    child: &mut Child,
    group: &ProcessGroup,
    command: &str,
    shutdown_deadline: Instant,
    failure: ExecutionFailure,
) -> Result<TerminationOutcome, ExecutionFailure> {
    let direct_reaped = child
        .try_wait()
        .map(|status| status.is_some())
        .map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::DirectProcess,
                source.to_string(),
            )
        });
    let group_exists = group.probe(command);
    reconcile_after_control_failure(failure, direct_reaped, group_exists, || {
        kill_and_reap_direct_child(child, command, shutdown_deadline)
    })
}

fn reconcile_after_control_failure<KillAndReap>(
    failure: ExecutionFailure,
    direct_reaped: Result<bool, ExecutionFailure>,
    group_exists: Result<bool, ExecutionFailure>,
    kill_and_reap: KillAndReap,
) -> Result<TerminationOutcome, ExecutionFailure>
where
    KillAndReap: FnOnce() -> Result<(), ExecutionFailure>,
{
    match (direct_reaped, group_exists) {
        (Ok(true), Ok(false)) => Ok(TerminationOutcome::TerminationRequested),
        (Ok(false), Ok(false)) => kill_and_reap()
            .map(|()| TerminationOutcome::TerminationRequested)
            .map_err(|cleanup| failure.with_reconciliation(cleanup)),
        (Ok(_), Ok(true)) => Err(failure),
        (Err(direct), Ok(_)) => Err(failure.with_reconciliation(direct)),
        (Ok(_), Err(group)) => Err(failure.with_reconciliation(group)),
        (Err(direct), Err(group)) => Err(failure
            .with_reconciliation(direct)
            .with_reconciliation(group)),
    }
}

fn kill_and_reap_direct_child(
    child: &mut Child,
    command: &str,
    shutdown_deadline: Instant,
) -> Result<(), ExecutionFailure> {
    require_shutdown_time(
        command,
        shutdown_deadline,
        "direct-child forced termination",
    )?;
    let kill_failure = child.kill().err();
    wait_for_direct_child(child, command, shutdown_deadline, None, None, None)
        .map(|_| ())
        .map_err(|failure| {
            let kill_context = kill_failure.map_or_else(String::new, |source| {
                format!("kill direct child after process-group closure: {source}; ")
            });
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                format!(
                    "{kill_context}reap direct child after process-group closure: {}",
                    failure.detail
                ),
            )
        })
}

fn wait_for_group_while_reaping_direct(
    child: &mut Child,
    group: &ProcessGroup,
    command: &str,
    progress_deadline: Instant,
    shutdown_deadline: Instant,
) -> Result<bool, ExecutionFailure> {
    loop {
        let direct_reaped = child.try_wait().map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::DirectProcess,
                source.to_string(),
            )
        })?;
        if !group.exists(command, shutdown_deadline)? {
            if direct_reaped.is_none() {
                kill_and_reap_direct_child(child, command, shutdown_deadline)?;
            }
            return Ok(true);
        }
        if Instant::now() >= progress_deadline {
            return Ok(false);
        }
        wait_for_progress(progress_deadline);
    }
}

fn wait_for_progress(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    thread::park_timeout(remaining.min(POLL_INTERVAL));
}

pub(super) struct ProcessGroup {
    identifier: u32,
}

impl ProcessGroup {
    pub(super) fn new(identifier: u32) -> Self {
        Self { identifier }
    }

    pub(super) fn exists(
        &self,
        command: &str,
        deadline: Instant,
    ) -> Result<bool, ExecutionFailure> {
        let exists = self.probe(command)?;
        if exists {
            require_shutdown_time(command, deadline, "process-group probe")?;
        }
        Ok(exists)
    }

    fn probe(&self, command: &str) -> Result<bool, ExecutionFailure> {
        let identifier = self.identifier(command)?;
        match rustix::process::test_kill_process_group(identifier) {
            Ok(()) => Ok(true),
            Err(rustix::io::Errno::SRCH) => Ok(false),
            Err(source) => Err(process_control_failure(
                command,
                "probe",
                self.identifier,
                source,
            )),
        }
    }

    fn signal(
        &self,
        signal: Signal,
        command: &str,
        deadline: Instant,
    ) -> Result<(), ExecutionFailure> {
        require_shutdown_time(command, deadline, signal.operation())?;
        let identifier = self.identifier(command)?;
        match rustix::process::kill_process_group(identifier, signal.as_rustix()) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(source) => Err(process_control_failure(
                command,
                signal.name(),
                self.identifier,
                source,
            )),
        }
    }

    fn identifier(&self, command: &str) -> Result<rustix::process::Pid, ExecutionFailure> {
        let raw = i32::try_from(self.identifier).map_err(|_| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                format!(
                    "controlled process group identifier {} exceeded the platform range",
                    self.identifier
                ),
            )
        })?;
        rustix::process::Pid::from_raw(raw).ok_or_else(|| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                "controlled process group identifier was zero",
            )
        })
    }

    fn not_empty_failure(&self, command: &str) -> ExecutionFailure {
        ExecutionFailure::new(
            command.to_owned(),
            FailurePhase::Cleanup,
            format!(
                "controlled process group {} remained alive after forced termination",
                self.identifier
            ),
        )
    }
}

#[derive(Clone, Copy)]
enum Signal {
    Terminate,
    Kill,
}

impl Signal {
    fn as_rustix(self) -> rustix::process::Signal {
        match self {
            Self::Terminate => rustix::process::Signal::TERM,
            Self::Kill => rustix::process::Signal::KILL,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Terminate => "termination signal",
            Self::Kill => "forced termination signal",
        }
    }

    fn operation(self) -> &'static str {
        match self {
            Self::Terminate => "process-group termination signal",
            Self::Kill => "process-group forced termination signal",
        }
    }
}

fn process_control_failure(
    command: &str,
    operation: &str,
    identifier: u32,
    source: rustix::io::Errno,
) -> ExecutionFailure {
    ExecutionFailure::new(
        command.to_owned(),
        FailurePhase::Cleanup,
        format!(
            "{operation} controlled process group {identifier}: {}",
            std::io::Error::from_raw_os_error(source.raw_os_error())
        ),
    )
}

fn require_shutdown_time(
    command: &str,
    deadline: Instant,
    operation: &str,
) -> Result<Duration, ExecutionFailure> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ExecutionFailure::new(
            command.to_owned(),
            FailurePhase::Cleanup,
            format!("{operation} reached the registered shutdown deadline"),
        ));
    }
    Ok(remaining)
}

#[cfg(test)]
#[path = "controlled_process_group_tests.rs"]
mod tests;
