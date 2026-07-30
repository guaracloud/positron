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
    if direct_already_exited.is_some() && !group.exists(command, shutdown_deadline)? {
        return Ok(TerminationOutcome::AlreadyExited);
    }
    group.signal(Signal::Terminate, command, shutdown_deadline)?;
    let grace_deadline = Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or(shutdown_deadline)
        .min(shutdown_deadline);
    if !wait_for_group_while_reaping_direct(
        child,
        group,
        command,
        grace_deadline,
        shutdown_deadline,
    )? {
        group.signal(Signal::Kill, command, shutdown_deadline)?;
        if !wait_for_group_while_reaping_direct(
            child,
            group,
            command,
            shutdown_deadline,
            shutdown_deadline,
        )? {
            return Err(group.not_empty_failure(command));
        }
    }
    wait_for_direct_child(child, command, shutdown_deadline, None, None, None)
        .map(|_| TerminationOutcome::TerminationRequested)
}

fn wait_for_group_while_reaping_direct(
    child: &mut Child,
    group: &ProcessGroup,
    command: &str,
    progress_deadline: Instant,
    shutdown_deadline: Instant,
) -> Result<bool, ExecutionFailure> {
    loop {
        child.try_wait().map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::DirectProcess,
                source.to_string(),
            )
        })?;
        if !group.exists(command, shutdown_deadline)? {
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
        require_shutdown_time(command, deadline, "process-group probe")?;
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
mod tests {
    use std::os::unix::process::CommandExt as _;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::{ProcessGroup, TerminationOutcome, terminate_and_reap};

    #[test]
    fn already_exited_child_is_reaped_without_a_termination_request() -> Result<(), std::io::Error>
    {
        let mut command = Command::new("/usr/bin/true");
        command.process_group(0);
        let mut child = command.spawn()?;
        let group = ProcessGroup::new(child.id());
        child.wait()?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(100))
            .ok_or_else(|| std::io::Error::other("test shutdown deadline overflowed"))?;
        let outcome = terminate_and_reap(&mut child, &group, "true", deadline)
            .map_err(|failure| std::io::Error::other(failure.detail))?;
        if outcome != TerminationOutcome::AlreadyExited {
            return Err(std::io::Error::other(
                "already exited child requested process-group termination",
            ));
        }
        Ok(())
    }
}
