#![cfg(test)]

use std::cell::RefCell;
use std::os::unix::process::CommandExt as _;
use std::process::Command;
use std::time::{Duration, Instant};

use super::{
    ProcessGroup, TerminationOutcome, reconcile_after_control_failure, terminate_and_reap,
};
use crate::controlled_execution::{ExecutionFailure, FailurePhase};

#[cfg(test)]
#[test]
fn already_exited_child_is_reaped_without_a_termination_request() -> Result<(), std::io::Error> {
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

#[cfg(test)]
#[test]
fn already_exited_child_is_closed_when_the_group_probe_reaches_the_shutdown_deadline()
-> Result<(), std::io::Error> {
    let mut command = Command::new("/usr/bin/true");
    command.process_group(0);
    let mut child = command.spawn()?;
    let group = ProcessGroup::new(child.id());
    child.wait()?;

    let outcome = terminate_and_reap(&mut child, &group, "true", Instant::now())
        .map_err(|failure| std::io::Error::other(failure.detail))?;
    if outcome != TerminationOutcome::AlreadyExited {
        return Err(std::io::Error::other(
            "already exited child at the shutdown boundary requested termination",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn reaps_an_exit_between_the_live_probe_and_forced_signal_deadline() -> Result<(), std::io::Error> {
    let schedule = RefCell::new(Vec::new());
    let failure = ExecutionFailure::new(
        "scheduled-child".to_owned(),
        FailurePhase::Cleanup,
        "forced termination signal reached the shutdown deadline",
    );
    schedule.borrow_mut().push("try-wait");
    let direct_reaped = Ok(true);
    schedule.borrow_mut().push("group-probe");
    let group_exists = Ok(false);
    let outcome = reconcile_after_control_failure(failure, direct_reaped, group_exists, || {
        schedule.borrow_mut().push("kill-reap");
        Ok(())
    })
    .map_err(|failure| std::io::Error::other(failure.detail))?;
    if outcome != TerminationOutcome::TerminationRequested {
        return Err(std::io::Error::other(
            "the scheduled post-signal exit was not reconciled",
        ));
    }
    if schedule.into_inner() != ["try-wait", "group-probe"] {
        return Err(std::io::Error::other(
            "post-signal reconciliation did not try-wait before the final group probe",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn kills_and_reaps_a_live_direct_child_after_the_group_is_absent() -> Result<(), std::io::Error> {
    let schedule = RefCell::new(Vec::new());
    schedule.borrow_mut().push("try-wait");
    let direct_reaped = Ok(false);
    schedule.borrow_mut().push("group-probe");
    let group_exists = Ok(false);
    let outcome = reconcile_after_control_failure(
        ExecutionFailure::new(
            "scheduled-child".to_owned(),
            FailurePhase::Cleanup,
            "forced termination signal reached the shutdown deadline",
        ),
        direct_reaped,
        group_exists,
        || {
            schedule.borrow_mut().push("kill-reap");
            Ok(())
        },
    )
    .map_err(|failure| std::io::Error::other(failure.detail))?;
    if outcome != TerminationOutcome::TerminationRequested
        || schedule.into_inner() != ["try-wait", "group-probe", "kill-reap"]
    {
        return Err(std::io::Error::other(
            "group absence did not trigger direct child kill and reap",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn retains_a_direct_try_wait_error_when_the_group_is_absent() -> Result<(), std::io::Error> {
    let Err(failure) = reconcile_after_control_failure(
        ExecutionFailure::new(
            "scheduled-child".to_owned(),
            FailurePhase::Cleanup,
            "forced termination signal reached the shutdown deadline",
        ),
        Err(ExecutionFailure::new(
            "scheduled-child".to_owned(),
            FailurePhase::DirectProcess,
            "scheduled try-wait failure",
        )),
        Ok(false),
        || Ok(()),
    ) else {
        return Err(std::io::Error::other(
            "group absence erased a direct try-wait failure",
        ));
    };
    let reconciliation = failure.reconciliation.ok_or_else(|| {
        std::io::Error::other("direct try-wait failure omitted reconciliation context")
    })?;
    if reconciliation.phase != FailurePhase::DirectProcess
        || !reconciliation.detail.contains("scheduled try-wait failure")
    {
        return Err(std::io::Error::other(
            "direct try-wait failure context was not retained",
        ));
    }
    Ok(())
}
