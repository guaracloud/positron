//! Process lifecycle contract through the public runtime seam.

#[path = "support/process_lifecycle.rs"]
mod lifecycle;

use lifecycle::{ObservingListeners, ObservingTasks, TaskEvent, TestRoots};
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, ListenerRole, ProcessPhase, Readiness,
    ServeConfiguration, ShutdownTrigger, TaskRole,
};

#[test]
fn partial_task_spawn_failure_aborts_started_tasks_and_releases_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("spawn-fault")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::Api),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("task spawn failure must fail startup");

    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::TaskUnavailable(TaskRole::Api)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter(|event| matches!(event, TaskEvent::Aborted(..)))
            .cloned()
            .collect::<Vec<_>>(),
        [
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true),
        ]
    );
    Ok(())
}

#[test]
fn partial_spawn_with_failed_rollback_reports_internal_cleanup_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("spawn-rollback-fault")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::Api),
        fail_abort: Some(TaskRole::Operations),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("failed rollback must not report only the later spawn failure");

    let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) = failure else {
        panic!("unexpected startup outcome: {failure:?}");
    };
    assert_eq!(cleanup.first_task(), Some(TaskRole::Operations));
    assert_eq!(cleanup.task_failures(), 1);
    assert_eq!(cleanup.listener_failures(), 1);
    assert!(roots.acquire_volume_again().is_ok());
    assert!(tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true)
    )));
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter(|event| matches!(event, TaskEvent::Aborted(..)))
            .cloned()
            .collect::<Vec<_>>(),
        [
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
        ]
    );
    Ok(())
}

#[test]
fn nested_spawn_rollback_merges_data_control_and_listener_cleanup_truth()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("nested-cleanup")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::OtlpHttp),
        fail_abort: Some(TaskRole::Api),
        fail_abort_also: Some(TaskRole::Control),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("nested cleanup ambiguity must be preserved");
    let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) = failure else {
        panic!("unexpected outcome: {failure:?}");
    };
    assert_eq!(cleanup.task_failures(), 2);
    assert_eq!(cleanup.listener_failures(), 1);
    assert_eq!(
        cleanup.primary(),
        positron_runtime::CleanupPrimary::TaskUnavailable(TaskRole::OtlpHttp)
    );
    assert_eq!(
        cleanup.failed_roles().collect::<Vec<_>>(),
        [
            positron_runtime::CleanupRole::Task(TaskRole::Api),
            positron_runtime::CleanupRole::Task(TaskRole::Control),
            positron_runtime::CleanupRole::Listener(ListenerRole::Api),
        ]
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn fenced_partial_task_spawn_failure_aborts_started_tasks_and_releases_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("fenced-spawn-fault")?;
    std::fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::Operations),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("fenced task spawn failure must fail startup");

    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::TaskUnavailable(TaskRole::Operations)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert!(tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true)
    )));
    Ok(())
}

#[path = "process_lifecycle/cleanup_outcomes.rs"]
mod cleanup_outcomes;
#[path = "process_lifecycle/listeners.rs"]
mod listeners;
#[path = "process_lifecycle/outcomes.rs"]
mod outcomes;
