use super::*;

#[test]
fn cleanup_failures_never_report_graceful_completion_or_retain_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("cleanup-faults")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_abort: Some(TaskRole::Api),
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let health = process.health();

    let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) =
        process.shutdown(ShutdownTrigger::FirstSignal)
    else {
        panic!("graceful cleanup ambiguity must be typed");
    };
    assert_eq!(cleanup.primary(), positron_runtime::CleanupPrimary::Forced);
    assert_eq!(health.phase(), ProcessPhase::Stopped);
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn forced_shutdown_reports_abort_and_listener_cleanup_ambiguity()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("forced-cleanup-truth")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_abort: Some(TaskRole::Control),
        fail_abort_also: Some(TaskRole::Api),
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;

    let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) =
        process.shutdown(ShutdownTrigger::DeadlineExpired)
    else {
        panic!("forced cleanup ambiguity must be typed");
    };
    assert_eq!(cleanup.task_failures(), 2);
    assert_eq!(cleanup.listener_failures(), 1);
    assert_eq!(cleanup.first_task(), Some(TaskRole::Api));
    assert_eq!(cleanup.primary(), positron_runtime::CleanupPrimary::Forced);
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn second_signal_cleanup_overflow_is_bounded_and_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("cleanup-overflow")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_abort_all: true,
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;

    let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) =
        process.shutdown(ShutdownTrigger::SecondSignal)
    else {
        panic!("cleanup overflow must remain typed");
    };
    assert_eq!(cleanup.task_failures(), 5);
    assert_eq!(cleanup.listener_failures(), 1);
    assert!(cleanup.overflowed());
    assert_eq!(
        cleanup.failed_roles().collect::<Vec<_>>(),
        [
            positron_runtime::CleanupRole::Task(TaskRole::OtlpHttp),
            positron_runtime::CleanupRole::Task(TaskRole::OtlpGrpc),
            positron_runtime::CleanupRole::Task(TaskRole::Api),
            positron_runtime::CleanupRole::Task(TaskRole::Operations),
        ]
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn drop_cleanup_failure_remains_observable_and_releases_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("drop-cleanup-truth")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_abort: Some(TaskRole::Control),
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let health = process.health();

    drop(process);

    assert_eq!(health.phase(), ProcessPhase::Fenced);
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn deadline_aborts_every_task_and_never_reports_graceful_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("deadline")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let health = process.health();

    let outcome = process.shutdown(ShutdownTrigger::DeadlineExpired);

    assert_eq!(outcome, positron_runtime::ExitOutcome::Forced);
    assert_eq!(health.phase(), ProcessPhase::Stopped);
    assert_eq!(health.readiness(), Readiness::NotReady);
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
            TaskEvent::Aborted(TaskRole::OtlpHttp, ProcessPhase::Stopping, true),
            TaskEvent::Aborted(TaskRole::OtlpGrpc, ProcessPhase::Stopping, true),
            TaskEvent::Aborted(TaskRole::Api, ProcessPhase::Stopping, true),
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Stopping, true),
            TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Stopping, true),
        ]
    );
    Ok(())
}

#[test]
fn task_join_failure_reconciles_with_abort_and_forced_exit()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("join-fault")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_join: Some(TaskRole::Api),
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let health = process.health();

    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Forced
    );
    assert_eq!(health.phase(), ProcessPhase::Stopped);
    assert!(roots.acquire_volume_again().is_ok());
    assert!(tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Aborted(TaskRole::Api, ProcessPhase::Stopping, true)
    )));
    Ok(())
}

#[test]
fn missing_instance_is_a_typed_dependency_outage_without_data_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("missing")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(roots.bootstrap_paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("missing instance must fail closed");

    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::StartupUnavailable(
            positron_runtime::BootstrapFailureCode::InconsistentRoots
        )
    );
    assert_eq!(listeners.bound.borrow().as_slice(), control_plane());
    Ok(())
}

#[test]
fn ambiguous_bootstrap_fences_without_exposing_a_data_endpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("fenced")?;
    std::fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(process.health().phase(), ProcessPhase::Fenced);
    assert_eq!(process.health().readiness(), Readiness::NotReady);
    assert_eq!(listeners.bound.borrow().as_slice(), control_plane());
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter_map(|event| match event {
                TaskEvent::Spawned(role) => Some(*role),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [TaskRole::Control, TaskRole::Operations]
    );
    assert!(roots.acquire_volume_again().is_err());
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn first_signal_closes_admission_joins_registered_tasks_and_releases_ownership_last()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("graceful")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let configuration = ServeConfiguration::new(
        roots.bootstrap_paths()?,
        InitializationMode::InitializeIfEmpty,
    );
    let process = ApplicationRuntime::start(configuration, HostInputs::new(&listeners, &tasks))?;
    let health = process.health();
    assert!(format!("{process:?}").contains("RunningProcess"));

    let outcome = process.shutdown(ShutdownTrigger::FirstSignal);

    assert_eq!(outcome, positron_runtime::ExitOutcome::Graceful);
    assert_eq!(health.phase(), ProcessPhase::Stopped);
    assert_eq!(health.readiness(), Readiness::NotReady);
    assert!(roots.acquire_volume_again().is_ok());
    let events = tasks.events.borrow();
    assert_eq!(events.len(), 15);
    assert!(matches!(
        events.last(),
        Some(TaskEvent::Joined(TaskRole::OtlpHttp, ..))
    ));
    Ok(())
}

pub(super) trait TestPort {
    fn test_port(self) -> u16;
}

const fn control_plane() -> &'static [ListenerRole] {
    &[ListenerRole::Control, ListenerRole::Operations]
}

impl TestPort for ListenerRole {
    fn test_port(self) -> u16 {
        match self {
            ListenerRole::Control => 42_399,
            ListenerRole::Operations => 42_400,
            ListenerRole::Api => 42_401,
            ListenerRole::OtlpGrpc => 42_402,
            ListenerRole::OtlpHttp => 42_403,
        }
    }
}
