use super::*;

#[test]
fn empty_cleanup_failure_has_no_synthetic_truth() {
    let cleanup = positron_runtime::CleanupFailure::default();
    assert_eq!(cleanup.primary(), positron_runtime::CleanupPrimary::None);
    assert_eq!(cleanup.first_task(), None);
    assert_eq!(cleanup.task_failures(), 0);
    assert_eq!(cleanup.listener_failures(), 0);
    assert_eq!(cleanup.failed_roles().count(), 0);
    assert!(!cleanup.overflowed());
}

#[test]
fn listener_only_cleanup_truth_is_typed_for_every_listener_role()
-> Result<(), Box<dyn std::error::Error>> {
    for role in [
        ListenerRole::Control,
        ListenerRole::Operations,
        ListenerRole::Api,
        ListenerRole::OtlpHttp,
    ] {
        let roots = TestRoots::new(&format!("listener-only-{role:?}"))?;
        let listeners = ObservingListeners {
            fail_close: Some(role),
            ..ObservingListeners::default()
        };
        let tasks = ObservingTasks::default();
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(
                roots.bootstrap_paths()?,
                InitializationMode::InitializeIfEmpty,
            ),
            HostInputs::new(&listeners, &tasks),
        )?;
        let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) =
            process.shutdown(ShutdownTrigger::FirstSignal)
        else {
            panic!("persistent listener failure must remain typed");
        };
        let expected_primary = if role.is_data() {
            positron_runtime::CleanupPrimary::Forced
        } else {
            positron_runtime::CleanupPrimary::Graceful
        };
        assert_eq!(cleanup.primary(), expected_primary);
        assert_eq!(cleanup.first_task(), None);
        assert_eq!(cleanup.task_failures(), 0);
        assert_eq!(cleanup.listener_failures(), 1);
        assert_eq!(
            cleanup.failed_roles().collect::<Vec<_>>(),
            [positron_runtime::CleanupRole::Listener(role)]
        );
        assert!(!cleanup.overflowed());
        assert!(roots.acquire_volume_again().is_ok());
    }
    Ok(())
}

#[test]
fn task_only_cleanup_truth_deduplicates_retried_abort_role()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("task-only-dedupe")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_abort: Some(TaskRole::Operations),
        fail_abort_also: Some(TaskRole::Operations),
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
        panic!("persistent task failure must remain typed");
    };
    assert_eq!(cleanup.primary(), positron_runtime::CleanupPrimary::Forced);
    assert_eq!(cleanup.first_task(), Some(TaskRole::Operations));
    assert_eq!(cleanup.task_failures(), 1);
    assert_eq!(cleanup.listener_failures(), 0);
    assert_eq!(
        cleanup.failed_roles().collect::<Vec<_>>(),
        [positron_runtime::CleanupRole::Task(TaskRole::Operations)]
    );
    assert!(!cleanup.overflowed());
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn transient_abort_failure_is_retried_without_false_cleanup_ambiguity()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("transient-abort")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_abort_once: Some(TaskRole::Operations),
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::DeadlineExpired),
        positron_runtime::ExitOutcome::Forced
    );
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter(|event| matches!(event, TaskEvent::Aborted(TaskRole::Operations, ..)))
            .count(),
        2
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}
