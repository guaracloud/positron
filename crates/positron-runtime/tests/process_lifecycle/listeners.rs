use super::*;

#[test]
fn listener_bind_failure_is_typed_and_releases_the_volume_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("bind-fault")?;
    let listeners = ObservingListeners {
        fail_role: Some(ListenerRole::OtlpHttp),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks::default();
    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("listener bind failure must fail startup");
    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::ListenerUnavailable(ListenerRole::OtlpHttp)
    );
    assert!(roots.acquire_volume_again().is_ok());
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
    Ok(())
}

#[test]
fn listener_endpoint_role_mismatch_fails_closed_before_startup()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("listener-role-mismatch")?;
    let listeners = ObservingListeners {
        mismatched_role: Some(ListenerRole::Operations),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks::default();
    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("a listener claiming the wrong role must fail closed");
    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::ListenerUnavailable(ListenerRole::Operations)
    );
    assert!(tasks.no_task_spawned());
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}
