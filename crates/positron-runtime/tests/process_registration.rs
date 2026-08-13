//! Registration-before-spawn failure contract.

#[path = "process_lifecycle.rs"]
mod lifecycle;

use lifecycle::{ObservingListeners, ObservingTasks, TestRoots};
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, ServeConfiguration, TaskRole,
};

#[test]
fn task_registration_failure_is_typed_before_any_spawn() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("register-fault")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::failing_registration(TaskRole::Api);
    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("registration failure must fail startup");
    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::TaskUnavailable(TaskRole::Api)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert!(tasks.no_task_spawned());
    Ok(())
}
