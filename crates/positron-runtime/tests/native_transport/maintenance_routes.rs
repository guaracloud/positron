use super::*;

#[test]
fn system_administrator_can_read_redacted_bounded_maintenance_status()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("maintenance-status")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "maintenance-status")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let response = http(
        address(
            &process.bound_endpoints(),
            positron_runtime::ListenerRole::Api,
        )?,
        "POST",
        "/v1/maintenance:status",
        &[
            ("Authorization", &format!("Bearer {}", claim.secret())),
            ("Content-Type", "application/json"),
        ],
        br#"{}"#,
    )?;
    assert_status(response.clone(), 200);
    assert!(response.contains("\"tasks\":"), "status must expose tasks");
    assert!(
        response.contains("\"queued\":"),
        "status must expose bounded counts"
    );
    assert!(
        !response.contains(claim.secret()),
        "status must never disclose the administrator credential"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn maintenance_status_rejects_an_unauthenticated_request_before_decoding()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("maint-auth")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let _claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "maint-auth")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    assert_status(
        http(
            address(
                &process.bound_endpoints(),
                positron_runtime::ListenerRole::Api,
            )?,
            "POST",
            positron_api::maintenance::STATUS_HTTP_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unexpected":"body must remain unread"}"#,
        )?,
        401,
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn system_administrator_can_explain_one_bounded_maintenance_task()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("maint-explain")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "maint-explain")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    assert_status(
        http(
            address(
                &process.bound_endpoints(),
                positron_runtime::ListenerRole::Api,
            )?,
            "POST",
            positron_api::maintenance::STATUS_HTTP_PATH,
            &[
                ("Authorization", &format!("Bearer {}", claim.secret())),
                ("Content-Type", "application/json"),
            ],
            br#"{}"#,
        )?,
        200,
    );
    let response = http(
        address(
            &process.bound_endpoints(),
            positron_runtime::ListenerRole::Api,
        )?,
        "POST",
        "/v1/maintenance:explain",
        &[
            ("Authorization", &format!("Bearer {}", claim.secret())),
            ("Content-Type", "application/json"),
        ],
        br#"{"identity":"00000000000000000000000000000001"}"#,
    )?;
    assert_status(response.clone(), 404);
    assert!(response.contains("\"code\":\"task_unavailable\""));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}
