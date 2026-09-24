use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use positron_config::{
    CommandLineOverrides, ConfigurationDiff, ConfigurationDriftDisposition, ConfigurationInputs,
    EnvironmentOverrides, LogLevel, resolve,
};
use positron_governance::{
    CompatibilityHints, ConfigurationAuditOutcome, PresentedCredential, RequestedIntent,
};
use positron_runtime::{
    ApplicationRuntime, ConfigurationPublication, ConfigurationPublicationDisposition,
    ConfigurationReloadOutcome, ConfigurationRuntimeFailure, HostInputs, InitializationMode,
    InstanceBootstrap, ListenerRole, NativeBindings, NativeHost, ProcessPhase, Readiness,
    RuntimeConfiguration, ServeConfiguration, ShutdownTrigger,
};

#[allow(dead_code)]
#[path = "support/process_lifecycle.rs"]
mod lifecycle;
use lifecycle::{ObservingListeners, ObservingTasks, TestRoots};

struct FailingPublication;

impl ConfigurationPublication for FailingPublication {
    fn publish(
        &self,
        _: &positron_config::EffectiveConfiguration,
        _: &positron_config::EffectiveConfiguration,
        _: &ConfigurationDiff,
        _: ConfigurationPublicationDisposition,
    ) -> Result<u64, ConfigurationRuntimeFailure> {
        Err(ConfigurationRuntimeFailure::PublicationUnavailable)
    }
}

struct ReceiptPublication(u64);

impl ConfigurationPublication for ReceiptPublication {
    fn publish(
        &self,
        _: &positron_config::EffectiveConfiguration,
        _: &positron_config::EffectiveConfiguration,
        _: &ConfigurationDiff,
        _: ConfigurationPublicationDisposition,
    ) -> Result<u64, ConfigurationRuntimeFailure> {
        Ok(self.0)
    }
}

struct BlockingPublication {
    gate: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl BlockingPublication {
    fn new() -> Self {
        Self {
            gate: Mutex::new((false, false)),
            changed: Condvar::new(),
        }
    }

    fn wait_until_publish_started(&self) -> Result<(), Box<dyn std::error::Error>> {
        let guard = self.gate.lock().map_err(|_| "publication gate poisoned")?;
        let (_released, timed_out) = self
            .changed
            .wait_timeout_while(guard, Duration::from_secs(2), |(entered, _)| !*entered)
            .map_err(|_| "publication gate poisoned")?;
        if timed_out.timed_out() {
            return Err("publication did not begin".into());
        }
        Ok(())
    }

    fn release(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut gate = self.gate.lock().map_err(|_| "publication gate poisoned")?;
        gate.1 = true;
        self.changed.notify_all();
        Ok(())
    }
}

impl ConfigurationPublication for BlockingPublication {
    fn publish(
        &self,
        _: &positron_config::EffectiveConfiguration,
        _: &positron_config::EffectiveConfiguration,
        _: &ConfigurationDiff,
        _: ConfigurationPublicationDisposition,
    ) -> Result<u64, ConfigurationRuntimeFailure> {
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)?;
        gate.0 = true;
        self.changed.notify_all();
        let (gate, _) = self
            .changed
            .wait_timeout_while(gate, Duration::from_secs(2), |(_, released)| !*released)
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)?;
        if !gate.1 {
            return Err(ConfigurationRuntimeFailure::PublicationUnavailable);
        }
        Ok(2)
    }
}

fn configuration(
    document: Option<&str>,
) -> Result<Arc<positron_config::EffectiveConfiguration>, Box<dyn std::error::Error>> {
    let inputs = ConfigurationInputs::try_new(
        document,
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?;
    Ok(Arc::new(resolve(inputs)?))
}

#[test]
fn rejected_immutable_reload_preserves_the_observed_complete_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeConfiguration::new(configuration(None)?);
    let before = runtime.observed()?;
    let candidate = configuration(Some(
        "schema_version = 1\n[storage]\ndata_directory = \"/different-data\"\n",
    ))?;

    let outcome = runtime.reload_with(candidate, &ReceiptPublication(2))?;

    assert!(matches!(
        outcome,
        ConfigurationReloadOutcome::RejectedImmutable { .. }
    ));
    let after = runtime.observed()?;
    assert_eq!(after.generation(), before.generation());
    assert_eq!(after.effective().data_directory(), "/var/lib/positron");
    assert_eq!(after.effective().log_level(), LogLevel::Info);
    Ok(())
}

#[test]
fn mixed_live_and_restart_required_reload_publishes_only_live_settings_and_keeps_candidate_pending()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeConfiguration::new(configuration(None)?);
    let candidate = configuration(Some(
        "schema_version = 1\n[diagnostics]\nlog_level = \"debug\"\n[runtime]\nshutdown_grace_seconds = 60\n",
    ))?;

    let outcome = runtime.reload_with(Arc::clone(&candidate), &ReceiptPublication(2))?;

    assert!(matches!(
        outcome,
        ConfigurationReloadOutcome::PendingRestart { generation: 2, .. }
    ));
    let observed = runtime.observed()?;
    assert_eq!(observed.generation(), 2);
    assert_eq!(observed.effective().log_level(), LogLevel::Debug);
    assert_eq!(observed.effective().shutdown_grace_seconds(), 30);
    let pending = observed
        .pending_restart()
        .ok_or("restart candidate missing")?;
    assert_eq!(pending.candidate().shutdown_grace_seconds(), 60);
    assert_eq!(pending.candidate().log_level(), LogLevel::Debug);
    Ok(())
}

#[test]
fn restart_only_reload_advances_to_the_catalog_generation_which_records_the_pending_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeConfiguration::new(configuration(None)?);
    let candidate = configuration(Some(
        "schema_version = 1\n[runtime]\nshutdown_grace_seconds = 60\n",
    ))?;

    let outcome = runtime.reload_with(Arc::clone(&candidate), &ReceiptPublication(7))?;

    assert!(matches!(
        outcome,
        ConfigurationReloadOutcome::PendingRestart { generation: 7, .. }
    ));
    let observed = runtime.observed()?;
    assert_eq!(observed.generation(), 7);
    assert_eq!(observed.effective().shutdown_grace_seconds(), 30);
    assert_eq!(
        observed
            .pending_restart()
            .ok_or("restart candidate missing")?
            .candidate()
            .shutdown_grace_seconds(),
        60
    );
    Ok(())
}

#[test]
fn drain_and_reload_candidate_is_visible_as_unapplied_until_the_listener_owner_can_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeConfiguration::new(configuration(None)?);
    let candidate = configuration(Some(
        "schema_version = 1\n[listener]\noperations_bind_address = \"127.0.0.1:4318\"\n",
    ))?;

    let outcome = runtime.reload_with(candidate, &ReceiptPublication(2))?;

    assert!(matches!(
        outcome,
        ConfigurationReloadOutcome::RequiresDrain { .. }
    ));
    let observed = runtime.observed()?;
    assert_eq!(observed.generation(), 1);
    assert_eq!(observed.effective().operations_bind_address().port(), 13133);
    Ok(())
}

#[test]
fn failed_durable_publication_preserves_the_active_generation_and_consumer_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeConfiguration::new(configuration(None)?);
    let candidate = configuration(Some(
        "schema_version = 1\n[diagnostics]\nlog_level = \"debug\"\n",
    ))?;

    let failure = runtime
        .reload_with(candidate, &FailingPublication)
        .expect_err("audit or catalog failure rejects the reload");

    assert_eq!(failure, ConfigurationRuntimeFailure::PublicationUnavailable);
    let observed = runtime.observed()?;
    assert_eq!(observed.generation(), 1);
    assert_eq!(observed.effective().log_level(), LogLevel::Info);
    assert!(observed.pending_restart().is_none());
    Ok(())
}

#[test]
fn catalog_receipt_generation_is_the_only_generation_exposed_after_live_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeConfiguration::new(configuration(None)?);
    let candidate = configuration(Some(
        "schema_version = 1\n[diagnostics]\nlog_level = \"debug\"\n",
    ))?;

    let outcome = runtime.reload_with(candidate, &ReceiptPublication(41))?;

    assert!(matches!(
        outcome,
        ConfigurationReloadOutcome::PublishedLive { generation: 41, .. }
    ));
    let observed = runtime.observed()?;
    assert_eq!(observed.generation(), 41);
    assert_eq!(observed.effective().log_level(), LogLevel::Debug);
    Ok(())
}

#[test]
fn observation_waits_for_a_durable_reload_and_never_exposes_a_stale_configuration_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = Arc::new(RuntimeConfiguration::new(configuration(None)?));
    let candidate = configuration(Some(
        "schema_version = 1\n[diagnostics]\nlog_level = \"debug\"\n",
    ))?;
    let publication = Arc::new(BlockingPublication::new());
    let reloading_runtime = Arc::clone(&runtime);
    let reloading_publication = Arc::clone(&publication);
    let reloader =
        thread::spawn(move || reloading_runtime.reload_with(candidate, &*reloading_publication));
    publication.wait_until_publish_started()?;

    let observing_runtime = Arc::clone(&runtime);
    let (observed_tx, observed_rx) = mpsc::channel();
    let observer = thread::spawn(move || observed_tx.send(observing_runtime.observed()));
    assert!(
        observed_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "the canonical observation must not report the prior generation while publication is pending"
    );

    publication.release()?;
    assert!(matches!(
        reloader.join().map_err(|_| "reloader panicked")??,
        ConfigurationReloadOutcome::PublishedLive { generation: 2, .. }
    ));
    let observed = observed_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| "observer did not receive the committed observation")??;
    observer.join().map_err(|_| "observer panicked")??;
    assert_eq!(observed.generation(), 2);
    assert_eq!(observed.effective().log_level(), LogLevel::Debug);
    assert_eq!(observed.desired().log_level(), LogLevel::Debug);
    assert_eq!(
        observed.drift_disposition(),
        ConfigurationDriftDisposition::None
    );
    Ok(())
}

#[test]
fn desired_configuration_drift_is_redacted_and_fences_security_or_storage_identity_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeConfiguration::new(configuration(None)?);
    let ordinary_desired = configuration(Some(
        "schema_version = 1\n[diagnostics]\nlog_level = \"debug\"\n",
    ))?;
    let fenced_desired = configuration(Some(
        "schema_version = 1\n[storage]\ndata_directory = \"/different-data\"\n",
    ))?;

    let ordinary = runtime.drift_against(ordinary_desired)?;
    let fenced = runtime.drift_against(fenced_desired)?;

    assert_eq!(
        ordinary.disposition(),
        ConfigurationDriftDisposition::Reconcile
    );
    assert_eq!(fenced.disposition(), ConfigurationDriftDisposition::Fence);
    assert_eq!(fenced.diff().changes().len(), 1);
    assert_eq!(
        fenced.diff().changes()[0].setting().path(),
        "storage.data_directory"
    );
    Ok(())
}

#[test]
fn catalog_and_governance_audit_publication_survives_restart_without_replacing_the_active_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("configuration-publication")?;
    let initial = configuration(None)?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        )
        .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&listeners, &tasks),
    )?;
    let runtime = process
        .configuration()
        .ok_or("configuration runtime missing")?;
    let initial_generation = runtime.observed()?.generation();
    let desired = configuration(Some(
        "schema_version = 1\n[diagnostics]\nlog_level = \"debug\"\n",
    ))?;

    let outcome = process.reload_configuration(Arc::clone(&desired))?;
    let ConfigurationReloadOutcome::PublishedLive { generation, .. } = outcome else {
        return Err("live configuration was not published".into());
    };
    assert!(generation > initial_generation);
    assert_eq!(runtime.observed()?.effective().log_level(), LogLevel::Debug);
    assert!(matches!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));

    let restarted_listeners = ObservingListeners::default();
    let restarted_tasks = ObservingTasks::default();
    let restarted = ApplicationRuntime::start(
        ServeConfiguration::new(roots.bootstrap_paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(desired),
        HostInputs::new(&restarted_listeners, &restarted_tasks),
    )?;
    let observed = restarted
        .configuration()
        .ok_or("configuration runtime missing after restart")?
        .observed()?;
    assert_eq!(observed.generation(), generation);
    assert_eq!(observed.effective().log_level(), LogLevel::Debug);
    assert!(matches!(
        restarted.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    Ok(())
}

#[test]
fn listener_reload_publishes_the_staged_configuration_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("configuration-listener-generation")?;
    let first_operations = available_loopback_port()?;
    let successor_operations = available_loopback_port()?;
    let control_path = std::env::temp_dir().join(format!(
        "p77-listener-generation-{}-{first_operations}.sock",
        std::process::id()
    ));
    let initial = configuration(Some(&listener_configuration(
        control_path.clone(),
        first_operations,
    )))?;
    let host = NativeHost::new(NativeBindings::from_effective(&initial)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        )
        .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&host, &host),
    )?;
    let runtime = process
        .configuration()
        .ok_or("configuration runtime missing")?;
    let before = runtime.observed()?;
    let candidate = configuration(Some(&listener_configuration(
        control_path,
        successor_operations,
    )))?;

    let outcome = process.reload_configuration(candidate)?;

    assert!(matches!(
        outcome,
        ConfigurationReloadOutcome::PublishedLive { .. }
    ));
    let after = runtime.observed()?;
    assert!(after.generation() > before.generation());
    assert_eq!(
        after.effective().operations_bind_address().port(),
        successor_operations
    );
    let operations = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == ListenerRole::Operations)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("replacement operations endpoint missing")?;
    assert_eq!(operations.port(), successor_operations);
    assert!(matches!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    Ok(())
}

#[test]
fn same_endpoint_reload_drains_accepted_old_work_before_the_successor_serves()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};

    let roots = TestRoots::new("configuration-listener-drain")?;
    let operations_port = available_loopback_port()?;
    let control_path = std::env::temp_dir().join(format!(
        "p77-listener-drain-{}-{operations_port}.sock",
        std::process::id()
    ));
    let initial = configuration(Some(&listener_configuration(
        control_path.clone(),
        operations_port,
    )))?;
    let host = NativeHost::new(NativeBindings::from_effective(&initial)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        )
        .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&host, &host),
    )?;
    let mut old = std::net::TcpStream::connect(("127.0.0.1", operations_port))?;
    old.set_read_timeout(Some(Duration::from_secs(3)))?;
    old.write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\n")?;
    std::thread::sleep(Duration::from_millis(25));
    let candidate = configuration(Some(&format!(
        "{}\n[listener.operations]\ntrusted_proxy_cidrs = [\"127.0.0.1/32\"]\nforwarded_hops = 1\n",
        listener_configuration(control_path, operations_port)
    )))?;

    let outcome = process.reload_configuration(candidate)?;

    assert!(matches!(
        outcome,
        ConfigurationReloadOutcome::PublishedLive { .. }
    ));
    let mut old_terminal = String::new();
    old.read_to_string(&mut old_terminal)?;
    assert!(
        old_terminal.starts_with("HTTP/1.1 400 "),
        "accepted old connection did not receive its bounded terminal response: {old_terminal:?}"
    );
    let mut fresh = std::net::TcpStream::connect(("127.0.0.1", operations_port))?;
    fresh.set_read_timeout(Some(Duration::from_secs(1)))?;
    fresh
        .write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")?;
    let mut successor = String::new();
    fresh.read_to_string(&mut successor)?;
    assert!(successor.starts_with("HTTP/1.1 200 "));
    assert!(matches!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    Ok(())
}

#[test]
fn failed_listener_staging_preserves_the_serving_generation_and_endpoints()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("configuration-listener-staging-failure")?;
    let paths = roots.bootstrap_paths()?;
    let operations_port = available_loopback_port()?;
    let control_path = std::env::temp_dir().join(format!(
        "p77-listener-staging-failure-{}-{operations_port}.sock",
        std::process::id()
    ));
    let initial = configuration(Some(&listener_configuration(
        control_path.clone(),
        operations_port,
    )))?;
    let host = NativeHost::new(NativeBindings::from_effective(&initial)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty)
            .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&host, &host),
    )?;
    let runtime = process
        .configuration()
        .ok_or("configuration runtime missing")?;
    let before = runtime.observed()?;
    let endpoints = process.bound_endpoints();
    let occupied_api_port = endpoints
        .iter()
        .find(|endpoint| endpoint.role() == ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint missing")?
        .port();
    let candidate = configuration(Some(&listener_configuration(
        control_path,
        occupied_api_port,
    )))?;

    let failure = process
        .reload_configuration(Arc::clone(&candidate))
        .expect_err("a staged role cannot bind another active role's endpoint");

    assert_eq!(failure, ConfigurationRuntimeFailure::ListenerUnavailable);
    assert_eq!(process.health().phase(), ProcessPhase::Serving);
    assert_eq!(process.health().readiness(), Readiness::Ready);
    assert_eq!(process.bound_endpoints(), endpoints);
    let after = runtime.observed()?;
    assert_eq!(after.generation(), before.generation());
    assert_eq!(
        after.effective().operations_bind_address(),
        before.effective().operations_bind_address()
    );
    assert!(matches!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    let claim = InstanceBootstrap::claim(&paths)?;
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let administrator = reopened.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let history = reopened.inspect_governance_audit_history(administrator)?;
    let rejected = history
        .records()
        .iter()
        .filter_map(positron_governance::GovernanceAuditEntry::as_configuration)
        .find(|entry| entry.outcome() == ConfigurationAuditOutcome::RejectedListenerStaging)
        .ok_or("listener staging rejection audit missing")?;
    assert_ne!(rejected.active_digest(), rejected.candidate_digest());
    Ok(())
}

#[test]
fn failed_listener_staging_reports_audit_publication_failure_without_advancing_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("configuration-listener-staging-audit-failure")?;
    let paths = roots.bootstrap_paths()?;
    let operations_port = available_loopback_port()?;
    let control_path = std::env::temp_dir().join(format!(
        "p77-listener-staging-audit-failure-{}-{operations_port}.sock",
        std::process::id()
    ));
    let initial = configuration(Some(&listener_configuration(
        control_path.clone(),
        operations_port,
    )))?;
    let host = NativeHost::new(NativeBindings::from_effective(&initial)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty)
            .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&host, &host),
    )?;
    let runtime = process
        .configuration()
        .ok_or("configuration runtime missing")?;
    let before = runtime.observed()?;
    let occupied_api_port = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint missing")?
        .port();
    let candidate = configuration(Some(&listener_configuration(
        control_path,
        occupied_api_port,
    )))?;

    let failure = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || process.reload_configuration(candidate),
    )
    .expect_err("a rejected staging audit must fail explicitly when it cannot commit");

    assert_eq!(failure, ConfigurationRuntimeFailure::PublicationUnavailable);
    assert_eq!(runtime.observed()?.generation(), before.generation());
    assert_eq!(process.health().phase(), ProcessPhase::Serving);
    assert!(matches!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    let claim = InstanceBootstrap::claim(&paths)?;
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let administrator = reopened.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let history = reopened.inspect_governance_audit_history(administrator)?;
    assert!(
        history
            .records()
            .iter()
            .filter_map(positron_governance::GovernanceAuditEntry::as_configuration)
            .all(|entry| entry.outcome() != ConfigurationAuditOutcome::RejectedListenerStaging)
    );
    Ok(())
}

#[test]
fn same_endpoint_proxy_policy_reload_keeps_the_serving_endpoints_stable()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("configuration-listener-policy-generation")?;
    let operations_port = available_loopback_port()?;
    let control_path = std::env::temp_dir().join(format!(
        "p77-listener-policy-generation-{}-{operations_port}.sock",
        std::process::id()
    ));
    let initial = configuration(Some(&listener_configuration(
        control_path.clone(),
        operations_port,
    )))?;
    let host = NativeHost::new(NativeBindings::from_effective(&initial)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        )
        .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&host, &host),
    )?;
    let endpoints = process.bound_endpoints();
    let candidate = configuration(Some(&format!(
        "{}\n[listener.operations]\ntrusted_proxy_cidrs = [\"127.0.0.1/32\"]\nforwarded_hops = 1\n",
        listener_configuration(control_path, operations_port)
    )))?;

    let outcome = process.reload_configuration(candidate)?;

    assert!(matches!(
        outcome,
        ConfigurationReloadOutcome::PublishedLive { .. }
    ));
    assert_eq!(process.bound_endpoints(), endpoints);
    assert_eq!(process.health().phase(), ProcessPhase::Serving);
    assert_eq!(process.health().readiness(), Readiness::Ready);
    assert!(matches!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    Ok(())
}

fn available_loopback_port() -> Result<u16, std::io::Error> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr().map(|address| address.port())
}

fn listener_configuration(control_path: std::path::PathBuf, operations_port: u16) -> String {
    format!(
        "schema_version = 1\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:{operations_port}\"\noperations_transport = \"plaintext\"\napi_bind_address = \"127.0.0.1:0\"\napi_transport = \"plaintext\"\notlp_grpc_bind_address = \"127.0.0.1:0\"\notlp_grpc_transport = \"plaintext\"\notlp_http_bind_address = \"127.0.0.1:0\"\notlp_http_transport = \"plaintext\"\nloki_push_bind_address = \"127.0.0.1:0\"\nloki_push_transport = \"plaintext\"\n",
        control_path.display(),
    )
}

#[test]
fn protected_reference_changes_have_distinct_opaque_audit_bindings()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("configuration-audit-binding")?;
    let paths = roots.bootstrap_paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let initial = configuration(Some(
        "schema_version = 1\n[listener]\napi_tls_certificate_file = \"/protected/certificate-a.pem\"\n",
    ))?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly)
            .with_effective_configuration(initial),
        HostInputs::new(&listeners, &tasks),
    )
    .map_err(|failure| format!("starting protected-reference configuration: {failure:?}"))?;
    for certificate in [
        "/protected/certificate-b.pem",
        "/protected/certificate-c.pem",
    ] {
        let candidate = configuration(Some(&format!(
            "schema_version = 1\n[listener]\napi_tls_certificate_file = \"{certificate}\"\n"
        )))?;
        let outcome = process.reload_configuration(candidate).map_err(|failure| {
            format!("publishing protected-reference configuration: {failure:?}")
        })?;
        assert!(matches!(
            outcome,
            ConfigurationReloadOutcome::RequiresDrain { .. }
        ));
    }
    assert!(matches!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    let claim = InstanceBootstrap::claim(&paths)?;
    let reopened = InstanceBootstrap::reopen(&paths)
        .map_err(|failure| format!("reopening protected-reference audit: {failure:?}"))?;
    let administrator = reopened.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let history = reopened.inspect_governance_audit_history(administrator)?;
    let reloads = history
        .records()
        .iter()
        .filter_map(positron_governance::GovernanceAuditEntry::as_configuration)
        .filter(|entry| entry.outcome() == ConfigurationAuditOutcome::RequiresDrain)
        .collect::<Vec<_>>();
    assert_eq!(reloads.len(), 2);
    let first = reloads
        .first()
        .ok_or("first protected reload audit missing")?;
    let second = reloads
        .get(1)
        .ok_or("second protected reload audit missing")?;
    assert_eq!(first.active_digest(), first.candidate_digest());
    assert_eq!(second.active_digest(), second.candidate_digest());
    assert_eq!(first.candidate_digest(), second.candidate_digest());
    assert_ne!(first.request_id(), second.request_id());
    Ok(())
}

#[test]
fn startup_refuses_an_immutable_configuration_change_after_initialization()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("configuration-startup-immutable")?;
    let initial = configuration(None)?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let initialized = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        )
        .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert!(matches!(
        initialized.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));

    let changed_storage_identity = configuration(Some(
        "schema_version = 1\n[storage]\ndata_directory = \"/different-data\"\n",
    ))?;
    let rejected = ApplicationRuntime::start(
        ServeConfiguration::new(roots.bootstrap_paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(changed_storage_identity),
        HostInputs::new(&listeners, &tasks),
    );
    let failure = match rejected {
        Ok(process) => {
            let _ = process.shutdown(ShutdownTrigger::FirstSignal);
            return Err("immutable startup change was accepted".into());
        },
        Err(failure) => failure,
    };
    assert_eq!(failure, positron_runtime::ExitOutcome::InvalidConfiguration);

    let recovered = ApplicationRuntime::start(
        ServeConfiguration::new(roots.bootstrap_paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(initial),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert!(matches!(
        recovered.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    Ok(())
}

#[test]
fn security_or_storage_drift_is_durably_reported_before_the_process_fences_data_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("configuration-drift-fence")?;
    let active = configuration(None)?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        )
        .with_effective_configuration(Arc::clone(&active)),
        HostInputs::new(&listeners, &tasks),
    )?;
    let runtime = process
        .configuration()
        .ok_or("configuration runtime missing")?;
    let before = runtime.observed()?;
    let desired = configuration(Some(
        "schema_version = 1\n[storage]\ndata_directory = \"/different-data\"\n",
    ))?;

    let drift = process.reconcile_configuration_drift(desired)?;

    assert_eq!(drift.disposition(), ConfigurationDriftDisposition::Fence);
    assert_eq!(process.health().phase(), ProcessPhase::Fenced);
    assert_eq!(process.health().readiness(), Readiness::NotReady);
    let after = runtime.observed()?;
    assert_eq!(after.generation(), before.generation());
    assert_eq!(after.effective().data_directory(), active.data_directory());
    assert!(matches!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    Ok(())
}
