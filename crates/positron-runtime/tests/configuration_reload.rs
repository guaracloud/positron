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
    InstanceBootstrap, ProcessPhase, Readiness, RuntimeConfiguration, ServeConfiguration,
    ShutdownTrigger,
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
