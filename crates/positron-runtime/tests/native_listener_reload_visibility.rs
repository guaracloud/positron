//! Listener reload visibility is part of the public native process contract.

#[path = "support/process_roots.rs"]
mod roots;

use std::sync::Arc;

use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use positron_governance::{
    CompatibilityHints, ConfigurationAuditOutcome, PresentedCredential, RequestedIntent,
};
use positron_runtime::{
    ApplicationRuntime, ConfigurationReloadOutcome, ConfigurationRuntimeFailure, HealthWarning,
    HostInputs, InitializationMode, InstanceBootstrap, ListenerRole, NativeBindings, NativeHost,
    ProcessPhase, Readiness, ServeConfiguration, ShutdownTrigger,
};

#[test]
fn native_listener_reload_updates_visible_plaintext_generation_and_rejected_staging_preserves_it()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = roots::TestRoots::new("native-listener-reload-visibility")?;
    let control = std::env::temp_dir().join(format!(
        "positron-native-listener-reload-visibility-{}.sock",
        std::process::id()
    ));
    let initial = configuration(&listener_document(&control, "plaintext", "plaintext", 0))?;
    let host = NativeHost::new(NativeBindings::from_effective(&initial)?);
    let paths = roots.bootstrap_paths()?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty)
            .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&host, &host),
    )?;
    assert_eq!(
        process.health().security_warnings(),
        [
            HealthWarning::PublicPlaintextApi,
            HealthWarning::PlaintextListener(ListenerRole::OtlpHttp),
        ]
    );
    let runtime = process
        .configuration()
        .ok_or("configuration runtime unavailable")?;
    let initial_generation = runtime.observed()?.generation();

    let tls = configuration(&listener_document(&control, "tls", "tls", 0))?;
    assert!(matches!(
        process.reload_configuration(Arc::clone(&tls))?,
        ConfigurationReloadOutcome::PublishedLive { .. }
    ));
    let tls_observation = runtime.observed()?;
    assert!(tls_observation.generation() > initial_generation);
    assert_eq!(tls_observation.effective().api_transport().as_str(), "tls");
    assert!(process.health().security_warnings().is_empty());

    let plaintext = configuration(&listener_document(&control, "plaintext", "plaintext", 0))?;
    assert!(matches!(
        process.reload_configuration(Arc::clone(&plaintext))?,
        ConfigurationReloadOutcome::PublishedLive { .. }
    ));
    let plaintext_observation = runtime.observed()?;
    assert!(plaintext_observation.generation() > tls_observation.generation());
    assert_eq!(
        process.health().security_warnings(),
        [
            HealthWarning::PublicPlaintextApi,
            HealthWarning::PlaintextListener(ListenerRole::OtlpHttp),
        ]
    );

    let occupied_api_port = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint unavailable")?
        .port();
    let rejected = configuration(&listener_document(
        &control,
        "plaintext",
        "plaintext",
        occupied_api_port,
    ))?;
    assert!(matches!(
        process.reload_configuration(rejected),
        Err(ConfigurationRuntimeFailure::ListenerUnavailable)
    ));
    assert_eq!(
        runtime.observed()?.generation(),
        plaintext_observation.generation()
    );
    assert_eq!(
        process.health().security_warnings(),
        [
            HealthWarning::PublicPlaintextApi,
            HealthWarning::PlaintextListener(ListenerRole::OtlpHttp),
        ]
    );
    assert_eq!(process.health().phase(), ProcessPhase::Serving);
    assert_eq!(process.health().readiness(), Readiness::Ready);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    drop(roots.acquire_volume_again()?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let administrator = reopened.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let records = reopened.inspect_governance_audit_history(administrator)?;
    let configuration_records = records
        .records()
        .iter()
        .filter_map(positron_governance::GovernanceAuditEntry::as_configuration)
        .collect::<Vec<_>>();
    let plaintext_receipts = configuration_records
        .iter()
        .flat_map(|entry| entry.plaintext_listener_opt_outs())
        .collect::<Vec<_>>();
    assert!(
        configuration_records
            .iter()
            .any(|entry| { entry.outcome() == ConfigurationAuditOutcome::PublishedLive })
    );
    assert!(
        configuration_records
            .iter()
            .any(|entry| { entry.outcome() == ConfigurationAuditOutcome::RejectedListenerStaging })
    );
    assert_eq!(plaintext_receipts.len(), 2);
    assert!(plaintext_receipts.iter().any(|receipt| {
        receipt.listener_role() == Some(positron_governance::ListenerTransportRole::Api)
            && receipt.is_configuration_file_intent()
    }));
    assert!(plaintext_receipts.iter().any(|receipt| {
        receipt.listener_role() == Some(positron_governance::ListenerTransportRole::OtlpHttp)
            && receipt.is_configuration_file_intent()
    }));
    Ok(())
}

#[test]
fn failed_joint_plaintext_publication_keeps_the_tls_generation_and_no_role_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = roots::TestRoots::new("native-listener-plaintext-joint-failure")?;
    let control =
        std::env::temp_dir().join(format!("p77-joint-plaintext-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&control);
    let initial = configuration(&listener_document(&control, "tls", "tls", 0))?;
    let host = NativeHost::new(NativeBindings::from_effective(&initial)?);
    let paths = roots.bootstrap_paths()?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty)
            .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&host, &host),
    )?;
    let runtime = process
        .configuration()
        .ok_or("configuration runtime unavailable")?;
    let before = runtime.observed()?;
    let candidate = configuration(&listener_document(&control, "plaintext", "plaintext", 0))?;
    let failure = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || process.reload_configuration(candidate),
    )
    .expect_err("a failed joint commit must reject the plaintext successor");
    assert_eq!(failure, ConfigurationRuntimeFailure::PublicationUnavailable);
    assert_eq!(runtime.observed()?.generation(), before.generation());
    assert!(process.health().security_warnings().is_empty());
    assert_eq!(process.health().phase(), ProcessPhase::Serving);
    assert_eq!(process.health().readiness(), Readiness::Ready);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    drop(roots.acquire_volume_again()?);
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
            .all(|entry| entry.plaintext_listener_opt_outs().is_empty())
    );
    Ok(())
}

fn configuration(
    document: &str,
) -> Result<Arc<positron_config::EffectiveConfiguration>, Box<dyn std::error::Error>> {
    let inputs = ConfigurationInputs::try_new(
        Some(document),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?;
    Ok(Arc::new(resolve(inputs)?))
}

fn listener_document(
    control: &std::path::Path,
    api_transport: &str,
    otlp_http_transport: &str,
    operations_port: u16,
) -> String {
    let fixture = format!(
        "{}/tests/native_transport/fixtures",
        env!("CARGO_MANIFEST_DIR")
    );
    format!(
        "schema_version = 1\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:{operations_port}\"\noperations_transport = \"tls\"\napi_bind_address = \"127.0.0.1:0\"\napi_transport = \"{api_transport}\"\notlp_grpc_bind_address = \"127.0.0.1:0\"\notlp_grpc_transport = \"tls\"\notlp_http_bind_address = \"127.0.0.1:0\"\notlp_http_transport = \"{otlp_http_transport}\"\nloki_push_bind_address = \"127.0.0.1:0\"\nloki_push_transport = \"tls\"\noperations_tls_certificate_file = \"{fixture}/api-test-cert.pem\"\noperations_tls_private_key_file = \"{fixture}/api-test-key.pem\"\napi_tls_certificate_file = \"{fixture}/api-test-cert.pem\"\napi_tls_private_key_file = \"{fixture}/api-test-key.pem\"\notlp_grpc_tls_certificate_file = \"{fixture}/api-test-cert.pem\"\notlp_grpc_tls_private_key_file = \"{fixture}/api-test-key.pem\"\notlp_http_tls_certificate_file = \"{fixture}/api-test-cert.pem\"\notlp_http_tls_private_key_file = \"{fixture}/api-test-key.pem\"\nloki_push_tls_certificate_file = \"{fixture}/api-test-cert.pem\"\nloki_push_tls_private_key_file = \"{fixture}/api-test-key.pem\"\n",
        control.display(),
    )
}
