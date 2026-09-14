use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::identity::{Scope, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_ingest::{IngestRequestOutcome, NativeLogAdmissionGroups};
use positron_kernel::{CatalogPublicationFault, FormatEpoch, with_catalog_publication_fault_after};
use positron_query::QueryBudget;
use prost::Message;

use super::super::{InitializationPlan, InstanceBootstrap, resources};
use super::support::Roots;
use crate::services::{QueryExecutionTestHook, ReceiverTestBackend};
use crate::{ServiceFailure, ServiceHandle};

struct BlockingSecondaryIngest {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ReceiverTestBackend for BlockingSecondaryIngest {
    fn ingest(&self, _groups: NativeLogAdmissionGroups<'_>) -> IngestRequestOutcome {
        let _ = self.entered.send(());
        if let Ok(release) = self.release.lock() {
            let _ = release.recv();
        }
        IngestRequestOutcome::new(Vec::new())
    }
}

struct BlockingSecondaryQuery {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl QueryExecutionTestHook for BlockingSecondaryQuery {
    fn after_admission(&self) {
        let _ = self.entered.send(());
        if let Ok(release) = self.release.lock() {
            let _ = release.recv();
        }
    }
}

#[test]
fn default_lifecycle_drains_do_not_block_active_secondary_data_routes()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize_with_max_registered_tenants(
        &paths,
        InitializationPlan::non_interactive(),
        2,
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = Arc::new(InstanceBootstrap::reopen_with_max_registered_tenants(
        &paths, 2,
    )?);
    let secondary = TenantId::from_bytes([0xa1; 16])?;
    initialized.create_tenant(
        system(&initialized, claim.secret())?,
        secondary,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("drain-secondary")?,
            "Drain secondary",
            2_592_000,
            1,
            resources::initial_tenant_quota(),
        ),
        AdministrativeIdempotencyKey::new([0xa2; 16])?,
    )?;
    let ingest = initialized.create_api_key_for_tenant(
        system(&initialized, claim.secret())?,
        secondary,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xa3; 16])?,
    )?;
    let query = initialized.create_api_key_for_tenant(
        system(&initialized, claim.secret())?,
        secondary,
        Scope::Query,
        None,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xa4; 16])?,
    )?;
    let ingest = ingest.secret().ok_or("secondary ingest key")?.to_owned();
    let query = query.secret().ok_or("secondary query key")?.to_owned();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    let (ingest_entered_tx, ingest_entered_rx) = mpsc::channel();
    let (ingest_release_tx, ingest_release_rx) = mpsc::channel();
    services.install_receiver_test_backend(Arc::new(BlockingSecondaryIngest {
        entered: ingest_entered_tx,
        release: Mutex::new(ingest_release_rx),
    }))?;
    let ingest_services = services.clone();
    let in_flight_ingest = std::thread::spawn(move || {
        ingest_services
            .ingest_otlp_logs(&ingest, log_request("secondary-in-flight").encode_to_vec())
    });
    ingest_entered_rx.recv()?;

    let (read_only_rx, read_only_thread) = start_default_transition(
        Arc::clone(&initialized),
        claim.secret().to_owned(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xa5; 16])?,
    );
    let read_only = read_only_rx.recv_timeout(Duration::from_secs(1));
    ingest_release_tx.send(())?;
    assert!(
        in_flight_ingest
            .join()
            .map_err(|_| "secondary ingest panicked")?
            .is_ok()
    );
    read_only_thread
        .join()
        .map_err(|_| "default lifecycle transition panicked")?;
    assert_eq!(
        read_only
            .map_err(|_| "default lifecycle transition waited for unrelated secondary ingest")??
            .to(),
        TenantLifecycleState::ReadOnly,
        "a default ReadOnly transition must not drain an active secondary ingest"
    );

    let (query_entered_tx, query_entered_rx) = mpsc::channel();
    let (query_release_tx, query_release_rx) = mpsc::channel();
    services.install_query_execution_test_hook(Arc::new(BlockingSecondaryQuery {
        entered: query_entered_tx,
        release: Mutex::new(query_release_rx),
    }))?;
    let query_services = services.clone();
    let in_flight_query = std::thread::spawn(move || {
        query_services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            query_budget().expect("fixed query budget"),
        )
    });
    query_entered_rx.recv()?;
    let (suspended_rx, suspended_thread) = start_default_transition(
        Arc::clone(&initialized),
        claim.secret().to_owned(),
        TenantLifecycleState::Suspended,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xa6; 16])?,
    );
    let suspended = suspended_rx.recv_timeout(Duration::from_secs(1));
    query_release_tx.send(())?;
    assert!(
        in_flight_query
            .join()
            .map_err(|_| "secondary query panicked")?
            .is_ok()
    );
    suspended_thread
        .join()
        .map_err(|_| "default lifecycle transition panicked")?;
    let suspended = suspended
        .map_err(|_| "default lifecycle transition waited for unrelated secondary query")?;
    assert!(matches!(
        suspended,
        Err(failure) if failure.code() == crate::BootstrapFailureCode::CatalogUnavailable
    ));
    assert_eq!(
        initialized
            .transition_tenant_lifecycle(
                system(&initialized, claim.secret())?,
                initialized.default_tenant_id(),
                TenantLifecycleState::Suspended,
                ResourceGeneration::new(2)?,
                AdministrativeIdempotencyKey::new([0xa6; 16])?,
            )?
            .to(),
        TenantLifecycleState::Suspended,
        "the failed catalog publication leaves the default lifecycle unchanged for a retry"
    );
    Ok(())
}

fn start_default_transition(
    initialized: Arc<InstanceBootstrapResult>,
    administrator_secret: String,
    target: TenantLifecycleState,
    expected: ResourceGeneration,
    idempotency: AdministrativeIdempotencyKey,
) -> (
    mpsc::Receiver<Result<positron_governance::TenantLifecycleTransition, crate::BootstrapFailure>>,
    std::thread::JoinHandle<()>,
) {
    let (completed_tx, completed_rx) = mpsc::channel();
    let transitioning = Arc::clone(&initialized);
    let transition = std::thread::spawn(move || {
        let result = (|| {
            let actor = system(&transitioning, &administrator_secret).map_err(|_| {
                crate::BootstrapFailure::new(
                    crate::BootstrapFailureCode::TenantLifecycleUnauthorized,
                )
            })?;
            transitioning.transition_tenant_lifecycle(
                actor,
                transitioning.default_tenant_id(),
                target,
                expected,
                idempotency,
            )
        })();
        let _ = completed_tx.send(result);
    });
    (completed_rx, transition)
}

#[test]
fn secondary_read_only_transition_is_audited_idempotent_and_survives_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize_with_max_registered_tenants(
        &paths,
        InitializationPlan::non_interactive(),
        2,
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = Arc::new(InstanceBootstrap::reopen_with_max_registered_tenants(
        &paths, 2,
    )?);
    let secondary = TenantId::from_bytes([0x91; 16])?;
    let administrator = system(&initialized, claim.secret())?;
    initialized.create_tenant(
        administrator,
        secondary,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("lifecycle-secondary")?,
            "Lifecycle secondary",
            2_592_000,
            1,
            resources::initial_tenant_quota(),
        ),
        AdministrativeIdempotencyKey::new([0x92; 16])?,
    )?;
    let ingest = initialized.create_api_key_for_tenant(
        system(&initialized, claim.secret())?,
        secondary,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x93; 16])?,
    )?;
    let query = initialized.create_api_key_for_tenant(
        system(&initialized, claim.secret())?,
        secondary,
        Scope::Query,
        None,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x94; 16])?,
    )?;
    let ingest = ingest.secret().ok_or("secondary ingest key")?.to_owned();
    let query = query.secret().ok_or("secondary query key")?.to_owned();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, log_request("secondary-retained").encode_to_vec())?
            .accepted_records(),
        1
    );

    let idempotency = AdministrativeIdempotencyKey::new([0x95; 16])?;
    let transition = initialized
        .transition_tenant_lifecycle(
            system(&initialized, claim.secret())?,
            secondary,
            TenantLifecycleState::ReadOnly,
            ResourceGeneration::new(1)?,
            idempotency,
        )
        .expect("secondary lifecycle transition must use its canonical tenant record");
    assert_eq!(transition.tenant_id(), secondary);
    assert_eq!(transition.from(), TenantLifecycleState::Active);
    assert_eq!(transition.to(), TenantLifecycleState::ReadOnly);
    assert_eq!(transition.resource_generation().get(), 2);
    assert!(
        initialized
            .governance_audit_for_test()?
            .iter()
            .any(|entry| {
                entry.position() == transition.audit_position()
                    && entry.as_tenant_lifecycle().is_some_and(|audit| {
                        audit.tenant_id() == secondary
                            && audit.from() == TenantLifecycleState::Active
                            && audit.to() == TenantLifecycleState::ReadOnly
                            && audit.generation().get() == 2
                    })
            })
    );
    assert_eq!(
        initialized.transition_tenant_lifecycle(
            system(&initialized, claim.secret())?,
            secondary,
            TenantLifecycleState::ReadOnly,
            ResourceGeneration::new(1)?,
            idempotency,
        )?,
        transition
    );
    assert!(matches!(
        services.ingest_otlp_logs(&ingest, log_request("secondary-closed").encode_to_vec()),
        Err(ServiceFailure::Unauthorized)
    ));
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            query_budget()?,
        )?,
        ["secondary-retained"]
    );
    assert_eq!(
        services
            .ingest_otlp_logs(
                claim.ingest_secret().ok_or("default ingest key")?,
                log_request("default-still-active").encode_to_vec(),
            )?
            .accepted_records(),
        1
    );
    assert_eq!(
        initialized.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2),
        "a secondary query must not downgrade the Catalog generation format"
    );
    drop((services, initialized));

    let reopened = Arc::new(InstanceBootstrap::reopen_with_max_registered_tenants(
        &paths, 2,
    )?);
    let replay = reopened.transition_tenant_lifecycle(
        system(&reopened, claim.secret())?,
        secondary,
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        idempotency,
    )?;
    assert_eq!(replay, transition);

    let reopened_services = ServiceHandle::new(Arc::clone(&reopened))?;
    let suspended = reopened.transition_tenant_lifecycle(
        system(&reopened, claim.secret())?,
        secondary,
        TenantLifecycleState::Suspended,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x96; 16])?,
    )?;
    assert_eq!(suspended.from(), TenantLifecycleState::ReadOnly);
    assert_eq!(suspended.to(), TenantLifecycleState::Suspended);
    assert!(matches!(
        reopened_services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            query_budget()?,
        ),
        Err(ServiceFailure::Unauthorized)
    ));
    assert_eq!(
        reopened_services
            .ingest_otlp_logs(
                claim.ingest_secret().ok_or("default ingest key")?,
                log_request("default-after-secondary-suspend").encode_to_vec(),
            )?
            .accepted_records(),
        1,
        "suspending a secondary tenant must not close the default tenant"
    );

    let purging = reopened.transition_tenant_lifecycle(
        system(&reopened, claim.secret())?,
        secondary,
        TenantLifecycleState::Purging,
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([0x97; 16])?,
    )?;
    assert_eq!(purging.to(), TenantLifecycleState::Purging);
    assert_eq!(
        reopened
            .transition_tenant_lifecycle(
                system(&reopened, claim.secret())?,
                secondary,
                TenantLifecycleState::Purged,
                ResourceGeneration::new(4)?,
                AdministrativeIdempotencyKey::new([0x98; 16])?,
            )
            .expect_err("lifecycle administration cannot complete a purge")
            .code(),
        crate::BootstrapFailureCode::TenantLifecyclePurgeCompletionUnavailable
    );
    assert_eq!(
        reopened
            .transition_tenant_lifecycle(
                system(&reopened, claim.secret())?,
                secondary,
                TenantLifecycleState::Active,
                ResourceGeneration::new(4)?,
                AdministrativeIdempotencyKey::new([0x99; 16])?,
            )
            .expect_err("Purging is one-way")
            .code(),
        crate::BootstrapFailureCode::TenantLifecycleInvalidTransition
    );
    Ok(())
}

#[test]
fn failed_secondary_lifecycle_publication_keeps_predecessor_authoritative()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize_with_max_registered_tenants(
        &paths,
        InitializationPlan::non_interactive(),
        2,
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = Arc::new(InstanceBootstrap::reopen_with_max_registered_tenants(
        &paths, 2,
    )?);
    let secondary = TenantId::from_bytes([0xb1; 16])?;
    initialized.create_tenant(
        system(&initialized, claim.secret())?,
        secondary,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("fault-secondary")?,
            "Fault secondary",
            2_592_000,
            1,
            resources::initial_tenant_quota(),
        ),
        AdministrativeIdempotencyKey::new([0xb2; 16])?,
    )?;
    let idempotency = AdministrativeIdempotencyKey::new([0xb3; 16])?;
    let generation = initialized.catalog_generation();
    let audit = initialized.governance_audit_for_test()?;
    let failed =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.transition_tenant_lifecycle(
                system(&initialized, claim.secret()).expect("system actor"),
                secondary,
                TenantLifecycleState::ReadOnly,
                ResourceGeneration::new(1).expect("generation"),
                idempotency,
            )
        })
        .expect_err("a pre-marker lifecycle failure must not publish its successor");
    assert_eq!(
        failed.code(),
        crate::BootstrapFailureCode::CatalogUnavailable
    );
    assert_eq!(initialized.catalog_generation(), generation);
    assert_eq!(initialized.governance_audit_for_test()?, audit);
    assert_eq!(
        initialized
            .transition_tenant_lifecycle(
                system(&initialized, claim.secret())?,
                secondary,
                TenantLifecycleState::ReadOnly,
                ResourceGeneration::new(1)?,
                idempotency,
            )?
            .resource_generation()
            .get(),
        2,
        "the unchanged predecessor accepts the exact retry"
    );
    Ok(())
}

fn system(
    initialized: &InstanceBootstrapResult,
    secret: &str,
) -> Result<positron_governance::AuthorizedContext, Box<dyn std::error::Error>> {
    initialized
        .attribute(
            PresentedCredential::parse(secret)?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
        .map_err(Into::into)
}

type InstanceBootstrapResult = super::super::InitializedInstance;

fn query_budget() -> Result<QueryBudget, Box<dyn std::error::Error>> {
    Ok(QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(15)?)
}

fn log_request(body: &str) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(body.to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}
