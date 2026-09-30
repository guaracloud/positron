use std::error::Error;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, GovernanceAuditEntry, PresentedCredential,
    RequestedIntent, ResourceGeneration,
};
use positron_ingest::load_schema_checkpoint;
use positron_kernel::{
    ActiveSegmentLedger, AuditIntent, Catalog, CatalogObject, CatalogProposal,
    CatalogPublicationFault, FormatEpoch, MaintenanceTask, MaintenanceTaskClass, MaintenanceTaskId,
    MaintenanceTaskPhase, MountQualification, RetentionTimeAuthority, SegmentScope, TransactionId,
    WorkClass, with_catalog_publication_fault_after,
};
use positron_query::QueryBudget;
use prost::Message;

use super::super::{ServiceFailure, ServiceHandle, schema_maintenance};
use crate::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InitializationPlan,
    InstanceBootstrap, NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};

type InitializedCredentials = (Arc<crate::InitializedInstance>, String, String, String);

#[test]
fn service_startup_restores_catalog_backed_maintenance_before_serving() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let task = MaintenanceTask::new(
        MaintenanceTaskId::new([0x91; 16]).expect("stable maintenance identity"),
        MaintenanceTaskClass::SchemaPromotion,
    );
    let identity = task.identity();
    let catalog = open_catalog(&initialized)?;
    initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?
        .submit_and_persist(&catalog, task, 7)
        .expect("durable task submission");
    drop(catalog);

    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(identity)
            .expect("restored task")
            .task()
            .class(),
        MaintenanceTaskClass::SchemaPromotion
    );
    drop(services);
    Ok(())
}

#[test]
fn startup_rebuild_publishes_before_service_and_preserves_unrelated_objects()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let unrelated = publish_unrelated(&initialized)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("rebuild").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop(services);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        snapshot.object(unrelated)?,
        Some(b"unrelated-runtime-state".as_slice())
    );
    assert!(
        load_schema_checkpoint(
            &snapshot,
            initialized.tenant,
            initialized.resource_governor()
        )
        .map_err(|_| "schema checkpoint load failed")?
        .is_some()
    );
    drop((snapshot, catalog, services));
    Ok(())
}

#[test]
fn serving_updates_live_schema_without_catalog_publication() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let initial_audits = schema_audit_count(&initialized)?;

    for body in ["first", "latest"] {
        assert_eq!(
            services
                .ingest_otlp_logs(&ingest, request(body).encode_to_vec())?
                .accepted_records(),
            1
        );
    }
    assert_eq!(schema_audit_count(&initialized)?, initial_audits);
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["first", "latest"]
    );

    services.prepare_shutdown_schema_checkpoint()?;
    services.publish_prepared_shutdown_schema_checkpoint()?;
    assert_eq!(schema_audit_count(&initialized)?, initial_audits + 1);
    Ok(())
}

#[test]
fn production_query_publishes_a_durable_snapshot_lease_expiry_task() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("lease-task").encode_to_vec())?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["lease-task"]
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .durable_records()
            .expect("query expiry task is coordinator-owned")
            .len(),
        1,
        "the runtime query path asks the kernel lease publisher to atomically create expiry work"
    );
    let catalog = open_catalog(&initialized)?;
    assert!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .start_next_with_reservation_and_persist(
                &catalog,
                &initialized._authority,
                u64::MAX,
                false,
            )
            .expect("released query expiry task is terminal")
            .is_none(),
        "collecting the ordinary query releases its lease and cancels its paired expiry task"
    );
    Ok(())
}

#[test]
fn runtime_maintenance_worker_wake_dispatches_and_completes_a_due_snapshot_lease_expiry()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _) = fixture.initialized()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        0,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let lease_id = lease.identity();
    let task = MaintenanceTaskId::new(lease_id.to_bytes()).expect("lease task id");
    drop(lease);
    drop(coordinator);
    drop(ledger);
    drop(catalog);
    elapsed.advance(1_000_000_000)?;

    assert!(services.wake_maintenance_worker()?);

    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    assert!(
        reopened
            .resume_snapshot_lease(lease_id, 11)
            .expect_err("the runtime handler removed the expired lease")
            .code()
            == positron_kernel::LedgerFailureCode::SnapshotExpired,
        "the runtime handler removes the expired lease"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .expect("terminal task")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    Ok(())
}

#[test]
fn runtime_maintenance_worker_discovers_and_completes_expired_log_and_trace_retention()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let tenant = initialized.default_tenant_id();
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let retention = std::num::NonZeroU64::new(1).ok_or("one second retention")?;
    let preview = initialized.inspect_tenant_retention_impact(system, tenant, retention)?;
    initialized.update_tenant_retention(
        system,
        tenant,
        retention,
        ResourceGeneration::new(1)?,
        Some(&preview),
        AdministrativeIdempotencyKey::new([0x83; 16])?,
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("runtime-retention-log").encode_to_vec())?
            .accepted_records(),
        1
    );
    assert_eq!(
        services
            .ingest_otlp_traces(
                &ingest,
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans {
                        scope_spans: vec![ScopeSpans {
                            spans: vec![Span {
                                trace_id: vec![0x83; 16],
                                span_id: vec![0x84; 8],
                                name: "runtime-retention-trace".to_owned(),
                                start_time_unix_nano: 41,
                                end_time_unix_nano: 42,
                                ..Span::default()
                            }],
                            ..ScopeSpans::default()
                        }],
                        ..ResourceSpans::default()
                    }],
                }
                .encode_to_vec(),
            )?
            .accepted_records(),
        1
    );

    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    let scopes = [SignalKind::Logs, SignalKind::Traces]
        .into_iter()
        .map(|signal| snapshot.reachable_ledger_scopes(tenant, signal))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(
        scopes.len(),
        2,
        "one canonical scope for each stored signal"
    );
    drop((snapshot, catalog));
    for scope in &scopes {
        let catalog = open_catalog(&initialized)?;
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        let protection = super::super::tenant_segment_key(&initialized, &identity, *scope)?;
        ActiveSegmentLedger::open_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            *scope,
            protection,
        )?
        .seal()?;
    }
    elapsed.advance(2_000_000_000)?;

    assert!(
        services.wake_maintenance_worker()?,
        "the sole runtime worker discovers and begins due retention work"
    );
    for _ in 0..3 {
        assert!(services.wake_maintenance_worker()?);
    }
    let catalog = open_catalog(&initialized)?;
    let idle_generation = catalog.pin()?.number();
    let idle_task_count = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?
        .durable_records()
        .map_err(|_| "durable maintenance records")?
        .len();
    drop(catalog);
    for _ in 0..4 {
        assert!(
            !services.wake_maintenance_worker()?,
            "an idle maintenance pass must not roll an empty active segment"
        );
    }
    let catalog = open_catalog(&initialized)?;
    assert_eq!(
        catalog.pin()?.number(),
        idle_generation,
        "idle discovery does not publish a Catalog generation"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .durable_records()
            .map_err(|_| "durable maintenance records")?
            .len(),
        idle_task_count,
        "idle discovery does not create a new durable task"
    );
    drop(catalog);

    for scope in scopes {
        let catalog = open_catalog(&initialized)?;
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
        let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            protection,
        )?;
        assert_eq!(
            ledger
                .prepare_retention_publication()
                .expect_err("the runtime worker has consumed this expired scope")
                .code(),
            positron_kernel::LedgerFailureCode::InvalidInput
        );
    }
    Ok(())
}

#[test]
fn cancellation_after_maintenance_dispatch_preserves_the_lease_for_recovery()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _) = fixture.initialized()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        0,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let lease_id = lease.identity();
    let task = MaintenanceTaskId::new(lease_id.to_bytes()).expect("lease task id");
    drop(lease);
    drop(coordinator);
    drop(ledger);
    drop(catalog);
    elapsed.advance(1_000_000_000)?;

    let cancellation = crate::TaskCancellation::new();
    cancellation.cancel_after_polls(2);
    assert!(matches!(
        services.wake_maintenance_worker_with_cancellation(&cancellation),
        Err(ServiceFailure::Cancelled)
    ));

    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .expect("running task")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    drop(services);

    let recovered = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .expect("recovered task")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    drop(recovered);
    Ok(())
}

#[test]
fn maintenance_worker_treats_cancellation_before_dispatch_as_a_normal_exit()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(initialized)?;
    let cancellation = crate::TaskCancellation::new();
    // Poll one is the outer worker-loop check; poll two is the scheduler
    // admission boundary immediately before a task can become Running.
    cancellation.cancel_after_polls(2);

    assert_eq!(services.run_maintenance_worker(&cancellation), Ok(()));
    Ok(())
}

#[test]
fn runtime_worker_wakes_for_a_poststart_future_lease_expiry() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _) = fixture.initialized()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));

    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog_operation = services.catalog_operation()?;
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let now = initialized.retention_time.governance_now_seconds()?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        now,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let task = MaintenanceTaskId::new(lease.identity().to_bytes()).expect("lease task id");
    drop(lease);
    drop(coordinator);
    drop(ledger);
    drop(catalog);
    drop(catalog_operation);

    elapsed.advance(2_000_000_000)?;
    services.notify_maintenance_worker();
    let deadline = Instant::now() + Duration::from_secs(2);
    while initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?
        .status(task)
        .map_err(|_| "maintenance task status")?
        .phase()
        != MaintenanceTaskPhase::Succeeded
    {
        if Instant::now() >= deadline {
            cancellation.cancel();
            return Err("runtime maintenance worker did not wake for poststart expiry work".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    cancellation.cancel();
    assert_eq!(
        worker.join().map_err(|_| "maintenance worker panicked")?,
        Ok(())
    );
    Ok(())
}

#[test]
fn runtime_worker_retries_a_running_expiry_after_terminal_publication_outage()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _) = fixture.initialized()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog_operation = services.catalog_operation()?;
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        0,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let task = MaintenanceTaskId::new(lease.identity().to_bytes()).expect("lease task id");
    drop(lease);
    drop(coordinator);
    drop(ledger);
    drop(catalog);
    drop(catalog_operation);
    elapsed.advance(1_000_000_000)?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker = std::thread::spawn(move || {
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 1, || {
            worker_services.run_maintenance_worker(&worker_cancellation)
        })
    });
    services.notify_maintenance_worker();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_running = false;
    while initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?
        .status(task)
        .map_err(|_| "maintenance task status")?
        .phase()
        != MaintenanceTaskPhase::Succeeded
    {
        let phase = initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .map_err(|_| "maintenance task status")?
            .phase();
        saw_running |= phase == MaintenanceTaskPhase::Running;
        if Instant::now() >= deadline {
            cancellation.cancel();
            return Err("worker did not retry running expiry".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        saw_running,
        "terminal-publication fault retains the same Running execution before retry"
    );
    cancellation.cancel();
    worker.join().map_err(|_| "maintenance worker panicked")??;
    Ok(())
}

#[test]
fn public_audit_checkpoint_reports_the_worker_task_before_artifact_publication()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let task = initialized.queue_governance_audit_checkpoint_for_test()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let cancellation = crate::TaskCancellation::new();
    // The runtime worker checks cancellation once before scheduling and once
    // after durably transitioning the selected task to Running, before any
    // handler can publish its checkpoint artifact.
    cancellation.cancel_after_polls(2);
    assert_eq!(
        services.wake_maintenance_worker_with_cancellation(&cancellation),
        Err(ServiceFailure::Cancelled)
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .map_err(|_| "audit task status")?
            .phase(),
        MaintenanceTaskPhase::Running
    );
    assert_eq!(
        initialized.latest_governance_audit_checkpoint_for_test()?,
        None,
        "the public caller arrives before the worker handler can publish an artifact"
    );

    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let attached = initialized
        .publish_governance_audit_checkpoint(actor)
        .expect_err(
            "the public caller must not claim storage is unavailable for a worker-owned task",
        );
    assert_eq!(
        attached.code(),
        crate::BootstrapFailureCode::GovernanceAuditCheckpointInProgress
    );
    assert_eq!(
        attached.maintenance_task(),
        Some(task),
        "the retryable result exposes the exact stable worker identity"
    );
    assert!(
        attached.to_string().ends_with(
            &task
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
        "the retryable public message provides the stable task identity without credential material"
    );
    assert_eq!(
        initialized.governance_audit_checkpoint_state_for_test()?,
        (false, 1),
        "the public request neither redispatches nor duplicates the worker-owned task"
    );
    drop(services);

    let recovered = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .map_err(|_| "recovered audit task status")?
            .phase(),
        MaintenanceTaskPhase::Queued,
        "restart recovery returns the interrupted worker task to its durable queue"
    );
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let checkpoint = initialized.publish_governance_audit_checkpoint(actor)?;
    assert_eq!(checkpoint.position(), 1);
    assert_eq!(
        initialized.governance_audit_checkpoint_state_for_test()?,
        (true, 1),
        "retry completes the recovered worker task instead of granting a duplicate"
    );
    drop(recovered);
    Ok(())
}

#[test]
fn public_audit_checkpoint_returns_a_running_worker_artifact_without_redispatch()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let task = initialized.queue_governance_audit_checkpoint_for_test()?;
    let worker_checkpoint =
        initialized.publish_running_governance_audit_checkpoint_for_test(task)?;
    assert_eq!(
        initialized.governance_audit_checkpoint_phase_for_test(task)?,
        MaintenanceTaskPhase::Running,
        "the handler published before terminalization"
    );

    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        initialized.publish_governance_audit_checkpoint(actor)?,
        worker_checkpoint,
        "the authenticated public call reads the worker-owned signed artifact"
    );
    assert_eq!(
        initialized.governance_audit_checkpoint_phase_for_test(task)?,
        MaintenanceTaskPhase::Running,
        "reading the artifact does not redispatch or terminalize the worker task"
    );
    assert_eq!(
        initialized.governance_audit_checkpoint_state_for_test()?,
        (true, 1),
        "attachment retains one durable artifact and one stable task"
    );
    Ok(())
}

#[test]
fn native_runtime_worker_expires_a_durable_lease_and_joins_before_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _) = fixture.initialized()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let coordinator = initialized
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        0,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let task = MaintenanceTaskId::new(lease.identity().to_bytes()).expect("lease task id");
    drop(lease);
    drop(coordinator);
    drop(ledger);
    drop(catalog);
    elapsed.advance(1_000_000_000)?;
    drop(initialized);

    let [operations, api, otlp_grpc, otlp_http, loki_push] = reserve_native_addresses()?;
    static NEXT_NATIVE_CONTROL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let control = std::env::temp_dir().join(format!(
        "positron-maintenance-worker-{}-{}.sock",
        std::process::id(),
        NEXT_NATIVE_CONTROL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    match fs::remove_file(&control) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }
    let host = NativeHost::new(NativeBindings::new(
        control, operations, api, otlp_grpc, otlp_http, loki_push,
    )?);
    let paths = BootstrapPaths::new(
        &fixture.root.join("data"),
        &fixture.root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let services = process.services().ok_or("serving services")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while services
        .instance
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?
        .status(task)
        .map_err(|_| "maintenance task status")?
        .phase()
        != MaintenanceTaskPhase::Succeeded
    {
        if Instant::now() >= deadline {
            return Err("native maintenance worker did not complete the due lease expiry".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful,
        "shutdown joins the internal maintenance worker"
    );

    let reopened = fixture.reopen()?;
    let restored = ServiceHandle::new(reopened)?;
    assert_eq!(
        restored
            .instance
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .map_err(|_| "maintenance task status")?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "the worker-published terminal result survives reopen"
    );
    Ok(())
}

#[test]
fn native_runtime_worker_periodically_expires_a_poststart_future_lease_and_persists_completion()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    drop(initialized);

    let [operations, api, otlp_grpc, otlp_http, loki_push] = reserve_native_addresses()?;
    static NEXT_POSTSTART_NATIVE_CONTROL: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    let control = std::env::temp_dir().join(format!(
        "positron-poststart-maintenance-worker-{}-{}.sock",
        std::process::id(),
        NEXT_POSTSTART_NATIVE_CONTROL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    match fs::remove_file(&control) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }
    let host = NativeHost::new(NativeBindings::new(
        control, operations, api, otlp_grpc, otlp_http, loki_push,
    )?);
    let paths = BootstrapPaths::new(
        &fixture.root.join("data"),
        &fixture.root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let services = process.services().ok_or("serving services")?;
    let scope = SegmentScope::new(
        services.instance.tenant,
        positron_domain::routing::SignalKind::Logs,
        services.instance.logs_shard,
    );
    let _catalog_operation = services.catalog_operation()?;
    let catalog = open_catalog(&services.instance)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::tenant_segment_key(&services.instance, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &services.instance._authority,
        &services.instance.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let now = services.instance.retention_time.governance_now_seconds()?;
    let coordinator = services
        .instance
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        now,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let task = MaintenanceTaskId::new(lease.identity().to_bytes()).expect("lease task id");
    drop(lease);
    drop(coordinator);
    drop(ledger);
    drop(catalog);
    drop(_catalog_operation);

    let deadline = Instant::now() + Duration::from_secs(4);
    while services
        .instance
        .maintenance_coordinator()
        .lock()
        .map_err(|_| "maintenance lock")?
        .status(task)
        .map_err(|_| "maintenance task status")?
        .phase()
        != MaintenanceTaskPhase::Succeeded
    {
        if Instant::now() >= deadline {
            return Err(
                "native maintenance role did not complete poststart future expiry work".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful,
        "shutdown joins the native maintenance role after poststart expiry work"
    );
    let reopened = ServiceHandle::new(fixture.reopen()?)?;
    assert_eq!(
        reopened
            .instance
            .maintenance_coordinator()
            .lock()
            .map_err(|_| "maintenance lock")?
            .status(task)
            .map_err(|_| "restored maintenance task status")?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "the poststart worker completion survives reopen"
    );
    Ok(())
}

#[test]
fn crash_without_publication_rebuilds_from_committed_blocks() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("replayed").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop(services);

    let reopened = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        reopened.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["replayed"]
    );
    Ok(())
}

#[test]
fn shutdown_capacity_is_reserved_before_admission_closes_and_released_after_publish()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("shutdown").encode_to_vec())?
            .accepted_records(),
        1
    );
    services
        .prepare_shutdown_schema_checkpoint()
        .map_err(|failure| format!("prepare shutdown checkpoint: {failure:?}"))?;
    services
        .publish_prepared_shutdown_schema_checkpoint()
        .map_err(|failure| format!("publish shutdown checkpoint: {failure:?}"))?;
    let after = initialized._authority.begin_shutdown()?;
    assert_eq!(
        after.outstanding_for(WorkClass::OrdinaryMaintenanceBackup),
        0
    );
    Ok(())
}

#[test]
fn unchanged_session_skips_shutdown_checkpoint_publication() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let initial_audits = schema_audit_count(&initialized)?;

    services.prepare_shutdown_schema_checkpoint()?;
    services.publish_prepared_shutdown_schema_checkpoint()?;

    assert_eq!(schema_audit_count(&initialized)?, initial_audits);
    let after = initialized._authority.begin_shutdown()?;
    assert_eq!(
        after.outstanding_for(WorkClass::OrdinaryMaintenanceBackup),
        0
    );
    Ok(())
}

#[test]
fn failed_shutdown_publication_releases_its_pre_admitted_capacity() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("shutdown-failure").encode_to_vec())?
            .accepted_records(),
        1
    );
    services.prepare_shutdown_schema_checkpoint()?;
    publish_unrelated_bytes(&initialized, vec![0x55; 1_048_576])?;
    initialized._authority.begin_shutdown()?;
    assert!(
        services
            .publish_prepared_shutdown_schema_checkpoint()
            .is_err()
    );
    let after = initialized._authority.begin_shutdown()?;
    assert_eq!(
        after.outstanding_for(WorkClass::OrdinaryMaintenanceBackup),
        0
    );
    Ok(())
}

#[test]
fn quiescent_publication_is_tenant_bound_and_same_content_is_idempotent()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let checkpoint = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?;
    let audits = schema_audit_count(&initialized)?;

    schema_maintenance::publish_quiescent_checkpoint(&initialized, checkpoint)?;
    assert_eq!(schema_audit_count(&initialized)?, audits + 1);
    let checkpoint = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?;
    schema_maintenance::publish_quiescent_checkpoint(&initialized, checkpoint)?;
    assert_eq!(schema_audit_count(&initialized)?, audits + 1);

    let other_fixture = Fixture::new()?;
    let (other, _, _) = other_fixture.initialized()?;
    let other_services = ServiceHandle::new(Arc::clone(&other))?;
    let foreign = other_services
        .schema_sessions
        .session(other.tenant, other.resource_governor())?
        .checkpoint()?;
    assert_eq!(
        schema_maintenance::publish_quiescent_checkpoint(&initialized, foreign),
        Err(ServiceFailure::CorruptState)
    );
    Ok(())
}

#[test]
fn corrupted_schema_checkpoint_blocks_serving() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    publish_unrelated_bytes(&initialized, b"PSCHEMA1-corrupt".to_vec())?;
    assert!(matches!(
        ServiceHandle::new(Arc::clone(&initialized)),
        Err(ServiceFailure::CorruptState)
    ));
    Ok(())
}

#[test]
fn duplicate_tenant_checkpoints_block_serving() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let older = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?
        .into_catalog_bytes();
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("new-schema").encode_to_vec())?
            .accepted_records(),
        1
    );
    let newer = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?
        .into_catalog_bytes();
    assert_ne!(older, newer);
    publish_unrelated_bytes(&initialized, older)?;
    publish_unrelated_bytes_with_transaction(&initialized, newer, [0x76; 16])?;
    drop(services);

    assert!(matches!(
        ServiceHandle::new(Arc::clone(&initialized)),
        Err(ServiceFailure::CorruptState)
    ));
    Ok(())
}

fn publish_unrelated(
    initialized: &crate::InitializedInstance,
) -> Result<positron_kernel::CatalogObjectId, Box<dyn Error>> {
    let catalog = open_catalog(initialized)?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .map(|identity| {
            basis
                .object(identity)?
                .ok_or_else(|| "missing object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let unrelated = CatalogObject::new(b"unrelated-runtime-state".to_vec())?;
    let identity = unrelated.identity();
    objects.push(unrelated);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x91; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        Some(AuditIntent::new(b"test-unrelated-state".to_vec())?),
    )?;
    Ok(identity)
}

fn publish_unrelated_bytes(
    initialized: &crate::InitializedInstance,
    bytes: Vec<u8>,
) -> Result<positron_kernel::CatalogObjectId, Box<dyn Error>> {
    publish_unrelated_bytes_with_transaction(initialized, bytes, [0x75; 16])
}

fn publish_unrelated_bytes_with_transaction(
    initialized: &crate::InitializedInstance,
    bytes: Vec<u8>,
    transaction: [u8; 16],
) -> Result<positron_kernel::CatalogObjectId, Box<dyn Error>> {
    let catalog = open_catalog(initialized)?;
    let before = catalog.pin()?;
    let object = CatalogObject::new(bytes)?;
    let identity = object.identity();
    let mut objects = before
        .object_identities()
        .map(|known| {
            before
                .object(known)?
                .ok_or_else(|| "missing object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.push(object);
    catalog.commit(
        before.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(identity)
}

fn schema_audit_count(initialized: &crate::InitializedInstance) -> Result<usize, Box<dyn Error>> {
    Ok(open_catalog(initialized)?
        .governance_audit_records()?
        .iter()
        .filter(|record| {
            GovernanceAuditEntry::decode(record)
                .ok()
                .and_then(|entry| entry.as_schema_checkpoint().cloned())
                .is_some()
        })
        .count())
}

pub(super) fn open_catalog(
    initialized: &crate::InitializedInstance,
) -> Result<Catalog<'_>, Box<dyn Error>> {
    Ok(Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?)
}

pub(super) fn request(body: &str) -> ExportLogsServiceRequest {
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

fn reserve_native_addresses() -> Result<[SocketAddr; 5], Box<dyn Error>> {
    let mut listeners = Vec::with_capacity(5);
    let mut addresses = Vec::with_capacity(5);
    for _ in 0..5 {
        let listener =
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
        addresses.push(listener.local_addr()?);
        listeners.push(listener);
    }
    drop(listeners);
    addresses
        .try_into()
        .map_err(|_| "five native listener addresses".into())
}

pub(super) struct Fixture {
    root: PathBuf,
}

impl Fixture {
    pub(super) fn new() -> Result<Self, Box<dyn Error>> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-schema-maintenance-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("data"))?;
        fs::create_dir_all(root.join("secrets"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("secrets"), fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { root })
    }

    pub(super) fn initialized(
        &self,
    ) -> Result<(Arc<crate::InitializedInstance>, String, String), Box<dyn Error>> {
        let (initialized, ingest, query, _) = self.initialized_with_admin()?;
        Ok((initialized, ingest, query))
    }

    pub(super) fn initialized_with_admin(&self) -> Result<InitializedCredentials, Box<dyn Error>> {
        self.initialized_with_admin_max_registered_tenants(2)
    }

    fn initialized_with_admin_max_registered_tenants(
        &self,
        max_registered_tenants: u16,
    ) -> Result<InitializedCredentials, Box<dyn Error>> {
        let paths = BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        drop(InstanceBootstrap::initialize_with_max_registered_tenants(
            &paths,
            InitializationPlan::non_interactive(),
            max_registered_tenants,
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let ingest = claim.ingest_secret().ok_or("ingest secret")?.to_owned();
        let query = claim.query_secret().ok_or("query secret")?.to_owned();
        let administrator = claim.secret().to_owned();
        Ok((
            Arc::new(InstanceBootstrap::reopen_with_max_registered_tenants(
                &paths,
                max_registered_tenants,
            )?),
            ingest,
            query,
            administrator,
        ))
    }

    pub(super) fn reopen(&self) -> Result<Arc<crate::InitializedInstance>, Box<dyn Error>> {
        let paths = BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        Ok(Arc::new(InstanceBootstrap::reopen(&paths)?))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
