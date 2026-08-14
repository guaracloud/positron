use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_governance::GovernanceAuditEntry;
use positron_ingest::load_schema_checkpoint;
use positron_kernel::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, FormatEpoch, MountQualification,
    TransactionId, WorkClass,
};
use positron_query::QueryBudget;
use prost::Message;

use super::super::{ServiceFailure, ServiceHandle, schema_maintenance};
use crate::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

#[test]
fn startup_rebuild_publishes_before_service_and_preserves_unrelated_objects()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let unrelated = publish_unrelated(&initialized)?;
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
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?,
        )?,
        ["first", "latest"]
    );

    services.prepare_shutdown_schema_checkpoint()?;
    services.publish_prepared_shutdown_schema_checkpoint()?;
    assert_eq!(schema_audit_count(&initialized)?, initial_audits + 1);
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
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?,
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
    assert_eq!(schema_audit_count(&initialized)?, audits);

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
    publish_unrelated_bytes(&initialized, newer)?;
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
            TransactionId::new([0x75; 16])?,
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
        let paths = BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let ingest = claim.ingest_secret().ok_or("ingest secret")?.to_owned();
        let query = claim.query_secret().ok_or("query secret")?.to_owned();
        Ok((Arc::new(InstanceBootstrap::reopen(&paths)?), ingest, query))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
