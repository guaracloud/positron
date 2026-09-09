use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::Scope;
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration, TenantAdministration,
};
use positron_kernel::{
    CatalogObject, CatalogProposal, FormatEpoch, MountQualification, TransactionId,
};
use positron_query::QueryBudget;
use prost::Message;

use super::super::{ServiceFailure, ServiceHandle};
use super::schema_maintenance::{Fixture, open_catalog, request};
use crate::{BootstrapPaths, InstanceBootstrap};

#[test]
fn ordinary_ingest_fails_closed_when_its_tenant_envelope_is_corrupt() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    corrupt_default_tenant_envelope(&initialized)?;
    assert!(
        matches!(
            ServiceHandle::new(Arc::clone(&initialized)),
            Err(ServiceFailure::KeyUnavailable)
        ),
        "ordinary services must not recover or admit data with a corrupt authenticated tenant envelope"
    );
    assert!(
        initialized
            .attribute(
                PresentedCredential::parse(&ingest)?,
                RequestedIntent::Ingest,
                CompatibilityHints::none(),
            )
            .is_ok(),
        "envelope corruption is a key-custody failure, not a credential mutation"
    );
    Ok(())
}

#[test]
fn new_default_tenant_envelope_serves_data_after_reopen() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    assert!(
        initialized
            .durable_identity()?
            .tenant_key_envelope(initialized.tenant)?
            .starts_with(b"POSTKE01"),
        "new initial tenants must persist a provisioned tenant KEK envelope"
    );
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("postke-reopen").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["postke-reopen"]
    );
    Ok(())
}

#[test]
fn fresh_instance_publishes_epoch_two_default_tenant_registry_before_serving()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator_secret) = fixture.initialized_with_admin()?;
    assert_eq!(
        initialized.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2),
        "fresh initialization must never publish provisioned tenant state as Epoch 1"
    );
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::registered_tenant_ids(&snapshot)?,
        [initialized.default_tenant_id()],
        "the directory must contain the one default tenant state held by POSGOV"
    );
    drop((snapshot, catalog));

    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant_key = initialized.create_api_key(
        system,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x71; 16])?,
    )?;
    let tenant_administrator = initialized.attribute(
        PresentedCredential::parse(tenant_key.secret().ok_or("tenant key")?)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_tenant_quota(
        tenant_administrator,
        initialized.default_tenant_id(),
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x72; 16])?,
        1,
        [
            32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
        ],
    )?;
    initialized.transition_tenant_lifecycle(
        system,
        initialized.default_tenant_id(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x73; 16])?,
    )?;
    initialized.transition_tenant_lifecycle(
        system,
        initialized.default_tenant_id(),
        TenantLifecycleState::Active,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x74; 16])?,
    )?;

    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("fresh-epoch-two").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    let catalog = open_catalog(&reopened)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::registered_tenant_ids(&snapshot)?,
        [reopened.default_tenant_id()]
    );
    drop((snapshot, catalog));
    let reconstructed_tenant_administrator = reopened.attribute(
        PresentedCredential::parse(tenant_key.secret().ok_or("tenant key")?)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    assert!(
        reconstructed_tenant_administrator
            .tenant_attribution()
            .is_some_and(|attribution| attribution.tenant_id() == reopened.default_tenant_id())
    );
    assert!(
        reopened
            .durable_identity()?
            .tenant_key_envelope(reopened.default_tenant_id())?
            .starts_with(b"POSTKE01")
    );
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["fresh-epoch-two"]
    );
    Ok(())
}

#[test]
fn released_legacy_envelope_data_serves_after_epoch_two_migration() -> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let data = fixture.root().join("data");
    let secrets = fixture.root().join("secrets");
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let administrator_secret = claim.secret().to_owned();
    let query = claim
        .query_secret()
        .ok_or("legacy query credential")?
        .to_owned();
    let initialized = Arc::new(InstanceBootstrap::reopen(&paths)?);
    assert_eq!(
        initialized.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V1)
    );
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized
        .migrate_catalog_to_epoch_two(system, AdministrativeIdempotencyKey::new([0xd3; 16])?)?;
    assert_eq!(
        initialized.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::registered_tenant_ids(&snapshot)?,
        [initialized.default_tenant_id()],
        "migration must publish the V2 directory for the legacy default tenant"
    );
    drop(snapshot);
    let policy = positron_governance::IngestPolicyAdministration::open(
        &catalog,
        initialized.default_tenant_id(),
    )?;
    assert_eq!(policy.serving().pin()?.generation(), 1);
    drop(catalog);
    drop(initialized);
    let reopened = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["legacy-f9-before-v2"]
    );
    Ok(())
}

struct LegacyFixtureRoots {
    root: PathBuf,
}

impl LegacyFixtureRoots {
    fn from_f9_fixture() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-f9-v1-compatibility-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        let fixture = Self { root };
        let source = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy-f9-v1"
        ));
        for name in ["data", "secrets"] {
            copy_tree(&source.join(name), &fixture.root().join(name))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                fixture.root().join("secrets"),
                fs::Permissions::from_mode(0o700),
            )?;
            for name in ["bootstrap-claim.v1", "local-root-key.v1"] {
                fs::set_permissions(
                    fixture.root().join("secrets").join(name),
                    fs::Permissions::from_mode(0o600),
                )?;
            }
            assert_eq!(
                fs::metadata(fixture.root().join("secrets"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o700,
                "copied legacy secrets root stays owner-only"
            );
            for name in ["bootstrap-claim.v1", "local-root-key.v1"] {
                assert_eq!(
                    fs::metadata(fixture.root().join("secrets").join(name))?
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600,
                    "copied legacy {name} stays owner-only"
                );
            }
        }
        Ok(fixture)
    }

    fn root(&self) -> &std::path::Path {
        &self.root
    }
}

fn copy_tree(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), std::io::Error> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), destination_path)?;
        } else {
            return Err(std::io::Error::other(
                "legacy V1 fixture contains an unsupported entry",
            ));
        }
    }
    Ok(())
}

impl Drop for LegacyFixtureRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn corrupt_default_tenant_envelope(
    initialized: &crate::InitializedInstance,
) -> Result<(), Box<dyn Error>> {
    let envelope = initialized
        .durable_identity()?
        .tenant_key_envelope(initialized.tenant)?
        .to_vec();
    let catalog = open_catalog(initialized)?;
    let snapshot = catalog.pin()?;
    let mut changed = false;
    let objects = snapshot
        .object_identities()
        .map(|identity| {
            let mut bytes = snapshot
                .object(identity)?
                .ok_or("missing catalog object")?
                .to_vec();
            if !changed {
                if let Some(offset) = bytes
                    .windows(envelope.len())
                    .position(|candidate| candidate == envelope)
                {
                    bytes[offset] ^= 0x01;
                    changed = true;
                }
            }
            CatalogObject::new(bytes).map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    assert!(
        changed,
        "the authenticated tenant envelope must be catalog-carried"
    );
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0xd2; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
