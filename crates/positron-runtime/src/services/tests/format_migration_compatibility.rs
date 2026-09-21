use std::error::Error;
use std::fs;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration, TenantAdministration,
};
use positron_ingest::IngestPolicy;
use positron_kernel::{FormatEpoch, MountQualification};
use positron_query::QueryBudget;

use super::super::ServiceHandle;
use super::schema_maintenance::open_catalog;
use crate::{BootstrapPaths, InstanceBootstrap};

#[test]
fn legacy_queries_remain_compatible_after_epoch_two_migration_without_policy_injection()
-> Result<(), Box<dyn Error>> {
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
    let migration_key = AdministrativeIdempotencyKey::new([0xd3; 16])?;
    let migration = initialized.migrate_catalog_to_epoch_two(system, migration_key)?;
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
    let mut policies = 0_usize;
    for identity in snapshot.object_identities() {
        let object = snapshot.object(identity)?.ok_or("catalog object")?;
        if IngestPolicy::decode_activated_object(initialized.default_tenant_id(), object)?.is_some()
        {
            policies += 1;
        }
    }
    assert_eq!(
        policies, 0,
        "format migration copies legacy state without activating a new policy"
    );
    drop(snapshot);
    drop(catalog);
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        system,
        NonZeroU64::new(1).ok_or("retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xd4; 16])?,
    )?;
    drop(initialized);
    let reopened = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let system = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        reopened.migrate_catalog_to_epoch_two(system, migration_key)?,
        migration,
        "the terminal migration receipt survives reclamation of its audit record"
    );
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
