use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{InitializationPlan, InstanceBootstrap};
use positron_domain::identity::Scope;
use positron_domain::identity::{TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CatalogFormatMigrationAdministration, CompatibilityHints,
    PresentedCredential, RequestedIntent, ResourceGeneration,
};
use positron_governance::{Identity, IngestPolicyAdministration};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule};
use positron_kernel::Catalog;
use positron_kernel::FormatEpoch;
use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_after};
use positron_query::QueryCancellation;

use super::initialization::Roots;

#[test]
fn fresh_bootstrap_publishes_epoch_two_and_reopens() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(
        instance.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    let administrator = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;

    assert_eq!(administrator.scope(), Scope::SystemAdministration);
    drop(instance);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    assert!(
        reopened
            .attribute(
                PresentedCredential::parse(claim.secret())?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn epoch_two_catalog_keeps_format_after_api_key_and_lifecycle_successors()
-> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    instance.create_api_key(
        administrator()?,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe4; 16])?,
    )?;
    instance.transition_tenant_lifecycle(
        administrator()?,
        instance.default_tenant_id(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe5; 16])?,
    )?;
    assert_eq!(
        instance.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    drop(instance);
    assert_eq!(
        InstanceBootstrap::reopen(&paths)?.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    Ok(())
}

#[test]
fn epoch_two_catalog_keeps_format_after_quota_and_policy_successors() -> Result<(), Box<dyn Error>>
{
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    instance.update_tenant_quota(
        administrator()?,
        instance.default_tenant_id(),
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe7; 16])?,
        1,
        [
            32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
        ],
    )?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let identity = Identity::open(&catalog.pin()?)?;
    let policy = IngestPolicyAdministration::open(&catalog, instance.default_tenant_id())?;
    policy.activate(
        &catalog,
        &identity,
        administrator()?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe8; 16])?,
        IngestPolicy::compile(
            2,
            vec![PolicyRule::new("v2", Vec::new(), PolicyAction::Accept)?],
        )?,
    )?;
    drop(catalog);
    assert_eq!(
        instance.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    drop(instance);
    assert_eq!(
        InstanceBootstrap::reopen(&paths)?.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    Ok(())
}

#[test]
fn epoch_two_prepared_tenant_creation_restarts_without_downgrade() -> Result<(), Box<dyn Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths().map_err(|code| format!("paths: {code:?}"))?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("claim"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let tenant = TenantId::from_bytes([0xea; 16])?;
    let key = AdministrativeIdempotencyKey::new([0xeb; 16])?;
    with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
        instance.create_tenant(
            administrator().expect("admin"),
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("v2-prepared").expect("slug"),
                "V2 prepared",
                2_592_000,
                1,
                [1; 11],
            ),
            key,
        )
    })
    .expect_err("pre-marker V2 creation must remain prepared");
    let manifest = roots
        .data
        .join("catalog/staging/ebebebebebebebebebebebebebebebeb/prepared.manifest");
    let staged = fs::read(&manifest)?;
    drop(instance);
    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    let changed = reopened.create_tenant(
        reopened.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("v2-prepared")?,
            "changed",
            2_592_000,
            1,
            [1; 11],
        ),
        key,
    );
    assert!(changed.is_err());
    assert_eq!(fs::read(&manifest)?, staged);
    let resumed = reopened.create_tenant(
        reopened.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("v2-prepared")?,
            "V2 prepared",
            2_592_000,
            1,
            [1; 11],
        ),
        key,
    )?;
    assert_eq!(resumed.tenant_id(), tenant);
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    Ok(())
}

#[test]
fn unauthorized_and_exact_replayed_migrations_do_not_close_data_admission()
-> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let unauthorized = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query credential")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let (ingest_closed_tx, ingest_closed_rx) = std::sync::mpsc::channel();
    let (query_closed_tx, query_closed_rx) = std::sync::mpsc::channel();
    instance.install_lifecycle_transition_observer(ingest_closed_tx)?;
    instance.install_lifecycle_query_transition_observer(query_closed_tx)?;
    let key = AdministrativeIdempotencyKey::new([0xed; 16])?;

    let unauthorized_failure = instance
        .migrate_catalog_to_epoch_two(unauthorized, key)
        .expect_err("query actor cannot migrate the Catalog");
    assert_eq!(
        unauthorized_failure.code(),
        crate::BootstrapFailureCode::ApiKeyUnauthorized
    );
    assert!(
        ingest_closed_rx.try_recv().is_err(),
        "unauthorized migration does not close ingest admission"
    );
    assert!(
        query_closed_rx.try_recv().is_err(),
        "unauthorized migration does not close query admission"
    );
    drop(
        instance
            .enter_ingest_finalization_for(instance.default_tenant_id())
            .expect("ingest remains admitted"),
    );
    drop(
        instance
            .enter_query_execution_for(instance.default_tenant_id(), QueryCancellation::new())
            .expect("query remains admitted"),
    );

    let administrator = || {
        instance.attribute(
            PresentedCredential::parse(claim.secret()).expect("administrator credential"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    let first_administrator = administrator()?;
    let committed = instance.migrate_catalog_to_epoch_two(first_administrator, key)?;
    let (ingest_closed_tx, ingest_closed_rx) = std::sync::mpsc::channel();
    let (query_closed_tx, query_closed_rx) = std::sync::mpsc::channel();
    instance.install_lifecycle_transition_observer(ingest_closed_tx)?;
    instance.install_lifecycle_query_transition_observer(query_closed_tx)?;

    let replay_administrator = administrator()?;
    assert_eq!(
        instance.migrate_catalog_to_epoch_two(replay_administrator, key)?,
        committed,
        "exact replay resolves the committed migration"
    );
    assert!(
        ingest_closed_rx.try_recv().is_err(),
        "exact replay does not close fresh ingest admission"
    );
    assert!(
        query_closed_rx.try_recv().is_err(),
        "exact replay does not close fresh query admission"
    );
    drop(
        instance
            .enter_ingest_finalization_for(instance.default_tenant_id())
            .expect("ingest remains admitted after replay"),
    );
    drop(
        instance
            .enter_query_execution_for(instance.default_tenant_id(), QueryCancellation::new())
            .expect("query remains admitted after replay"),
    );
    Ok(())
}

#[test]
fn migration_rechecks_the_current_epoch_and_replays_a_concurrent_successor()
-> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let paths = fixture.paths()?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let actor = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let key = AdministrativeIdempotencyKey::new([0xee; 16])?;
    let audit_before = instance.governance_audit_for_test()?.len();
    let (successor_tx, successor_rx) = std::sync::mpsc::channel();
    let successor_instance = Arc::clone(&instance);
    instance.install_catalog_migration_preflight_hook(Arc::new(move || {
        let secret = successor_instance
            .key
            .catalog_secret(successor_instance.instance)
            .expect("catalog secret");
        let catalog = Catalog::open(
            &successor_instance._authority,
            successor_instance.instance,
            secret,
        )
        .expect("catalog");
        let successor = CatalogFormatMigrationAdministration::migrate_to_epoch_two(
            &catalog,
            successor_instance.administrator,
            actor,
            key,
        )
        .expect("concurrent successor migration");
        let _ = successor_tx.send(successor);
    }))?;

    let migration = instance.migrate_catalog_to_epoch_two(actor, key)?;
    assert_eq!(
        migration,
        successor_rx.recv().expect("concurrent successor result"),
        "the second preflight resolves the successor's exact migration"
    );
    assert_eq!(
        instance.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2),
        "the successor remains the sole V2 publication"
    );
    assert_eq!(
        instance.governance_audit_for_test()?.len(),
        audit_before + 1,
        "revalidation does not publish a duplicate migration audit record"
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
            "positron-migration-drain-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let fixture = Self { root };
        let source = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy-f9-v1"
        ));
        for name in ["data", "secrets"] {
            copy_tree(&source.join(name), &fixture.root.join(name))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                fixture.root.join("secrets"),
                fs::Permissions::from_mode(0o700),
            )?;
            for name in ["bootstrap-claim.v1", "local-root-key.v1"] {
                fs::set_permissions(
                    fixture.root.join("secrets").join(name),
                    fs::Permissions::from_mode(0o600),
                )?;
            }
        }
        Ok(fixture)
    }

    fn paths(&self) -> Result<crate::BootstrapPaths, crate::BootstrapFailure> {
        crate::BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            positron_kernel::MountQualification::LocalHost,
        )
    }
}

fn copy_tree(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), std::io::Error> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination_path)?;
        } else if entry.file_type()?.is_file() {
            fs::copy(entry.path(), destination_path)?;
        } else {
            return Err(std::io::Error::other("unsupported legacy fixture entry"));
        }
    }
    Ok(())
}

impl Drop for LegacyFixtureRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
