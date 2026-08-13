use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use positron_domain::identity::{PrincipalId, Scope, TenantId, TenantSlug};
use positron_governance::{
    CompatibilityHints, InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent,
    PresentedCredential, RequestedIntent,
};
use positron_kernel::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, CatalogSecret, CatalogWrappingKey,
    FormatEpoch, MountQualification, PrimaryDataVolume, TransactionId,
};

use super::super::InitializationPlan;
use super::super::operation::governance_audit_records;
use super::super::resources;
use super::support::Roots;
use crate::InstanceBootstrap;

#[test]
fn identity_failures_do_not_enumerate_or_expose_secret_material()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let secret = claim.secret().to_owned();

    let authorized = reopened.attribute(
        PresentedCredential::parse(&secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(authorized.scope(), Scope::SystemAdministration);
    assert_eq!(authorized.tenant_attribution(), None);

    let mut wrong = secret.clone();
    wrong.replace_range(4..6, if &secret[4..6] == "00" { "01" } else { "00" });
    let expected = "credential or authority was rejected";
    for intent in [
        RequestedIntent::Ingest,
        RequestedIntent::Query,
        RequestedIntent::TenantAdministration,
        RequestedIntent::SystemAdministration,
    ] {
        let failure = reopened
            .attribute(
                PresentedCredential::parse(&wrong)?,
                intent,
                CompatibilityHints::none(),
            )
            .expect_err("unknown credentials must fail closed");
        assert_eq!(failure.to_string(), expected);
    }
    let alias_failure = reopened
        .attribute(
            PresentedCredential::parse(&secret)?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::external_tenant_alias("default")?,
        )
        .expect_err("an alias cannot turn system authority into tenant authority");
    assert_eq!(alias_failure.to_string(), expected);
    assert_eq!(
        PresentedCredential::parse("pos_not-a-credential")
            .expect_err("malformed credentials must fail closed")
            .to_string(),
        expected
    );
    assert!(!format!("{claim:?} {reopened:?}").contains(&secret));
    assert!(durable_tree(roots.parent())?.values().all(|bytes| {
        !bytes
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    }));
    Ok(())
}

#[test]
fn initialization_audit_and_non_reuse_survive_idempotent_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let tenant = initialized.default_tenant_id();
    let slug = initialized.default_tenant_slug().clone();
    let administrator = initialized.system_administrator_id();
    let first_generation = initialized.catalog_generation();
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let administrator_context = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let inspection = initialized.inspect_governance(administrator_context)?;
    let audit = inspection.audit_records().to_vec();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].position(), 1);
    assert_eq!(audit[0].principal_id(), administrator);
    assert_eq!(audit[0].tenant_id(), Some(tenant));
    assert_eq!(audit[0].action(), "instance.initialize");
    assert_eq!(audit[0].outcome(), "succeeded");
    assert!(audit[0].ingest_time_unix_seconds() > 0);
    assert_eq!(audit[0].target(), initialized.instance_id().to_bytes());
    assert_ne!(audit[0].request_id(), [0; 16]);
    assert_eq!(audit[0].metadata().initialization_mode(), "non-interactive");
    assert_eq!(audit[0].metadata().tenant_slug(), slug.as_str());
    assert!(inspection.contains_tenant_id(tenant));
    assert!(inspection.contains_tenant_slug(&slug));
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert!(reopened.catalog_generation() >= first_generation);
    let context = reopened.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(reopened.inspect_governance(context)?.audit_records(), audit);
    drop(reopened);

    let retried = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    assert!(retried.catalog_generation() >= first_generation);
    let context = retried.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(retried.inspect_governance(context)?.audit_records(), audit);
    Ok(())
}

#[test]
fn initialization_audit_projection_survives_a_heterogeneous_root_rotation_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    catalog.rewrap(
        TransactionId::new([44; 16])?,
        CatalogWrappingKey::from_owned_at_epoch(Box::new([45; 32]), [46; 16], 2)?,
        AuditIntent::new(b"approved bootstrap catalog rotation".to_vec())?,
    )?;

    assert_eq!(catalog.governance_audit_records()?.len(), 4);
    let initialization = governance_audit_records(&catalog)?;
    assert_eq!(initialization.len(), 1);
    assert_eq!(initialization[0].action(), "instance.initialize");
    Ok(())
}

#[test]
fn heterogeneous_audit_chain_reopens_under_the_successor_catalog_route()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let tenant = TenantId::from_bytes([52; 16])?;
    let volume =
        PrimaryDataVolume::acquire(&roots.parent().join("data"), MountQualification::LocalHost)?;
    let authority = resources::establish(volume, tenant)?;
    let instance = positron_kernel::InstanceId::new([51; 16])?;
    let marker = [53; 32];
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned_at_epoch(Box::new(marker), Box::new([54; 32]), [55; 16], 1)?,
    )?;
    let governance = InitialGovernanceIntent::create_tenant(InitialTenantIntent::new(
        instance.to_bytes(),
        tenant,
        TenantSlug::parse_canonical("default")?,
        "Default tenant",
        PrincipalId::from_bytes([56; 16])?,
        [57; 32],
        [58; 32],
        [59; 32],
        [60; 32],
        vec![61; 64],
        vec![62; 48],
        2_592_000,
        1,
        1,
        [1; 11],
        InitialAuditContext::new(1_725_000_001, [63; 16], true)?,
    )?)?;
    let (object, audit) = governance.into_parts();
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([64; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(object)?],
        )?,
        Some(AuditIntent::new(audit)?),
    )?;
    catalog.rewrap(
        TransactionId::new([65; 16])?,
        CatalogWrappingKey::from_owned_at_epoch(Box::new([66; 32]), [67; 16], 2)?,
        AuditIntent::new(b"approved governance rotation".to_vec())?,
    )?;
    drop(catalog);

    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned_at_epoch(Box::new(marker), Box::new([66; 32]), [67; 16], 2)?,
    )?;
    assert_eq!(reopened.governance_audit_records()?.len(), 4);
    let initialization = governance_audit_records(&reopened)?;
    assert_eq!(initialization.len(), 1);
    assert_eq!(initialization[0].action(), "instance.initialize");
    Ok(())
}

fn durable_tree(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, std::io::Error> {
    fn visit(
        root: &Path,
        current: &Path,
        observed: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<(), std::io::Error> {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            if entry.file_type()?.is_dir() {
                observed.insert(relative.clone(), Vec::new());
                visit(root, &path, observed)?;
            } else {
                observed.insert(relative, std::fs::read(path)?);
            }
        }
        Ok(())
    }

    let mut observed = BTreeMap::new();
    visit(root, root, &mut observed)?;
    Ok(observed)
}
