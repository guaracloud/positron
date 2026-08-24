use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use positron_domain::identity::{PrincipalId, Scope};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_governance::{
    CatalogRootRotationStage, CompatibilityHints, InitialAuditContext, InitialGovernanceIntent,
    InitialTenantIntent, PresentedCredential, RequestedIntent,
};
use positron_kernel::{
    ActiveSegmentLedger, AuditIntent, Catalog, CatalogObject, CatalogProposal, CatalogSecret,
    CatalogWrappingKey, FormatEpoch, MountQualification, PrimaryDataVolume, SegmentScope,
    TransactionId,
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
    let inspection = initialized.inspect_governance_for_fixture(administrator_context)?;
    let audit = inspection.audit_records().to_vec();
    assert_eq!(audit.len(), 1);
    let initialization = audit[0].as_initialization().expect("initialization audit");
    assert_eq!(initialization.position(), 1);
    assert_eq!(initialization.principal_id(), administrator);
    assert_eq!(initialization.tenant_id(), Some(tenant));
    assert_eq!(initialization.action(), "instance.initialize");
    assert_eq!(initialization.outcome(), "succeeded");
    assert!(initialization.ingest_time_unix_seconds() > 0);
    assert_eq!(
        initialization.target(),
        initialized.instance_id().to_bytes()
    );
    assert_ne!(initialization.request_id(), [0; 16]);
    assert_eq!(
        initialization.metadata().initialization_mode(),
        "non-interactive"
    );
    assert_eq!(initialization.metadata().tenant_slug(), slug.as_str());
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
    assert_eq!(
        reopened
            .inspect_governance_for_fixture(context)?
            .audit_records(),
        audit
    );
    drop(reopened);

    let retried = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    assert!(retried.catalog_generation() >= first_generation);
    let context = retried.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        retried
            .inspect_governance_for_fixture(context)?
            .audit_records(),
        audit
    );
    Ok(())
}

#[test]
fn query_authorization_generation_ignores_non_security_catalog_churn()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
        .map_err(|error| format!("initialize: {error:?}"))?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths).map_err(|error| format!("claim: {error:?}"))?;
    let initialized =
        InstanceBootstrap::reopen(&paths).map_err(|error| format!("reopen: {error:?}"))?;
    let credential = PresentedCredential::parse(claim.query_secret().ok_or("query secret")?)?;
    let before = initialized
        .attribute(
            credential,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        )
        .map_err(|error| format!("before attribute: {error:?}"))?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )
    .map_err(|error| format!("catalog open: {error:?}"))?;
    let scope = SegmentScope::new(
        initialized.tenant,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let protection = initialized.key.segment_key(initialized.instance, scope)?;
    let ledger = ActiveSegmentLedger::open(&initialized._authority, &catalog, scope, protection)
        .map_err(|error| format!("ledger open: {error:?}"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expiry = now.checked_add(100).ok_or("lease expiry overflow")?;
    drop(
        ledger
            .create_snapshot_lease(now, expiry)
            .map_err(|error| format!("lease create: {error:?}"))?,
    );
    drop(ledger);
    let pinned = catalog
        .pin()
        .map_err(|error| format!("catalog pin: {error:?}"))?;
    let after = positron_governance::Identity::open(&pinned)
        .map_err(|error| format!("identity open: {error:?}"))?
        .attribute(
            &initialized.key,
            PresentedCredential::parse(claim.query_secret().ok_or("query secret")?)?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        )?;
    drop(catalog);
    drop(initialized);
    assert_eq!(
        before.authorization_generation(),
        after.authorization_generation()
    );
    Ok(())
}

#[test]
fn heterogeneous_audit_decoder_preserves_every_committed_rotation_position()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let rotation_transaction = TransactionId::new([44; 16])?;
    catalog.rewrap(
        rotation_transaction,
        CatalogWrappingKey::from_owned_at_epoch(Box::new([45; 32]), [46; 16], 2)?,
        AuditIntent::new(b"sensitive operator approval".to_vec())?,
    )?;

    let records = catalog.governance_audit_records()?;
    let audit = governance_audit_records(&catalog)?;
    assert_eq!(audit.len(), records.len());
    assert_eq!(audit.len(), 4);
    assert!(audit[0].as_initialization().is_some());
    let expected = [
        CatalogRootRotationStage::Started,
        CatalogRootRotationStage::Verified,
        CatalogRootRotationStage::Completed,
    ];
    for ((record, entry), stage) in records.iter().zip(&audit).skip(1).zip(expected) {
        let rotation = entry.as_catalog_root_rotation().expect("rotation audit");
        assert_eq!(entry.position(), record.position());
        assert_eq!(rotation.stage(), stage);
        assert_eq!(rotation.provider_key_reference(), [46; 16]);
        assert_eq!(rotation.key_epoch(), 2);
        assert_eq!(rotation.transaction_id(), record.transaction().to_bytes());
        assert_ne!(rotation.transaction_id(), rotation_transaction.to_bytes());
        assert_eq!(rotation.outcome(), "committed");
        let rendered = format!("{entry:?} {entry}");
        assert!(!rendered.contains("sensitive operator approval"));
        assert!(!rendered.contains(&format!("{:?}", [45_u8; 32])));
    }
    Ok(())
}

#[test]
fn authenticated_system_administrator_reads_the_successor_heterogeneous_audit_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let bootstrap_roots = Roots::new()?;
    let bootstrap_paths = bootstrap_roots.paths();
    let initialized =
        InstanceBootstrap::initialize(&bootstrap_paths, InitializationPlan::non_interactive())?;
    let instance = initialized.instance_id();
    let tenant = initialized.default_tenant_id();
    let tenant_slug = initialized.default_tenant_slug().clone();
    let administrator = initialized.system_administrator_id();
    drop(initialized);
    let claim = InstanceBootstrap::claim(&bootstrap_paths)?;
    let initialized = InstanceBootstrap::reopen(&bootstrap_paths)?;
    let administrator_context = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    drop(initialized);

    let roots = Roots::new()?;
    let volume =
        PrimaryDataVolume::acquire(&roots.parent().join("data"), MountQualification::LocalHost)?;
    let authority = resources::establish(volume, tenant)?;
    let marker = [53; 32];
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned_at_epoch(Box::new(marker), Box::new([54; 32]), [55; 16], 1)?,
    )?;
    let governance = InitialGovernanceIntent::create_tenant(InitialTenantIntent::new(
        instance.to_bytes(),
        tenant,
        tenant_slug.clone(),
        "Default tenant",
        administrator,
        [57; 32],
        [58; 32],
        PrincipalId::from_bytes([70; 16])?,
        [71; 32],
        [72; 32],
        PrincipalId::from_bytes([73; 16])?,
        [74; 32],
        [75; 32],
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
        AuditIntent::new(b"sensitive successor rotation context".to_vec())?,
    )?;
    drop(catalog);

    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned_at_epoch(Box::new(marker), Box::new([66; 32]), [67; 16], 2)?,
    )?;
    assert_eq!(reopened.governance_audit_records()?.len(), 4);
    let audit = governance_audit_records(&reopened)?;
    let identity = positron_governance::Identity::open(&reopened.pin()?)?;
    let inspection = identity.inspect(administrator_context, &audit)?;
    assert_eq!(inspection.audit_records().len(), 4);
    assert_eq!(
        inspection
            .audit_records()
            .iter()
            .map(|entry| entry.position())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert!(inspection.audit_records()[0].as_initialization().is_some());
    assert_eq!(
        inspection.audit_records()[1..]
            .iter()
            .map(|entry| entry.as_catalog_root_rotation().expect("rotation").stage())
            .collect::<Vec<_>>(),
        [
            CatalogRootRotationStage::Started,
            CatalogRootRotationStage::Verified,
            CatalogRootRotationStage::Completed,
        ]
    );
    assert!(inspection.contains_tenant_id(tenant));
    assert!(inspection.contains_tenant_slug(&tenant_slug));
    assert!(!format!("{inspection:?}").contains("sensitive successor rotation context"));
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
