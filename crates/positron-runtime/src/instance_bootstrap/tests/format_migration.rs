use std::error::Error;
use std::fs;

use crate::{InitializationPlan, InstanceBootstrap};
use positron_domain::identity::Scope;
use positron_domain::identity::{TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_governance::{Identity, IngestPolicyAdministration};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule};
use positron_kernel::Catalog;
use positron_kernel::FormatEpoch;
use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_after};

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
