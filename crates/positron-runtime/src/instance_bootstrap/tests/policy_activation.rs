use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule};
use positron_kernel::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, FormatEpoch, TransactionId,
};

use super::super::{InitializationPlan, InstanceBootstrap};
use super::support::Roots;

#[test]
fn catalog_activation_is_loaded_unchanged_after_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let policy = IngestPolicy::compile(
        12,
        vec![PolicyRule::new(
            "catalog-accept",
            Vec::new(),
            PolicyAction::Accept,
        )?],
    )?;
    let expected_digest = policy.digest();
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let before = catalog.pin()?;
    let mut objects = Vec::new();
    for identity in before.object_identities() {
        let bytes = before
            .object(identity)?
            .ok_or("Catalog snapshot identity disappeared")?;
        objects.push(CatalogObject::new(bytes.to_vec())?);
    }
    let (activation, audit) = policy.activated_object(initialized.tenant)?.into_parts();
    objects.push(CatalogObject::new(activation)?);
    catalog.commit(
        before.identity(),
        CatalogProposal::new(
            TransactionId::new([0x92; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        Some(AuditIntent::new(audit)?),
    )?;
    let activated = super::super::operation::activated_policy(&catalog.pin()?, initialized.tenant)
        .map_err(|failure| format!("activation load: {:?}", failure.code()))?;
    assert_eq!(activated.digest(), expected_digest);
    drop(catalog);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)
        .map_err(|failure| format!("bootstrap reopen: {:?}", failure.code()))?;
    assert_eq!(reopened.ingest_policy.generation(), 12);
    assert_eq!(reopened.ingest_policy.digest(), expected_digest);
    Ok(())
}
