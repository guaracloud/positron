use positron_domain::identity::TenantId;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, IngestPolicyAdministration,
    PolicyAdministrationFailureCode, PresentedCredential, RequestedIntent, ResourceGeneration,
};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule};
use positron_kernel::{Catalog, CatalogObject, CatalogProposal, FormatEpoch, TransactionId};

use super::super::super::{InitializationPlan, InstanceBootstrap};
use super::super::support::Roots;

const RECEIPT_MAGIC: &[u8] = b"POSPID01";

#[test]
fn malformed_current_activation_fails_closed_during_administration_open()
-> Result<(), Box<dyn std::error::Error>> {
    let (roots, initialized, _claim) = initialized()?;
    let catalog = catalog(&initialized)?;
    let tenant = initialized.tenant;
    let mut activation = IngestPolicy::preserving(2)?
        .activated_object(tenant)?
        .into_bytes();
    activation.push(0);
    append_object(&catalog, activation, 0xa1)?;

    let failure = match IngestPolicyAdministration::open(&catalog, tenant) {
        Ok(_) => return Err("malformed current activation was accepted".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.code(),
        PolicyAdministrationFailureCode::CorruptState
    );
    drop(catalog);
    drop(initialized);
    drop(roots);
    Ok(())
}

#[test]
fn duplicate_current_activations_fail_closed_without_selecting_one()
-> Result<(), Box<dyn std::error::Error>> {
    let (roots, initialized, _claim) = initialized()?;
    let catalog = catalog(&initialized)?;
    let tenant = initialized.tenant;
    let first = IngestPolicy::preserving(2)?
        .activated_object(tenant)?
        .into_bytes();
    let second = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "distinct-current",
            Vec::new(),
            PolicyAction::Accept,
        )?],
    )?
    .activated_object(tenant)?
    .into_bytes();
    assert_ne!(first, second, "test requires two distinct current objects");
    append_objects(&catalog, [first, second], 0xa2)?;

    let failure = match IngestPolicyAdministration::open(&catalog, tenant) {
        Ok(_) => return Err("duplicate current activations were accepted".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.code(),
        PolicyAdministrationFailureCode::CorruptState
    );
    drop(catalog);
    drop(initialized);
    drop(roots);
    Ok(())
}

#[test]
fn malformed_activation_receipt_blocks_the_next_mutation() -> Result<(), Box<dyn std::error::Error>>
{
    let (roots, initialized, claim) = initialized()?;
    let catalog = catalog(&initialized)?;
    let administration = IngestPolicyAdministration::open(&catalog, initialized.tenant)?;
    let administrator = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    administration.activate(
        &catalog,
        &initialized.identity,
        administrator,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb1; 16])?,
        IngestPolicy::preserving(2)?,
    )?;
    truncate_receipt(&catalog, 0xa3)?;

    let failure = administration
        .activate(
            &catalog,
            &initialized.identity,
            administrator,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0xb2; 16])?,
            IngestPolicy::preserving(3)?,
        )
        .expect_err("malformed receipt must prevent a new activation");
    assert_eq!(
        failure.code(),
        PolicyAdministrationFailureCode::CorruptState
    );
    drop(catalog);
    drop(initialized);
    drop(roots);
    Ok(())
}

#[test]
fn foreign_tenant_activation_is_retained_during_local_activation()
-> Result<(), Box<dyn std::error::Error>> {
    let (roots, initialized, claim) = initialized()?;
    let catalog = catalog(&initialized)?;
    let foreign = TenantId::from_bytes([0xd4; 16])?;
    assert_ne!(foreign, initialized.tenant);
    append_object(
        &catalog,
        IngestPolicy::preserving(2)?
            .activated_object(foreign)?
            .into_bytes(),
        0xa4,
    )?;
    let administration = IngestPolicyAdministration::open(&catalog, initialized.tenant)?;
    let administrator = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    administration.activate(
        &catalog,
        &initialized.identity,
        administrator,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb3; 16])?,
        IngestPolicy::preserving(2)?,
    )?;

    let snapshot = catalog.pin()?;
    let mut retained = 0;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)?
            .ok_or("catalog object disappeared")?;
        if IngestPolicy::decode_activated_object(foreign, bytes)?.is_some() {
            retained += 1;
        }
    }
    assert_eq!(retained, 1, "foreign activation must remain in the catalog");
    drop(catalog);
    drop(initialized);
    drop(roots);
    Ok(())
}

fn initialized() -> Result<
    (
        Roots,
        super::super::super::InitializedInstance,
        super::super::super::BootstrapClaim,
    ),
    Box<dyn std::error::Error>,
> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    Ok((roots, initialized, claim))
}

fn catalog(
    initialized: &super::super::super::InitializedInstance,
) -> Result<Catalog<'_>, Box<dyn std::error::Error>> {
    Ok(Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?)
}

fn append_object(
    catalog: &Catalog<'_>,
    object: Vec<u8>,
    marker: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    append_objects(catalog, [object], marker)
}

fn append_objects<const N: usize>(
    catalog: &Catalog<'_>,
    additions: [Vec<u8>; N],
    marker: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let current = catalog.pin()?;
    let mut objects = Vec::new();
    for identity in current.object_identities() {
        let bytes = current
            .object(identity)?
            .ok_or("catalog object disappeared")?;
        objects.push(CatalogObject::new(bytes.to_vec())?);
    }
    for object in additions {
        objects.push(CatalogObject::new(object)?);
    }
    catalog.commit(
        current.identity(),
        CatalogProposal::new(
            TransactionId::new([marker; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

fn truncate_receipt(catalog: &Catalog<'_>, marker: u8) -> Result<(), Box<dyn std::error::Error>> {
    let current = catalog.pin()?;
    let mut objects = Vec::new();
    let mut changed = false;
    for identity in current.object_identities() {
        let bytes = current
            .object(identity)?
            .ok_or("catalog object disappeared")?;
        let object = if bytes.starts_with(RECEIPT_MAGIC) {
            changed = true;
            CatalogObject::new(
                bytes
                    .get(..bytes.len().checked_sub(1).ok_or("empty receipt")?)
                    .ok_or("receipt truncation range")?
                    .to_vec(),
            )?
        } else {
            CatalogObject::new(bytes.to_vec())?
        };
        objects.push(object);
    }
    assert!(changed, "valid activation must have produced a receipt");
    catalog.commit(
        current.identity(),
        CatalogProposal::new(
            TransactionId::new([marker; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
