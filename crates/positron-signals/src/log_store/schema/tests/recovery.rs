use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue,
};
use positron_kernel::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, CatalogSecret, CatalogSnapshot,
    FormatEpoch, InstanceId, MountQualification, PrimaryDataVolume, TransactionId,
};

use super::{SchemaBudget, SchemaCatalog, SchemaPath, profile};
use crate::log_store::tests::support::{TemporaryRoot, establish_kernel_authority};

#[test]
fn schema_catalog_commits_through_catalog_and_reopens_equivalently() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0x18; 16])?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::new(16, 16_384, 16_384, 4_096)?)?;
    let set = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "durable".to_owned(),
        vec![CandidateAttributeValue::signed_integer(7)],
    )
    .validate(profile())?;
    schema.observe(&[set])?;
    let secret = || CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    let commit = catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0x61; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(schema.encode_catalog_object()?)?],
        )?,
        Some(AuditIntent::new(b"schema-catalog-update".to_vec())?),
    )?;
    assert_eq!(
        commit
            .governance_audit_record()
            .map(|audit| audit.position()),
        Some(1)
    );
    assert!(commit.snapshot().object_identities().next().is_some());

    let mut replacement =
        SchemaCatalog::new(tenant, SchemaBudget::new(16, 16_384, 16_384, 4_096)?)?;
    let replacement_set = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "replacement".to_owned(),
        vec![CandidateAttributeValue::boolean(true)],
    )
    .validate(profile())?;
    replacement.observe(&[replacement_set])?;
    let replacement_commit = catalog.commit(
        commit.identity(),
        CatalogProposal::new(
            TransactionId::new([0x63; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(replacement.encode_catalog_object()?)?],
        )?,
        Some(AuditIntent::new(b"schema-catalog-replacement".to_vec())?),
    )?;
    assert_eq!(replacement_commit.number(), 2);
    drop(catalog);

    let reopened = Catalog::open(&authority, instance, secret())?;
    let recovered =
        load_schema(&reopened.pin()?, tenant)?.ok_or("schema catalog missing after reopen")?;
    assert_eq!(recovered, replacement);
    assert!(
        recovered
            .entry(&SchemaPath::new(
                AttributeNamespace::Record,
                "durable".to_owned()
            )?)
            .is_none()
    );
    assert_eq!(
        recovered
            .entry(&SchemaPath::new(
                AttributeNamespace::Record,
                "replacement".to_owned(),
            )?)
            .map(|entry| entry.observations()),
        Some(1)
    );
    Ok(())
}

#[test]
fn duplicate_or_malformed_schema_objects_fail_closed() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0x19; 16])?;
    let tenant = TenantId::from_bytes([0x42; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let malformed = CatalogObject::new(b"PSCHEMA1\0\x01bad".to_vec())?;
    let proposal = CatalogProposal::new(
        TransactionId::new([0x62; 16])?,
        FormatEpoch::CATALOG_V1,
        vec![malformed],
    )?;
    catalog.commit(catalog.pin()?.identity(), proposal, None)?;
    assert!(load_schema(&catalog.pin()?, tenant).is_err());
    Ok(())
}

fn load_schema(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<SchemaCatalog>, Box<dyn Error>> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot.object(identity)?.ok_or("catalog object missing")?;
        let Some(schema) = SchemaCatalog::decode_catalog_object_if_recognized(bytes)? else {
            continue;
        };
        if schema.tenant() == tenant && found.replace(schema).is_some() {
            return Err("duplicate tenant schema object".into());
        }
    }
    Ok(found)
}
