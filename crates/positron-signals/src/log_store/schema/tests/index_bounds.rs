use std::error::Error;

use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::StoreBlockIdentity;

use super::*;

#[test]
fn root_overflows_before_append_when_block_index_ceiling_is_reached() -> Result<(), Box<dyn Error>>
{
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;

    for sequence in 1_u128..=4_096 {
        let (delta, index) = staged_index(&catalog, tenant, &attribute, sequence)?;
        catalog.apply_delta(delta, index)?;
    }
    let mut excess = super::super::SchemaDelta::empty(tenant, true);
    let observation = catalog.stage_record(
        std::slice::from_ref(&attribute),
        &mut excess,
        &mut super::super::delta::DiscoveryMeter::new(),
    )?;
    assert_eq!(
        observation.representation(&path(AttributeNamespace::Record, "indexed")),
        Some(super::super::SchemaRepresentation::Overflow)
    );
    let (excess, index) = excess.into_block_index(
        StoreBlockIdentity::new(4_097_u128.to_be_bytes())?,
        [0x61; 32],
    );
    assert!(index.is_none(), "overflow must not create a sidecar");
    catalog.apply_delta(excess, index)?;
    assert_eq!(catalog.overflow_record_count(), 1);
    Ok(())
}

fn staged_index(
    catalog: &SchemaCatalog,
    tenant: positron_domain::identity::TenantId,
    attribute: &positron_domain::value::AttributeOccurrenceSet,
    sequence: u128,
) -> Result<
    (
        super::super::SchemaDelta,
        Option<super::super::index::SchemaBlockIndex>,
    ),
    Box<dyn Error>,
> {
    let mut delta = super::super::SchemaDelta::empty(tenant, true);
    catalog.stage_record(
        std::slice::from_ref(attribute),
        &mut delta,
        &mut super::super::delta::DiscoveryMeter::new(),
    )?;
    let identity = StoreBlockIdentity::new(sequence.to_be_bytes())?;
    Ok(delta.into_block_index(identity, [0x61; 32]))
}

#[test]
fn query_indexes_merge_idempotently_and_reconcile_reachability() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::new(8, 32_768, 32_768, 8_192)?)?;
    for key in ["alpha", "beta"] {
        catalog.observe(&[occurrence(
            AttributeNamespace::Record,
            key,
            CandidateAttributeValue::string(key.to_owned()),
        )?])?;
        catalog.record_query_use(&path(AttributeNamespace::Record, key))?;
    }
    catalog.record_query_use(&path(AttributeNamespace::Record, "alpha"))?;
    assert_eq!(
        catalog
            .entry(&path(AttributeNamespace::Record, "alpha"))
            .ok_or("alpha")?
            .query_uses(),
        2
    );
    assert_eq!(
        catalog.record_query_use(&path(AttributeNamespace::Record, "missing")),
        Err(super::super::SchemaFailure::InvalidPath)
    );

    let first = StoreBlockIdentity::new(1_u128.to_be_bytes())?;
    let second = StoreBlockIdentity::new(2_u128.to_be_bytes())?;
    let digest = [0x62; 32];
    let forged = super::super::index::SchemaBlockIndex::one(
        StoreBlockIdentity::new(9_u128.to_be_bytes())?,
        digest,
        super::super::index::SchemaIndexPath {
            path: path(AttributeNamespace::Record, "missing"),
            kind_mask: 1,
            values: Vec::new(),
        },
    )?;
    assert_eq!(
        catalog.install_query_index(forged),
        Err(super::super::SchemaFailure::InvalidValue)
    );
    catalog.install_query_index(index_for(&catalog, first, digest, "alpha")?)?;
    catalog.install_query_index(index_for(&catalog, first, digest, "alpha")?)?;
    catalog.install_query_index(index_for(&catalog, first, digest, "beta")?)?;
    catalog.install_query_index(index_for(&catalog, first, digest, "beta")?)?;
    assert_eq!(
        catalog.install_query_index(index_for(&catalog, first, [0x63; 32], "alpha")?),
        Err(super::super::SchemaFailure::InvalidValue)
    );
    catalog.install_query_index(index_for(&catalog, second, digest, "alpha")?)?;

    let before = catalog.index_bytes();
    catalog.reconcile_block_identity(first, digest)?;
    assert_eq!(catalog.index_bytes(), before);
    catalog.retain_reachable_indexes(&[(first, digest)])?;
    assert!(catalog.has_verified_block(first, digest));
    assert!(!catalog.has_verified_block(second, digest));
    catalog.reconcile_block_identity(first, [0x64; 32])?;
    assert!(!catalog.has_verified_block(first, digest));
    Ok(())
}

#[test]
fn demotion_removes_only_its_paths_and_sidecar_budget_is_exact() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 32_768, 32_768, 8_192)?)?;
    for key in ["alpha", "beta"] {
        catalog.observe(&[occurrence(
            AttributeNamespace::Record,
            key,
            CandidateAttributeValue::signed_integer(7),
        )?])?;
        catalog.record_query_use(&path(AttributeNamespace::Record, key))?;
    }
    let identity = StoreBlockIdentity::new(3_u128.to_be_bytes())?;
    let digest = [0x65; 32];
    catalog.install_query_index(index_for(&catalog, identity, digest, "alpha")?)?;
    catalog.install_query_index(index_for(&catalog, identity, digest, "beta")?)?;

    catalog.remove_query_evidence(&path(AttributeNamespace::Record, "alpha"))?;
    assert!(
        !catalog
            .entry(&path(AttributeNamespace::Record, "alpha"))
            .ok_or("alpha")?
            .promoted()
    );
    assert!(catalog.has_verified_block(identity, digest));
    catalog.remove_query_evidence(&path(AttributeNamespace::Record, "beta"))?;
    assert!(!catalog.has_verified_block(identity, digest));
    catalog.remove_query_evidence(&path(AttributeNamespace::Record, "beta"))?;

    let mut tight = SchemaCatalog::new(tenant(), SchemaBudget::new(2, 8_192, 8_192, 3)?)?;
    tight.observe(&[occurrence(
        AttributeNamespace::Record,
        "tight",
        CandidateAttributeValue::signed_integer(1),
    )?])?;
    tight.record_query_use(&path(AttributeNamespace::Record, "tight"))?;
    assert_eq!(
        tight.install_query_index(index_for(&tight, identity, digest, "tight")?),
        Err(super::super::SchemaFailure::LimitExceeded)
    );
    Ok(())
}

#[test]
fn composite_kinds_always_fall_back_while_scalar_kinds_remain_prunable()
-> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let scalar = occurrence(
        AttributeNamespace::Record,
        "mixed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    let composite = occurrence(
        AttributeNamespace::Record,
        "mixed",
        CandidateAttributeValue::array(vec![CandidateAttributeValue::boolean(true)]),
    )?;
    catalog.observe(std::slice::from_ref(&scalar))?;
    catalog.observe(std::slice::from_ref(&composite))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "mixed"))?;

    let identity = StoreBlockIdentity::new(5_u128.to_be_bytes())?;
    let digest = [0x61; 32];
    let (delta, index) = staged_index(&catalog, tenant, &scalar, 5)?;
    catalog.apply_delta(delta, index)?;

    let indexed_path = path(AttributeNamespace::Record, "mixed");
    assert_eq!(
        catalog.verified_block_kind(
            identity,
            digest,
            &indexed_path,
            positron_domain::value::AttributeValueKind::String,
        ),
        Some(true)
    );
    assert_eq!(
        catalog.verified_block_kind(
            identity,
            digest,
            &indexed_path,
            positron_domain::value::AttributeValueKind::Boolean,
        ),
        Some(false)
    );
    for kind in [
        positron_domain::value::AttributeValueKind::Array,
        positron_domain::value::AttributeValueKind::KeyValueList,
    ] {
        assert_eq!(
            catalog.verified_block_kind(identity, digest, &indexed_path, kind),
            None
        );
    }
    Ok(())
}

fn index_for(
    catalog: &SchemaCatalog,
    identity: StoreBlockIdentity,
    digest: [u8; 32],
    key: &str,
) -> Result<super::super::index::SchemaBlockIndex, Box<dyn Error>> {
    let path = path(AttributeNamespace::Record, key);
    let variants = catalog.entry(&path).ok_or("entry")?.variants();
    let indexed = super::super::index::SchemaIndexPath::from_variants(&path, variants)?;
    Ok(super::super::index::SchemaBlockIndex::one(
        identity, digest, indexed,
    )?)
}
