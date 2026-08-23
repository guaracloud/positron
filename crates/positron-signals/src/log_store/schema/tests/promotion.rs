use super::*;
use positron_kernel::StoreBlockIdentity;

#[test]
fn scalar_discovery_consumes_exact_dictionary_index_bytes() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 8_192, 8_192, 8)?)?;
    let observed = occurrence(
        AttributeNamespace::Record,
        "scalar",
        CandidateAttributeValue::signed_integer(7),
    )?;
    let observation = catalog.observe(std::slice::from_ref(&observed))?;
    assert!(
        !catalog
            .entry(&path(AttributeNamespace::Record, "scalar"))
            .ok_or("entry")?
            .promoted()
    );
    catalog.observe(std::slice::from_ref(&observed))?;
    let entry = catalog
        .entry(&path(AttributeNamespace::Record, "scalar"))
        .ok_or("entry missing")?;

    assert!(
        observation
            .attributes()
            .all(|(_, representation)| representation.is_cataloged())
    );
    assert!(entry.promoted());
    assert_eq!(entry.index_bytes(), 3);
    assert_eq!(entry.path().as_string()?, "scalar");
    assert_eq!(catalog.index_bytes(), 3);
    Ok(())
}

#[test]
fn container_only_conflicts_never_allocate_scalar_index_bytes() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 8_192, 8_192, 8)?)?;
    let containers = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "container".to_owned(),
        vec![
            CandidateAttributeValue::array(vec![CandidateAttributeValue::boolean(true)]),
            CandidateAttributeValue::key_value_list(vec![
                positron_domain::value::CandidateKeyValue::new(
                    "child".to_owned(),
                    CandidateAttributeValue::boolean(true),
                ),
            ]),
        ],
    )
    .validate(profile())?;
    catalog.observe(&[containers])?;
    let entry = catalog
        .entry(&path(AttributeNamespace::Record, "container"))
        .ok_or("entry")?;
    assert_eq!(entry.path().as_string()?, "container");
    assert_eq!(entry.variants().len(), 2);
    assert!(!entry.promoted());
    assert_eq!(entry.index_bytes(), 0);
    Ok(())
}

#[test]
fn root_overflows_atomically_when_its_dictionary_index_does_not_fit() -> Result<(), Box<dyn Error>>
{
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 8_192, 8_192, 2)?)?;
    let observed = occurrence(
        AttributeNamespace::Record,
        "scalar",
        CandidateAttributeValue::string("still preserved".to_owned()),
    )?;
    let first = catalog.observe(std::slice::from_ref(&observed))?;
    assert!(
        first
            .attributes()
            .all(|(_, representation)| representation.is_cataloged())
    );
    let observation = catalog.observe(std::slice::from_ref(&observed))?;

    assert_eq!(catalog.entry_count(), 1);
    assert_eq!(catalog.index_bytes(), 0);
    assert_eq!(observation.overflow_records(), 1);
    assert_eq!(
        observation.representation(&path(AttributeNamespace::Record, "scalar")),
        Some(super::super::SchemaRepresentation::Overflow)
    );
    Ok(())
}

#[test]
fn repeated_and_conflicting_occurrences_update_one_exact_dictionary() -> Result<(), Box<dyn Error>>
{
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 8_192, 8_192, 4)?)?;
    let repeated = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "scalar".to_owned(),
        vec![
            CandidateAttributeValue::signed_integer(7),
            CandidateAttributeValue::signed_integer(8),
        ],
    )
    .validate(profile())?;
    catalog.observe(&[repeated])?;
    assert_eq!(catalog.index_bytes(), 3);
    assert_eq!(
        catalog
            .entry(&path(AttributeNamespace::Record, "scalar"))
            .ok_or("entry")?
            .observations(),
        2
    );

    catalog.observe(&[occurrence(
        AttributeNamespace::Record,
        "scalar",
        CandidateAttributeValue::string("typed conflict".to_owned()),
    )?])?;
    let entry = catalog
        .entry(&path(AttributeNamespace::Record, "scalar"))
        .ok_or("entry")?;
    assert_eq!(entry.variants().len(), 2);
    assert_eq!(entry.conflicts(), 1);
    assert_eq!(catalog.index_bytes(), 4);
    Ok(())
}

#[test]
fn removing_scalar_evidence_retains_unrelated_text_only_block() -> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let text_identity = StoreBlockIdentity::new(1_u128.to_be_bytes())?;
    let mut text_delta = super::super::SchemaDelta::empty(tenant, true);
    text_delta.attach_text_summary(
        &catalog,
        super::super::TextBlockSummary::from_bodies([Some("text-only block")])?,
    )?;
    let (text_delta, text_index) = text_delta.into_block_index(text_identity, [0x21; 32]);
    catalog.apply_delta(text_delta, text_index)?;

    let scalar = occurrence(
        AttributeNamespace::Record,
        "scalar",
        CandidateAttributeValue::signed_integer(7),
    )?;
    catalog.observe(std::slice::from_ref(&scalar))?;
    catalog.observe(std::slice::from_ref(&scalar))?;
    let scalar_path = path(AttributeNamespace::Record, "scalar");
    catalog.record_query_use(&scalar_path)?;
    let mut scalar_delta = super::super::SchemaDelta::empty(tenant, true);
    catalog.stage_record(
        std::slice::from_ref(&scalar),
        &mut scalar_delta,
        &mut super::super::delta::DiscoveryMeter::new(),
    )?;
    let (scalar_delta, scalar_index) =
        scalar_delta.into_block_index(StoreBlockIdentity::new(2_u128.to_be_bytes())?, [0x22; 32]);
    catalog.apply_delta(scalar_delta, scalar_index)?;

    catalog.remove_query_evidence(&scalar_path)?;
    assert!(
        catalog
            .block_indexes
            .iter()
            .any(|block| block.identity == text_identity && block.text_summary.is_some())
    );
    Ok(())
}
