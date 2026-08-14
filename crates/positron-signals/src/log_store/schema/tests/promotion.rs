use super::*;

#[test]
fn scalar_discovery_consumes_exact_dictionary_index_bytes() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 8_192, 8_192, 8)?)?;
    let observed = occurrence(
        AttributeNamespace::Record,
        "scalar",
        CandidateAttributeValue::signed_integer(7),
    )?;
    let observation = catalog.observe(std::slice::from_ref(&observed))?;
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
    let observation = catalog.observe(std::slice::from_ref(&observed))?;

    assert_eq!(catalog.entry_count(), 0);
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
