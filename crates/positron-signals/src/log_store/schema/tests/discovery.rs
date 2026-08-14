use super::*;

#[test]
fn discovery_keeps_namespaces_and_counts_typed_conflicts() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(SchemaBudget::new(8, 8_192, 8_192, 4_096)?)?;
    let resource = occurrence(
        AttributeNamespace::Resource,
        "same",
        CandidateAttributeValue::string("resource".to_owned()),
    )?;
    let record_integer = occurrence(
        AttributeNamespace::Record,
        "same",
        CandidateAttributeValue::signed_integer(42),
    )?;
    let record_string = occurrence(
        AttributeNamespace::Record,
        "same",
        CandidateAttributeValue::string("record".to_owned()),
    )?;

    let first = catalog.observe(&[resource.clone(), record_integer.clone()])?;
    assert_eq!(first.overflow_records(), 0);
    assert_eq!(catalog.entry_count(), 2);
    assert_eq!(
        catalog
            .entry(&path(AttributeNamespace::Resource, "same"))
            .map(|e| e.observations()),
        Some(1)
    );
    assert_eq!(
        catalog
            .entry(&path(AttributeNamespace::Record, "same"))
            .map(|e| e.conflicts()),
        Some(0)
    );

    catalog.observe(&[record_string])?;
    let record = catalog
        .entry(&path(AttributeNamespace::Record, "same"))
        .ok_or("record entry missing")?;
    assert_eq!(record.observations(), 2);
    assert_eq!(record.conflicts(), 1);
    assert_eq!(record.variants().len(), 2);
    assert!(
        catalog
            .entry(&path(AttributeNamespace::Resource, "same"))
            .is_some()
    );
    Ok(())
}

#[test]
fn discovery_preserves_nested_key_paths_without_enumerating_array_indexes()
-> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(SchemaBudget::new(16, 8_192, 8_192, 4_096)?)?;
    let nested = CandidateAttributeValue::key_value_list(vec![
        positron_domain::value::CandidateKeyValue::new(
            "child".to_owned(),
            CandidateAttributeValue::signed_integer(7),
        ),
        positron_domain::value::CandidateKeyValue::new(
            "items".to_owned(),
            CandidateAttributeValue::array(vec![CandidateAttributeValue::boolean(true)]),
        ),
    ]);
    catalog.observe(&[occurrence(AttributeNamespace::Record, "root", nested)?])?;
    assert!(
        catalog
            .entry(&path(AttributeNamespace::Record, "root"))
            .is_some()
    );
    assert!(
        catalog
            .entry(&path(AttributeNamespace::Record, "root.child"))
            .is_some()
    );
    assert!(
        catalog
            .entry(&path(AttributeNamespace::Record, "root.items"))
            .is_some()
    );
    assert!(
        catalog
            .entry(&path(AttributeNamespace::Record, "root.items[0]"))
            .is_none()
    );
    Ok(())
}
