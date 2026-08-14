use super::*;

#[test]
fn budget_exhaustion_marks_valid_values_as_lossless_overflow() -> Result<(), Box<dyn Error>> {
    let mut catalog = catalog_with_small_budget();
    let first = occurrence(
        AttributeNamespace::Record,
        "first",
        CandidateAttributeValue::string("one".to_owned()),
    )?;
    let second = occurrence(
        AttributeNamespace::Record,
        "second",
        CandidateAttributeValue::string("two".to_owned()),
    )?;
    let observation = catalog.observe(&[first.clone(), second.clone()])?;
    assert_eq!(observation.overflow_records(), 1);
    assert!(observation.overflow_bytes() > 0);
    assert_eq!(catalog.entry_count(), 1);
    assert_eq!(catalog.overflow_record_count(), 1);
    assert!(catalog.overflow_byte_count() >= 5);
    assert!(
        observation
            .representation(&path(AttributeNamespace::Record, "first"))
            .is_some_and(|r| r.is_cataloged())
    );
    assert!(
        observation
            .representation(&path(AttributeNamespace::Record, "second"))
            .is_some_and(|r| r.is_overflow())
    );
    assert_eq!(
        second,
        occurrence(
            AttributeNamespace::Record,
            "second",
            CandidateAttributeValue::string("two".to_owned())
        )?
    );
    Ok(())
}

#[test]
fn overflow_does_not_change_typed_query_semantics() -> Result<(), Box<dyn Error>> {
    let mut catalog = catalog_with_small_budget();
    let first = occurrence(
        AttributeNamespace::Record,
        "first",
        CandidateAttributeValue::string("one".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&first))?;
    let overflow = occurrence(
        AttributeNamespace::Record,
        "overflow",
        CandidateAttributeValue::signed_integer(42),
    )?;
    let observation = catalog.observe(std::slice::from_ref(&overflow))?;
    let result = catalog.query(
        &observation,
        &query(
            path(AttributeNamespace::Record, "overflow"),
            SchemaValue::signed_integer(42),
            OccurrenceSelector::Any,
        ),
    );
    assert!(result.is_match());
    assert!(result.reduced_pruning());
    Ok(())
}

#[test]
fn promoted_type_mismatch_still_scans_later_overflow_for_the_same_path()
-> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(4, 4_096, 4_096, 3)?)?;
    let first = occurrence(
        AttributeNamespace::Record,
        "mixed",
        CandidateAttributeValue::string("string".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&first))?;
    let later = occurrence(
        AttributeNamespace::Record,
        "mixed",
        CandidateAttributeValue::signed_integer(42),
    )?;
    let overflow = catalog.observe(std::slice::from_ref(&later))?;

    let result = catalog.query(
        &overflow,
        &query(
            path(AttributeNamespace::Record, "mixed"),
            SchemaValue::signed_integer(42),
            OccurrenceSelector::Any,
        ),
    );
    assert!(result.is_match());
    assert!(result.reduced_pruning());
    Ok(())
}
