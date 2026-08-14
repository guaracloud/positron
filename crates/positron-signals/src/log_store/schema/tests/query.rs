use super::*;
use positron_domain::value::AttributeValueKind;

#[test]
fn occurrence_queries_are_explicit_and_preserve_order() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(SchemaBudget::new(8, 8_192, 8_192, 4_096)?)?;
    let values = vec![
        CandidateAttributeValue::string("first".to_owned()),
        CandidateAttributeValue::string("second".to_owned()),
    ];
    let set = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "duplicate".to_owned(),
        values,
    )
    .validate(profile())?;
    let observation = catalog.observe(std::slice::from_ref(&set))?;
    assert!(
        catalog
            .query(
                &observation,
                &query(
                    path(AttributeNamespace::Record, "duplicate"),
                    SchemaValue::string("first"),
                    OccurrenceSelector::Index(0),
                ),
            )
            .is_match()
    );
    assert!(
        !catalog
            .query(
                &observation,
                &query(
                    path(AttributeNamespace::Record, "duplicate"),
                    SchemaValue::string("first"),
                    OccurrenceSelector::Index(1),
                ),
            )
            .is_match()
    );
    assert!(
        catalog
            .query(
                &observation,
                &query(
                    path(AttributeNamespace::Record, "duplicate"),
                    SchemaValue::string("second"),
                    OccurrenceSelector::Any,
                ),
            )
            .is_match()
    );
    assert!(
        !catalog
            .query(
                &observation,
                &query(
                    path(AttributeNamespace::Record, "duplicate"),
                    SchemaValue::string("first"),
                    OccurrenceSelector::All,
                ),
            )
            .is_match()
    );
    Ok(())
}

#[test]
fn typed_values_do_not_coerce() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(SchemaBudget::new(8, 8_192, 8_192, 4_096)?)?;
    let set = occurrence(
        AttributeNamespace::Record,
        "number",
        CandidateAttributeValue::signed_integer(42),
    )?;
    let observation = catalog.observe(std::slice::from_ref(&set))?;
    assert!(
        !catalog
            .query(
                &observation,
                &query(
                    path(AttributeNamespace::Record, "number"),
                    SchemaValue::string("42"),
                    OccurrenceSelector::Any,
                ),
            )
            .is_match()
    );
    Ok(())
}

#[test]
fn every_native_query_value_is_typed_and_nested_paths_are_explicit() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(SchemaBudget::new(16, 16_384, 16_384, 4_096)?)?;
    let values = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "values".to_owned(),
        vec![
            CandidateAttributeValue::null(),
            CandidateAttributeValue::boolean(true),
            CandidateAttributeValue::signed_integer(-4),
            CandidateAttributeValue::floating_point_bits(1.5_f64.to_bits()),
            CandidateAttributeValue::string("text".to_owned()),
            CandidateAttributeValue::bytes(vec![1, 2]),
            CandidateAttributeValue::array(vec![CandidateAttributeValue::boolean(false)]),
            CandidateAttributeValue::key_value_list(vec![]),
        ],
    )
    .validate(profile())?;
    let nested = occurrence(
        AttributeNamespace::Record,
        "nested",
        CandidateAttributeValue::key_value_list(vec![
            positron_domain::value::CandidateKeyValue::new(
                "child".to_owned(),
                CandidateAttributeValue::signed_integer(9),
            ),
        ]),
    )?;
    let observation = catalog.observe(&[values, nested])?;

    let cases = [
        SchemaValue::null(),
        SchemaValue::boolean(true),
        SchemaValue::signed_integer(-4),
        SchemaValue::floating_point_bits(1.5_f64.to_bits()),
        SchemaValue::string("text"),
        SchemaValue::bytes(vec![1, 2]),
        SchemaValue::kind(AttributeValueKind::Array),
        SchemaValue::kind(AttributeValueKind::KeyValueList),
    ];
    for value in cases {
        assert!(
            catalog
                .query(
                    &observation,
                    &query(
                        path(AttributeNamespace::Record, "values"),
                        value,
                        OccurrenceSelector::Any,
                    ),
                )
                .is_match()
        );
    }

    let nested_path = path(AttributeNamespace::Record, "nested.child");
    let nested_query = query(
        nested_path.clone(),
        SchemaValue::signed_integer(9),
        OccurrenceSelector::All,
    );
    assert_eq!(nested_query.path(), &nested_path);
    assert_eq!(nested_query.selector(), OccurrenceSelector::All);
    let nested_result = catalog.query(&observation, &nested_query);
    assert!(nested_result.is_match());
    assert!(!nested_result.reduced_pruning());

    assert!(
        !catalog
            .query(
                &observation,
                &query(
                    path(AttributeNamespace::Record, "nested.missing"),
                    SchemaValue::signed_integer(9),
                    OccurrenceSelector::Any,
                ),
            )
            .is_match()
    );
    assert!(
        !catalog
            .query(
                &observation,
                &query(
                    path(AttributeNamespace::Record, "values.child"),
                    SchemaValue::signed_integer(9),
                    OccurrenceSelector::Any,
                ),
            )
            .is_match()
    );
    assert!(
        !catalog
            .query(
                &observation,
                &query(
                    path(AttributeNamespace::Record, "absent"),
                    SchemaValue::null(),
                    OccurrenceSelector::Index(0),
                ),
            )
            .is_match()
    );
    assert!(
        !catalog
            .query(
                &observation,
                &query(
                    path(AttributeNamespace::Record, "values"),
                    SchemaValue::null(),
                    OccurrenceSelector::Index(100),
                ),
            )
            .is_match()
    );
    Ok(())
}
