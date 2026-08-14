use super::*;

#[test]
fn discovery_keeps_namespaces_and_counts_typed_conflicts() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 8_192, 8_192, 4_096)?)?;
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
fn tenant_state_is_the_single_bound_observation_authority() -> Result<(), Box<dyn Error>> {
    let catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 8_192, 8_192, 4_096)?)?;
    let mut state = super::super::TenantSchemaState::from_catalog(catalog);
    assert_eq!(state.tenant(), tenant());
    assert_eq!(state.catalog().entry_count(), 0);

    let observed = state.observe(&[occurrence(
        AttributeNamespace::Record,
        "governed",
        CandidateAttributeValue::boolean(true),
    )?])?;

    assert_eq!(observed.overflow_records(), 0);
    assert_eq!(state.catalog().entry_count(), 1);
    assert!(
        state
            .catalog()
            .entry(&path(AttributeNamespace::Record, "governed"))
            .is_some()
    );
    Ok(())
}

#[test]
fn discovery_preserves_nested_key_paths_without_enumerating_array_indexes()
-> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(16, 8_192, 8_192, 4_096)?)?;
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

#[test]
fn discovery_overflows_a_whole_root_when_only_its_prefix_fits() -> Result<(), Box<dyn Error>> {
    let mut catalog = catalog_with_small_budget();
    let nested = CandidateAttributeValue::key_value_list(vec![
        positron_domain::value::CandidateKeyValue::new(
            "child".to_owned(),
            CandidateAttributeValue::signed_integer(7),
        ),
    ]);

    let observation =
        catalog.observe(&[occurrence(AttributeNamespace::Record, "root", nested)?])?;

    assert_eq!(observation.overflow_records(), 1);
    assert_eq!(catalog.entry_count(), 0);
    assert_eq!(catalog.overflow_record_count(), 1);
    Ok(())
}

#[test]
fn discovery_snapshot_reports_bounded_sorted_paths_and_pressure() -> Result<(), Box<dyn Error>> {
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 8_192, 8_192, 8)?)?;
    let frequent = occurrence(
        AttributeNamespace::Record,
        "frequent",
        CandidateAttributeValue::signed_integer(7),
    )?;
    let other = occurrence(
        AttributeNamespace::Record,
        "other",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&frequent))?;
    catalog.observe(std::slice::from_ref(&frequent))?;
    catalog.observe(std::slice::from_ref(&other))?;

    let request = super::super::SchemaDiscoveryRequest::new(1, 1)?;
    let snapshot = catalog.discover(request)?;
    assert_eq!(snapshot.tenant(), tenant());
    assert_eq!(snapshot.top_paths().len(), 1);
    let top = snapshot.top_paths().first().ok_or("top path missing")?;
    assert_eq!(top.path().as_string()?, "frequent");
    assert_eq!(
        top.variants(),
        &[positron_domain::value::AttributeValueKind::SignedInteger]
    );
    assert_eq!(top.observations(), 2);
    assert_eq!(top.conflicts(), 0);
    assert!(matches!(
        top.promotion(),
        super::super::SchemaPromotionDecision::Promoted { .. }
    ));
    assert_eq!(snapshot.sampled_path_digests().len(), 1);
    assert_eq!(snapshot.catalog_memory().used(), catalog.memory_bytes());
    assert_eq!(
        snapshot.catalog_memory().limit(),
        catalog.budget().max_memory_bytes()
    );
    assert_eq!(snapshot.index().used(), catalog.index_bytes());
    assert_eq!(snapshot.index().limit(), catalog.budget().max_index_bytes());
    assert_eq!(snapshot.overflow_records(), 0);
    assert_eq!(snapshot.overflow_bytes(), catalog.overflow_byte_count());

    let second = catalog.discover(request)?;
    assert_eq!(snapshot, second);
    Ok(())
}

#[test]
fn discovery_snapshot_reports_container_decisions_and_digest_samples() -> Result<(), Box<dyn Error>>
{
    let mut catalog = SchemaCatalog::new(tenant(), SchemaBudget::new(8, 8_192, 8_192, 64)?)?;
    let container = occurrence(
        AttributeNamespace::Record,
        "container",
        CandidateAttributeValue::array(vec![CandidateAttributeValue::boolean(true)]),
    )?;
    let same_key_other_namespace = occurrence(
        AttributeNamespace::Resource,
        "container",
        CandidateAttributeValue::array(vec![CandidateAttributeValue::boolean(true)]),
    )?;
    catalog.observe(&[container, same_key_other_namespace])?;

    let request = super::super::SchemaDiscoveryRequest::new(2, 2)?;
    assert_eq!(request.top_paths(), 2);
    assert_eq!(request.sampled_paths(), 2);
    let snapshot = catalog.discover(request)?;
    let summary = snapshot.top_paths().first().ok_or("summary missing")?;
    assert_eq!(summary.query_uses(), 0);
    assert_eq!(summary.index_bytes(), 0);
    assert!(matches!(
        summary.promotion(),
        super::super::SchemaPromotionDecision::NotPromoted {
            reason: super::super::SchemaPromotionReason::NoScalarVariant
        }
    ));
    assert_eq!(snapshot.sampled_path_digests().len(), 2);
    let first_digest = snapshot
        .sampled_path_digests()
        .first()
        .ok_or("first digest missing")?;
    let second_digest = snapshot
        .sampled_path_digests()
        .get(1)
        .ok_or("second digest missing")?;
    assert_ne!(first_digest.as_bytes(), second_digest.as_bytes());
    assert!(!snapshot.catalog_memory().exhausted());
    assert!(!snapshot.catalog_persistent().exhausted());
    assert!(!snapshot.index().exhausted());
    assert!(
        super::super::SchemaDiscoveryRequest::new(
            super::super::SchemaBudget::system_max_discovery_nodes() + 1,
            0
        )
        .is_err()
    );
    Ok(())
}
