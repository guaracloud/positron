use super::super::SchemaFailure;
use super::*;
use positron_domain::identity::TenantId;
use positron_domain::value::AttributeValueKind;

fn header(tenant: TenantId, budget: SchemaBudget, count: u64) -> Vec<u8> {
    let mut bytes = b"PSCHEMA1".to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&tenant.to_bytes());
    for value in [
        budget.max_entries(),
        budget.max_memory_bytes(),
        budget.max_persistent_bytes(),
        budget.max_index_bytes(),
    ] {
        bytes.extend_from_slice(&(value as u64).to_be_bytes());
    }
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes
}

fn entry(mut bytes: Vec<u8>, variants: &[u8]) -> Vec<u8> {
    bytes.push(4);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&4_u64.to_be_bytes());
    bytes.extend_from_slice(b"name");
    bytes.extend_from_slice(&(variants.len() as u64).to_be_bytes());
    bytes.extend_from_slice(variants);
    bytes.extend_from_slice(&2_u64.to_be_bytes());
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&3_u64.to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&(2_u64 + variants.len() as u64).to_be_bytes());
    bytes
}

#[test]
fn catalog_codec_round_trips_all_entry_metadata() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x52; 16])?;
    let budget = SchemaBudget::new(8, 8_192, 8_192, 4_096)?;
    let bytes = entry(header(tenant, budget, 1), &[4, 2]);
    let catalog = SchemaCatalog::decode_catalog_object(&bytes)?;
    assert_eq!(catalog.tenant(), tenant);
    assert_eq!(catalog.budget(), budget);
    assert_eq!(catalog.entry_count(), 1);
    assert_eq!(catalog.entries().count(), 1);
    assert!(catalog.memory_bytes() > 0);
    assert!(catalog.persistent_bytes() > 0);
    assert_eq!(catalog.index_bytes(), 4);
    assert_eq!(catalog.overflow_record_count(), 0);
    let decoded = catalog
        .entry(&path(AttributeNamespace::Record, "name"))
        .ok_or("decoded entry missing")?;
    assert_eq!(
        decoded.variants(),
        &[
            AttributeValueKind::String,
            AttributeValueKind::SignedInteger
        ]
    );
    assert_eq!(decoded.observations(), 2);
    assert_eq!(decoded.conflicts(), 1);
    assert_eq!(decoded.query_uses(), 3);
    assert!(decoded.promoted());
    assert_eq!(decoded.index_bytes(), 4);
    Ok(())
}

#[test]
fn catalog_decoder_rejects_structural_and_budget_failures() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x53; 16])?;
    let budget = SchemaBudget::new(8, 8_192, 8_192, 4_096)?;
    let valid = entry(header(tenant, budget, 1), &[4]);

    for (index, malformed) in [
        Vec::new(),
        b"PSCHEMA1\0\0".to_vec(),
        {
            let mut bytes = valid.clone();
            bytes[9] = 0;
            bytes
        },
        {
            let mut bytes = valid.clone();
            bytes[0] = b'X';
            bytes
        },
        {
            let mut bytes = valid.clone();
            bytes.truncate(bytes.len() - 1);
            bytes
        },
        {
            let mut bytes = valid.clone();
            bytes.push(0);
            bytes
        },
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            SchemaCatalog::decode_catalog_object(&malformed).is_err(),
            "malformed fixture {index} unexpectedly decoded"
        );
    }

    let mut bad_budget = header(tenant, budget, 1);
    bad_budget[26..34].copy_from_slice(&0_u64.to_be_bytes());
    assert!(SchemaCatalog::decode_catalog_object(&bad_budget).is_err());

    let mut bad_namespace = valid.clone();
    bad_namespace[82] = 99;
    assert!(SchemaCatalog::decode_catalog_object(&bad_namespace).is_err());

    let mut bad_segment_count = valid.clone();
    bad_segment_count[83..85].copy_from_slice(&0_u16.to_be_bytes());
    assert!(SchemaCatalog::decode_catalog_object(&bad_segment_count).is_err());

    let mut bad_utf8 = valid.clone();
    bad_utf8[93] = 0xff;
    assert!(SchemaCatalog::decode_catalog_object(&bad_utf8).is_err());

    let duplicate_variants = entry(header(tenant, budget, 1), &[4, 4]);
    assert!(SchemaCatalog::decode_catalog_object(&duplicate_variants).is_err());

    let mut bad_promoted = entry(header(tenant, budget, 1), &[4]);
    bad_promoted[130] = 2;
    assert!(SchemaCatalog::decode_catalog_object(&bad_promoted).is_err());

    Ok(())
}

#[test]
fn catalog_object_honors_persistent_budget_and_paths_reject_ambiguous_shapes()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        SchemaBudget::new(1, 512, 81, 64),
        Err(SchemaFailure::InvalidBudget)
    );
    assert!(SchemaBudget::new(0, 1, 1, 1).is_err());
    assert!(SchemaPath::new(AttributeNamespace::Record, String::new()).is_err());
    assert!(SchemaPath::new(AttributeNamespace::Record, "a..b".to_owned()).is_err());
    assert!(SchemaPath::new(AttributeNamespace::Record, "a.".to_owned()).is_err());
    assert!(SchemaPath::root(AttributeNamespace::Record, String::new()).is_err());
    let dotted = SchemaPath::root(AttributeNamespace::Record, "producer.key".to_owned())?;
    assert_eq!(dotted.as_string()?, "producer.key");
    assert!(dotted.segments().len() == 1);
    assert_eq!(
        SchemaPath::new(AttributeNamespace::Record, "parent.child".to_owned())?.as_string()?,
        "parent.child"
    );
    Ok(())
}

#[test]
fn schema_failures_have_stable_bounded_messages() {
    let failures = [
        (SchemaFailure::InvalidBudget, "invalid schema budget"),
        (SchemaFailure::InvalidPath, "invalid schema path"),
        (SchemaFailure::PathTooLong, "schema path too long"),
        (SchemaFailure::InvalidValue, "invalid schema value"),
        (SchemaFailure::LimitExceeded, "schema limit exceeded"),
        (
            SchemaFailure::AllocationUnavailable,
            "schema allocation unavailable",
        ),
        (SchemaFailure::MalformedCatalog, "malformed schema catalog"),
    ];
    for (failure, expected) in failures {
        assert_eq!(failure.to_string(), expected);
    }
}

#[test]
fn catalog_codec_round_trips_every_namespace_and_native_value_kind() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x54; 16])?;
    let budget = SchemaBudget::new(8, 8_192, 8_192, 4_096)?;
    let all_kinds = [0, 1, 2, 3, 4, 5, 6, 7];

    for namespace in 1..=4 {
        let mut bytes = entry(header(tenant, budget, 1), &all_kinds);
        bytes[82] = namespace;
        let decoded = SchemaCatalog::decode_catalog_object(&bytes)?;
        assert_eq!(decoded.entries().next().ok_or("entry")?.variants().len(), 8);
        assert_eq!(
            SchemaCatalog::decode_catalog_object(&decoded.encode_catalog_object()?)?,
            decoded
        );
    }
    Ok(())
}

#[test]
fn catalog_decoder_rejects_invalid_variant_and_index_contracts() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x55; 16])?;
    let budget = SchemaBudget::new(8, 8_192, 8_192, 4_096)?;

    let mut unknown_kind = entry(header(tenant, budget, 1), &[4]);
    unknown_kind[105] = 8;
    assert!(SchemaCatalog::decode_catalog_object(&unknown_kind).is_err());

    let mut zero_variants = entry(header(tenant, budget, 1), &[4]);
    zero_variants[97..105].copy_from_slice(&0_u64.to_be_bytes());
    assert!(SchemaCatalog::decode_catalog_object(&zero_variants).is_err());

    let mut wrong_index = entry(header(tenant, budget, 1), &[4]);
    let index_offset = wrong_index.len() - 8;
    wrong_index[index_offset..].copy_from_slice(&4_u64.to_be_bytes());
    assert!(SchemaCatalog::decode_catalog_object(&wrong_index).is_err());

    let one = entry(header(tenant, budget, 1), &[4]);
    let mut duplicate_path = header(tenant, budget, 2);
    duplicate_path.extend_from_slice(&one[82..]);
    duplicate_path.extend_from_slice(&one[82..]);
    assert!(SchemaCatalog::decode_catalog_object(&duplicate_path).is_err());

    let small = SchemaBudget::new(1, 512, 8_192, 64)?;
    assert!(SchemaCatalog::decode_catalog_object(&header(tenant, small, 2)).is_err());

    let mut container_only = entry(header(tenant, budget, 1), &[6]);
    let promoted = container_only.len() - 9;
    container_only[promoted] = 0;
    let index = container_only.len() - 8;
    container_only[index..].copy_from_slice(&0_u64.to_be_bytes());
    assert!(SchemaCatalog::decode_catalog_object(&container_only).is_ok());
    Ok(())
}
