use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::value::AttributeNamespace;
use positron_domain::value::{AttributeOccurrenceSetCandidate, CandidateAttributeValue};

use super::super::SchemaFailure;
use super::{SchemaBudget, SchemaCatalog, SchemaPath};

const MIB: usize = 1_048_576;

#[test]
fn schema_configuration_rejects_values_above_system_ceilings() {
    let budgets = [
        SchemaBudget::new(4_097, 16 * MIB, MIB, 16 * MIB),
        SchemaBudget::new(4_096, 16 * MIB + 1, MIB, 16 * MIB),
        SchemaBudget::new(4_096, 16 * MIB, MIB + 1, 16 * MIB),
        SchemaBudget::new(4_096, 16 * MIB, MIB, 16 * MIB + 1),
    ];
    assert!(
        budgets
            .into_iter()
            .all(|result| result == Err(SchemaFailure::InvalidBudget))
    );

    let path = std::iter::repeat_n("a", 129).collect::<Vec<_>>().join(".");
    assert_eq!(
        SchemaPath::new(AttributeNamespace::Record, path),
        Err(SchemaFailure::PathTooLong)
    );
}

#[test]
fn schema_configuration_rejects_memory_that_cannot_hold_its_entry_slots() {
    assert_eq!(
        SchemaBudget::new(4_096, 1, 1_048_576, 16_777_216),
        Err(SchemaFailure::InvalidBudget)
    );
}

#[test]
fn catalog_encoding_is_structurally_bound_to_its_tenant() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x31; 16])?;
    let catalog = SchemaCatalog::new(tenant, SchemaBudget::new(8, 8_192, 8_192, 4_096)?)?;

    let encoded = catalog.encode_catalog_object()?;
    let decoded = SchemaCatalog::decode_catalog_object(&encoded)?;

    assert_eq!(decoded.tenant(), tenant);
    assert_eq!(decoded, catalog);
    Ok(())
}

#[test]
fn persistent_accounting_covers_the_whole_object_and_is_enforced_by_the_reader()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x32; 16])?;
    let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::new(8, 8_192, 8_192, 4_096)?)?;
    let attribute = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "persistent".to_owned(),
        vec![CandidateAttributeValue::signed_integer(7)],
    )
    .validate(crate::log_store::LogStore::value_limit_profile())?;
    catalog.observe(&[attribute])?;

    let mut encoded = catalog.encode_catalog_object()?;
    assert_eq!(catalog.persistent_bytes(), encoded.len());
    let too_small = u64::try_from(encoded.len() - 1)?;
    encoded
        .get_mut(42..50)
        .ok_or("persistent budget field missing")?
        .copy_from_slice(&too_small.to_be_bytes());
    assert_eq!(
        SchemaCatalog::decode_catalog_object(&encoded),
        Err(SchemaFailure::MalformedCatalog)
    );
    Ok(())
}
