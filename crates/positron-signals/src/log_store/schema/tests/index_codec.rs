use std::error::Error;

use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::StoreBlockIdentity;

use super::*;

#[test]
fn checkpoint_preflight_includes_physical_index_and_frontier_memory() -> Result<(), Box<dyn Error>>
{
    let (catalog, bytes) = indexed_checkpoint(true)?;
    let (decoded, frontiers) = SchemaCatalog::decode_checkpoint_object(&bytes)?;
    let frontier_memory = frontiers
        .len()
        .checked_mul(std::mem::size_of::<super::super::SchemaCheckpointFrontier>())
        .ok_or("frontier memory overflow")?;
    let required = decoded
        .memory_bytes()
        .checked_add(frontier_memory)
        .ok_or("checkpoint memory overflow")?;

    assert!(catalog.index_bytes() > 0);
    assert!(SchemaCatalog::catalog_memory_bound(&bytes)? >= required);
    Ok(())
}

#[test]
fn physical_index_must_match_catalog_path_and_complete_kind_set() -> Result<(), Box<dyn Error>> {
    let (_, valid) = indexed_checkpoint(false)?;
    let sidecar = valid
        .windows(8)
        .position(|window| window == b"PINDEX1\0")
        .ok_or("physical index missing")?;
    let path_bytes = sidecar + 72 + 1 + 2 + 8;
    let kind = path_bytes + "indexed".len();

    let mut foreign_path = valid.clone();
    foreign_path[path_bytes..kind].copy_from_slice(b"forged!");
    assert!(SchemaCatalog::decode_catalog_object(&foreign_path).is_err());

    let mut omitted_kind = valid;
    omitted_kind[kind] = 1 << 1;
    assert!(SchemaCatalog::decode_catalog_object(&omitted_kind).is_err());
    Ok(())
}

#[test]
fn physical_index_rejects_duplicate_wire_paths() -> Result<(), Box<dyn Error>> {
    let (_, valid) = indexed_checkpoint(false)?;
    let marker = valid
        .windows(8)
        .position(|window| window == b"PINDEX1\0")
        .ok_or("physical index missing")?;
    let path_count = marker.checked_add(64).ok_or("path count offset overflow")?;
    let path_start = marker.checked_add(73).ok_or("path offset overflow")?;
    let path_end = valid
        .windows(8)
        .position(|window| window == b"PVALUES\0")
        .ok_or("scalar dictionary missing")?
        .checked_sub(1)
        .ok_or("presence offset underflow")?;
    let path = valid
        .get(path_start..path_end)
        .ok_or("path bytes missing")?
        .to_vec();
    let mut duplicate = valid;
    duplicate[path_count..path_count + 8].copy_from_slice(&2_u64.to_be_bytes());
    duplicate.splice(path_end..path_end, path);
    assert!(SchemaCatalog::decode_catalog_object(&duplicate).is_err());
    Ok(())
}

#[test]
fn physical_scalar_dictionary_must_be_canonical_and_unique() -> Result<(), Box<dyn Error>> {
    let (_, valid) = indexed_checkpoint(false)?;
    let marker = valid
        .windows(8)
        .position(|window| window == b"PVALUES\0")
        .ok_or("scalar dictionary missing")?;
    let value_count = marker.checked_add(8).ok_or("count offset overflow")?;
    let value_start = marker.checked_add(16).ok_or("value offset overflow")?;
    let value = valid.get(value_start..).ok_or("scalar value missing")?;
    let mut duplicate = valid.clone();
    duplicate[value_count..value_start].copy_from_slice(&2_u64.to_be_bytes());
    duplicate.extend_from_slice(value);
    assert!(SchemaCatalog::decode_catalog_object(&duplicate).is_err());
    Ok(())
}

#[test]
fn physical_scalar_dictionary_rejects_malformed_native_payloads() -> Result<(), Box<dyn Error>> {
    let (_, valid) = indexed_checkpoint(false)?;
    let marker = valid
        .windows(8)
        .position(|window| window == b"PVALUES\0")
        .ok_or("scalar dictionary missing")?;
    let presence = marker.checked_sub(1).ok_or("presence field missing")?;
    let mut invalid_presence = valid.clone();
    *invalid_presence
        .get_mut(presence)
        .ok_or("presence field missing")? = 2;
    assert!(SchemaCatalog::decode_catalog_object(&invalid_presence).is_err());
    let value_count = marker.checked_add(8).ok_or("count offset overflow")?;
    let value_start = marker.checked_add(16).ok_or("value offset overflow")?;

    let mut invalid_tag = valid.clone();
    *invalid_tag
        .get_mut(value_start)
        .ok_or("value tag missing")? = 9;
    assert!(SchemaCatalog::decode_catalog_object(&invalid_tag).is_err());

    let mut invalid_boolean = valid.clone();
    *invalid_boolean
        .get_mut(value_start)
        .ok_or("value tag missing")? = 1;
    *invalid_boolean
        .get_mut(value_start + 1)
        .ok_or("boolean payload missing")? = 2;
    assert!(SchemaCatalog::decode_catalog_object(&invalid_boolean).is_err());

    let mut invalid_utf8 = valid.clone();
    *invalid_utf8
        .get_mut(value_start + 9)
        .ok_or("string payload missing")? = 0xff;
    assert!(SchemaCatalog::decode_catalog_object(&invalid_utf8).is_err());

    let truncated = valid
        .get(..valid.len().checked_sub(1).ok_or("empty catalog")?)
        .ok_or("truncation boundary missing")?;
    assert!(SchemaCatalog::decode_catalog_object(truncated).is_err());

    let mut too_many_values = valid.clone();
    too_many_values[value_count..value_start].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(SchemaCatalog::decode_catalog_object(&too_many_values).is_err());

    let mut empty_values = valid;
    empty_values[value_count..value_start].copy_from_slice(&0_u64.to_be_bytes());
    assert!(SchemaCatalog::decode_catalog_object(&empty_values).is_err());
    Ok(())
}

#[test]
fn legacy_scalar_dictionary_without_explicit_presence_remains_readable()
-> Result<(), Box<dyn Error>> {
    let (_, valid) = indexed_checkpoint(false)?;
    let mut legacy = valid;
    legacy[8..10].copy_from_slice(&1_u16.to_be_bytes());
    let presence = legacy
        .windows(8)
        .position(|window| window == b"PVALUES\0")
        .and_then(|marker| marker.checked_sub(1))
        .ok_or("presence field missing")?;
    legacy.truncate(presence);
    assert!(SchemaCatalog::decode_catalog_object(&legacy).is_ok());
    Ok(())
}

#[test]
fn legacy_identity_starting_with_scalar_marker_is_not_consumed_as_sidecar()
-> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let budget = SchemaBudget::new(8, 16_384, 16_384, 8_192)?;
    let mut catalog = SchemaCatalog::new(tenant, budget)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    let path = path(AttributeNamespace::Record, "indexed");
    catalog.record_query_use(&path)?;
    let variants = catalog
        .entry(&path)
        .ok_or("indexed entry")?
        .variants()
        .to_vec();
    let first = StoreBlockIdentity::new([0x11; 16])?;
    let mut marker_identity = [0_u8; 16];
    marker_identity[..8].copy_from_slice(super::super::index::SCALAR_VALUES_MAGIC);
    marker_identity[8..].copy_from_slice(&[0x12; 8]);
    let following = StoreBlockIdentity::new(marker_identity)?;
    for (identity, digest) in [(first, [0x63; 32]), (following, [0x64; 32])] {
        let indexed = super::super::index::SchemaIndexPath::from_variants(&path, &variants)?;
        catalog.install_query_index(super::super::index::SchemaBlockIndex::one(
            identity, digest, indexed,
        )?)?;
    }
    let mut legacy = catalog.encode_catalog_object()?;
    legacy[8..10].copy_from_slice(&1_u16.to_be_bytes());
    let first_marker = legacy
        .windows(16)
        .position(|window| window == first.to_bytes())
        .ok_or("first identity")?;
    let first_presence = first_marker
        .checked_add(16 + 32 + 8 + 1 + 2 + 8 + 7 + 1)
        .ok_or("first presence offset")?;
    legacy.remove(first_presence);
    let second_presence = legacy.len().checked_sub(1).ok_or("second presence")?;
    legacy.remove(second_presence);
    let (decoded, _) = SchemaCatalog::decode_checkpoint_object(&legacy)?;
    let reencoded = decoded.encode_catalog_object()?;
    assert!(
        reencoded
            .windows(16)
            .any(|window| window == following.to_bytes())
    );
    Ok(())
}

#[test]
fn checkpoint_round_trips_a_following_identity_starting_with_scalar_marker()
-> Result<(), Box<dyn Error>> {
    let tenant = tenant();
    let budget = SchemaBudget::new(8, 16_384, 16_384, 8_192)?;
    let mut catalog = SchemaCatalog::new(tenant, budget)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    let path = path(AttributeNamespace::Record, "indexed");
    catalog.record_query_use(&path)?;
    let variants = catalog
        .entry(&path)
        .ok_or("indexed entry")?
        .variants()
        .to_vec();
    let first = StoreBlockIdentity::new([0x01; 16])?;
    let mut marker_identity = [0_u8; 16];
    marker_identity[..8].copy_from_slice(super::super::index::SCALAR_VALUES_MAGIC);
    marker_identity[8..].copy_from_slice(&[0x02; 8]);
    let following = StoreBlockIdentity::new(marker_identity)?;
    for (identity, digest) in [(first, [0x61; 32]), (following, [0x62; 32])] {
        let indexed = super::super::index::SchemaIndexPath::from_variants(&path, &variants)?;
        catalog.install_query_index(super::super::index::SchemaBlockIndex::one(
            identity, digest, indexed,
        )?)?;
    }
    let frontier = super::super::SchemaCheckpointFrontier::new(
        VirtualShardId::new(17)?,
        CommitPosition::origin().next()?,
        following,
        [0x62; 32],
    )?;
    let bytes = catalog.encode_checkpoint_object(&[frontier])?;

    let (decoded, frontiers) = SchemaCatalog::decode_checkpoint_object(&bytes)?;

    assert_eq!(decoded, catalog);
    assert_eq!(frontiers, vec![frontier]);
    Ok(())
}

fn indexed_checkpoint(frontier: bool) -> Result<(SchemaCatalog, Vec<u8>), Box<dyn Error>> {
    let tenant = tenant();
    let budget = SchemaBudget::new(8, 8_192, 8_192, 4_096)?;
    let mut catalog = SchemaCatalog::new(tenant, budget)?;
    let attribute = occurrence(
        AttributeNamespace::Record,
        "indexed",
        CandidateAttributeValue::string("value".to_owned()),
    )?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    catalog.record_query_use(&path(AttributeNamespace::Record, "indexed"))?;
    let mut delta = super::super::SchemaDelta::empty(tenant, true);
    catalog.stage_record(
        &[attribute],
        &mut delta,
        &mut super::super::delta::DiscoveryMeter::new(),
    )?;
    let identity = StoreBlockIdentity::new([0x57; 16])?;
    let digest = [0x58; 32];
    let (delta, block_index) = delta.into_block_index(identity, digest);
    catalog.apply_delta(delta, block_index)?;
    let bytes = if frontier {
        catalog.encode_checkpoint_object(&[super::super::SchemaCheckpointFrontier::new(
            VirtualShardId::new(9)?,
            CommitPosition::origin().next()?,
            identity,
            digest,
        )?])?
    } else {
        catalog.encode_catalog_object()?
    };
    Ok((catalog, bytes))
}
