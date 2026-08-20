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
