use std::error::Error;

use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::{
    MountQualification, PrimaryDataVolume, ResourceAmounts, ResourceDimension, StoreBlockIdentity,
    WorkClaim, WorkKind,
};

use crate::log_store::SchemaFailure;
use crate::log_store::schema::SchemaSessionStore;
use crate::log_store::tests::support::{TemporaryRoot, establish_kernel_authority};

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
fn scalar_sidecar_string_and_bytes_payloads_obey_the_value_limit() -> Result<(), Box<dyn Error>> {
    let maximum = super::super::model::MAX_SCALAR_VALUE_BYTES;
    for (is_string, value, candidate) in [
        (
            true,
            SchemaValue::string("a".repeat(maximum)),
            CandidateAttributeValue::string("a".repeat(maximum)),
        ),
        (
            false,
            SchemaValue::bytes(vec![0; maximum]),
            CandidateAttributeValue::bytes(vec![0; maximum]),
        ),
    ] {
        let valid = scalar_payload_checkpoint(value, candidate)?;
        let decoded = SchemaCatalog::decode_catalog_object(&valid)?;
        assert_eq!(decoded.encode_catalog_object()?, valid);
        let marker = valid
            .windows(8)
            .position(|window| window == b"PVALUES\0")
            .ok_or("scalar dictionary")?;
        let value_start = marker.checked_add(16).ok_or("value start")?;
        let length_start = value_start.checked_add(1).ok_or("length start")?;

        let mut oversized = valid.clone();
        oversized[length_start..length_start + 8]
            .copy_from_slice(&u64::try_from(maximum + 1)?.to_be_bytes());
        oversized.push(if is_string { b'a' } else { 0 });
        assert!(SchemaCatalog::decode_catalog_object(&oversized).is_err());

        let truncated = valid
            .get(..valid.len().checked_sub(1).ok_or("truncation")?)
            .ok_or("truncation")?;
        assert!(SchemaCatalog::decode_catalog_object(truncated).is_err());

        let mut overflowing = valid;
        overflowing[length_start..length_start + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(SchemaCatalog::decode_catalog_object(&overflowing).is_err());

        let oversized_candidate = if is_string {
            CandidateAttributeValue::string("seed".to_owned())
        } else {
            CandidateAttributeValue::bytes(vec![0])
        };
        let oversized = scalar_payload_catalog(
            if is_string {
                SchemaValue::string("a".repeat(maximum + 1))
            } else {
                SchemaValue::bytes(vec![0; maximum + 1])
            },
            oversized_candidate,
        )?;
        assert_eq!(
            oversized.encode_catalog_object(),
            Err(SchemaFailure::LimitExceeded)
        );
    }
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
fn legacy_single_block_at_exact_v1_budgets_reopens_without_synthetic_framing()
-> Result<(), Box<dyn Error>> {
    let (legacy, index_bytes) = exact_legacy_budget_checkpoint(1)?;
    let (decoded, _) = SchemaCatalog::decode_checkpoint_object(&legacy)?;
    assert_eq!(decoded.persistent_bytes(), legacy.len());
    assert_eq!(decoded.index_bytes(), index_bytes);

    // The exact v1 budget deliberately excludes v2 presence framing; an
    // explicit v2 write must therefore fail closed rather than mutating the
    // accepted v1 accounting during decode.
    assert_eq!(
        decoded.encode_catalog_object(),
        Err(SchemaFailure::LimitExceeded)
    );
    Ok(())
}

#[test]
fn legacy_multiple_blocks_at_exact_v1_budgets_reopen_without_sidecars() -> Result<(), Box<dyn Error>>
{
    let (legacy, index_bytes) = exact_legacy_budget_checkpoint(2)?;
    let (decoded, _) = SchemaCatalog::decode_checkpoint_object(&legacy)?;
    assert_eq!(decoded.persistent_bytes(), legacy.len());
    assert_eq!(decoded.index_bytes(), index_bytes);
    assert_eq!(decoded.entry_count(), 1);
    Ok(())
}

#[test]
fn legacy_mutation_upgrades_to_v2_framing_before_accounting_publication()
-> Result<(), Box<dyn Error>> {
    let (legacy, index_bytes) = exact_legacy_budget_checkpoint(1)?;
    let legacy_len = legacy.len();
    let added_wire = 29_u64;
    let mut with_headroom = legacy.clone();
    with_headroom[42..50].copy_from_slice(
        &u64::try_from(legacy_len)?
            .checked_add(added_wire)
            .ok_or("persistent budget")?
            .to_be_bytes(),
    );
    with_headroom[50..58].copy_from_slice(
        &u64::try_from(index_bytes)?
            .checked_add(added_wire)
            .ok_or("index budget")?
            .to_be_bytes(),
    );
    let (mut decoded, _) = SchemaCatalog::decode_checkpoint_object(&with_headroom)?;
    let path = path(AttributeNamespace::Record, "indexed");
    let incoming = super::super::index::SchemaIndexPath::from_variants_and_values(
        &path,
        &[positron_domain::value::AttributeValueKind::String],
        &[SchemaValue::string("new")],
    )?;
    decoded.install_query_index(super::super::index::SchemaBlockIndex::one(
        StoreBlockIdentity::new([0x11; 16])?,
        [0x51; 32],
        incoming,
    )?)?;
    let encoded = decoded.encode_catalog_object()?;
    assert_eq!(decoded.persistent_bytes(), encoded.len());
    assert_eq!(
        decoded.persistent_bytes(),
        legacy_len + usize::try_from(added_wire)?
    );
    let reopened = SchemaCatalog::decode_catalog_object(&encoded)?;
    assert_eq!(reopened.persistent_bytes(), encoded.len());

    let mut without_headroom = legacy;
    without_headroom[42..50].copy_from_slice(
        &u64::try_from(legacy_len)?
            .checked_add(added_wire - 1)
            .ok_or("persistent budget")?
            .to_be_bytes(),
    );
    without_headroom[50..58].copy_from_slice(
        &u64::try_from(index_bytes)?
            .checked_add(added_wire - 1)
            .ok_or("index budget")?
            .to_be_bytes(),
    );
    let (mut tight, _) = SchemaCatalog::decode_checkpoint_object(&without_headroom)?;
    let incoming = super::super::index::SchemaIndexPath::from_variants_and_values(
        &path,
        &[positron_domain::value::AttributeValueKind::String],
        &[SchemaValue::string("new")],
    )?;
    assert_eq!(
        tight.install_query_index(super::super::index::SchemaBlockIndex::one(
            StoreBlockIdentity::new([0x11; 16])?,
            [0x51; 32],
            incoming,
        )?),
        Err(SchemaFailure::LimitExceeded)
    );
    Ok(())
}

#[test]
fn legacy_survivor_upgrade_and_new_index_budget_refusal_are_atomic() -> Result<(), Box<dyn Error>> {
    let (legacy, index_bytes) = exact_legacy_budget_checkpoint(2)?;
    let legacy_len = legacy.len();
    let mut bounded = legacy.clone();
    bounded[42..50].copy_from_slice(&u64::try_from(legacy_len + 1)?.to_be_bytes());
    bounded[50..58].copy_from_slice(&u64::try_from(index_bytes + 1)?.to_be_bytes());
    let (mut decoded, _) = SchemaCatalog::decode_checkpoint_object(&bounded)?;
    let path = path(AttributeNamespace::Record, "indexed");
    let incoming = super::super::index::SchemaIndexPath::from_variants_and_values(
        &path,
        &[positron_domain::value::AttributeValueKind::String],
        &[SchemaValue::string("new")],
    )?;
    assert_eq!(
        decoded.install_query_index(super::super::index::SchemaBlockIndex::one(
            StoreBlockIdentity::new([0x11; 16])?,
            [0x51; 32],
            incoming,
        )?),
        Err(SchemaFailure::LimitExceeded)
    );
    assert_eq!(decoded.persistent_bytes(), legacy_len);
    assert_eq!(decoded.index_bytes(), index_bytes);
    assert_eq!(
        decoded.encode_catalog_object(),
        Err(SchemaFailure::LimitExceeded)
    );
    Ok(())
}

#[test]
fn governed_v1_exact_budget_demotion_releases_legacy_block_bytes() -> Result<(), Box<dyn Error>> {
    let (legacy, _) = exact_legacy_budget_checkpoint(1)?;
    with_governed_legacy_session(&legacy, |session| {
        let mut update = session.stage_query_update()?;
        update.remove_query_evidence(&path(AttributeNamespace::Record, "indexed"))?;
        session.commit_query_update(update)?;
        let encoded = session.catalog().encode_catalog_object()?;
        assert_eq!(session.catalog().persistent_bytes(), encoded.len());
        let reopened = SchemaCatalog::decode_catalog_object(&encoded)?;
        assert_eq!(reopened.persistent_bytes(), encoded.len());
        assert_eq!(reopened.index_bytes(), 0);
        Ok(())
    })
}

#[test]
fn governed_v1_exact_budget_reachability_removal_reopens_remaining_block()
-> Result<(), Box<dyn Error>> {
    let (legacy, _) = exact_legacy_budget_checkpoint(2)?;
    with_governed_legacy_session(&legacy, |session| {
        session.retain_reachable_indexes(&[(StoreBlockIdentity::new([0x11; 16])?, [0x51; 32])])?;
        let encoded = session.catalog().encode_catalog_object()?;
        assert_eq!(session.catalog().persistent_bytes(), encoded.len());
        let reopened = SchemaCatalog::decode_catalog_object(&encoded)?;
        assert_eq!(session.catalog().index_bytes(), reopened.index_bytes());
        assert_eq!(reopened.persistent_bytes(), encoded.len());
        assert_eq!(reopened.entry_count(), 1);
        Ok(())
    })
}

#[test]
fn governed_v1_exact_budget_reconciliation_removes_stale_block() -> Result<(), Box<dyn Error>> {
    let (legacy, _) = exact_legacy_budget_checkpoint(2)?;
    with_governed_legacy_session(&legacy, |session| {
        session.reconcile_block_identity(StoreBlockIdentity::new([0x12; 16])?, [0x61; 32])?;
        let encoded = session.catalog().encode_catalog_object()?;
        assert_eq!(session.catalog().persistent_bytes(), encoded.len());
        let reopened = SchemaCatalog::decode_catalog_object(&encoded)?;
        assert_eq!(session.catalog().index_bytes(), reopened.index_bytes());
        assert_eq!(reopened.persistent_bytes(), encoded.len());
        assert_eq!(reopened.entry_count(), 1);
        Ok(())
    })
}

#[test]
fn legacy_identity_starting_with_scalar_marker_is_not_consumed_as_sidecar()
-> Result<(), Box<dyn Error>> {
    let tenant = positron_domain::identity::TenantId::from_bytes([0x41; 16])?;
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
    assert_eq!(decoded.entry_count(), catalog.entry_count());
    assert_eq!(
        decoded.encode_catalog_object(),
        Err(SchemaFailure::InvalidValue)
    );
    Ok(())
}

#[test]
fn checkpoint_round_trips_a_following_identity_starting_with_scalar_marker()
-> Result<(), Box<dyn Error>> {
    let tenant = positron_domain::identity::TenantId::from_bytes([0x41; 16])?;
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

fn scalar_payload_checkpoint(
    value: SchemaValue,
    candidate: CandidateAttributeValue,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(scalar_payload_catalog(value, candidate)?.encode_catalog_object()?)
}

fn scalar_payload_catalog(
    value: SchemaValue,
    candidate: CandidateAttributeValue,
) -> Result<SchemaCatalog, Box<dyn Error>> {
    let tenant = tenant();
    let budget = SchemaBudget::new(8, 16_000_000, 1_048_576, 16_000_000)?;
    let mut catalog = SchemaCatalog::new(tenant, budget)?;
    let attribute = occurrence(AttributeNamespace::Record, "indexed", candidate)?;
    catalog.observe(std::slice::from_ref(&attribute))?;
    let path = path(AttributeNamespace::Record, "indexed");
    catalog.record_query_use(&path)?;
    let kind = value.kind_value().ok_or("scalar value kind")?;
    let indexed =
        super::super::index::SchemaIndexPath::from_variants_and_values(&path, &[kind], &[value])?;
    catalog.install_query_index(super::super::index::SchemaBlockIndex::one(
        StoreBlockIdentity::new([0x59; 16])?,
        [0x5a; 32],
        indexed,
    )?)?;
    Ok(catalog)
}

fn exact_legacy_budget_checkpoint(blocks: usize) -> Result<(Vec<u8>, usize), Box<dyn Error>> {
    let tenant = positron_domain::identity::TenantId::from_bytes([0x41; 16])?;
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
    for offset in 0..blocks {
        let marker = u8::try_from(0x11_usize.checked_add(offset).ok_or("identity overflow")?)?;
        let identity = StoreBlockIdentity::new([marker; 16])?;
        let indexed = super::super::index::SchemaIndexPath::from_variants(&path, &variants)?;
        catalog.install_query_index(super::super::index::SchemaBlockIndex::one(
            identity,
            [marker.wrapping_add(0x40); 32],
            indexed,
        )?)?;
    }
    let mut legacy = catalog.encode_catalog_object()?;
    legacy[8..10].copy_from_slice(&1_u16.to_be_bytes());
    let mut presence_offsets = Vec::new();
    for offset in 0..blocks {
        let marker_byte = u8::try_from(0x11_usize.checked_add(offset).ok_or("identity overflow")?)?;
        let identity = [marker_byte; 16];
        let identity_offset = legacy
            .windows(identity.len())
            .position(|window| window == identity)
            .ok_or("block identity")?;
        let presence = identity_offset
            .checked_add(16 + 32 + 8 + 1 + 2 + 8 + 7 + 1)
            .ok_or("presence offset")?;
        presence_offsets.push(presence);
    }
    presence_offsets.sort_unstable_by(|left, right| right.cmp(left));
    for presence in presence_offsets {
        legacy.remove(presence);
    }
    let index_bytes = catalog
        .index_bytes()
        .checked_sub(blocks)
        .ok_or("v1 index accounting underflow")?;
    let persistent_bytes = u64::try_from(legacy.len())?;
    let index_bytes = u64::try_from(index_bytes)?;
    legacy[42..50].copy_from_slice(&persistent_bytes.to_be_bytes());
    legacy[50..58].copy_from_slice(&index_bytes.to_be_bytes());
    Ok((legacy, usize::try_from(index_bytes)?))
}

fn with_governed_legacy_session(
    checkpoint: &[u8],
    operation: impl FnOnce(&mut SchemaSessionStore) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let tenant = positron_domain::identity::TenantId::from_bytes([0x41; 16])?;
    let reservation = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 200_000)?,
    )?)?;
    let Some((mut session, _)) =
        SchemaSessionStore::from_checkpoint(reservation, tenant, checkpoint)?
    else {
        return Err("legacy checkpoint tenant".into());
    };
    operation(&mut session)
}
