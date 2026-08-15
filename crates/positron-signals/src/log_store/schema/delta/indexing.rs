use super::SchemaDelta;
use crate::log_store::schema::catalog::SchemaCatalog;
use crate::log_store::schema::failure::SchemaFailure;
use crate::log_store::schema::index::{
    BLOCK_INDEX_HEADER_BYTES, INDEX_HEADER_BYTES, SchemaBlockIndex, SchemaIndexPath,
};
use crate::log_store::schema::model::SchemaEntry;

pub(crate) fn additional_physical_cost(
    catalog: &SchemaCatalog,
    delta: &SchemaDelta,
    root: &[SchemaEntry],
) -> Result<(usize, usize), SchemaFailure> {
    if !delta.build_physical_index {
        return Ok((0, 0));
    }
    let mut wire = 0_usize;
    let mut memory = 0_usize;
    let mut added = false;
    for entry in root {
        if entry.query_uses == 0 || !entry.promoted || delta.path_is_unverified(&entry.path) {
            continue;
        }
        if delta
            .index_paths
            .binary_search_by(|known| known.wire_cmp_path(&entry.path))
            .is_ok()
        {
            continue;
        }
        added = true;
        let indexed = SchemaIndexPath::from_variants(&entry.path, &entry.variants)?;
        wire = wire
            .checked_add(indexed.encoded_bytes()?)
            .ok_or(SchemaFailure::LimitExceeded)?;
        memory = memory
            .checked_add(indexed.memory_bytes()?)
            .ok_or(SchemaFailure::LimitExceeded)?;
    }
    if added && delta.index_paths.is_empty() {
        wire = wire
            .checked_add(BLOCK_INDEX_HEADER_BYTES)
            .and_then(|bytes| {
                bytes.checked_add(if catalog.block_indexes.is_empty() {
                    INDEX_HEADER_BYTES
                } else {
                    0
                })
            })
            .ok_or(SchemaFailure::LimitExceeded)?;
        memory = memory
            .checked_add(std::mem::size_of::<SchemaBlockIndex>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<SchemaIndexPath>>()))
            .ok_or(SchemaFailure::LimitExceeded)?;
    }
    Ok((memory, wire))
}

pub(super) fn stage_index_root(
    catalog: &SchemaCatalog,
    delta: &mut SchemaDelta,
    root: &[SchemaEntry],
) -> Result<(), SchemaFailure> {
    if !delta.build_physical_index {
        return Ok(());
    }
    let was_empty = delta.index_paths.is_empty();
    for entry in root {
        if entry.query_uses == 0 || !entry.promoted || delta.path_is_unverified(&entry.path) {
            continue;
        }
        match delta
            .index_paths
            .binary_search_by(|known| known.wire_cmp_path(&entry.path))
        {
            Err(position) => insert_path(delta, position, entry)?,
            Ok(position) => merge_kinds(delta, position, entry)?,
        }
    }
    if was_empty && !delta.index_paths.is_empty() {
        delta.physical_index_bytes = delta
            .physical_index_bytes
            .checked_add(BLOCK_INDEX_HEADER_BYTES)
            .and_then(|bytes| {
                bytes.checked_add(if catalog.block_indexes.is_empty() {
                    INDEX_HEADER_BYTES
                } else {
                    0
                })
            })
            .ok_or(SchemaFailure::LimitExceeded)?;
        delta.physical_memory_bytes = delta
            .physical_memory_bytes
            .checked_add(std::mem::size_of::<SchemaBlockIndex>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<SchemaIndexPath>>()))
            .ok_or(SchemaFailure::LimitExceeded)?;
    }
    Ok(())
}

fn insert_path(
    delta: &mut SchemaDelta,
    position: usize,
    entry: &SchemaEntry,
) -> Result<(), SchemaFailure> {
    let indexed = SchemaIndexPath::from_variants(&entry.path, &entry.variants)?;
    let wire = indexed.encoded_bytes()?;
    let memory = indexed.memory_bytes()?;
    delta
        .index_paths
        .try_reserve_exact(1)
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    delta.index_paths.insert(position, indexed);
    delta.physical_index_bytes = delta
        .physical_index_bytes
        .checked_add(wire)
        .ok_or(SchemaFailure::LimitExceeded)?;
    delta.physical_memory_bytes = delta
        .physical_memory_bytes
        .checked_add(memory)
        .ok_or(SchemaFailure::LimitExceeded)?;
    Ok(())
}

fn merge_kinds(
    delta: &mut SchemaDelta,
    position: usize,
    entry: &SchemaEntry,
) -> Result<(), SchemaFailure> {
    let known = delta
        .index_paths
        .get_mut(position)
        .ok_or(SchemaFailure::InvalidValue)?;
    known.kind_mask |= crate::log_store::schema::index::scalar_kind_mask(&entry.variants);
    Ok(())
}
