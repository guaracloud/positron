use positron_domain::value::AttributeOccurrenceSet;

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
    attributes: &[AttributeOccurrenceSet],
) -> Result<(usize, usize), SchemaFailure> {
    if !delta.build_physical_index {
        return Ok((0, 0));
    }
    let include_values =
        delta.scalar_values && scalar_values_fit(catalog, delta, root, attributes)?;
    let (memory, wire) = projected_physical_cost(catalog, delta, root, attributes, include_values)?;
    let added_memory = memory
        .checked_sub(delta.physical_memory_bytes())
        .map_or(0, |value| value);
    let added_wire = wire
        .checked_sub(delta.physical_index_bytes())
        .map_or(0, |value| value);
    Ok((added_memory, added_wire))
}

fn scalar_values_fit(
    catalog: &SchemaCatalog,
    delta: &SchemaDelta,
    root: &[SchemaEntry],
    attributes: &[AttributeOccurrenceSet],
) -> Result<bool, SchemaFailure> {
    let (memory, wire) = projected_physical_cost(catalog, delta, root, attributes, true)?;
    Ok(catalog
        .memory_bytes
        .checked_add(memory)
        .is_some_and(|used| used <= catalog.budget.max_memory_bytes())
        && catalog
            .persistent_bytes
            .checked_add(wire)
            .is_some_and(|used| used <= catalog.budget.max_persistent_bytes())
        && catalog
            .index_bytes
            .checked_add(wire)
            .is_some_and(|used| used <= catalog.budget.max_index_bytes()))
}

fn projected_physical_cost(
    catalog: &SchemaCatalog,
    delta: &SchemaDelta,
    root: &[SchemaEntry],
    attributes: &[AttributeOccurrenceSet],
    include_values: bool,
) -> Result<(usize, usize), SchemaFailure> {
    let paths = projected_paths(delta, root, attributes, include_values)?;
    if paths.is_empty() {
        return Ok((0, 0));
    }
    let mut memory = 0_usize;
    let wire = SchemaBlockIndex::paths_encoded_bytes(&paths)?
        .checked_add(BLOCK_INDEX_HEADER_BYTES)
        .and_then(|bytes| {
            bytes.checked_add(if catalog.block_indexes.is_empty() {
                INDEX_HEADER_BYTES
            } else {
                0
            })
        })
        .ok_or(SchemaFailure::LimitExceeded)?;
    for path in &paths {
        memory = memory
            .checked_add(path.memory_bytes()?)
            .ok_or(SchemaFailure::LimitExceeded)?;
    }
    memory = memory
        .checked_add(std::mem::size_of::<SchemaBlockIndex>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<SchemaIndexPath>>()))
        .ok_or(SchemaFailure::LimitExceeded)?;
    Ok((memory, wire))
}

fn projected_paths(
    delta: &SchemaDelta,
    root: &[SchemaEntry],
    attributes: &[AttributeOccurrenceSet],
    include_values: bool,
) -> Result<Vec<SchemaIndexPath>, SchemaFailure> {
    let mut paths = Vec::new();
    paths
        .try_reserve_exact(delta.index_paths.len().saturating_add(root.len()))
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    for known in &delta.index_paths {
        paths.push(known.try_clone()?);
    }
    for entry in root {
        if entry.query_uses == 0 || !entry.promoted || delta.path_is_unverified(&entry.path) {
            continue;
        }
        let incoming = if include_values {
            SchemaIndexPath::from_variants_and_attributes(&entry.path, &entry.variants, attributes)?
        } else {
            SchemaIndexPath::from_variants(&entry.path, &entry.variants)?
        };
        match paths.binary_search_by(|known| known.wire_cmp_path(&entry.path)) {
            Ok(position) => merge_paths(
                paths.get_mut(position).ok_or(SchemaFailure::InvalidValue)?,
                incoming,
                include_values,
            )?,
            Err(position) => paths.insert(position, incoming),
        }
    }
    Ok(paths)
}

fn merge_paths(
    known: &mut SchemaIndexPath,
    incoming: SchemaIndexPath,
    include_values: bool,
) -> Result<(), SchemaFailure> {
    known.kind_mask |= incoming.kind_mask;
    if !include_values {
        return Ok(());
    }
    for value in incoming.values {
        if known.values.contains(&value) {
            continue;
        }
        known
            .values
            .try_reserve_exact(1)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        known.values.push(value);
    }
    known.values.sort_unstable();
    Ok(())
}

pub(super) fn stage_index_root(
    catalog: &SchemaCatalog,
    delta: &mut SchemaDelta,
    root: &[SchemaEntry],
    attributes: &[AttributeOccurrenceSet],
) -> Result<(), SchemaFailure> {
    if !delta.build_physical_index {
        return Ok(());
    }
    let include_values =
        delta.scalar_values && scalar_values_fit(catalog, delta, root, attributes)?;
    delta.index_paths = projected_paths(delta, root, attributes, include_values)?;
    let (memory, wire) = projected_physical_cost(catalog, delta, &[], &[], include_values)?;
    delta.physical_memory_bytes = memory;
    delta.physical_index_bytes = wire;
    Ok(())
}
