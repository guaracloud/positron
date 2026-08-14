use positron_domain::value::AttributeOccurrenceSet;

use super::SchemaDelta;
use crate::log_store::schema::catalog::SchemaCatalog;
use crate::log_store::schema::failure::SchemaFailure;
use crate::log_store::schema::model::{
    CATALOG_HEADER_BYTES, MAX_VARIANTS, SchemaEntry, entry_memory_bytes, entry_persistent_bytes,
};

pub(super) fn root_fits(
    catalog: &SchemaCatalog,
    delta: &SchemaDelta,
    root: &[SchemaEntry],
) -> Result<bool, SchemaFailure> {
    let (memory, persistent, index, new_entries) = projected_cost(catalog, delta, Some(root))?;
    let entries = catalog
        .entries
        .len()
        .checked_add(new_entries)
        .ok_or(SchemaFailure::LimitExceeded)?;
    Ok(entries <= catalog.budget.max_entries()
        && catalog
            .memory_bytes
            .checked_add(memory)
            .is_some_and(|value| value <= catalog.budget.max_memory_bytes())
        && catalog
            .persistent_bytes
            .checked_add(persistent)
            .is_some_and(|value| value <= catalog.budget.max_persistent_bytes())
        && catalog
            .index_bytes
            .checked_add(index)
            .is_some_and(|value| value <= catalog.budget.max_index_bytes())
        && catalog.persistent_bytes >= CATALOG_HEADER_BYTES)
}

pub(super) fn projected_cost(
    catalog: &SchemaCatalog,
    delta: &SchemaDelta,
    root: Option<&[SchemaEntry]>,
) -> Result<(usize, usize, usize, usize), SchemaFailure> {
    let mut memory = 0_usize;
    let mut persistent = 0_usize;
    let mut index = 0_usize;
    let mut new_entries = 0_usize;
    for staged in &delta.entries {
        let selected = root
            .and_then(|entries| {
                entries
                    .binary_search_by(|entry| entry.path.cmp(&staged.path))
                    .ok()
                    .and_then(|index| entries.get(index))
            })
            .unwrap_or(staged);
        add_entry_cost(
            catalog,
            selected,
            &mut memory,
            &mut persistent,
            &mut index,
            &mut new_entries,
        )?;
    }
    if let Some(root) = root {
        for staged in root {
            if delta
                .entries
                .binary_search_by(|entry| entry.path.cmp(&staged.path))
                .is_err()
            {
                add_entry_cost(
                    catalog,
                    staged,
                    &mut memory,
                    &mut persistent,
                    &mut index,
                    &mut new_entries,
                )?;
            }
        }
    }
    Ok((memory, persistent, index, new_entries))
}

fn add_entry_cost(
    catalog: &SchemaCatalog,
    staged: &SchemaEntry,
    memory: &mut usize,
    persistent: &mut usize,
    index: &mut usize,
    new_entries: &mut usize,
) -> Result<(), SchemaFailure> {
    if let Some(old) = catalog.entry(&staged.path) {
        let added = staged
            .variants
            .len()
            .checked_sub(old.variants.len())
            .ok_or(SchemaFailure::InvalidValue)?;
        *persistent = persistent
            .checked_add(added)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let added_index = staged
            .index_bytes
            .checked_sub(old.index_bytes)
            .ok_or(SchemaFailure::InvalidValue)?;
        *index = index
            .checked_add(added_index)
            .ok_or(SchemaFailure::LimitExceeded)?;
        return Ok(());
    }
    *new_entries = new_entries
        .checked_add(1)
        .ok_or(SchemaFailure::LimitExceeded)?;
    *memory = memory
        .checked_add(
            entry_memory_bytes(&staged.path, MAX_VARIANTS).ok_or(SchemaFailure::LimitExceeded)?,
        )
        .ok_or(SchemaFailure::LimitExceeded)?;
    *persistent = persistent
        .checked_add(
            entry_persistent_bytes(&staged.path, staged.variants.len())
                .ok_or(SchemaFailure::LimitExceeded)?,
        )
        .ok_or(SchemaFailure::LimitExceeded)?;
    *index = index
        .checked_add(staged.index_bytes)
        .ok_or(SchemaFailure::LimitExceeded)?;
    Ok(())
}

pub(super) fn staged_memory_bytes(delta: &SchemaDelta) -> Result<usize, SchemaFailure> {
    delta.entries.iter().try_fold(
        delta
            .entries
            .capacity()
            .checked_mul(std::mem::size_of::<SchemaEntry>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<SchemaEntry>>()))
            .ok_or(SchemaFailure::LimitExceeded)?,
        |total, entry| {
            total
                .checked_add(
                    entry_memory_bytes(&entry.path, entry.variants.capacity())
                        .ok_or(SchemaFailure::LimitExceeded)?,
                )
                .ok_or(SchemaFailure::LimitExceeded)
        },
    )
}

pub(super) fn attribute_bytes(set: &AttributeOccurrenceSet) -> Result<u64, SchemaFailure> {
    let mut bytes = u64::try_from(set.key().len()).map_err(|_| SchemaFailure::LimitExceeded)?;
    for index in 0..set.len() {
        let value = set.occurrence(index).ok_or(SchemaFailure::InvalidValue)?;
        bytes = bytes
            .checked_add(
                u64::try_from(
                    value
                        .decoded_size_bytes()
                        .map_err(|_| SchemaFailure::InvalidValue)?,
                )
                .map_err(|_| SchemaFailure::LimitExceeded)?,
            )
            .ok_or(SchemaFailure::LimitExceeded)?;
    }
    Ok(bytes)
}
