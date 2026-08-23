use super::{
    MAGIC, PREVIOUS_VERSION, VERSION, namespace_tag, put_bytes, put_len, put_u8, put_u16, put_u64,
    value_tag,
};
use crate::log_store::schema::index::{
    BLOCK_INDEX_HEADER_BYTES, INDEX_HEADER_BYTES, ScalarIndexFraming,
};
use crate::log_store::schema::model::{
    CATALOG_HEADER_BYTES, MAX_SCALAR_VALUE_BYTES, entry_persistent_bytes,
};
use crate::log_store::schema::query::SchemaValue;
use crate::log_store::{SchemaCatalog, SchemaFailure};

pub(super) fn catalog(catalog: &SchemaCatalog) -> Result<Vec<u8>, SchemaFailure> {
    let expected_len = preflight_length(catalog)?;
    if expected_len > catalog.budget.max_persistent_bytes() {
        return Err(SchemaFailure::LimitExceeded);
    }
    if expected_len != catalog.persistent_bytes {
        return Err(SchemaFailure::InvalidValue);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_len)
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&catalog_version(catalog).to_be_bytes());
    bytes.extend_from_slice(&catalog.tenant.to_bytes());
    for value in [
        catalog.budget.max_entries(),
        catalog.budget.max_memory_bytes(),
        catalog.budget.max_persistent_bytes(),
        catalog.budget.max_index_bytes(),
    ] {
        bytes.extend_from_slice(
            &u64::try_from(value)
                .map_err(|_| SchemaFailure::LimitExceeded)?
                .to_be_bytes(),
        );
    }
    put_len(&mut bytes, catalog.entries.len())?;
    put_u64(&mut bytes, catalog.overflow_records);
    put_u64(&mut bytes, catalog.overflow_bytes);
    for entry in &catalog.entries {
        put_u8(&mut bytes, namespace_tag(entry.path.namespace()));
        put_u16(&mut bytes, entry.path.segments().len())?;
        for segment in entry.path.segments() {
            put_bytes(&mut bytes, segment.as_bytes())?;
        }
        put_len(&mut bytes, entry.variants.len())?;
        for variant in &entry.variants {
            put_u8(&mut bytes, value_tag(*variant));
        }
        put_u64(&mut bytes, entry.observations);
        put_u64(&mut bytes, entry.conflicts);
        put_u64(&mut bytes, entry.query_uses);
        put_u8(&mut bytes, u8::from(entry.promoted));
        put_u64(
            &mut bytes,
            u64::try_from(entry.index_bytes).map_err(|_| SchemaFailure::LimitExceeded)?,
        );
    }
    super::index::append(catalog, &mut bytes)?;
    if bytes.len() != expected_len {
        return Err(SchemaFailure::InvalidValue);
    }
    Ok(bytes)
}

fn preflight_length(catalog: &SchemaCatalog) -> Result<usize, SchemaFailure> {
    let entries = catalog.entries.iter().try_fold(0_usize, |total, entry| {
        total
            .checked_add(
                entry_persistent_bytes(&entry.path, entry.variants.len())
                    .ok_or(SchemaFailure::LimitExceeded)?,
            )
            .ok_or(SchemaFailure::LimitExceeded)
    })?;
    let version = catalog_version(catalog);
    let indexes = if catalog.block_indexes.is_empty() {
        0
    } else {
        catalog
            .block_indexes
            .iter()
            .try_fold(INDEX_HEADER_BYTES, |total, block| {
                for path in &block.paths {
                    for value in &path.values {
                        validate_value(value)?;
                    }
                }
                let block_bytes = if version == VERSION {
                    block.encoded_bytes()?
                } else {
                    super::super::index::SchemaBlockIndex::paths_encoded_bytes_with_framing(
                        &block.paths,
                        ScalarIndexFraming::V2,
                    )?
                    .checked_add(BLOCK_INDEX_HEADER_BYTES)
                    .ok_or(SchemaFailure::LimitExceeded)?
                };
                total
                    .checked_add(block_bytes)
                    .ok_or(SchemaFailure::LimitExceeded)
            })?
    };
    CATALOG_HEADER_BYTES
        .checked_add(entries)
        .and_then(|bytes| bytes.checked_add(indexes))
        .ok_or(SchemaFailure::LimitExceeded)
}

fn catalog_version(catalog: &SchemaCatalog) -> u16 {
    if catalog
        .block_indexes
        .iter()
        .any(|block| block.text_framing == super::super::index::TextIndexFraming::V1)
    {
        VERSION
    } else {
        PREVIOUS_VERSION
    }
}

fn validate_value(value: &SchemaValue) -> Result<(), SchemaFailure> {
    let length = match value {
        SchemaValue::String(value) => value.len(),
        SchemaValue::Bytes(value) => value.len(),
        _ => return Ok(()),
    };
    if length > MAX_SCALAR_VALUE_BYTES {
        Err(SchemaFailure::LimitExceeded)
    } else {
        Ok(())
    }
}
