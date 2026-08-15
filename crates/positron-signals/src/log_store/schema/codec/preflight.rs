use super::{Input, MAGIC, MAX_SEGMENTS_ON_WIRE, VERSION, decode_namespace, decode_value_kind};
use crate::log_store::SchemaFailure;
use crate::log_store::schema::model::{
    CATALOG_HEADER_BYTES, MAX_VARIANTS, SchemaBudget, catalog_base_memory_bytes,
};

pub(super) struct CatalogPrefix {
    pub(super) offset: usize,
    pub(super) memory_bound: usize,
    pub(super) sidecar_memory_bound: usize,
    pub(super) budget: SchemaBudget,
}

pub(super) fn catalog_prefix(bytes: &[u8]) -> Result<CatalogPrefix, SchemaFailure> {
    if bytes.len() < CATALOG_HEADER_BYTES || bytes.len() > 1_048_576 {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let mut input = Input::new(bytes);
    if input.take(MAGIC.len())? != MAGIC || input.u16()? != VERSION {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let _: [u8; 16] = input.array()?;
    let budget = SchemaBudget::new(
        input.usize()?,
        input.usize()?,
        input.usize()?,
        input.usize()?,
    )
    .map_err(|_| SchemaFailure::MalformedCatalog)?;
    if bytes.len() > budget.max_persistent_bytes() {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let count = input.usize()?;
    if count > budget.max_entries() {
        return Err(SchemaFailure::MalformedCatalog);
    }
    input.u64()?;
    input.u64()?;
    let mut memory =
        catalog_base_memory_bytes(budget.max_entries()).ok_or(SchemaFailure::MalformedCatalog)?;
    let mut index_bytes = 0_usize;
    for _ in 0..count {
        decode_namespace(input.u8()?)?;
        let segments = usize::from(input.u16()?);
        if segments == 0 || segments > MAX_SEGMENTS_ON_WIRE {
            return Err(SchemaFailure::MalformedCatalog);
        }
        memory = memory
            .checked_add(16)
            .and_then(|value| {
                value.checked_add(segments.checked_mul(std::mem::size_of::<String>())?)
            })
            .ok_or(SchemaFailure::MalformedCatalog)?;
        let mut path_bytes = 0_usize;
        for _ in 0..segments {
            let length = input.usize()?;
            let segment = input.take(length)?;
            if segment.is_empty() || std::str::from_utf8(segment).is_err() {
                return Err(SchemaFailure::MalformedCatalog);
            }
            path_bytes = path_bytes
                .checked_add(
                    length
                        .checked_add(1)
                        .ok_or(SchemaFailure::MalformedCatalog)?,
                )
                .filter(|value| *value <= 65_536)
                .ok_or(SchemaFailure::MalformedCatalog)?;
            memory = memory
                .checked_add(16)
                .and_then(|value| value.checked_add(length))
                .ok_or(SchemaFailure::MalformedCatalog)?;
        }
        let variants = input.usize()?;
        if variants == 0 || variants > MAX_VARIANTS {
            return Err(SchemaFailure::MalformedCatalog);
        }
        let mut seen = [false; 8];
        let mut has_scalar = false;
        let mut previous_tag = None;
        for _ in 0..variants {
            let tag = input.u8()?;
            decode_value_kind(tag)?;
            if previous_tag.is_some_and(|previous| tag <= previous) {
                return Err(SchemaFailure::MalformedCatalog);
            }
            previous_tag = Some(tag);
            has_scalar |= tag <= 5;
            let slot = seen
                .get_mut(usize::from(tag))
                .ok_or(SchemaFailure::MalformedCatalog)?;
            if std::mem::replace(slot, true) {
                return Err(SchemaFailure::MalformedCatalog);
            }
        }
        memory = memory
            .checked_add(16)
            .and_then(|value| {
                value.checked_add(MAX_VARIANTS.checked_mul(std::mem::size_of::<
                    positron_domain::value::AttributeValueKind,
                >())?)
            })
            .filter(|value| *value <= budget.max_memory_bytes())
            .ok_or(SchemaFailure::MalformedCatalog)?;
        input.u64()?;
        input.u64()?;
        input.u64()?;
        let promoted = match input.u8()? {
            0 => false,
            1 => true,
            _ => return Err(SchemaFailure::MalformedCatalog),
        };
        let promoted_index = if has_scalar {
            // The preflight bound above limits variants to the closed kind set.
            2 + variants
        } else {
            0
        };
        let entry_index = input.usize()?;
        let expected_index = if promoted { promoted_index } else { 0 };
        if entry_index != expected_index || (promoted && !has_scalar) {
            return Err(SchemaFailure::MalformedCatalog);
        }
        index_bytes = index_bytes
            .checked_add(entry_index)
            .filter(|value| *value <= budget.max_index_bytes())
            .ok_or(SchemaFailure::MalformedCatalog)?;
    }
    let physical = super::index::preflight(&mut input, budget)?;
    memory = memory
        .checked_add(physical.memory_bound)
        .filter(|value| *value <= budget.max_memory_bytes())
        .ok_or(SchemaFailure::MalformedCatalog)?;
    index_bytes = index_bytes
        .checked_add(physical.encoded_bytes)
        .filter(|value| *value <= budget.max_index_bytes())
        .ok_or(SchemaFailure::MalformedCatalog)?;
    let _ = index_bytes;
    Ok(CatalogPrefix {
        offset: bytes.len().saturating_sub(input.remaining_len()),
        memory_bound: memory,
        sidecar_memory_bound: physical.memory_bound,
        budget,
    })
}
