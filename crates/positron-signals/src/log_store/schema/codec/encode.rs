use super::{
    MAGIC, VERSION, namespace_tag, put_bytes, put_len, put_u8, put_u16, put_u64, value_tag,
};
use crate::log_store::{SchemaCatalog, SchemaFailure};

pub(super) fn catalog(catalog: &SchemaCatalog) -> Result<Vec<u8>, SchemaFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(catalog.persistent_bytes)
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
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
    if bytes.len() < catalog.persistent_bytes || bytes.len() > catalog.budget.max_persistent_bytes()
    {
        return Err(SchemaFailure::LimitExceeded);
    }
    Ok(bytes)
}
