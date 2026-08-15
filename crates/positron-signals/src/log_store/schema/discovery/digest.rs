use sha2::{Digest, Sha256};

use super::SchemaPathDigest;
use crate::log_store::schema::{SchemaCatalog, SchemaFailure, SchemaPath};

pub(super) fn path_digest(path: &SchemaPath) -> Result<SchemaPathDigest, SchemaFailure> {
    let mut hasher = Sha256::new();
    hasher.update(b"positron-schema-path-v1");
    hasher.update(path.namespace().as_str().as_bytes());
    hasher.update([0]);
    for segment in path.segments() {
        update_usize(&mut hasher, segment.len())?;
        hasher.update(segment.as_bytes());
    }
    Ok(SchemaPathDigest(hasher.finalize().into()))
}

pub(super) fn catalog_digest(catalog: &SchemaCatalog) -> Result<[u8; 32], SchemaFailure> {
    let mut hasher = Sha256::new();
    hasher.update(b"positron-schema-discovery-v2");
    hasher.update(catalog.tenant.to_bytes());
    update_usize(&mut hasher, catalog.budget.max_entries())?;
    update_usize(&mut hasher, catalog.budget.max_memory_bytes())?;
    update_usize(&mut hasher, catalog.budget.max_persistent_bytes())?;
    update_usize(&mut hasher, catalog.budget.max_index_bytes())?;
    update_usize(&mut hasher, catalog.memory_bytes)?;
    update_usize(&mut hasher, catalog.persistent_bytes)?;
    update_usize(&mut hasher, catalog.index_bytes)?;
    update_usize(&mut hasher, catalog.entries.len())?;
    for entry in &catalog.entries {
        hasher.update(path_digest(entry.path())?.as_bytes());
        update_usize(&mut hasher, entry.variants().len())?;
        for variant in entry.variants() {
            hasher.update([*variant as u8]);
        }
        hasher.update(entry.observations().to_be_bytes());
        hasher.update(entry.conflicts().to_be_bytes());
        hasher.update(entry.query_uses().to_be_bytes());
        hasher.update([u8::from(entry.promoted())]);
        update_usize(&mut hasher, entry.index_bytes())?;
    }
    update_usize(&mut hasher, catalog.block_indexes.len())?;
    for block in &catalog.block_indexes {
        hasher.update(block.identity.to_bytes());
        hasher.update(block.digest);
        update_usize(&mut hasher, block.paths.len())?;
        for indexed in &block.paths {
            hasher.update(path_digest(&indexed.path)?.as_bytes());
            hasher.update([indexed.kind_mask]);
        }
    }
    hasher.update(catalog.overflow_records.to_be_bytes());
    hasher.update(catalog.overflow_bytes.to_be_bytes());
    Ok(hasher.finalize().into())
}

fn update_usize(hasher: &mut Sha256, value: usize) -> Result<(), SchemaFailure> {
    let value = u64::try_from(value).map_err(|_| SchemaFailure::LimitExceeded)?;
    hasher.update(value.to_be_bytes());
    Ok(())
}
