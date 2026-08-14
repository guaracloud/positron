use positron_kernel::StoreBlockIdentity;

use super::{Input, decode_namespace, namespace_tag, put_bytes, put_len, put_u16};
use crate::log_store::schema::index::{
    BLOCK_INDEX_HEADER_BYTES, INDEX_HEADER_BYTES, INDEX_MAGIC, MAX_BLOCK_INDEXES, SchemaBlockIndex,
    SchemaIndexPath,
};
use crate::log_store::{SchemaBudget, SchemaCatalog, SchemaFailure, SchemaPath};

pub(super) fn append(catalog: &SchemaCatalog, bytes: &mut Vec<u8>) -> Result<(), SchemaFailure> {
    if catalog.block_indexes.is_empty() {
        return Ok(());
    }
    bytes.extend_from_slice(INDEX_MAGIC);
    put_len(bytes, catalog.block_indexes.len())?;
    for block in &catalog.block_indexes {
        bytes.extend_from_slice(&block.identity.to_bytes());
        bytes.extend_from_slice(&block.digest);
        put_len(bytes, block.paths.len())?;
        for indexed in &block.paths {
            bytes.push(namespace_tag(indexed.path.namespace()));
            put_u16(bytes, indexed.path.segments().len())?;
            for segment in indexed.path.segments() {
                put_bytes(bytes, segment.as_bytes())?;
            }
            bytes.push(indexed.kind_mask);
        }
    }
    Ok(())
}

pub(super) fn preflight(
    input: &mut Input<'_>,
    budget: SchemaBudget,
) -> Result<usize, SchemaFailure> {
    if !input.starts_with(INDEX_MAGIC) {
        return Ok(0);
    }
    let before = input.remaining_len();
    input.take(INDEX_MAGIC.len())?;
    let count = input.usize()?;
    if count == 0 || count > MAX_BLOCK_INDEXES {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let mut previous_identity = None;
    for _ in 0..count {
        let identity: [u8; 16] = input.array()?;
        let digest: [u8; 32] = input.array()?;
        if identity.iter().all(|byte| *byte == 0)
            || digest.iter().all(|byte| *byte == 0)
            || previous_identity.is_some_and(|previous| previous >= identity)
        {
            return Err(SchemaFailure::MalformedCatalog);
        }
        previous_identity = Some(identity);
        let paths = input.usize()?;
        if paths == 0 || paths > budget.max_entries() {
            return Err(SchemaFailure::MalformedCatalog);
        }
        let mut previous_path: Option<&[u8]> = None;
        for _ in 0..paths {
            let path_start = input.remaining_bytes();
            let namespace = input.u8()?;
            decode_namespace(namespace)?;
            let segments = usize::from(input.u16()?);
            if segments == 0 || segments > SchemaPath::system_max_segments() {
                return Err(SchemaFailure::MalformedCatalog);
            }
            for _ in 0..segments {
                let length = input.usize()?;
                let segment = input.take(length)?;
                if segment.is_empty() || std::str::from_utf8(segment).is_err() {
                    return Err(SchemaFailure::MalformedCatalog);
                }
            }
            if input.u8()? == 0 {
                return Err(SchemaFailure::MalformedCatalog);
            }
            let current_length = path_start
                .len()
                .checked_sub(input.remaining_len())
                .ok_or(SchemaFailure::MalformedCatalog)?;
            let current = path_start
                .get(..current_length)
                .ok_or(SchemaFailure::MalformedCatalog)?;
            if previous_path.is_some_and(|previous| previous >= current) {
                return Err(SchemaFailure::MalformedCatalog);
            }
            previous_path = Some(current);
        }
    }
    before
        .checked_sub(input.remaining_len())
        .filter(|bytes| *bytes >= INDEX_HEADER_BYTES + BLOCK_INDEX_HEADER_BYTES)
        .filter(|bytes| *bytes <= budget.max_index_bytes())
        .ok_or(SchemaFailure::MalformedCatalog)
}

pub(super) fn decode(
    input: &mut Input<'_>,
    budget: SchemaBudget,
) -> Result<(Vec<SchemaBlockIndex>, usize, usize), SchemaFailure> {
    if !input.starts_with(INDEX_MAGIC) {
        return Ok((Vec::new(), 0, 0));
    }
    let before = input.remaining_len();
    input.take(INDEX_MAGIC.len())?;
    let count = input.usize()?;
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(count)
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    let mut memory = count
        .checked_mul(
            std::mem::size_of::<SchemaBlockIndex>()
                .checked_add(std::mem::size_of::<Vec<SchemaIndexPath>>())
                .ok_or(SchemaFailure::MalformedCatalog)?,
        )
        .ok_or(SchemaFailure::MalformedCatalog)?;
    for _ in 0..count {
        let identity =
            StoreBlockIdentity::new(input.array()?).map_err(|_| SchemaFailure::MalformedCatalog)?;
        let digest = input.array()?;
        let path_count = input.usize()?;
        let mut paths = Vec::new();
        paths
            .try_reserve_exact(path_count)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for _ in 0..path_count {
            let namespace = decode_namespace(input.u8()?)?;
            let segments = usize::from(input.u16()?);
            let mut path_segments = Vec::new();
            path_segments
                .try_reserve_exact(segments)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            for _ in 0..segments {
                path_segments.push(input.string()?);
            }
            let path = SchemaPath::from_segments(namespace, path_segments)
                .map_err(|_| SchemaFailure::MalformedCatalog)?;
            let indexed = SchemaIndexPath {
                path,
                kind_mask: input.u8()?,
            };
            memory = memory
                .checked_add(indexed.memory_bytes()?)
                .ok_or(SchemaFailure::MalformedCatalog)?;
            paths.push(indexed);
        }
        blocks.push(SchemaBlockIndex {
            identity,
            digest,
            paths,
        });
    }
    let physical = before
        .checked_sub(input.remaining_len())
        .ok_or(SchemaFailure::MalformedCatalog)?;
    if physical > budget.max_index_bytes() || memory > budget.max_memory_bytes() {
        return Err(SchemaFailure::MalformedCatalog);
    }
    Ok((blocks, physical, memory))
}
