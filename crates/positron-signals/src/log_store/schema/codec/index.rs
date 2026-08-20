use positron_kernel::StoreBlockIdentity;

use super::{Input, decode_namespace, namespace_tag, put_bytes, put_len, put_u16};
use crate::log_store::schema::index::{
    BLOCK_INDEX_HEADER_BYTES, INDEX_HEADER_BYTES, INDEX_MAGIC, MAX_BLOCK_INDEXES, MAX_INDEX_VALUES,
    SCALAR_VALUES_MAGIC, SchemaBlockIndex, SchemaIndexPath,
};
use crate::log_store::schema::query::SchemaValue;
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
        let has_values = block.paths.iter().any(|indexed| !indexed.values.is_empty());
        bytes.push(u8::from(has_values));
        if has_values {
            bytes.extend_from_slice(SCALAR_VALUES_MAGIC);
            for indexed in &block.paths {
                put_len(bytes, indexed.values.len())?;
                for value in &indexed.values {
                    put_value(bytes, value)?;
                }
            }
        }
    }
    Ok(())
}

pub(super) struct IndexPreflight {
    pub(super) encoded_bytes: usize,
    pub(super) memory_bound: usize,
}

pub(super) fn preflight(
    input: &mut Input<'_>,
    budget: SchemaBudget,
    legacy: bool,
) -> Result<IndexPreflight, SchemaFailure> {
    if !input.starts_with(INDEX_MAGIC) {
        return Ok(IndexPreflight {
            encoded_bytes: 0,
            memory_bound: 0,
        });
    }
    let before = input.remaining_len();
    input.take(INDEX_MAGIC.len())?;
    let count = input.usize()?;
    if count == 0 || count > MAX_BLOCK_INDEXES {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let mut previous_identity = None;
    let mut memory = count
        .checked_mul(SchemaBudget::block_index_memory_bytes())
        .ok_or(SchemaFailure::MalformedCatalog)?;
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
            let mut path_bytes = 0_usize;
            for _ in 0..segments {
                let length = input.usize()?;
                let segment = input.take(length)?;
                if segment.is_empty() || std::str::from_utf8(segment).is_err() {
                    return Err(SchemaFailure::MalformedCatalog);
                }
                path_bytes = path_bytes
                    .checked_add(length)
                    .ok_or(SchemaFailure::MalformedCatalog)?;
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
            memory = memory
                .checked_add(
                    SchemaBudget::index_path_memory_bytes(path_bytes, segments)
                        .ok_or(SchemaFailure::MalformedCatalog)?,
                )
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<SchemaValue>>()))
                .filter(|bytes| *bytes <= budget.max_memory_bytes())
                .ok_or(SchemaFailure::MalformedCatalog)?;
        }
        let has_values = if legacy {
            input.starts_with(SCALAR_VALUES_MAGIC)
        } else {
            match input.u8()? {
                0 => false,
                1 => true,
                _ => return Err(SchemaFailure::MalformedCatalog),
            }
        };
        if has_values {
            input.take(SCALAR_VALUES_MAGIC.len())?;
            let mut any_values = false;
            for _ in 0..paths {
                let values = input.usize()?;
                if values > MAX_INDEX_VALUES {
                    return Err(SchemaFailure::MalformedCatalog);
                }
                any_values |= values > 0;
                for _ in 0..values {
                    memory = memory
                        .checked_add(preflight_value(&mut *input)?)
                        .filter(|bytes| *bytes <= budget.max_memory_bytes())
                        .ok_or(SchemaFailure::MalformedCatalog)?;
                }
            }
            if !legacy && !any_values {
                return Err(SchemaFailure::MalformedCatalog);
            }
        }
    }
    let encoded_bytes = before
        .checked_sub(input.remaining_len())
        .filter(|bytes| *bytes >= INDEX_HEADER_BYTES + BLOCK_INDEX_HEADER_BYTES)
        .filter(|bytes| *bytes <= budget.max_index_bytes())
        .ok_or(SchemaFailure::MalformedCatalog)?;
    Ok(IndexPreflight {
        encoded_bytes,
        memory_bound: memory,
    })
}

pub(super) fn decode(
    input: &mut Input<'_>,
    budget: SchemaBudget,
    legacy: bool,
) -> Result<(Vec<SchemaBlockIndex>, usize, usize), SchemaFailure> {
    // `decode_checkpoint` performs the complete bounded and canonical preflight
    // immediately before this pass; this pass retains checked allocation and
    // arithmetic while avoiding a second, drifting grammar implementation.
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
                values: Vec::new(),
            };
            memory = memory
                .checked_add(indexed.memory_bytes()?)
                .ok_or(SchemaFailure::MalformedCatalog)?;
            paths.push(indexed);
        }
        let has_values = if legacy {
            input.starts_with(SCALAR_VALUES_MAGIC)
        } else {
            input.u8()? == 1
        };
        if has_values {
            input.take(SCALAR_VALUES_MAGIC.len())?;
            for path in &mut paths {
                let count = input.usize()?;
                path.values
                    .try_reserve_exact(count)
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                for _ in 0..count {
                    path.values.push(decode_value(&mut *input)?);
                }
                if path
                    .values
                    .windows(2)
                    .any(|values| values.first() >= values.get(1))
                {
                    return Err(SchemaFailure::MalformedCatalog);
                }
            }
        }
        for path in &paths {
            memory = memory
                .checked_add(path.values.iter().try_fold(0_usize, |total, value| {
                    total
                        .checked_add(value.memory_bytes()?)
                        .ok_or(SchemaFailure::MalformedCatalog)
                })?)
                .ok_or(SchemaFailure::MalformedCatalog)?;
        }
        blocks.push(SchemaBlockIndex {
            identity,
            digest,
            paths,
        });
    }
    let physical = before
        .checked_sub(input.remaining_len())
        .filter(|bytes| *bytes <= budget.max_index_bytes())
        .ok_or(SchemaFailure::MalformedCatalog)?;
    Ok((blocks, physical, memory))
}

#[derive(Clone, Copy)]
enum ScalarTag {
    Null,
    Boolean,
    SignedInteger,
    FloatingPointBits,
    String,
    Bytes,
}

impl ScalarTag {
    fn from_byte(byte: u8) -> Result<Self, SchemaFailure> {
        match byte {
            0 => Ok(Self::Null),
            1 => Ok(Self::Boolean),
            2 => Ok(Self::SignedInteger),
            3 => Ok(Self::FloatingPointBits),
            4 => Ok(Self::String),
            5 => Ok(Self::Bytes),
            _ => Err(SchemaFailure::MalformedCatalog),
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::Null => 0,
            Self::Boolean => 1,
            Self::SignedInteger => 2,
            Self::FloatingPointBits => 3,
            Self::String => 4,
            Self::Bytes => 5,
        }
    }
}

fn value_tag(value: &SchemaValue) -> Result<ScalarTag, SchemaFailure> {
    match value {
        SchemaValue::Null => Ok(ScalarTag::Null),
        SchemaValue::Boolean(_) => Ok(ScalarTag::Boolean),
        SchemaValue::SignedInteger(_) => Ok(ScalarTag::SignedInteger),
        SchemaValue::FloatingPointBits(_) => Ok(ScalarTag::FloatingPointBits),
        SchemaValue::String(_) => Ok(ScalarTag::String),
        SchemaValue::Bytes(_) => Ok(ScalarTag::Bytes),
        SchemaValue::Kind(_) => Err(SchemaFailure::InvalidValue),
    }
}

fn put_value(bytes: &mut Vec<u8>, value: &SchemaValue) -> Result<(), SchemaFailure> {
    let tag = value_tag(value)?;
    bytes.push(tag.byte());
    match value {
        SchemaValue::Null => {},
        SchemaValue::Boolean(value) => {
            bytes.push(u8::from(*value));
        },
        SchemaValue::SignedInteger(value) => {
            bytes.extend_from_slice(&value.to_be_bytes());
        },
        SchemaValue::FloatingPointBits(value) => {
            bytes.extend_from_slice(&value.to_be_bytes());
        },
        SchemaValue::String(value) => {
            put_bytes(bytes, value.as_bytes())?;
        },
        SchemaValue::Bytes(value) => {
            put_bytes(bytes, value)?;
        },
        SchemaValue::Kind(_) => return Err(SchemaFailure::InvalidValue),
    }
    Ok(())
}

fn preflight_value(input: &mut Input<'_>) -> Result<usize, SchemaFailure> {
    let tag = ScalarTag::from_byte(input.u8()?)?;
    let payload = match tag {
        ScalarTag::Null => 0,
        ScalarTag::Boolean => {
            if input.u8()? > 1 {
                return Err(SchemaFailure::MalformedCatalog);
            }
            1
        },
        ScalarTag::SignedInteger | ScalarTag::FloatingPointBits => {
            input.take(8)?;
            8
        },
        ScalarTag::String | ScalarTag::Bytes => {
            let length = input.usize()?;
            let bytes = input.take(length)?;
            if matches!(tag, ScalarTag::String) && std::str::from_utf8(bytes).is_err() {
                return Err(SchemaFailure::MalformedCatalog);
            }
            length
        },
    };
    std::mem::size_of::<SchemaValue>()
        .checked_add(payload)
        .ok_or(SchemaFailure::MalformedCatalog)
}

fn decode_value(input: &mut Input<'_>) -> Result<SchemaValue, SchemaFailure> {
    match ScalarTag::from_byte(input.u8()?)? {
        ScalarTag::Null => Ok(SchemaValue::Null),
        ScalarTag::Boolean => Ok(SchemaValue::Boolean(input.u8()? == 1)),
        ScalarTag::SignedInteger => Ok(SchemaValue::SignedInteger(i64::from_be_bytes(
            input.array()?,
        ))),
        ScalarTag::FloatingPointBits => Ok(SchemaValue::FloatingPointBits(u64::from_be_bytes(
            input.array()?,
        ))),
        ScalarTag::String => Ok(SchemaValue::String(input.string()?)),
        ScalarTag::Bytes => {
            let length = input.usize()?;
            let source = input.take(length)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            bytes.extend_from_slice(source);
            Ok(SchemaValue::Bytes(bytes))
        },
    }
}
