use positron_domain::value::{AttributeOccurrenceSet, AttributeValueKind};
use positron_kernel::StoreBlockIdentity;
use std::cmp::Ordering;

use super::query::SchemaValue;
use super::{SchemaBudget, SchemaEntry, SchemaFailure, SchemaPath};

pub(crate) const INDEX_MAGIC: &[u8; 8] = b"PINDEX1\0";
pub(crate) const INDEX_HEADER_BYTES: usize = 16;
pub(crate) const BLOCK_INDEX_HEADER_BYTES: usize = 16 + 32 + 8;
pub(crate) const MAX_BLOCK_INDEXES: usize = 4_096;
pub(crate) const SCALAR_VALUES_MAGIC: &[u8; 8] = b"PVALUES\0";
pub(crate) const MAX_INDEX_VALUES: usize = 4_096;
const BLOCK_SCALAR_FRAMING_BYTES: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarIndexFraming {
    LegacyV1,
    V2,
}

impl ScalarIndexFraming {
    const fn encoded_bytes(self) -> usize {
        match self {
            Self::LegacyV1 => 0,
            Self::V2 => BLOCK_SCALAR_FRAMING_BYTES,
        }
    }

    pub(crate) const fn for_mutation(self) -> Self {
        match self {
            Self::LegacyV1 | Self::V2 => Self::V2,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SchemaIndexPath {
    pub(crate) path: SchemaPath,
    pub(crate) kind_mask: u8,
    pub(crate) values: Vec<SchemaValue>,
}

impl SchemaIndexPath {
    pub(crate) fn try_clone(&self) -> Result<Self, SchemaFailure> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(self.values.capacity())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for value in &self.values {
            values.push(value.try_clone()?);
        }
        Ok(Self {
            path: self.path.try_clone()?,
            kind_mask: self.kind_mask,
            values,
        })
    }

    pub(crate) fn from_variants(
        path: &SchemaPath,
        variants: &[AttributeValueKind],
    ) -> Result<Self, SchemaFailure> {
        let kind_mask = scalar_kind_mask(variants);
        Ok(Self {
            path: path.try_clone()?,
            kind_mask,
            values: Vec::new(),
        })
    }

    pub(crate) fn from_variants_and_attributes(
        path: &SchemaPath,
        variants: &[AttributeValueKind],
        attributes: &[AttributeOccurrenceSet],
    ) -> Result<Self, SchemaFailure> {
        let (_, nested_segments) = path
            .segments()
            .split_first()
            .ok_or(SchemaFailure::InvalidPath)?;
        let mut values = Vec::new();
        let mut complete = true;
        for set in attributes {
            if set.namespace() != path.namespace()
                || path
                    .segments()
                    .first()
                    .is_none_or(|segment| set.key() != segment)
            {
                continue;
            }
            values
                .try_reserve(set.len())
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            for occurrence in 0..set.len() {
                let value = set
                    .occurrence(occurrence)
                    .ok_or(SchemaFailure::InvalidValue)?;
                if !Self::collect_values(value, nested_segments, &mut values)? {
                    values.clear();
                    complete = false;
                    break;
                }
            }
            if !complete {
                break;
            }
        }
        if !complete {
            return Self::from_variants(path, variants);
        }
        values.sort_unstable();
        Self::from_variants_and_values(path, variants, &values)
    }

    pub(crate) fn from_variants_and_values(
        path: &SchemaPath,
        variants: &[AttributeValueKind],
        values: &[SchemaValue],
    ) -> Result<Self, SchemaFailure> {
        if values.len() > MAX_INDEX_VALUES {
            return Err(SchemaFailure::LimitExceeded);
        }
        let mut cloned = Vec::new();
        cloned
            .try_reserve_exact(values.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for value in values {
            if value.kind_value().is_none() {
                return Err(SchemaFailure::InvalidValue);
            }
            cloned.push(value.try_clone()?);
        }
        Ok(Self {
            path: path.try_clone()?,
            kind_mask: scalar_kind_mask(variants),
            values: cloned,
        })
    }

    fn collect_values(
        value: &positron_domain::value::ValidatedAttributeValue,
        segments: &[String],
        values: &mut Vec<SchemaValue>,
    ) -> Result<bool, SchemaFailure> {
        let Some((segment, remaining)) = segments.split_first() else {
            let Some(scalar) = SchemaValue::try_from_validated(value)? else {
                return Ok(true);
            };
            if values.contains(&scalar) {
                return Ok(true);
            }
            if values.len() == MAX_INDEX_VALUES {
                return Ok(false);
            }
            values
                .try_reserve_exact(1)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            values.push(scalar);
            return Ok(true);
        };
        let Some(count) = value.key_value_list_len() else {
            return Ok(true);
        };
        let mut complete = true;
        for index in 0..count {
            let entry = value
                .key_value_entry(index)
                .ok_or(SchemaFailure::InvalidValue)?;
            if entry.key() == segment {
                complete &= Self::collect_values(entry.value(), remaining, values)?;
            }
        }
        Ok(complete)
    }

    pub(crate) fn encoded_bytes(&self) -> Result<usize, SchemaFailure> {
        let path_bytes = self
            .path
            .segments()
            .iter()
            .try_fold(4_usize, |total, segment| {
                total
                    .checked_add(8)
                    .and_then(|value| value.checked_add(segment.len()))
                    .ok_or(SchemaFailure::LimitExceeded)
            })?;
        let total = if self.values.is_empty() {
            path_bytes
        } else {
            self.values.iter().try_fold(
                path_bytes
                    .checked_add(8)
                    .ok_or(SchemaFailure::LimitExceeded)?,
                |total, value| {
                    total
                        .checked_add(value.encoded_bytes()?)
                        .ok_or(SchemaFailure::LimitExceeded)
                },
            )?
        };
        Ok(total)
    }

    pub(crate) fn memory_bytes(&self) -> Result<usize, SchemaFailure> {
        let values = self
            .values
            .capacity()
            .checked_mul(std::mem::size_of::<SchemaValue>())
            .and_then(|capacity| capacity.checked_add(std::mem::size_of::<Vec<SchemaValue>>()))
            .ok_or(SchemaFailure::LimitExceeded)?;
        let inline = std::mem::size_of::<SchemaValue>();
        let values = self.values.iter().try_fold(values, |total, value| {
            let owned_payload = value
                .memory_bytes()?
                .checked_sub(inline)
                .ok_or(SchemaFailure::LimitExceeded)?;
            total
                .checked_add(owned_payload)
                .ok_or(SchemaFailure::LimitExceeded)
        })?;
        super::model::path_memory_bytes(&self.path)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(values))
            .ok_or(SchemaFailure::LimitExceeded)
    }

    pub(crate) fn wire_cmp_path(&self, path: &SchemaPath) -> Ordering {
        path_wire_cmp(&self.path, path)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SchemaBlockIndex {
    pub(crate) identity: StoreBlockIdentity,
    pub(crate) digest: [u8; 32],
    pub(crate) paths: Vec<SchemaIndexPath>,
    pub(crate) scalar_framing: ScalarIndexFraming,
}

impl SchemaBlockIndex {
    pub(crate) fn try_clone(&self) -> Result<Self, SchemaFailure> {
        let mut paths = Vec::new();
        paths
            .try_reserve_exact(self.paths.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for path in &self.paths {
            paths.push(path.try_clone()?);
        }
        Ok(Self {
            identity: self.identity,
            digest: self.digest,
            paths,
            scalar_framing: self.scalar_framing,
        })
    }

    pub(crate) fn one(
        identity: StoreBlockIdentity,
        digest: [u8; 32],
        path: SchemaIndexPath,
    ) -> Result<Self, SchemaFailure> {
        let mut paths = Vec::new();
        paths
            .try_reserve_exact(1)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        paths.push(path);
        Ok(Self {
            identity,
            digest,
            paths,
            scalar_framing: ScalarIndexFraming::V2,
        })
    }

    pub(crate) fn encoded_bytes(&self) -> Result<usize, SchemaFailure> {
        self.paths_encoded_bytes_for(&self.paths)?
            .checked_add(BLOCK_INDEX_HEADER_BYTES)
            .ok_or(SchemaFailure::LimitExceeded)
    }

    pub(crate) fn paths_encoded_bytes(paths: &[SchemaIndexPath]) -> Result<usize, SchemaFailure> {
        Self::paths_encoded_bytes_with_framing(paths, ScalarIndexFraming::V2)
    }

    pub(crate) fn paths_encoded_bytes_with_framing(
        paths: &[SchemaIndexPath],
        framing: ScalarIndexFraming,
    ) -> Result<usize, SchemaFailure> {
        if paths.is_empty() {
            return Ok(0);
        }
        let has_values = paths.iter().any(|path| !path.values.is_empty());
        let value_count_slots = if has_values {
            paths.iter().filter(|path| path.values.is_empty()).count()
        } else {
            0
        };
        let paths_bytes = paths.iter().try_fold(0_usize, |total, path| {
            total
                .checked_add(path.encoded_bytes()?)
                .ok_or(SchemaFailure::LimitExceeded)
        })?;
        paths_bytes
            .checked_add(
                value_count_slots
                    .checked_mul(8)
                    .ok_or(SchemaFailure::LimitExceeded)?,
            )
            .and_then(|bytes| {
                bytes.checked_add(if has_values {
                    SCALAR_VALUES_MAGIC.len()
                } else {
                    0
                })
            })
            .and_then(|bytes| bytes.checked_add(framing.encoded_bytes()))
            .ok_or(SchemaFailure::LimitExceeded)
    }

    pub(crate) fn paths_encoded_bytes_for(
        &self,
        paths: &[SchemaIndexPath],
    ) -> Result<usize, SchemaFailure> {
        Self::paths_encoded_bytes_with_framing(paths, self.scalar_framing)
    }

    pub(crate) fn covers_kind(&self, path: &SchemaPath, kind: AttributeValueKind) -> Option<bool> {
        if matches!(
            kind,
            AttributeValueKind::Array | AttributeValueKind::KeyValueList
        ) {
            return None;
        }
        self.paths
            .binary_search_by(|known| known.wire_cmp_path(path))
            .ok()
            .and_then(|index| self.paths.get(index))
            .map(|known| known.kind_mask & kind_bit(kind) != 0)
    }

    pub(crate) fn covers_value(&self, path: &SchemaPath, expected: &SchemaValue) -> Option<bool> {
        let kind = expected.kind_value()?;
        self.paths
            .binary_search_by(|known| known.wire_cmp_path(path))
            .ok()
            .and_then(|index| self.paths.get(index))
            .and_then(|known| {
                if known.kind_mask & kind_bit(kind) == 0 {
                    Some(false)
                } else if known.values.is_empty() {
                    None
                } else {
                    Some(known.values.binary_search(expected).is_ok())
                }
            })
    }

    pub(crate) fn semantically_valid(&self, entries: &[SchemaEntry]) -> bool {
        self.semantically_valid_with_delta(entries, &[])
    }

    pub(crate) fn semantically_valid_with_delta(
        &self,
        entries: &[SchemaEntry],
        delta: &[SchemaEntry],
    ) -> bool {
        self.paths.iter().all(|indexed| {
            entry_for_path(delta, &indexed.path)
                .or_else(|| entry_for_path(entries, &indexed.path))
                .filter(|entry| entry.promoted)
                .is_some_and(|entry| {
                    indexed.kind_mask == scalar_kind_mask(&entry.variants)
                        && indexed.values.iter().all(|value| {
                            value
                                .kind_value()
                                .is_some_and(|kind| indexed.kind_mask & kind_bit(kind) != 0)
                        })
                })
        })
    }
}

fn entry_for_path<'a>(entries: &'a [SchemaEntry], path: &SchemaPath) -> Option<&'a SchemaEntry> {
    entries
        .binary_search_by(|entry| entry.path.cmp(path))
        .ok()
        .and_then(|position| entries.get(position))
}

fn path_wire_cmp(left: &SchemaPath, right: &SchemaPath) -> Ordering {
    namespace_tag(left)
        .cmp(&namespace_tag(right))
        .then_with(|| left.segments().len().cmp(&right.segments().len()))
        .then_with(|| {
            left.segments()
                .iter()
                .zip(right.segments())
                .find_map(|(left, right)| {
                    let order = left
                        .len()
                        .cmp(&right.len())
                        .then_with(|| left.as_bytes().cmp(right.as_bytes()));
                    (order != Ordering::Equal).then_some(order)
                })
                .unwrap_or(Ordering::Equal)
        })
}

const fn namespace_tag(path: &SchemaPath) -> u8 {
    match path.namespace() {
        positron_domain::value::AttributeNamespace::Stream => 1,
        positron_domain::value::AttributeNamespace::Resource => 2,
        positron_domain::value::AttributeNamespace::InstrumentationScope => 3,
        positron_domain::value::AttributeNamespace::Record => 4,
    }
}

pub(crate) const fn kind_bit(kind: AttributeValueKind) -> u8 {
    1_u8 << (kind as u8)
}

pub(crate) fn scalar_kind_mask(kinds: &[AttributeValueKind]) -> u8 {
    kinds
        .iter()
        .filter(|kind| {
            !matches!(
                kind,
                AttributeValueKind::Array | AttributeValueKind::KeyValueList
            )
        })
        .fold(0_u8, |mask, kind| mask | kind_bit(*kind))
}

impl SchemaBudget {
    /// Conservative retained-memory cost of one physical block-index owner.
    #[must_use]
    pub const fn block_index_memory_bytes() -> usize {
        std::mem::size_of::<SchemaBlockIndex>() + std::mem::size_of::<Vec<SchemaIndexPath>>()
    }

    /// Conservative retained-memory cost of one indexed path copy.
    pub fn index_path_memory_bytes(path_bytes: usize, depth: usize) -> Option<usize> {
        let overhead = 2_usize.checked_mul(std::mem::size_of::<usize>())?;
        overhead
            .checked_add(depth.checked_mul(std::mem::size_of::<String>())?)?
            .checked_add(depth.checked_mul(overhead)?)?
            .checked_add(path_bytes)?
            .checked_add(std::mem::size_of::<SchemaIndexPath>())
    }

    /// Conservative peak for decoding one authenticated v2 block and staging its schema delta.
    pub fn replay_working_memory_bytes(payload_bytes: usize) -> Option<usize> {
        payload_bytes
            .checked_mul(4)?
            .checked_add(Self::system_max_memory_bytes())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<SchemaEntry>>()))
    }
}
