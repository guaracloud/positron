use positron_domain::value::AttributeValueKind;
use positron_kernel::StoreBlockIdentity;
use std::cmp::Ordering;

use super::{SchemaBudget, SchemaEntry, SchemaFailure, SchemaPath};

pub(crate) const INDEX_MAGIC: &[u8; 8] = b"PINDEX1\0";
pub(crate) const INDEX_HEADER_BYTES: usize = 16;
pub(crate) const BLOCK_INDEX_HEADER_BYTES: usize = 16 + 32 + 8;
pub(crate) const MAX_BLOCK_INDEXES: usize = 4_096;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SchemaIndexPath {
    pub(crate) path: SchemaPath,
    pub(crate) kind_mask: u8,
}

impl SchemaIndexPath {
    pub(crate) fn try_clone(&self) -> Result<Self, SchemaFailure> {
        Ok(Self {
            path: self.path.try_clone()?,
            kind_mask: self.kind_mask,
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
        })
    }

    pub(crate) fn encoded_bytes(&self) -> Result<usize, SchemaFailure> {
        self.path
            .segments()
            .iter()
            .try_fold(4_usize, |total, segment| {
                total.checked_add(8)?.checked_add(segment.len())
            })
            .ok_or(SchemaFailure::LimitExceeded)
    }

    pub(crate) fn memory_bytes(&self) -> Result<usize, SchemaFailure> {
        super::model::path_memory_bytes(&self.path)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
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
        })
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
                .is_some_and(|entry| indexed.kind_mask == scalar_kind_mask(&entry.variants))
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
