use positron_domain::value::AttributeValueKind;
use positron_kernel::StoreBlockIdentity;

pub(crate) use super::index_path::SchemaIndexPath;
use super::query::SchemaValue;
use super::text_index::TextBlockSummary;
use super::{SchemaEntry, SchemaFailure, SchemaPath};

pub(crate) const INDEX_MAGIC: &[u8; 8] = b"PINDEX1\0";
pub(crate) const INDEX_HEADER_BYTES: usize = 16;
pub(crate) const BLOCK_INDEX_HEADER_BYTES: usize = 16 + 32 + 8;
pub(crate) const MAX_BLOCK_INDEXES: usize = 4_096;
pub(crate) const SCALAR_VALUES_MAGIC: &[u8; 8] = b"PVALUES\0";
pub(super) const MAX_INDEX_VALUES: usize = 4_096;
const BLOCK_SCALAR_FRAMING_BYTES: usize = 1;
const BLOCK_TEXT_FRAMING_BYTES: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarIndexFraming {
    LegacyV1,
    V2,
}

impl ScalarIndexFraming {
    pub(crate) const fn encoded_bytes(self) -> usize {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TextIndexFraming {
    LegacyV2,
    V1,
}

impl TextIndexFraming {
    pub(crate) const fn encoded_bytes(self) -> usize {
        match self {
            Self::LegacyV2 => 0,
            Self::V1 => BLOCK_TEXT_FRAMING_BYTES,
        }
    }

    pub(crate) const fn for_mutation(self) -> Self {
        match self {
            Self::LegacyV2 | Self::V1 => Self::V1,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SchemaBlockIndex {
    pub(crate) identity: StoreBlockIdentity,
    pub(crate) digest: [u8; 32],
    pub(crate) paths: Vec<SchemaIndexPath>,
    pub(crate) scalar_framing: ScalarIndexFraming,
    pub(crate) text_framing: TextIndexFraming,
    pub(crate) text_summary: Option<TextBlockSummary>,
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
            text_framing: self.text_framing,
            text_summary: self
                .text_summary
                .as_ref()
                .map(TextBlockSummary::try_clone)
                .transpose()?,
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
            text_framing: TextIndexFraming::LegacyV2,
            text_summary: None,
        })
    }

    pub(crate) fn encoded_bytes(&self) -> Result<usize, SchemaFailure> {
        let bytes = self
            .paths_encoded_bytes_for(&self.paths)?
            .checked_add(self.text_framing.encoded_bytes())
            .ok_or(SchemaFailure::LimitExceeded)?;
        let bytes = self.text_summary.as_ref().map_or(Ok(bytes), |summary| {
            bytes
                .checked_add(summary.encoded_bytes()?)
                .ok_or(SchemaFailure::LimitExceeded)
        })?;
        bytes
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
            return Ok(framing.encoded_bytes());
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
                    // A previously indexed immutable block can legitimately
                    // cover a strict subset of kinds after a later block
                    // promotes the same path with another scalar variant.
                    // The subset remains safe for pruning: values of a kind
                    // absent from that block cannot match its index.
                    let entry_kinds = scalar_kind_mask(&entry.variants);
                    indexed.kind_mask & !entry_kinds == 0
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

pub(super) const fn kind_bit(kind: AttributeValueKind) -> u8 {
    1_u8 << (kind as u8)
}

pub(super) fn scalar_kind_mask(kinds: &[AttributeValueKind]) -> u8 {
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
