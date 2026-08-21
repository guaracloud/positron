use positron_domain::value::{AttributeNamespace, AttributeValueKind, ValueLimitProfile};

use super::failure::SchemaFailure;

pub(crate) const MAX_VARIANTS: usize = 8;
pub(crate) const MAX_DISCOVERY_NODES: usize = 4_096;
pub(crate) const CATALOG_HEADER_BYTES: usize = 82;
const MAX_PATH_BYTES: usize = 65_536;
pub(crate) const MAX_SCALAR_VALUE_BYTES: usize = ValueLimitProfile::release_1_system_maximum()
    .system_limits()
    .dynamic_value()
    .individual_value_bytes()
    .value() as usize;
const MAX_PATH_SEGMENTS: usize = 128;
const MAX_SCHEMA_ENTRIES: usize = 4_096;
const MAX_SCHEMA_MEMORY_BYTES: usize = 16_777_216;
const MAX_SCHEMA_PERSISTENT_BYTES: usize = 1_048_576;
const MAX_SCHEMA_INDEX_BYTES: usize = 16_777_216;
const CATALOG_FIXED_MEMORY_BYTES: usize = 128;
const ALLOCATION_OVERHEAD_BYTES: usize = 2 * std::mem::size_of::<usize>();

pub(crate) fn catalog_base_memory_bytes(entry_slots: usize) -> Option<usize> {
    let slot = std::mem::size_of::<SchemaEntry>().max(128);
    CATALOG_FIXED_MEMORY_BYTES
        .checked_add(ALLOCATION_OVERHEAD_BYTES)?
        .checked_add(entry_slots.checked_mul(slot)?)
}

pub(crate) fn path_memory_bytes(path: &SchemaPath) -> Option<usize> {
    path.segments().iter().try_fold(
        ALLOCATION_OVERHEAD_BYTES.checked_add(
            path.segments()
                .len()
                .checked_mul(std::mem::size_of::<String>())?,
        )?,
        |total, segment| {
            total
                .checked_add(ALLOCATION_OVERHEAD_BYTES)?
                .checked_add(segment.capacity())
        },
    )
}

pub(crate) fn entry_persistent_bytes(path: &SchemaPath, variants: usize) -> Option<usize> {
    let segment_bytes = path.segments().iter().try_fold(0_usize, |total, segment| {
        total.checked_add(8)?.checked_add(segment.len())
    })?;
    44_usize.checked_add(segment_bytes)?.checked_add(variants)
}

pub(crate) fn entry_memory_bytes(path: &SchemaPath, variant_capacity: usize) -> Option<usize> {
    path_memory_bytes(path)?
        .checked_add(ALLOCATION_OVERHEAD_BYTES)?
        .checked_add(variant_capacity.checked_mul(std::mem::size_of::<AttributeValueKind>())?)
}

/// Explicit per-tenant bounds for schema discovery and physical indexing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaBudget {
    max_entries: usize,
    max_memory_bytes: usize,
    max_persistent_bytes: usize,
    max_index_bytes: usize,
}

impl SchemaBudget {
    #[must_use]
    pub const fn system_max_entries() -> usize {
        MAX_SCHEMA_ENTRIES
    }

    #[must_use]
    pub const fn system_max_memory_bytes() -> usize {
        MAX_SCHEMA_MEMORY_BYTES
    }

    #[must_use]
    pub const fn system_max_discovery_nodes() -> usize {
        MAX_DISCOVERY_NODES
    }

    /// Returns the hard-bounded Release 1 tenant schema budget.
    pub fn release_1() -> Result<Self, SchemaFailure> {
        Self::new(
            MAX_SCHEMA_ENTRIES,
            MAX_SCHEMA_MEMORY_BYTES,
            MAX_SCHEMA_PERSISTENT_BYTES,
            MAX_SCHEMA_INDEX_BYTES,
        )
    }

    pub fn new(
        max_entries: usize,
        max_memory_bytes: usize,
        max_persistent_bytes: usize,
        max_index_bytes: usize,
    ) -> Result<Self, SchemaFailure> {
        if max_entries == 0
            || max_memory_bytes == 0
            || max_persistent_bytes == 0
            || max_index_bytes == 0
            || max_entries > MAX_SCHEMA_ENTRIES
            || max_memory_bytes > MAX_SCHEMA_MEMORY_BYTES
            || max_persistent_bytes > MAX_SCHEMA_PERSISTENT_BYTES
            || max_index_bytes > MAX_SCHEMA_INDEX_BYTES
            || max_persistent_bytes < CATALOG_HEADER_BYTES
            || catalog_base_memory_bytes(max_entries)
                .is_none_or(|minimum| max_memory_bytes < minimum)
        {
            return Err(SchemaFailure::InvalidBudget);
        }
        Ok(Self {
            max_entries,
            max_memory_bytes,
            max_persistent_bytes,
            max_index_bytes,
        })
    }

    #[must_use]
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    #[must_use]
    pub const fn max_memory_bytes(self) -> usize {
        self.max_memory_bytes
    }

    #[must_use]
    pub const fn max_persistent_bytes(self) -> usize {
        self.max_persistent_bytes
    }

    #[must_use]
    pub const fn max_index_bytes(self) -> usize {
        self.max_index_bytes
    }
}

/// A namespace-qualified dynamic attribute path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaPath {
    namespace: AttributeNamespace,
    segments: Vec<String>,
}

impl SchemaPath {
    #[must_use]
    pub const fn system_max_segments() -> usize {
        MAX_PATH_SEGMENTS
    }

    /// Parses a dotted query path into bounded key segments.
    pub fn new(namespace: AttributeNamespace, path: String) -> Result<Self, SchemaFailure> {
        if path.is_empty() || path.len() > MAX_PATH_BYTES {
            return Err(SchemaFailure::PathTooLong);
        }
        let count = path.split('.').count();
        if count > MAX_PATH_SEGMENTS {
            return Err(SchemaFailure::PathTooLong);
        }
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(count)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for segment in path.split('.') {
            segments.push(try_string(segment)?);
        }
        Self::from_segments(namespace, segments)
    }

    /// Creates an attribute-root path without interpreting dots in producer keys.
    pub fn root(namespace: AttributeNamespace, key: String) -> Result<Self, SchemaFailure> {
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(1)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        segments.push(key);
        Self::from_segments(namespace, segments)
    }

    pub(crate) fn root_borrowed(
        namespace: AttributeNamespace,
        key: &str,
    ) -> Result<Self, SchemaFailure> {
        Self::root(namespace, try_string(key)?)
    }

    /// Creates a checked path from already separated producer-key segments.
    pub fn from_segments(
        namespace: AttributeNamespace,
        segments: Vec<String>,
    ) -> Result<Self, SchemaFailure> {
        let bytes = segments.iter().try_fold(0_usize, |total, segment| {
            total.checked_add(segment.len() + 1)
        });
        if segments.is_empty()
            || segments.len() > MAX_PATH_SEGMENTS
            || segments.iter().any(String::is_empty)
            || bytes.is_none_or(|value| value > MAX_PATH_BYTES)
        {
            return Err(if segments.len() > MAX_PATH_SEGMENTS {
                SchemaFailure::PathTooLong
            } else {
                SchemaFailure::InvalidPath
            });
        }
        Ok(Self {
            namespace,
            segments,
        })
    }

    pub(crate) fn child(&self, key: &str) -> Result<Option<Self>, SchemaFailure> {
        if self.segments.len() == MAX_PATH_SEGMENTS {
            return Ok(None);
        }
        let mut segments = Vec::new();
        let capacity = self
            .segments
            .len()
            .checked_add(1)
            .ok_or(SchemaFailure::LimitExceeded)?;
        segments
            .try_reserve_exact(capacity)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for segment in &self.segments {
            segments.push(try_string(segment)?);
        }
        segments.push(try_string(key)?);
        match Self::from_segments(self.namespace, segments) {
            Ok(path) => Ok(Some(path)),
            Err(SchemaFailure::InvalidPath | SchemaFailure::PathTooLong) => Ok(None),
            Err(failure) => Err(failure),
        }
    }

    pub(crate) fn try_clone(&self) -> Result<Self, SchemaFailure> {
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(self.segments.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for segment in &self.segments {
            segments.push(try_string(segment)?);
        }
        Ok(Self {
            namespace: self.namespace,
            segments,
        })
    }

    #[must_use]
    pub const fn namespace(&self) -> AttributeNamespace {
        self.namespace
    }

    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    pub fn as_string(&self) -> Result<String, SchemaFailure> {
        let length = self.segments.iter().try_fold(0_usize, |total, segment| {
            total.checked_add(segment.len())?.checked_add(1)
        });
        let length = length
            .and_then(|length| length.checked_sub(1))
            .ok_or(SchemaFailure::LimitExceeded)?;
        let mut path = String::new();
        path.try_reserve_exact(length)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for (index, segment) in self.segments.iter().enumerate() {
            if index > 0 {
                path.push('.');
            }
            path.push_str(segment);
        }
        Ok(path)
    }
}

/// A bounded summary of one observed path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaEntry {
    pub(crate) path: SchemaPath,
    pub(crate) variants: Vec<AttributeValueKind>,
    pub(crate) observations: u64,
    pub(crate) conflicts: u64,
    pub(crate) query_uses: u64,
    pub(crate) promoted: bool,
    pub(crate) index_bytes: usize,
}

impl SchemaEntry {
    pub(crate) fn new(path: SchemaPath, kind: AttributeValueKind) -> Result<Self, SchemaFailure> {
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(MAX_VARIANTS)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        variants.push(kind);
        Ok(Self {
            path,
            variants,
            observations: 1,
            conflicts: 0,
            query_uses: 0,
            promoted: false,
            index_bytes: 0,
        })
    }

    pub(crate) fn try_clone(&self) -> Result<Self, SchemaFailure> {
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(MAX_VARIANTS)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        variants.extend_from_slice(&self.variants);
        Ok(Self {
            path: self.path.try_clone()?,
            variants,
            observations: self.observations,
            conflicts: self.conflicts,
            query_uses: self.query_uses,
            promoted: self.promoted,
            index_bytes: self.index_bytes,
        })
    }

    #[must_use]
    pub const fn path(&self) -> &SchemaPath {
        &self.path
    }

    #[must_use]
    pub fn variants(&self) -> &[AttributeValueKind] {
        &self.variants
    }

    #[must_use]
    pub const fn observations(&self) -> u64 {
        self.observations
    }

    #[must_use]
    pub const fn conflicts(&self) -> u64 {
        self.conflicts
    }

    #[must_use]
    pub const fn query_uses(&self) -> u64 {
        self.query_uses
    }

    #[must_use]
    pub const fn promoted(&self) -> bool {
        self.promoted
    }

    #[must_use]
    pub const fn index_bytes(&self) -> usize {
        self.index_bytes
    }
}

pub(crate) fn promoted_index_bytes(variants: &[AttributeValueKind]) -> usize {
    if variants.iter().any(|kind| scalar_kind(*kind)) {
        // The closed native kind set bounds `variants` to `MAX_VARIANTS`.
        2 + variants.len()
    } else {
        0
    }
}

pub(crate) const fn scalar_kind(kind: AttributeValueKind) -> bool {
    !matches!(
        kind,
        AttributeValueKind::Array | AttributeValueKind::KeyValueList
    )
}

fn try_string(value: &str) -> Result<String, SchemaFailure> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    owned.push_str(value);
    Ok(owned)
}
