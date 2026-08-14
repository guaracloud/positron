use positron_domain::value::{AttributeNamespace, AttributeOccurrenceSet, AttributeValueKind};

use super::failure::SchemaFailure;

pub(crate) const MAX_VARIANTS: usize = 64;
pub(crate) const MAX_DISCOVERY_NODES: usize = 4_096;
pub(crate) const ENTRY_MEMORY_OVERHEAD: usize = 64;
pub(crate) const ENTRY_PERSISTENT_OVERHEAD: usize = 32;
const MAX_PATH_BYTES: usize = 65_536;

/// Explicit per-tenant bounds for schema discovery and physical indexing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaBudget {
    max_entries: usize,
    max_memory_bytes: usize,
    max_persistent_bytes: usize,
    max_index_bytes: usize,
}

impl SchemaBudget {
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
    /// Parses a dotted query path into bounded key segments.
    pub fn new(namespace: AttributeNamespace, path: String) -> Result<Self, SchemaFailure> {
        if path.is_empty() || path.len() > MAX_PATH_BYTES {
            return Err(SchemaFailure::PathTooLong);
        }
        let segments = path.split('.').map(str::to_owned).collect::<Vec<_>>();
        if segments.iter().any(String::is_empty) {
            return Err(SchemaFailure::InvalidPath);
        }
        Self::from_segments(namespace, segments)
    }

    /// Creates an attribute-root path without interpreting dots in producer keys.
    pub fn root(namespace: AttributeNamespace, key: String) -> Result<Self, SchemaFailure> {
        Self::from_segments(namespace, vec![key])
    }

    pub(crate) fn from_segments(
        namespace: AttributeNamespace,
        segments: Vec<String>,
    ) -> Result<Self, SchemaFailure> {
        let bytes = segments.iter().try_fold(0_usize, |total, segment| {
            total.checked_add(segment.len() + 1)
        });
        if segments.is_empty()
            || segments.iter().any(String::is_empty)
            || bytes.is_none_or(|value| value > MAX_PATH_BYTES)
        {
            return Err(SchemaFailure::InvalidPath);
        }
        Ok(Self {
            namespace,
            segments,
        })
    }

    pub(crate) fn child(&self, key: &str) -> Option<Self> {
        let mut segments = self.segments.clone();
        segments.push(key.to_owned());
        Self::from_segments(self.namespace, segments).ok()
    }

    #[must_use]
    pub const fn namespace(&self) -> AttributeNamespace {
        self.namespace
    }

    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    #[must_use]
    pub fn as_string(&self) -> String {
        self.segments.join(".")
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
    pub(crate) fn new(path: SchemaPath, kind: AttributeValueKind) -> Self {
        Self {
            path,
            variants: vec![kind],
            observations: 1,
            conflicts: 0,
            query_uses: 0,
            promoted: false,
            index_bytes: 0,
        }
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

/// Physical placement selected for one valid attribute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaRepresentation {
    Cataloged,
    Overflow,
}

impl SchemaRepresentation {
    #[must_use]
    pub const fn is_cataloged(self) -> bool {
        matches!(self, Self::Cataloged)
    }

    #[must_use]
    pub const fn is_overflow(self) -> bool {
        matches!(self, Self::Overflow)
    }
}

/// One bounded result of observing one record's dynamic attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaObservation {
    attributes: Vec<ObservedAttribute>,
    overflow_records: u64,
    overflow_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedAttribute {
    set: AttributeOccurrenceSet,
    path: SchemaPath,
    representation: SchemaRepresentation,
}

impl ObservedAttribute {
    pub(crate) const fn new(
        set: AttributeOccurrenceSet,
        path: SchemaPath,
        representation: SchemaRepresentation,
    ) -> Self {
        Self {
            set,
            path,
            representation,
        }
    }
}

impl SchemaObservation {
    pub(crate) fn new(attributes: Vec<ObservedAttribute>, overflow_bytes: u64) -> Self {
        let overflow_records = u64::from(
            attributes
                .iter()
                .any(|attribute| attribute.representation.is_overflow()),
        );
        Self {
            attributes,
            overflow_records,
            overflow_bytes,
        }
    }

    #[must_use]
    pub const fn overflow_records(&self) -> u64 {
        self.overflow_records
    }

    #[must_use]
    pub const fn overflow_bytes(&self) -> u64 {
        self.overflow_bytes
    }

    pub fn attributes(
        &self,
    ) -> impl Iterator<Item = (&AttributeOccurrenceSet, SchemaRepresentation)> {
        self.attributes
            .iter()
            .map(|attribute| (&attribute.set, attribute.representation))
    }

    #[must_use]
    pub fn representation(&self, path: &SchemaPath) -> Option<SchemaRepresentation> {
        self.attributes
            .iter()
            .find(|attribute| &attribute.path == path)
            .map(|attribute| attribute.representation)
    }

    pub(crate) fn root_attribute(&self, path: &SchemaPath) -> Option<&AttributeOccurrenceSet> {
        self.attributes
            .iter()
            .find(|attribute| {
                attribute.path.namespace() == path.namespace()
                    && attribute.path.segments().first() == path.segments().first()
            })
            .map(|attribute| &attribute.set)
    }
}
