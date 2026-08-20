use positron_domain::value::{AttributeOccurrenceSet, AttributeValueKind, ValidatedAttributeValue};

use super::{SchemaCatalog, SchemaFailure, SchemaObservation, SchemaPath, SchemaRepresentation};
use crate::log_store::{AttributeRepresentation, StoredLogRecord};

/// Explicit selection semantics for repeated attribute occurrences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OccurrenceSelector {
    Index(usize),
    Any,
    All,
}

/// A typed scalar or structural value used by a Log Store path query.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SchemaValue {
    Null,
    Boolean(bool),
    SignedInteger(i64),
    FloatingPointBits(u64),
    String(String),
    Bytes(Vec<u8>),
    Kind(AttributeValueKind),
}

impl SchemaValue {
    #[must_use]
    pub const fn null() -> Self {
        Self::Null
    }
    #[must_use]
    pub const fn boolean(value: bool) -> Self {
        Self::Boolean(value)
    }
    #[must_use]
    pub const fn signed_integer(value: i64) -> Self {
        Self::SignedInteger(value)
    }
    #[must_use]
    pub const fn floating_point_bits(value: u64) -> Self {
        Self::FloatingPointBits(value)
    }
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }
    #[must_use]
    pub fn bytes(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
    #[must_use]
    pub const fn kind(value: AttributeValueKind) -> Self {
        Self::Kind(value)
    }

    pub(crate) fn try_from_validated(
        value: &ValidatedAttributeValue,
    ) -> Result<Option<Self>, SchemaFailure> {
        let scalar = match value.kind() {
            AttributeValueKind::Null => Self::Null,
            AttributeValueKind::Boolean => {
                Self::Boolean(value.as_boolean().ok_or(SchemaFailure::InvalidValue)?)
            },
            AttributeValueKind::SignedInteger => Self::SignedInteger(
                value
                    .as_signed_integer()
                    .ok_or(SchemaFailure::InvalidValue)?,
            ),
            AttributeValueKind::FloatingPoint => Self::FloatingPointBits(
                value
                    .as_floating_point_bits()
                    .ok_or(SchemaFailure::InvalidValue)?,
            ),
            AttributeValueKind::String => {
                let source = value.as_str().ok_or(SchemaFailure::InvalidValue)?;
                let mut owned = String::new();
                owned
                    .try_reserve_exact(source.len())
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                owned.push_str(source);
                Self::String(owned)
            },
            AttributeValueKind::Bytes => {
                let source = value.as_bytes().ok_or(SchemaFailure::InvalidValue)?;
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(source.len())
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                owned.extend_from_slice(source);
                Self::Bytes(owned)
            },
            AttributeValueKind::Array | AttributeValueKind::KeyValueList => return Ok(None),
        };
        Ok(Some(scalar))
    }

    pub(crate) fn try_clone(&self) -> Result<Self, SchemaFailure> {
        match self {
            Self::Null => Ok(Self::Null),
            Self::Boolean(value) => Ok(Self::Boolean(*value)),
            Self::SignedInteger(value) => Ok(Self::SignedInteger(*value)),
            Self::FloatingPointBits(value) => Ok(Self::FloatingPointBits(*value)),
            Self::String(value) => {
                let mut cloned = String::new();
                cloned
                    .try_reserve_exact(value.len())
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                cloned.push_str(value);
                Ok(Self::String(cloned))
            },
            Self::Bytes(value) => {
                let mut cloned = Vec::new();
                cloned
                    .try_reserve_exact(value.len())
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                cloned.extend_from_slice(value);
                Ok(Self::Bytes(cloned))
            },
            Self::Kind(_) => Err(SchemaFailure::InvalidValue),
        }
    }

    pub(crate) const fn kind_value(&self) -> Option<AttributeValueKind> {
        match self {
            Self::Null => Some(AttributeValueKind::Null),
            Self::Boolean(_) => Some(AttributeValueKind::Boolean),
            Self::SignedInteger(_) => Some(AttributeValueKind::SignedInteger),
            Self::FloatingPointBits(_) => Some(AttributeValueKind::FloatingPoint),
            Self::String(_) => Some(AttributeValueKind::String),
            Self::Bytes(_) => Some(AttributeValueKind::Bytes),
            Self::Kind(_) => None,
        }
    }

    pub(crate) fn encoded_bytes(&self) -> Result<usize, SchemaFailure> {
        let payload = match self {
            Self::Null => 0,
            Self::Boolean(_) => 1,
            Self::SignedInteger(_) | Self::FloatingPointBits(_) => 8,
            Self::String(value) => value.len(),
            Self::Bytes(value) => value.len(),
            Self::Kind(_) => return Err(SchemaFailure::InvalidValue),
        };
        let length: usize = match self {
            Self::Null => 1,
            Self::Boolean(_) | Self::SignedInteger(_) | Self::FloatingPointBits(_) => 1,
            Self::String(_) | Self::Bytes(_) => 1 + 8,
            Self::Kind(_) => return Err(SchemaFailure::InvalidValue),
        };
        length
            .checked_add(payload)
            .ok_or(SchemaFailure::LimitExceeded)
    }

    pub(crate) fn memory_bytes(&self) -> Result<usize, SchemaFailure> {
        std::mem::size_of::<Self>()
            .checked_add(match self {
                Self::String(value) => value.capacity(),
                Self::Bytes(value) => value.capacity(),
                Self::Null
                | Self::Boolean(_)
                | Self::SignedInteger(_)
                | Self::FloatingPointBits(_) => 0,
                Self::Kind(_) => return Err(SchemaFailure::InvalidValue),
            })
            .ok_or(SchemaFailure::LimitExceeded)
    }
}

/// A path and typed predicate evaluated against one immutable observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaQuery {
    path: SchemaPath,
    selector: OccurrenceSelector,
    value: SchemaValue,
}

impl SchemaQuery {
    #[must_use]
    pub const fn value(path: SchemaPath, selector: OccurrenceSelector, value: SchemaValue) -> Self {
        Self {
            path,
            selector,
            value,
        }
    }
    #[must_use]
    pub const fn path(&self) -> &SchemaPath {
        &self.path
    }
    #[must_use]
    pub const fn selector(&self) -> OccurrenceSelector {
        self.selector
    }
    pub(crate) const fn expected_kind(&self) -> AttributeValueKind {
        match &self.value {
            SchemaValue::Null => AttributeValueKind::Null,
            SchemaValue::Boolean(_) => AttributeValueKind::Boolean,
            SchemaValue::SignedInteger(_) => AttributeValueKind::SignedInteger,
            SchemaValue::FloatingPointBits(_) => AttributeValueKind::FloatingPoint,
            SchemaValue::String(_) => AttributeValueKind::String,
            SchemaValue::Bytes(_) => AttributeValueKind::Bytes,
            SchemaValue::Kind(kind) => *kind,
        }
    }

    pub(crate) const fn expected_scalar(&self) -> Option<&SchemaValue> {
        match self.value {
            SchemaValue::Kind(_) => None,
            _ => Some(&self.value),
        }
    }
}

/// Public query outcome, including whether generic fallback was needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaQueryResult {
    matched: bool,
    reduced_pruning: bool,
}

impl SchemaQueryResult {
    #[must_use]
    pub const fn is_match(self) -> bool {
        self.matched
    }
    #[must_use]
    pub const fn reduced_pruning(self) -> bool {
        self.reduced_pruning
    }
}

impl SchemaCatalog {
    /// Evaluates one explicit typed path query without coercion.
    pub fn query(&self, observation: &SchemaObservation, query: &SchemaQuery) -> SchemaQueryResult {
        evaluate(
            self.entry(query.path()),
            observation.root_attributes(query.path()),
            query,
        )
    }

    pub(crate) fn query_stored_record(
        &self,
        record: &StoredLogRecord,
        query: &SchemaQuery,
    ) -> SchemaQueryResult {
        let root = query.path().segments().first().map(String::as_str);
        evaluate(
            self.entry(query.path()),
            record.attributes().iter().filter_map(|attribute| {
                let set = attribute.occurrences();
                (set.namespace() == query.path().namespace() && Some(set.key()) == root).then_some(
                    (
                        set,
                        match attribute.representation() {
                            AttributeRepresentation::Generic => SchemaRepresentation::Cataloged,
                            AttributeRepresentation::SchemaOverflow => {
                                SchemaRepresentation::Overflow
                            },
                        },
                    ),
                )
            }),
            query,
        )
    }
}

fn evaluate<'a>(
    entry: Option<&super::SchemaEntry>,
    attributes: impl Iterator<Item = (&'a AttributeOccurrenceSet, SchemaRepresentation)>,
    query: &SchemaQuery,
) -> SchemaQueryResult {
    let indexed = entry.is_some_and(super::SchemaEntry::promoted);
    let mut state = SelectionState::new(query.selector, &query.value);
    let mut reduced_pruning = !indexed;
    for (attribute, representation) in attributes {
        reduced_pruning |= representation.is_overflow();
        for index in 0..attribute.len() {
            if let Some(value) = attribute.occurrence(index) {
                visit_terminals(value, &query.path.segments()[1..], &mut |terminal| {
                    state.visit(terminal)
                });
            }
            if state.complete() {
                break;
            }
        }
        if state.complete() {
            break;
        }
    }
    SchemaQueryResult {
        matched: state.matched(),
        reduced_pruning,
    }
}

struct SelectionState<'a> {
    selector: OccurrenceSelector,
    expected: &'a SchemaValue,
    ordinal: usize,
    selected: usize,
    matched: bool,
    complete: bool,
}

impl<'a> SelectionState<'a> {
    const fn new(selector: OccurrenceSelector, expected: &'a SchemaValue) -> Self {
        Self {
            selector,
            expected,
            ordinal: 0,
            selected: 0,
            matched: matches!(selector, OccurrenceSelector::All),
            complete: false,
        }
    }
    fn visit(&mut self, value: &ValidatedAttributeValue) -> bool {
        let current = self.ordinal;
        self.ordinal = self.ordinal.saturating_add(1);
        if matches!(self.selector, OccurrenceSelector::Index(wanted) if wanted != current) {
            return true;
        }
        self.selected = self.selected.saturating_add(1);
        let matches = value_matches(value, self.expected);
        match self.selector {
            OccurrenceSelector::Index(_) => {
                self.matched = matches;
                self.complete = true;
            },
            OccurrenceSelector::Any if matches => {
                self.matched = true;
                self.complete = true;
            },
            OccurrenceSelector::All if !matches => {
                self.matched = false;
                self.complete = true;
            },
            OccurrenceSelector::Any | OccurrenceSelector::All => {},
        }
        !self.complete
    }
    const fn complete(&self) -> bool {
        self.complete
    }
    const fn matched(&self) -> bool {
        self.selected > 0 && self.matched
    }
}

fn visit_terminals(
    value: &ValidatedAttributeValue,
    segments: &[String],
    visit: &mut impl FnMut(&ValidatedAttributeValue) -> bool,
) -> bool {
    let Some((segment, remaining)) = segments.split_first() else {
        return visit(value);
    };
    let Some(count) = value.key_value_list_len() else {
        return true;
    };
    for index in 0..count {
        if let Some(entry) = value.key_value_entry(index)
            && entry.key() == segment
            && !visit_terminals(entry.value(), remaining, visit)
        {
            return false;
        }
    }
    true
}

fn value_matches(value: &ValidatedAttributeValue, expected: &SchemaValue) -> bool {
    match expected {
        SchemaValue::Null => value.is_null(),
        SchemaValue::Boolean(expected) => value.as_boolean() == Some(*expected),
        SchemaValue::SignedInteger(expected) => value.as_signed_integer() == Some(*expected),
        SchemaValue::FloatingPointBits(expected) => {
            value.as_floating_point_bits() == Some(*expected)
        },
        SchemaValue::String(expected) => value.as_str() == Some(expected.as_str()),
        SchemaValue::Bytes(expected) => value.as_bytes() == Some(expected.as_slice()),
        SchemaValue::Kind(expected) => value.kind() == *expected,
    }
}
