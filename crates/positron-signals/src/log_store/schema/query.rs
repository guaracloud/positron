use positron_domain::value::{AttributeValueKind, ValidatedAttributeValue};

use super::{SchemaCatalog, SchemaObservation, SchemaPath};

/// Explicit selection semantics for repeated attribute occurrences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OccurrenceSelector {
    Index(usize),
    Any,
    All,
}

/// A typed scalar or structural value used by a Log Store path query.
#[derive(Clone, Debug, Eq, PartialEq)]
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
}

/// Public query outcome, including whether a generic overflow scan was needed.
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
    pub fn query(
        &mut self,
        observation: &SchemaObservation,
        query: &SchemaQuery,
    ) -> SchemaQueryResult {
        let Some(attribute) = observation.root_attribute(query.path()) else {
            return SchemaQueryResult {
                matched: false,
                reduced_pruning: false,
            };
        };
        if let Some(entry) = self.entries.get_mut(query.path()) {
            entry.query_uses = entry.query_uses.saturating_add(1);
        }
        let matched = match query.selector {
            OccurrenceSelector::Index(index) => attribute
                .occurrence(index)
                .is_some_and(|value| value_matches_path(value, query.path(), &query.value)),
            OccurrenceSelector::Any => (0..attribute.len()).any(|index| {
                attribute
                    .occurrence(index)
                    .is_some_and(|value| value_matches_path(value, query.path(), &query.value))
            }),
            OccurrenceSelector::All => {
                !attribute.is_empty()
                    && (0..attribute.len()).all(|index| {
                        attribute.occurrence(index).is_some_and(|value| {
                            value_matches_path(value, query.path(), &query.value)
                        })
                    })
            },
        };
        SchemaQueryResult {
            matched,
            reduced_pruning: observation
                .representation(query.path())
                .is_some_and(|representation| representation.is_overflow()),
        }
    }
}

fn value_matches_path(
    value: &ValidatedAttributeValue,
    path: &SchemaPath,
    expected: &SchemaValue,
) -> bool {
    let segments = path.segments();
    if segments.len() <= 1 {
        return value_matches(value, expected);
    }
    let mut current = value;
    for segment in segments.iter().skip(1) {
        let Some(count) = current.key_value_list_len() else {
            return false;
        };
        let mut next = None;
        for index in 0..count {
            if let Some(entry) = current.key_value_entry(index)
                && entry.key() == segment
            {
                next = Some(entry.value());
                break;
            }
        }
        let Some(value) = next else { return false };
        current = value;
    }
    value_matches(current, expected)
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
