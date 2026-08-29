use positron_domain::value::AttributeOccurrenceSet;

use super::{SchemaPath, SchemaRepresentation};

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
    #[cfg(test)]
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
    #[cfg(test)]
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

    pub(crate) fn root_attributes(
        &self,
        path: &SchemaPath,
    ) -> impl Iterator<Item = (&AttributeOccurrenceSet, SchemaRepresentation)> {
        self.attributes
            .iter()
            .filter(|attribute| {
                attribute.path.namespace() == path.namespace()
                    && attribute.path.segments().first() == path.segments().first()
            })
            .map(|attribute| (&attribute.set, attribute.representation))
    }
}
