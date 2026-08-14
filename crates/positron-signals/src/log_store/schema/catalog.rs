use std::collections::BTreeMap;

use positron_domain::value::{AttributeOccurrenceSet, ValidatedAttributeValue};

use super::failure::SchemaFailure;
use super::model::{
    ENTRY_MEMORY_OVERHEAD, ENTRY_PERSISTENT_OVERHEAD, MAX_DISCOVERY_NODES, MAX_VARIANTS,
    SchemaBudget, SchemaEntry, SchemaObservation, SchemaPath, SchemaRepresentation,
};

/// Observable typed schema and overflow state for one tenant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaCatalog {
    pub(crate) budget: SchemaBudget,
    pub(crate) entries: BTreeMap<SchemaPath, SchemaEntry>,
    pub(crate) memory_bytes: usize,
    pub(crate) persistent_bytes: usize,
    pub(crate) index_bytes: usize,
    pub(crate) overflow_records: u64,
    pub(crate) overflow_bytes: u64,
}

impl SchemaCatalog {
    pub fn new(budget: SchemaBudget) -> Result<Self, SchemaFailure> {
        Ok(Self {
            budget,
            entries: BTreeMap::new(),
            memory_bytes: 0,
            persistent_bytes: 0,
            index_bytes: 0,
            overflow_records: 0,
            overflow_bytes: 0,
        })
    }

    #[must_use]
    pub const fn budget(&self) -> SchemaBudget {
        self.budget
    }

    #[must_use]
    pub fn entry(&self, path: &SchemaPath) -> Option<&SchemaEntry> {
        self.entries.get(path)
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn memory_bytes(&self) -> usize {
        self.memory_bytes
    }

    #[must_use]
    pub const fn persistent_bytes(&self) -> usize {
        self.persistent_bytes
    }

    #[must_use]
    pub const fn index_bytes(&self) -> usize {
        self.index_bytes
    }

    #[must_use]
    pub const fn overflow_record_count(&self) -> u64 {
        self.overflow_records
    }

    #[must_use]
    pub const fn overflow_byte_count(&self) -> u64 {
        self.overflow_bytes
    }

    pub fn entries(&self) -> impl Iterator<Item = &SchemaEntry> {
        self.entries.values()
    }

    /// Observes one record's already validated occurrence sets.
    pub fn observe(
        &mut self,
        attributes: &[AttributeOccurrenceSet],
    ) -> Result<SchemaObservation, SchemaFailure> {
        let mut observed = Vec::new();
        observed
            .try_reserve_exact(attributes.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        let mut overflow_bytes = 0_u64;
        for set in attributes {
            let path = SchemaPath::root(set.namespace(), set.key().to_owned())?;
            let mut overflow = false;
            for index in 0..set.len() {
                let value = set.occurrence(index).ok_or(SchemaFailure::InvalidValue)?;
                if !self.observe_value(&path, value)? {
                    overflow = true;
                }
                if !self.observe_nested(&path, value)? {
                    overflow = true;
                }
            }
            if overflow {
                overflow_bytes = overflow_bytes
                    .checked_add(attribute_bytes(set)?)
                    .ok_or(SchemaFailure::LimitExceeded)?;
            }
            observed.push(super::model::ObservedAttribute::new(
                set.clone(),
                path,
                if overflow {
                    SchemaRepresentation::Overflow
                } else {
                    SchemaRepresentation::Cataloged
                },
            ));
        }
        if overflow_bytes > 0 {
            self.overflow_records = self.overflow_records.saturating_add(1);
            self.overflow_bytes = self.overflow_bytes.saturating_add(overflow_bytes);
        }
        Ok(SchemaObservation::new(observed, overflow_bytes))
    }

    fn observe_nested(
        &mut self,
        path: &SchemaPath,
        value: &ValidatedAttributeValue,
    ) -> Result<bool, SchemaFailure> {
        let mut nodes = 0_usize;
        self.observe_nested_bounded(path, value, &mut nodes)
    }

    fn observe_nested_bounded(
        &mut self,
        path: &SchemaPath,
        value: &ValidatedAttributeValue,
        nodes: &mut usize,
    ) -> Result<bool, SchemaFailure> {
        let Some(count) = value.key_value_list_len() else {
            return Ok(true);
        };
        let mut complete = true;
        for index in 0..count {
            *nodes = nodes.checked_add(1).ok_or(SchemaFailure::LimitExceeded)?;
            if *nodes > MAX_DISCOVERY_NODES {
                return Ok(false);
            }
            let entry = value
                .key_value_entry(index)
                .ok_or(SchemaFailure::InvalidValue)?;
            let Some(child) = path.child(entry.key()) else {
                return Ok(false);
            };
            if !self.observe_value(&child, entry.value())? {
                complete = false;
            }
            if !self.observe_nested_bounded(&child, entry.value(), nodes)? {
                complete = false;
            }
        }
        Ok(complete)
    }

    fn observe_value(
        &mut self,
        path: &SchemaPath,
        value: &ValidatedAttributeValue,
    ) -> Result<bool, SchemaFailure> {
        let kind = value.kind();
        if let Some(existing) = self.entries.get(path) {
            let known = existing.variants.contains(&kind);
            let variants_full = existing.variants.len() >= MAX_VARIANTS;
            if let Some(entry) = self.entries.get_mut(path) {
                entry.observations = entry.observations.saturating_add(1);
                if !known {
                    entry.conflicts = entry.conflicts.saturating_add(1);
                }
            }
            if known {
                return Ok(true);
            }
            if variants_full {
                return Ok(false);
            }
            let memory = variant_cost(path);
            let persistent = variant_persistent_cost(path);
            if !self.has_capacity(memory, persistent, 0) {
                return Ok(false);
            }
            if let Some(entry) = self.entries.get_mut(path) {
                entry.variants.push(kind);
            }
            self.memory_bytes += memory;
            self.persistent_bytes += persistent;
            return Ok(true);
        }
        if self.entries.len() >= self.budget.max_entries() {
            return Ok(false);
        }
        let memory = entry_cost(path);
        let persistent = entry_persistent_cost(path);
        if !self.has_capacity(memory, persistent, 0) {
            return Ok(false);
        }
        self.memory_bytes += memory;
        self.persistent_bytes += persistent;
        self.entries
            .insert(path.clone(), SchemaEntry::new(path.clone(), kind));
        Ok(true)
    }

    fn has_capacity(&self, memory: usize, persistent: usize, index: usize) -> bool {
        self.memory_bytes
            .checked_add(memory)
            .is_some_and(|value| value <= self.budget.max_memory_bytes())
            && self
                .persistent_bytes
                .checked_add(persistent)
                .is_some_and(|value| value <= self.budget.max_persistent_bytes())
            && self
                .index_bytes
                .checked_add(index)
                .is_some_and(|value| value <= self.budget.max_index_bytes())
    }
}

fn entry_cost(path: &SchemaPath) -> usize {
    ENTRY_MEMORY_OVERHEAD
        .saturating_add(path.as_string().len())
        .saturating_add(std::mem::size_of::<
            positron_domain::value::AttributeValueKind,
        >())
}

fn entry_persistent_cost(path: &SchemaPath) -> usize {
    ENTRY_PERSISTENT_OVERHEAD
        .saturating_add(path.as_string().len())
        .saturating_add(1)
}

fn variant_cost(path: &SchemaPath) -> usize {
    path.as_string().len().saturating_add(std::mem::size_of::<
        positron_domain::value::AttributeValueKind,
    >())
}

fn variant_persistent_cost(path: &SchemaPath) -> usize {
    path.as_string().len().saturating_add(1)
}

fn attribute_bytes(set: &AttributeOccurrenceSet) -> Result<u64, SchemaFailure> {
    let mut bytes = u64::try_from(set.key().len()).map_err(|_| SchemaFailure::LimitExceeded)?;
    for index in 0..set.len() {
        let value = set.occurrence(index).ok_or(SchemaFailure::InvalidValue)?;
        bytes = bytes
            .checked_add(
                u64::try_from(
                    value
                        .decoded_size_bytes()
                        .map_err(|_| SchemaFailure::InvalidValue)?,
                )
                .map_err(|_| SchemaFailure::LimitExceeded)?,
            )
            .ok_or(SchemaFailure::LimitExceeded)?;
    }
    Ok(bytes)
}
