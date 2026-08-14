use positron_domain::value::{AttributeOccurrenceSet, ValidatedAttributeValue};

use super::catalog::SchemaCatalog;
use super::failure::SchemaFailure;
use super::model::{MAX_DISCOVERY_NODES, SchemaEntry, SchemaPath, promoted_index_bytes};
use super::observation::{ObservedAttribute, SchemaObservation};
use super::representation::SchemaRepresentation;
use crate::log_store::{AttributeRepresentation, StoredLogAttribute};

mod accounting;
use accounting::{attribute_bytes, projected_cost, root_fits, staged_memory_bytes};

/// Opaque, bounded schema mutation staged before Store Block preparation.
pub struct SchemaDelta {
    entries: Vec<SchemaEntry>,
    overflow_records: u64,
    overflow_bytes: u64,
    retained_memory_bytes: usize,
    staged_memory_bytes: usize,
    persistent_bytes: usize,
    index_bytes: usize,
}

impl SchemaDelta {
    pub(crate) const fn empty() -> Self {
        Self {
            entries: Vec::new(),
            overflow_records: 0,
            overflow_bytes: 0,
            retained_memory_bytes: 0,
            staged_memory_bytes: 0,
            persistent_bytes: 0,
            index_bytes: 0,
        }
    }

    #[must_use]
    pub const fn retained_memory_bytes(&self) -> usize {
        self.retained_memory_bytes
    }

    #[must_use]
    pub const fn staged_memory_bytes(&self) -> usize {
        self.staged_memory_bytes
    }
}

pub(crate) struct DiscoveryMeter {
    used: usize,
}

impl DiscoveryMeter {
    pub(crate) const fn new() -> Self {
        Self { used: 0 }
    }

    fn consume(&mut self) -> Result<bool, SchemaFailure> {
        if self.used == MAX_DISCOVERY_NODES {
            return Ok(false);
        }
        self.used += 1;
        Ok(true)
    }
}

impl SchemaCatalog {
    pub(crate) fn stage_replayed_record(
        &self,
        attributes: &[StoredLogAttribute],
        delta: &mut SchemaDelta,
        meter: &mut DiscoveryMeter,
    ) -> Result<(), SchemaFailure> {
        let mut generic = Vec::new();
        generic
            .try_reserve_exact(attributes.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        let mut overflow_bytes = 0_u64;
        for attribute in attributes {
            match attribute.representation() {
                AttributeRepresentation::Generic => generic.push(
                    attribute
                        .occurrences()
                        .try_clone()
                        .map_err(|_| SchemaFailure::AllocationUnavailable)?,
                ),
                AttributeRepresentation::SchemaOverflow => {
                    overflow_bytes = overflow_bytes
                        .checked_add(attribute_bytes(attribute.occurrences())?)
                        .ok_or(SchemaFailure::LimitExceeded)?;
                },
            }
        }
        let observation = self.stage_record(&generic, delta, meter)?;
        if observation
            .attributes()
            .any(|(_, representation)| representation != SchemaRepresentation::Cataloged)
        {
            return Err(SchemaFailure::InvalidValue);
        }
        if overflow_bytes > 0 {
            delta.overflow_records = delta.overflow_records.saturating_add(1);
            delta.overflow_bytes = delta.overflow_bytes.saturating_add(overflow_bytes);
        }
        Ok(())
    }

    pub(crate) fn stage_record(
        &self,
        attributes: &[AttributeOccurrenceSet],
        delta: &mut SchemaDelta,
        meter: &mut DiscoveryMeter,
    ) -> Result<SchemaObservation, SchemaFailure> {
        let mut observed = Vec::new();
        observed
            .try_reserve_exact(attributes.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        let mut record_overflow_bytes = 0_u64;
        for set in attributes {
            let path = SchemaPath::root_borrowed(set.namespace(), set.key())?;
            let mut root = Vec::new();
            let mut complete = true;
            for index in 0..set.len() {
                let value = set.occurrence(index).ok_or(SchemaFailure::InvalidValue)?;
                if !stage_value(self, delta, &mut root, &path, value, meter)?
                    || !stage_nested(self, delta, &mut root, &path, value, meter)?
                {
                    complete = false;
                }
            }
            let cataloged = complete && root_fits(self, delta, &root)?;
            if cataloged {
                merge_root(delta, root)?;
                let (memory, persistent, index, _) = projected_cost(self, delta, None)?;
                delta.retained_memory_bytes = memory;
                delta.persistent_bytes = persistent;
                delta.index_bytes = index;
                delta.staged_memory_bytes = staged_memory_bytes(delta)?;
            } else {
                record_overflow_bytes = record_overflow_bytes
                    .checked_add(attribute_bytes(set)?)
                    .ok_or(SchemaFailure::LimitExceeded)?;
            }
            observed.push(ObservedAttribute::new(
                set.try_clone()
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?,
                path,
                if cataloged {
                    SchemaRepresentation::Cataloged
                } else {
                    SchemaRepresentation::Overflow
                },
            ));
        }
        if record_overflow_bytes > 0 {
            delta.overflow_records = delta.overflow_records.saturating_add(1);
            delta.overflow_bytes = delta.overflow_bytes.saturating_add(record_overflow_bytes);
        }
        Ok(SchemaObservation::new(observed, record_overflow_bytes))
    }

    pub(crate) fn apply_delta(&mut self, delta: SchemaDelta) -> Result<(), SchemaFailure> {
        for staged in delta.entries {
            match self
                .entries
                .binary_search_by(|entry| entry.path.cmp(&staged.path))
            {
                Ok(index) => {
                    let entry = self
                        .entries
                        .get_mut(index)
                        .ok_or(SchemaFailure::InvalidValue)?;
                    *entry = staged;
                },
                Err(index) => {
                    if self.entries.len() == self.entries.capacity() {
                        return Err(SchemaFailure::AllocationUnavailable);
                    }
                    self.entries.insert(index, staged);
                },
            }
        }
        self.memory_bytes = self
            .memory_bytes
            .checked_add(delta.retained_memory_bytes)
            .ok_or(SchemaFailure::LimitExceeded)?;
        self.persistent_bytes = self
            .persistent_bytes
            .checked_add(delta.persistent_bytes)
            .ok_or(SchemaFailure::LimitExceeded)?;
        self.index_bytes = self
            .index_bytes
            .checked_add(delta.index_bytes)
            .ok_or(SchemaFailure::LimitExceeded)?;
        self.overflow_records = self.overflow_records.saturating_add(delta.overflow_records);
        self.overflow_bytes = self.overflow_bytes.saturating_add(delta.overflow_bytes);
        Ok(())
    }
}

fn stage_value(
    catalog: &SchemaCatalog,
    delta: &SchemaDelta,
    root: &mut Vec<SchemaEntry>,
    path: &SchemaPath,
    value: &ValidatedAttributeValue,
    meter: &mut DiscoveryMeter,
) -> Result<bool, SchemaFailure> {
    if !meter.consume()? {
        return Ok(false);
    }
    let index = root.binary_search_by(|entry| entry.path.cmp(path));
    let (entry, created) = match index {
        Ok(index) => (
            root.get_mut(index).ok_or(SchemaFailure::InvalidValue)?,
            false,
        ),
        Err(index) => {
            let projected = projected_entry(catalog, delta, path)?;
            let (entry, created) = match projected {
                Some(entry) => (entry.try_clone()?, false),
                None => (SchemaEntry::new(path.try_clone()?, value.kind())?, true),
            };
            root.try_reserve_exact(1)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            root.insert(index, entry);
            (
                root.get_mut(index).ok_or(SchemaFailure::InvalidValue)?,
                created,
            )
        },
    };
    let kind = value.kind();
    if created {
        return Ok(true);
    }
    entry.observations = entry.observations.saturating_add(1);
    if entry.variants.contains(&kind) {
        return Ok(true);
    }
    entry.conflicts = entry.conflicts.saturating_add(1);
    let position = entry
        .variants
        .binary_search(&kind)
        .unwrap_or_else(|index| index);
    entry.variants.insert(position, kind);
    entry.index_bytes = promoted_index_bytes(&entry.variants);
    entry.promoted = entry.index_bytes > 0;
    Ok(true)
}

fn stage_nested(
    catalog: &SchemaCatalog,
    delta: &SchemaDelta,
    root: &mut Vec<SchemaEntry>,
    path: &SchemaPath,
    value: &ValidatedAttributeValue,
    meter: &mut DiscoveryMeter,
) -> Result<bool, SchemaFailure> {
    let Some(count) = value.key_value_list_len() else {
        return Ok(true);
    };
    let mut complete = true;
    for index in 0..count {
        let entry = value
            .key_value_entry(index)
            .ok_or(SchemaFailure::InvalidValue)?;
        let Some(child) = path.child(entry.key())? else {
            return Ok(false);
        };
        if !stage_value(catalog, delta, root, &child, entry.value(), meter)?
            || !stage_nested(catalog, delta, root, &child, entry.value(), meter)?
        {
            complete = false;
        }
    }
    Ok(complete)
}

fn projected_entry<'a>(
    catalog: &'a SchemaCatalog,
    delta: &'a SchemaDelta,
    path: &SchemaPath,
) -> Result<Option<&'a SchemaEntry>, SchemaFailure> {
    match delta.entries.binary_search_by(|entry| entry.path.cmp(path)) {
        Ok(index) => delta
            .entries
            .get(index)
            .map(Some)
            .ok_or(SchemaFailure::InvalidValue),
        Err(_) => Ok(catalog.entry(path)),
    }
}

fn merge_root(delta: &mut SchemaDelta, root: Vec<SchemaEntry>) -> Result<(), SchemaFailure> {
    for entry in root {
        match delta
            .entries
            .binary_search_by(|known| known.path.cmp(&entry.path))
        {
            Ok(index) => {
                *delta
                    .entries
                    .get_mut(index)
                    .ok_or(SchemaFailure::InvalidValue)? = entry
            },
            Err(index) => {
                delta
                    .entries
                    .try_reserve_exact(1)
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                delta.entries.insert(index, entry);
            },
        }
    }
    Ok(())
}
