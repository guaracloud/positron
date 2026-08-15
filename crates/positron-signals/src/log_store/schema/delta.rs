use positron_domain::identity::TenantId;
use positron_domain::value::{AttributeOccurrenceSet, ValidatedAttributeValue};

use super::catalog::SchemaCatalog;
use super::failure::SchemaFailure;
use super::index::{SchemaBlockIndex, SchemaIndexPath};
use super::model::{MAX_DISCOVERY_NODES, SchemaEntry, SchemaPath, promoted_index_bytes};
use super::observation::{ObservedAttribute, SchemaObservation};
use super::representation::SchemaRepresentation;
use crate::log_store::{AttributeRepresentation, StoredLogAttribute};

mod accounting;
mod apply;
mod indexing;
mod unverified;
use accounting::{attribute_bytes, projected_cost, root_fits, staged_memory_bytes};
pub(super) use indexing::additional_physical_cost;
use indexing::stage_index_root;

/// Opaque, bounded schema mutation staged before Store Block preparation.
pub struct SchemaDelta {
    tenant: TenantId,
    entries: Vec<SchemaEntry>,
    overflow_records: u64,
    overflow_bytes: u64,
    retained_memory_bytes: usize,
    staged_memory_bytes: usize,
    persistent_bytes: usize,
    index_bytes: usize,
    index_paths: Vec<SchemaIndexPath>,
    unverified_paths: Vec<SchemaPath>,
    physical_index_bytes: usize,
    physical_memory_bytes: usize,
    build_physical_index: bool,
}

impl SchemaDelta {
    pub(crate) const fn empty(tenant: TenantId, build_physical_index: bool) -> Self {
        Self {
            tenant,
            entries: Vec::new(),
            overflow_records: 0,
            overflow_bytes: 0,
            retained_memory_bytes: 0,
            staged_memory_bytes: 0,
            persistent_bytes: 0,
            index_bytes: 0,
            index_paths: Vec::new(),
            unverified_paths: Vec::new(),
            physical_index_bytes: 0,
            physical_memory_bytes: 0,
            build_physical_index,
        }
    }

    pub(crate) const fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn retained_memory_bytes(&self) -> usize {
        self.retained_memory_bytes
    }

    #[must_use]
    pub const fn staged_memory_bytes(&self) -> usize {
        self.staged_memory_bytes
    }

    pub(crate) const fn physical_index_bytes(&self) -> usize {
        self.physical_index_bytes
    }

    pub(crate) const fn physical_memory_bytes(&self) -> usize {
        self.physical_memory_bytes
    }

    pub fn try_clone(&self) -> Result<Self, SchemaFailure> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for entry in &self.entries {
            entries.push(entry.try_clone()?);
        }
        let mut index_paths = Vec::new();
        index_paths
            .try_reserve_exact(self.index_paths.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for path in &self.index_paths {
            index_paths.push(path.try_clone()?);
        }
        let mut unverified_paths = Vec::new();
        unverified_paths
            .try_reserve_exact(self.unverified_paths.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for path in &self.unverified_paths {
            unverified_paths.push(path.try_clone()?);
        }
        Ok(Self {
            tenant: self.tenant,
            entries,
            overflow_records: self.overflow_records,
            overflow_bytes: self.overflow_bytes,
            retained_memory_bytes: self.retained_memory_bytes,
            staged_memory_bytes: self.staged_memory_bytes,
            persistent_bytes: self.persistent_bytes,
            index_bytes: self.index_bytes,
            index_paths,
            unverified_paths,
            physical_index_bytes: self.physical_index_bytes,
            physical_memory_bytes: self.physical_memory_bytes,
            build_physical_index: self.build_physical_index,
        })
    }

    pub(crate) fn into_block_index(
        self,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
    ) -> (Self, Option<SchemaBlockIndex>) {
        if self.index_paths.is_empty() {
            return (self, None);
        }
        let mut delta = self;
        let paths = std::mem::take(&mut delta.index_paths);
        (
            delta,
            Some(SchemaBlockIndex {
                identity,
                digest,
                paths,
            }),
        )
    }

    pub(super) fn into_query_index(
        self,
        path: &super::SchemaPath,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<Option<SchemaBlockIndex>, SchemaFailure> {
        let Ok(position) = self
            .index_paths
            .binary_search_by(|known| known.wire_cmp_path(path))
        else {
            return Ok(None);
        };
        let indexed = self
            .index_paths
            .into_iter()
            .nth(position)
            .ok_or(SchemaFailure::InvalidValue)?;
        SchemaBlockIndex::one(identity, digest, indexed).map(Some)
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
                    delta.mark_overflow_paths(self, attribute.occurrences(), meter)?;
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
                stage_index_root(self, delta, &root)?;
                merge_root(delta, root)?;
            } else {
                delta.mark_paths_unverified(self, &root)?;
                record_overflow_bytes = record_overflow_bytes
                    .checked_add(attribute_bytes(set)?)
                    .ok_or(SchemaFailure::LimitExceeded)?;
            }
            let (memory, persistent, index, _) = projected_cost(self, delta, None)?;
            delta.retained_memory_bytes = memory;
            delta.persistent_bytes = persistent;
            delta.index_bytes = index;
            delta.staged_memory_bytes = staged_memory_bytes(delta)?;
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
    if !entry.variants.contains(&kind) {
        entry.conflicts = entry.conflicts.saturating_add(1);
        let position = entry
            .variants
            .binary_search(&kind)
            .unwrap_or_else(|index| index);
        entry.variants.insert(position, kind);
    }
    if entry.observations >= 2 || entry.query_uses > 0 {
        entry.index_bytes = promoted_index_bytes(&entry.variants);
        entry.promoted = entry.index_bytes > 0;
    }
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
