use std::cmp::Ordering;

use positron_domain::value::{AttributeOccurrenceSet, AttributeValueKind};

use super::index::{MAX_INDEX_VALUES, scalar_kind_mask};
use super::query::SchemaValue;
use super::{SchemaFailure, SchemaPath};

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SchemaIndexPath {
    pub(crate) path: SchemaPath,
    pub(crate) kind_mask: u8,
    pub(crate) values: Vec<SchemaValue>,
}

impl SchemaIndexPath {
    pub(crate) fn try_clone(&self) -> Result<Self, SchemaFailure> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(self.values.capacity())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for value in &self.values {
            values.push(value.try_clone()?);
        }
        Ok(Self {
            path: self.path.try_clone()?,
            kind_mask: self.kind_mask,
            values,
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
            values: Vec::new(),
        })
    }

    pub(crate) fn from_variants_and_attributes(
        path: &SchemaPath,
        variants: &[AttributeValueKind],
        attributes: &[&AttributeOccurrenceSet],
    ) -> Result<Self, SchemaFailure> {
        let (_, nested_segments) = path
            .segments()
            .split_first()
            .ok_or(SchemaFailure::InvalidPath)?;
        let mut values = Vec::new();
        let mut complete = true;
        for set in attributes {
            if set.namespace() != path.namespace()
                || path
                    .segments()
                    .first()
                    .is_none_or(|segment| set.key() != segment)
            {
                continue;
            }
            values
                .try_reserve(set.len())
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            for occurrence in 0..set.len() {
                let value = set
                    .occurrence(occurrence)
                    .ok_or(SchemaFailure::InvalidValue)?;
                if !Self::collect_values(value, nested_segments, &mut values)? {
                    values.clear();
                    complete = false;
                    break;
                }
            }
            if !complete {
                break;
            }
        }
        if !complete {
            return Self::from_variants(path, variants);
        }
        values.sort_unstable();
        Self::from_variants_and_values(path, variants, &values)
    }

    pub(crate) fn from_variants_and_values(
        path: &SchemaPath,
        variants: &[AttributeValueKind],
        values: &[SchemaValue],
    ) -> Result<Self, SchemaFailure> {
        if values.len() > MAX_INDEX_VALUES {
            return Err(SchemaFailure::LimitExceeded);
        }
        let mut cloned = Vec::new();
        cloned
            .try_reserve_exact(values.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for value in values {
            if value.kind_value().is_none() {
                return Err(SchemaFailure::InvalidValue);
            }
            cloned.push(value.try_clone()?);
        }
        Ok(Self {
            path: path.try_clone()?,
            kind_mask: scalar_kind_mask(variants),
            values: cloned,
        })
    }

    fn collect_values(
        value: &positron_domain::value::ValidatedAttributeValue,
        segments: &[String],
        values: &mut Vec<SchemaValue>,
    ) -> Result<bool, SchemaFailure> {
        let Some((segment, remaining)) = segments.split_first() else {
            let Some(scalar) = SchemaValue::try_from_validated(value)? else {
                return Ok(true);
            };
            if values.contains(&scalar) {
                return Ok(true);
            }
            if values.len() == MAX_INDEX_VALUES {
                return Ok(false);
            }
            values
                .try_reserve_exact(1)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            values.push(scalar);
            return Ok(true);
        };
        let Some(count) = value.key_value_list_len() else {
            return Ok(true);
        };
        let mut complete = true;
        for index in 0..count {
            let entry = value
                .key_value_entry(index)
                .ok_or(SchemaFailure::InvalidValue)?;
            if entry.key() == segment {
                complete &= Self::collect_values(entry.value(), remaining, values)?;
            }
        }
        Ok(complete)
    }

    pub(crate) fn encoded_bytes(&self) -> Result<usize, SchemaFailure> {
        let path_bytes = self
            .path
            .segments()
            .iter()
            .try_fold(4_usize, |total, segment| {
                total
                    .checked_add(8)
                    .and_then(|value| value.checked_add(segment.len()))
                    .ok_or(SchemaFailure::LimitExceeded)
            })?;
        let total = if self.values.is_empty() {
            path_bytes
        } else {
            self.values.iter().try_fold(
                path_bytes
                    .checked_add(8)
                    .ok_or(SchemaFailure::LimitExceeded)?,
                |total, value| {
                    total
                        .checked_add(value.encoded_bytes()?)
                        .ok_or(SchemaFailure::LimitExceeded)
                },
            )?
        };
        Ok(total)
    }

    pub(crate) fn memory_bytes(&self) -> Result<usize, SchemaFailure> {
        let values = self
            .values
            .capacity()
            .checked_mul(std::mem::size_of::<SchemaValue>())
            .and_then(|capacity| capacity.checked_add(std::mem::size_of::<Vec<SchemaValue>>()))
            .ok_or(SchemaFailure::LimitExceeded)?;
        let inline = std::mem::size_of::<SchemaValue>();
        let values = self.values.iter().try_fold(values, |total, value| {
            let owned_payload = value
                .memory_bytes()?
                .checked_sub(inline)
                .ok_or(SchemaFailure::LimitExceeded)?;
            total
                .checked_add(owned_payload)
                .ok_or(SchemaFailure::LimitExceeded)
        })?;
        super::model::path_memory_bytes(&self.path)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(values))
            .ok_or(SchemaFailure::LimitExceeded)
    }

    pub(crate) fn wire_cmp_path(&self, path: &SchemaPath) -> Ordering {
        path_wire_cmp(&self.path, path)
    }
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
