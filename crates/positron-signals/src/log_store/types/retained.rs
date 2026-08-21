use positron_domain::value::{AttributeValueKind, ValidatedAttributeValue};

use super::{LogRecord, StoredLogRecord};
use crate::log_store::LogStoreFailure;

// Canonical conservative slots keep accounting independent of allocator layout.
const VALUE_SLOT_BYTES: u64 = 64;
const ATTRIBUTE_SLOT_BYTES: u64 = 64;
const DYNAMIC_ENTRY_SLOT_BYTES: u64 = 32;

impl StoredLogRecord {
    pub(in crate::log_store) fn retained_dynamic_bytes(&self) -> Result<u64, LogStoreFailure> {
        self.record.retained_dynamic_bytes()
    }
}

impl LogRecord {
    fn retained_dynamic_bytes(&self) -> Result<u64, LogStoreFailure> {
        let mut total = self.body.as_ref().map_or(Ok(0), retained_value_bytes)?;
        for attribute in &self.attributes {
            let occurrences = attribute.occurrences();
            total = checked_add(total, ATTRIBUTE_SLOT_BYTES)?;
            total = checked_add(total, to_u64(occurrences.key().len())?)?;
            for index in 0..occurrences.len() {
                let value = occurrences
                    .occurrence(index)
                    .ok_or_else(LogStoreFailure::invalid_input)?;
                total = checked_add(total, retained_value_bytes(value)?)?;
            }
        }
        total = checked_add(
            total,
            to_u64(
                self.metadata
                    .decoded_size_bytes()
                    .ok_or_else(LogStoreFailure::limit_exceeded)?,
            )?,
        )?;
        for rule in self.policy.applied_rules() {
            total = checked_add(total, DYNAMIC_ENTRY_SLOT_BYTES)?;
            total = checked_add(total, to_u64(rule.len())?)?;
        }
        Ok(total)
    }
}

fn retained_value_bytes(value: &ValidatedAttributeValue) -> Result<u64, LogStoreFailure> {
    let payload = match value.kind() {
        AttributeValueKind::Null => 0,
        AttributeValueKind::Boolean => 1,
        AttributeValueKind::SignedInteger | AttributeValueKind::FloatingPoint => 8,
        AttributeValueKind::String => to_u64(
            value
                .as_str()
                .ok_or_else(LogStoreFailure::invalid_input)?
                .len(),
        )?,
        AttributeValueKind::Bytes => to_u64(
            value
                .as_bytes()
                .ok_or_else(LogStoreFailure::invalid_input)?
                .len(),
        )?,
        AttributeValueKind::Array => retained_array_bytes(value)?,
        AttributeValueKind::KeyValueList => retained_key_value_bytes(value)?,
    };
    checked_add(VALUE_SLOT_BYTES, payload)
}

fn retained_array_bytes(value: &ValidatedAttributeValue) -> Result<u64, LogStoreFailure> {
    let length = value
        .array_len()
        .ok_or_else(LogStoreFailure::invalid_input)?;
    (0..length).try_fold(0_u64, |total, index| {
        checked_add(
            total,
            retained_value_bytes(
                value
                    .array_entry(index)
                    .ok_or_else(LogStoreFailure::invalid_input)?,
            )?,
        )
    })
}

fn retained_key_value_bytes(value: &ValidatedAttributeValue) -> Result<u64, LogStoreFailure> {
    let length = value
        .key_value_list_len()
        .ok_or_else(LogStoreFailure::invalid_input)?;
    (0..length).try_fold(0_u64, |total, index| {
        let entry = value
            .key_value_entry(index)
            .ok_or_else(LogStoreFailure::invalid_input)?;
        let value_bytes = retained_value_bytes(entry.value())?;
        let entry_bytes = DYNAMIC_ENTRY_SLOT_BYTES
            .checked_add(to_u64(entry.key().len())?)
            .and_then(|bytes| bytes.checked_add(value_bytes))
            .ok_or_else(LogStoreFailure::limit_exceeded)?;
        checked_add(total, entry_bytes)
    })
}

fn to_u64(value: usize) -> Result<u64, LogStoreFailure> {
    u64::try_from(value).map_err(|_| LogStoreFailure::limit_exceeded())
}

fn checked_add(left: u64, right: u64) -> Result<u64, LogStoreFailure> {
    left.checked_add(right)
        .ok_or_else(LogStoreFailure::limit_exceeded)
}
