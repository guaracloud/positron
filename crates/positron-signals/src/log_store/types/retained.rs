use positron_domain::value::ValidatedAttributeValue;

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
    let heap = value
        .retained_heap_bytes()
        .map_err(LogStoreFailure::domain)?;
    checked_add(VALUE_SLOT_BYTES, to_u64(heap)?)
}

fn to_u64(value: usize) -> Result<u64, LogStoreFailure> {
    u64::try_from(value).map_err(|_| LogStoreFailure::limit_exceeded())
}

fn checked_add(left: u64, right: u64) -> Result<u64, LogStoreFailure> {
    left.checked_add(right)
        .ok_or_else(LogStoreFailure::limit_exceeded)
}
