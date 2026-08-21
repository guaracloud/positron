use positron_domain::value::ValidatedAttributeValue;

use super::{LogRecord, StoredLogRecord};
use crate::log_store::LogStoreFailure;

// Canonical conservative slots keep accounting independent of allocator layout.
const VALUE_SLOT_BYTES: u64 = 64;
const ATTRIBUTE_SLOT_BYTES: u64 = 64;
const DYNAMIC_ENTRY_SLOT_BYTES: u64 = 32;

impl StoredLogRecord {
    pub(in crate::log_store) fn retained_dynamic_bytes(
        &self,
    ) -> Result<RetainedRecordBytes, LogStoreFailure> {
        self.record.retained_dynamic_bytes()
    }
}

pub(in crate::log_store) struct RetainedRecordBytes {
    pub(in crate::log_store) total: u64,
    pub(in crate::log_store) body_heap: u64,
}

impl LogRecord {
    fn retained_dynamic_bytes(&self) -> Result<RetainedRecordBytes, LogStoreFailure> {
        let body_heap = self
            .body
            .as_ref()
            .map_or(Ok(0), retained_value_heap_bytes)?;
        let mut total = body_heap;
        if self.body.is_some() {
            total = checked_add(total, VALUE_SLOT_BYTES)?;
        }
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
        Ok(RetainedRecordBytes { total, body_heap })
    }
}

fn retained_value_bytes(value: &ValidatedAttributeValue) -> Result<u64, LogStoreFailure> {
    checked_add(VALUE_SLOT_BYTES, retained_value_heap_bytes(value)?)
}

fn retained_value_heap_bytes(value: &ValidatedAttributeValue) -> Result<u64, LogStoreFailure> {
    let heap = value
        .retained_heap_bytes()
        .map_err(LogStoreFailure::domain)?;
    to_u64(heap)
}

fn to_u64(value: usize) -> Result<u64, LogStoreFailure> {
    u64::try_from(value).map_err(|_| LogStoreFailure::limit_exceeded())
}

fn checked_add(left: u64, right: u64) -> Result<u64, LogStoreFailure> {
    left.checked_add(right)
        .ok_or_else(LogStoreFailure::limit_exceeded)
}
