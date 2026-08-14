use crate::log_store::LogStoreFailure;
use crate::log_store::types::LogRecord;

use super::limits::CodecLimits;
use super::value;

const MAX_BLOCK_BYTES: usize = 1_048_576;

pub(in crate::log_store) fn encoded_block_length(
    records: &[LogRecord],
) -> Result<usize, LogStoreFailure> {
    let limits = CodecLimits::release_1()?;
    if records.is_empty() || records.len() > limits.records {
        return Err(LogStoreFailure::limit_exceeded());
    }
    records.iter().try_fold(28_usize, |total, record| {
        bounded_add(total, encoded_record_length(record, limits.nesting_depth)?)
    })
}

fn encoded_record_length(
    record: &LogRecord,
    maximum_nesting_depth: u8,
) -> Result<usize, LogStoreFailure> {
    let mut bytes = if record.event_time().instant().is_some() {
        9
    } else {
        1
    };
    bytes = bounded_add(
        bytes,
        if record.observed_time().is_some() {
            10
        } else {
            1
        },
    )?;
    bytes = bounded_add(bytes, 9)?;
    if let Some(body) = record.body() {
        bytes = bounded_add(bytes, value::encoded_length(body, maximum_nesting_depth)?)?;
    }
    bytes = bounded_add(bytes, 2)?;
    for attribute in record.attributes() {
        bytes = bounded_add(bytes, 8)?;
        bytes = bounded_add(bytes, attribute.occurrences().key().len())?;
        for index in 0..attribute.occurrences().len() {
            let value = attribute
                .occurrences()
                .occurrence(index)
                .ok_or_else(LogStoreFailure::invalid_input)?;
            bytes = bounded_add(bytes, value::encoded_length(value, maximum_nesting_depth)?)?;
        }
    }
    bytes = bounded_add(bytes, 42)?;
    for rule in record.policy_provenance().applied_rules() {
        bytes = bounded_add(bytes, 4)?;
        bytes = bounded_add(bytes, rule.len())?;
    }
    Ok(bytes)
}

pub(super) fn bounded_add(left: usize, right: usize) -> Result<usize, LogStoreFailure> {
    left.checked_add(right)
        .filter(|total| *total <= MAX_BLOCK_BYTES)
        .ok_or_else(LogStoreFailure::limit_exceeded)
}
