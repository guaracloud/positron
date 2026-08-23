use std::fmt;

use super::TransformObserver;
use crate::{QueryFailure, QueryFailureCode};

const MIN_STRING_CAPACITY: usize = 8;

pub(super) fn format_scalar(
    formatter: impl Fn(&mut dyn fmt::Write) -> fmt::Result,
    observer: &mut impl TransformObserver,
) -> Result<String, QueryFailure> {
    let mut sizing = SizingWriter::default();
    formatter(&mut sizing).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let mut value = String::new();
    reserve_string_capacity(&mut value, sizing.bytes, observer)?;
    if formatter(&mut value).is_err() || value.len() != sizing.bytes {
        let bytes = u64::try_from(value.capacity())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        observer.release_memory(bytes)?;
        return Err(QueryFailure::new(QueryFailureCode::Internal));
    }
    Ok(value)
}

#[derive(Default)]
struct SizingWriter {
    bytes: usize,
}

impl fmt::Write for SizingWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.bytes = self.bytes.checked_add(text.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

pub(super) fn reserve_string_capacity(
    value: &mut String,
    additional: usize,
    observer: &mut impl TransformObserver,
) -> Result<(), QueryFailure> {
    if additional == 0 {
        return Ok(());
    }
    let requested = value
        .len()
        .checked_add(additional)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let upper = capacity_upper_bound(requested, MIN_STRING_CAPACITY)?.max(value.capacity());
    let old_capacity = value.capacity();
    let delta = upper
        .checked_sub(old_capacity)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    let admitted =
        u64::try_from(delta).map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    observer.reserve_memory(admitted)?;
    if value.try_reserve_exact(additional).is_err() {
        observer.release_memory(admitted)?;
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    let actual_capacity = value.capacity();
    if actual_capacity > upper {
        observer.release_memory(admitted)?;
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    let actual_delta = actual_capacity
        .checked_sub(old_capacity)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    let slack = delta
        .checked_sub(actual_delta)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    if slack > 0 {
        observer.release_memory(
            u64::try_from(slack)
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?,
        )?;
    }
    Ok(())
}

pub(super) fn reserve_vec_capacity<T>(
    values: &mut Vec<T>,
    additional: usize,
    element_bytes: u64,
    observer: &mut impl TransformObserver,
) -> Result<(), QueryFailure> {
    if additional == 0 {
        return Ok(());
    }
    let requested = values
        .len()
        .checked_add(additional)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let upper = capacity_upper_bound(requested, 1)?.max(values.capacity());
    let old_capacity = values.capacity();
    let delta = upper
        .checked_sub(old_capacity)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    let admitted = u64::try_from(delta)
        .ok()
        .and_then(|delta| delta.checked_mul(element_bytes))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    observer.reserve_memory(admitted)?;
    if values.try_reserve_exact(additional).is_err() {
        observer.release_memory(admitted)?;
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    let actual_capacity = values.capacity();
    if actual_capacity > upper {
        observer.release_memory(admitted)?;
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    let actual_delta = actual_capacity
        .checked_sub(old_capacity)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    let slack = delta
        .checked_sub(actual_delta)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    if slack > 0 {
        let slack_bytes = u64::try_from(slack)
            .ok()
            .and_then(|slack| slack.checked_mul(element_bytes))
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        observer.release_memory(slack_bytes)?;
    }
    Ok(())
}

fn capacity_upper_bound(requested: usize, minimum: usize) -> Result<usize, QueryFailure> {
    requested
        .max(minimum)
        .checked_next_power_of_two()
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))
}
