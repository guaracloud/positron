use std::fmt::Write;

use positron_domain::value::{CandidateAttributeValue, ValidatedAttributeValue, ValueLimitProfile};

use crate::{QueryFailure, QueryFailureCode};

mod json;
mod logfmt;

/// Query-time body transformations. They produce a new query value and never
/// alter the authenticated value held by the Signal Store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyTransform {
    Json,
    Logfmt,
    Cast(CastTarget),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CastTarget {
    String,
    Integer,
    Float,
    Boolean,
}

pub(crate) trait TransformObserver {
    fn step(&mut self) -> Result<(), QueryFailure>;

    fn reserve_memory(&mut self, _bytes: u64) -> Result<(), QueryFailure> {
        Ok(())
    }

    fn release_memory(&mut self, _bytes: u64) -> Result<(), QueryFailure> {
        Ok(())
    }
}

struct NativeValidationObserver<'a, O> {
    observer: &'a mut O,
}

impl<O: TransformObserver> positron_domain::value::NativeValueObserver
    for NativeValidationObserver<'_, O>
{
    type Error = QueryFailure;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        self.observer.step()
    }

    fn observe_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        for _chunk in payload.chunks(positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES) {
            self.observer.step()?;
        }
        Ok(())
    }

    fn observe_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        let bytes = u64::try_from(bytes)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        self.observer.reserve_memory(bytes)
    }

    fn release_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        let bytes = u64::try_from(bytes)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        self.observer.release_memory(bytes)
    }
}

impl BodyTransform {
    pub(crate) fn scratch_memory_bytes(
        self,
        value: &ValidatedAttributeValue,
    ) -> Result<u64, QueryFailure> {
        let source_bytes = value.as_str().map(str::len).unwrap_or(0).max(128);
        let bytes = source_bytes
            .checked_add(64)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        u64::try_from(bytes).map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))
    }

    #[cfg(fuzzing)]
    pub(crate) fn apply(
        self,
        value: &ValidatedAttributeValue,
        observer: &mut impl TransformObserver,
    ) -> Result<ValidatedAttributeValue, QueryFailure> {
        self.apply_with_facts(value, observer)
            .map(positron_domain::value::ObservedValueTransfer::into_value)
    }

    pub(crate) fn apply_with_facts(
        self,
        value: &ValidatedAttributeValue,
        observer: &mut impl TransformObserver,
    ) -> Result<positron_domain::value::ObservedValueTransfer, QueryFailure> {
        let candidate = match self {
            Self::Json => {
                let source = value.as_str().ok_or_else(unsupported)?;
                json::parse(source, observer)?
            },
            Self::Logfmt => {
                let source = value.as_str().ok_or_else(unsupported)?;
                logfmt::parse(source, observer)?
            },
            Self::Cast(target) => cast_value(value, target, observer)?,
        };
        let mut validation_observer = NativeValidationObserver { observer };
        candidate
            .validate_log_body_observed_with_facts(
                ValueLimitProfile::release_1_system_maximum(),
                &mut validation_observer,
            )
            .map_err(map_observed_failure)
    }
}

pub(super) const MAX_TRANSFORM_INPUT_BYTES: usize = 65_536;
pub(super) const MAX_TRANSFORM_DEPTH: u16 = 32;
pub(super) const MAX_TRANSFORM_ENTRIES: usize = 1_024;
pub(super) const PARSER_ENTRY_BYTES: u64 = 96;

fn cast_value(
    value: &ValidatedAttributeValue,
    target: CastTarget,
    observer: &mut impl TransformObserver,
) -> Result<CandidateAttributeValue, QueryFailure> {
    if value
        .as_str()
        .is_some_and(|source| source.len() > MAX_TRANSFORM_INPUT_BYTES)
    {
        return Err(unsupported());
    }
    if let Some(source) = value.as_str() {
        observe_length(source.len(), observer)?;
    }
    observer.step()?;
    match target {
        CastTarget::String => {
            let text = scalar_string(value, observer)?;
            Ok(CandidateAttributeValue::string(text))
        },
        CastTarget::Integer => {
            if let Some(value) = value.as_signed_integer() {
                return Ok(CandidateAttributeValue::signed_integer(value));
            }
            if let Some(value) = value.as_str() {
                return value
                    .parse::<i64>()
                    .map(CandidateAttributeValue::signed_integer)
                    .map_err(|_| unsupported());
            }
            if let Some(bits) = value.as_floating_point_bits() {
                let value = f64::from_bits(bits);
                if value.is_finite() && value.fract() == 0.0 {
                    let value = value as i128;
                    if (i64::MIN as i128..=i64::MAX as i128).contains(&value) {
                        return Ok(CandidateAttributeValue::signed_integer(value as i64));
                    }
                }
            }
            if let Some(value) = value.as_boolean() {
                return Ok(CandidateAttributeValue::signed_integer(i64::from(value)));
            }
            Err(unsupported())
        },
        CastTarget::Float => {
            if let Some(bits) = value.as_floating_point_bits() {
                return Ok(CandidateAttributeValue::floating_point_bits(bits));
            }
            let value = if let Some(value) = value.as_signed_integer() {
                value as f64
            } else if let Some(value) = value.as_str() {
                value.parse::<f64>().map_err(|_| unsupported())?
            } else {
                return Err(unsupported());
            };
            if !value.is_finite() {
                return Err(unsupported());
            }
            Ok(CandidateAttributeValue::floating_point_bits(
                value.to_bits(),
            ))
        },
        CastTarget::Boolean => {
            if let Some(value) = value.as_boolean() {
                return Ok(CandidateAttributeValue::boolean(value));
            }
            if let Some(value) = value.as_str() {
                return match value {
                    "true" => Ok(CandidateAttributeValue::boolean(true)),
                    "false" => Ok(CandidateAttributeValue::boolean(false)),
                    _ => Err(unsupported()),
                };
            }
            if let Some(value) = value.as_signed_integer() {
                return match value {
                    0 => Ok(CandidateAttributeValue::boolean(false)),
                    1 => Ok(CandidateAttributeValue::boolean(true)),
                    _ => Err(unsupported()),
                };
            }
            Err(unsupported())
        },
    }
}

fn observe_length(
    length: usize,
    observer: &mut impl TransformObserver,
) -> Result<(), QueryFailure> {
    for _ in 0..length {
        observer.step()?;
    }
    Ok(())
}

fn scalar_string(
    value: &ValidatedAttributeValue,
    observer: &mut impl TransformObserver,
) -> Result<String, QueryFailure> {
    if let Some(value) = value.as_str() {
        return copy_text(value, observer);
    }
    if let Some(value) = value.as_signed_integer() {
        return format_scalar(|output| write!(output, "{value}"), observer);
    }
    if let Some(value) = value.as_boolean() {
        return format_scalar(|output| write!(output, "{value}"), observer);
    }
    if let Some(bits) = value.as_floating_point_bits() {
        let value = f64::from_bits(bits);
        if !value.is_finite() {
            return Err(unsupported());
        }
        return format_scalar(|output| write!(output, "{value}"), observer);
    }
    if value.is_null() {
        return copy_text("null", observer);
    }
    Err(unsupported())
}

pub(super) fn copy_text(
    source: &str,
    observer: &mut impl TransformObserver,
) -> Result<String, QueryFailure> {
    let bytes = u64::try_from(source.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    observer.reserve_memory(bytes)?;
    let mut value = String::new();
    if value.try_reserve_exact(source.len()).is_err() {
        observer.release_memory(bytes)?;
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    value.push_str(source);
    Ok(value)
}

fn format_scalar(
    formatter: impl FnOnce(&mut String) -> std::fmt::Result,
    observer: &mut impl TransformObserver,
) -> Result<String, QueryFailure> {
    observer.reserve_memory(128)?;
    let mut value = String::new();
    if value.try_reserve_exact(128).is_err() {
        observer.release_memory(128)?;
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    if formatter(&mut value).is_err() {
        observer.release_memory(128)?;
        return Err(QueryFailure::new(QueryFailureCode::Internal));
    }
    Ok(value)
}

fn map_domain_failure(failure: positron_domain::outcome::DomainFailure) -> QueryFailure {
    map_domain_failure_code(failure.code())
}

fn map_domain_failure_code(code: positron_domain::outcome::DomainFailureCode) -> QueryFailure {
    if code == positron_domain::outcome::DomainFailureCode::AllocationUnavailable {
        QueryFailure::new(QueryFailureCode::ResourceExhausted)
    } else {
        unsupported()
    }
}

fn map_observed_failure(
    failure: positron_domain::value::ObservedValueFailure<QueryFailure>,
) -> QueryFailure {
    match failure {
        positron_domain::value::ObservedValueFailure::Domain(failure) => {
            map_domain_failure(failure)
        },
        positron_domain::value::ObservedValueFailure::Observer(failure) => failure,
    }
}

pub(super) const fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}

#[cfg(test)]
mod tests;
