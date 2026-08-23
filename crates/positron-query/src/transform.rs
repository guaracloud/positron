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
}

impl BodyTransform {
    pub(crate) fn apply(
        self,
        value: &ValidatedAttributeValue,
        observer: &mut impl TransformObserver,
    ) -> Result<ValidatedAttributeValue, QueryFailure> {
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
        candidate
            .validate_log_body(ValueLimitProfile::release_1_system_maximum())
            .map_err(map_domain_failure)
    }
}

pub(super) const MAX_TRANSFORM_INPUT_BYTES: usize = 65_536;
pub(super) const MAX_TRANSFORM_DEPTH: u16 = 32;
pub(super) const MAX_TRANSFORM_ENTRIES: usize = 1_024;

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
            let text = scalar_string(value)?;
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

fn scalar_string(value: &ValidatedAttributeValue) -> Result<String, QueryFailure> {
    if let Some(value) = value.as_str() {
        return copy_text(value);
    }
    if let Some(value) = value.as_signed_integer() {
        return format_scalar(|output| write!(output, "{value}"));
    }
    if let Some(value) = value.as_boolean() {
        return format_scalar(|output| write!(output, "{value}"));
    }
    if let Some(bits) = value.as_floating_point_bits() {
        let value = f64::from_bits(bits);
        if !value.is_finite() {
            return Err(unsupported());
        }
        return format_scalar(|output| write!(output, "{value}"));
    }
    if value.is_null() {
        return copy_text("null");
    }
    Err(unsupported())
}

pub(super) fn copy_text(source: &str) -> Result<String, QueryFailure> {
    let mut value = String::new();
    value
        .try_reserve_exact(source.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    value.push_str(source);
    Ok(value)
}

fn format_scalar(
    formatter: impl FnOnce(&mut String) -> std::fmt::Result,
) -> Result<String, QueryFailure> {
    let mut value = String::new();
    value
        .try_reserve_exact(128)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    formatter(&mut value).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    Ok(value)
}

fn map_domain_failure(failure: positron_domain::outcome::DomainFailure) -> QueryFailure {
    if failure.code() == positron_domain::outcome::DomainFailureCode::AllocationUnavailable {
        QueryFailure::new(QueryFailureCode::ResourceExhausted)
    } else {
        unsupported()
    }
}

pub(super) const fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}
