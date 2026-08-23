use super::{Input, put_bytes};
use crate::log_store::SchemaFailure;
use crate::log_store::schema::model::MAX_SCALAR_VALUE_BYTES;
use crate::log_store::schema::query::SchemaValue;

#[derive(Clone, Copy)]
enum ScalarTag {
    Null,
    Boolean,
    SignedInteger,
    FloatingPointBits,
    String,
    Bytes,
}

impl ScalarTag {
    fn from_byte(byte: u8) -> Result<Self, SchemaFailure> {
        match byte {
            0 => Ok(Self::Null),
            1 => Ok(Self::Boolean),
            2 => Ok(Self::SignedInteger),
            3 => Ok(Self::FloatingPointBits),
            4 => Ok(Self::String),
            5 => Ok(Self::Bytes),
            _ => Err(SchemaFailure::MalformedCatalog),
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::Null => 0,
            Self::Boolean => 1,
            Self::SignedInteger => 2,
            Self::FloatingPointBits => 3,
            Self::String => 4,
            Self::Bytes => 5,
        }
    }
}

fn value_tag(value: &SchemaValue) -> Result<ScalarTag, SchemaFailure> {
    match value {
        SchemaValue::Null => Ok(ScalarTag::Null),
        SchemaValue::Boolean(_) => Ok(ScalarTag::Boolean),
        SchemaValue::SignedInteger(_) => Ok(ScalarTag::SignedInteger),
        SchemaValue::FloatingPointBits(_) => Ok(ScalarTag::FloatingPointBits),
        SchemaValue::String(_) => Ok(ScalarTag::String),
        SchemaValue::Bytes(_) => Ok(ScalarTag::Bytes),
        SchemaValue::Kind(_) => Err(SchemaFailure::InvalidValue),
    }
}

pub(super) fn put_value(bytes: &mut Vec<u8>, value: &SchemaValue) -> Result<(), SchemaFailure> {
    let tag = value_tag(value)?;
    bytes.push(tag.byte());
    match value {
        SchemaValue::Null => {},
        SchemaValue::Boolean(value) => bytes.push(u8::from(*value)),
        SchemaValue::SignedInteger(value) => bytes.extend_from_slice(&value.to_be_bytes()),
        SchemaValue::FloatingPointBits(value) => bytes.extend_from_slice(&value.to_be_bytes()),
        SchemaValue::String(value) => {
            if value.len() > MAX_SCALAR_VALUE_BYTES {
                return Err(SchemaFailure::LimitExceeded);
            }
            put_bytes(bytes, value.as_bytes())?;
        },
        SchemaValue::Bytes(value) => {
            if value.len() > MAX_SCALAR_VALUE_BYTES {
                return Err(SchemaFailure::LimitExceeded);
            }
            put_bytes(bytes, value)?;
        },
        SchemaValue::Kind(_) => return Err(SchemaFailure::InvalidValue),
    }
    Ok(())
}

pub(super) fn preflight_value(input: &mut Input<'_>) -> Result<usize, SchemaFailure> {
    let tag = ScalarTag::from_byte(input.u8()?)?;
    let payload = match tag {
        ScalarTag::Null => 0,
        ScalarTag::Boolean => {
            if input.u8()? > 1 {
                return Err(SchemaFailure::MalformedCatalog);
            }
            1
        },
        ScalarTag::SignedInteger | ScalarTag::FloatingPointBits => {
            input.take(8)?;
            8
        },
        ScalarTag::String | ScalarTag::Bytes => {
            let length = input.usize()?;
            if length > MAX_SCALAR_VALUE_BYTES {
                return Err(SchemaFailure::MalformedCatalog);
            }
            let bytes = input.take(length)?;
            if matches!(tag, ScalarTag::String) && std::str::from_utf8(bytes).is_err() {
                return Err(SchemaFailure::MalformedCatalog);
            }
            length
        },
    };
    std::mem::size_of::<SchemaValue>()
        .checked_add(payload)
        .ok_or(SchemaFailure::MalformedCatalog)
}

pub(super) fn decode_value(input: &mut Input<'_>) -> Result<SchemaValue, SchemaFailure> {
    match ScalarTag::from_byte(input.u8()?)? {
        ScalarTag::Null => Ok(SchemaValue::Null),
        ScalarTag::Boolean => Ok(SchemaValue::Boolean(input.u8()? == 1)),
        ScalarTag::SignedInteger => Ok(SchemaValue::SignedInteger(i64::from_be_bytes(
            input.array()?,
        ))),
        ScalarTag::FloatingPointBits => Ok(SchemaValue::FloatingPointBits(u64::from_be_bytes(
            input.array()?,
        ))),
        ScalarTag::String => {
            let length = input.usize()?;
            if length > MAX_SCALAR_VALUE_BYTES {
                return Err(SchemaFailure::MalformedCatalog);
            }
            let bytes = input.take(length)?;
            let value = std::str::from_utf8(bytes).map_err(|_| SchemaFailure::MalformedCatalog)?;
            let mut decoded = String::new();
            decoded
                .try_reserve_exact(length)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            decoded.push_str(value);
            Ok(SchemaValue::String(decoded))
        },
        ScalarTag::Bytes => {
            let length = input.usize()?;
            if length > MAX_SCALAR_VALUE_BYTES {
                return Err(SchemaFailure::MalformedCatalog);
            }
            let source = input.take(length)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            bytes.extend_from_slice(source);
            Ok(SchemaValue::Bytes(bytes))
        },
    }
}
