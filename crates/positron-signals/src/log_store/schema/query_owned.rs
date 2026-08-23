use positron_domain::value::{ValidatedAttributeValue, ValidatedScalar};

use super::{SchemaFailure, query::SchemaValue};

impl SchemaValue {
    pub(crate) fn try_from_validated_owned(
        value: ValidatedAttributeValue,
    ) -> Result<Self, SchemaFailure> {
        let scalar = value.into_scalar().ok_or(SchemaFailure::InvalidValue)?;
        Ok(match scalar {
            ValidatedScalar::Null => Self::Null,
            ValidatedScalar::Boolean(value) => Self::Boolean(value),
            ValidatedScalar::SignedInteger(value) => Self::SignedInteger(value),
            ValidatedScalar::FloatingPointBits(value) => Self::FloatingPointBits(value),
            ValidatedScalar::String(value) => Self::String(value),
            ValidatedScalar::Bytes(value) => Self::Bytes(value),
        })
    }
}
