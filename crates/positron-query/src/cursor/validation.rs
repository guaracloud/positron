use super::{
    CURRENT_PREFIX_BYTES, CURSOR_BYTES, MAX_PLAN_SOURCE_BYTES, PAYLOAD_BYTES, QueryCursor,
};
use crate::{QueryFailure, QueryFailureCode};
use positron_kernel::ControlTokenFailure;
#[cfg(fuzzing)]
use positron_kernel::ControlTokenProtector;

#[cfg(fuzzing)]
pub(crate) fn fuzz_reauthenticate(
    protector: &ControlTokenProtector<'_>,
    bytes: &mut [u8],
) -> Result<(), QueryFailure> {
    let payload_bytes = bytes
        .len()
        .checked_sub(32)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let payload = bytes
        .get(..payload_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let authentication = protector
        .authenticate_query_cursor(super::CURSOR_PURPOSE, payload)
        .map_err(map_protection_failure)?;
    bytes
        .get_mut(8..16)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?
        .copy_from_slice(&authentication.epoch().to_be_bytes());
    let payload = bytes
        .get(..payload_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let authentication = protector
        .authenticate_query_cursor(super::CURSOR_PURPOSE, payload)
        .map_err(map_protection_failure)?;
    bytes
        .get_mut(payload_bytes..)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?
        .copy_from_slice(&authentication.tag());
    Ok(())
}

pub(super) fn map_protection_failure(failure: ControlTokenFailure) -> QueryFailure {
    match failure {
        ControlTokenFailure::InvalidInput | ControlTokenFailure::LimitExceeded => {
            QueryFailure::new(QueryFailureCode::InvalidCursor)
        },
        ControlTokenFailure::Authentication | ControlTokenFailure::Custody => {
            QueryFailure::new(QueryFailureCode::Internal)
        },
    }
}

pub(crate) fn source_length(cursor: &QueryCursor) -> Result<u64, QueryFailure> {
    if cursor.as_bytes().len() != CURSOR_BYTES {
        return Ok(0);
    }
    let payload = cursor
        .as_bytes()
        .get(..PAYLOAD_BYTES)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let language = payload
        .get(CURRENT_PREFIX_BYTES + 9)
        .copied()
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    if !matches!(language, 1 | 2) {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    let length = payload
        .get(CURRENT_PREFIX_BYTES + 10..CURRENT_PREFIX_BYTES + 12)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let length = usize::from(length);
    if length > MAX_PLAN_SOURCE_BYTES {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    u64::try_from(length).map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], QueryFailure> {
        let (value, rest) = self
            .bytes
            .split_at_checked(N)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        self.bytes = rest;
        value
            .try_into()
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))
    }

    pub(super) fn bytes(&mut self, length: usize) -> Result<&'a [u8], QueryFailure> {
        let (value, rest) = self
            .bytes
            .split_at_checked(length)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        self.bytes = rest;
        Ok(value)
    }

    pub(super) fn u16(&mut self) -> Result<u16, QueryFailure> {
        self.array().map(u16::from_be_bytes)
    }

    pub(super) fn u64(&mut self) -> Result<u64, QueryFailure> {
        self.array().map(u64::from_be_bytes)
    }

    pub(super) fn i64(&mut self) -> Result<i64, QueryFailure> {
        self.array().map(i64::from_be_bytes)
    }

    pub(super) const fn empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CURRENT_PREFIX_BYTES, CURSOR_BYTES, ControlTokenFailure, QueryCursor, QueryFailureCode,
        map_protection_failure, source_length,
    };

    #[test]
    fn protection_failures_keep_the_cursor_failure_boundary_closed() {
        assert_eq!(
            map_protection_failure(ControlTokenFailure::InvalidInput).code(),
            QueryFailureCode::InvalidCursor
        );
        assert_eq!(
            map_protection_failure(ControlTokenFailure::LimitExceeded).code(),
            QueryFailureCode::InvalidCursor
        );
        assert_eq!(
            map_protection_failure(ControlTokenFailure::Authentication).code(),
            QueryFailureCode::Internal
        );
        assert_eq!(
            map_protection_failure(ControlTokenFailure::Custody).code(),
            QueryFailureCode::Internal
        );
    }

    #[test]
    fn source_length_rejects_unknown_language_and_checked_overflow() {
        assert_eq!(
            source_length(&QueryCursor(vec![0; CURSOR_BYTES - 1]))
                .expect("legacy-sized input is handled before allocation"),
            0
        );

        let mut bytes = vec![0_u8; CURSOR_BYTES];
        bytes[CURRENT_PREFIX_BYTES + 9] = 3;
        assert_eq!(
            source_length(&QueryCursor(bytes.clone()))
                .expect_err("unknown language must fail closed")
                .code(),
            QueryFailureCode::InvalidCursor
        );

        bytes[CURRENT_PREFIX_BYTES + 9] = 1;
        bytes[CURRENT_PREFIX_BYTES + 10..CURRENT_PREFIX_BYTES + 12]
            .copy_from_slice(&4_097_u16.to_be_bytes());
        assert_eq!(
            source_length(&QueryCursor(bytes))
                .expect_err("source length above the checked cap must fail closed")
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }
}
