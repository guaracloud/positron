use super::{CURSOR_BYTES, MAGIC, QueryCursor, V1_CURSOR_BYTES, V3_CURSOR_BYTES};
use crate::{QueryFailure, QueryFailureCode};

impl QueryCursor {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, QueryFailure> {
        if !matches!(
            bytes.len(),
            V1_CURSOR_BYTES | V3_CURSOR_BYTES | CURSOR_BYTES
        ) {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        if bytes.len() == CURSOR_BYTES && bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for QueryCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QueryCursor { <opaque> }")
    }
}
