use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt::{Display, Formatter};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::catalog::CatalogSecret;

use super::DataProtection;

const CONTROL_TOKEN_DOMAIN: &[u8] = b"positron-authenticated-control-token-v1\0";
const MAX_PURPOSE_BYTES: usize = 64;
const MAX_PAYLOAD_BYTES: usize = 4_096;
const QUERY_RESULT_DIGEST_PURPOSE: &[u8] = b"query-result-batch-v1";

/// Data Protection-owned authentication attached to one bounded control payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlTokenAuthentication {
    epoch: u64,
    tag: [u8; 32],
}

impl ControlTokenAuthentication {
    pub fn new(epoch: u64, tag: [u8; 32]) -> Result<Self, ControlTokenFailure> {
        if epoch == 0 {
            return Err(ControlTokenFailure::InvalidInput);
        }
        Ok(Self { epoch, tag })
    }

    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn tag(self) -> [u8; 32] {
        self.tag
    }
}

/// Borrowed Data Protection operation. Key bytes never leave Catalog custody.
pub struct ControlTokenProtector<'key> {
    secret: &'key Mutex<CatalogSecret>,
}

impl<'key> ControlTokenProtector<'key> {
    pub(crate) const fn new(secret: &'key Mutex<CatalogSecret>) -> Self {
        Self { secret }
    }

    pub fn authenticate(
        &self,
        purpose: &[u8],
        payload: &[u8],
    ) -> Result<ControlTokenAuthentication, ControlTokenFailure> {
        let input = control_input(purpose, payload)?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| ControlTokenFailure::Custody)?;
        let tag = DataProtection::authenticate(&secret.marker_key, &input)
            .map_err(|_| ControlTokenFailure::Authentication)?;
        ControlTokenAuthentication::new(secret.wrapping.key_epoch, tag)
    }

    /// Authenticates the payload before any caller-owned decoding is attempted.
    pub fn verify(
        &self,
        purpose: &[u8],
        payload: &[u8],
        authentication: ControlTokenAuthentication,
    ) -> Result<(), ControlTokenFailure> {
        let input = control_input(purpose, payload)?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| ControlTokenFailure::Custody)?;
        if authentication.epoch != secret.wrapping.key_epoch {
            return Err(ControlTokenFailure::Authentication);
        }
        DataProtection::verify_authentication(&secret.marker_key, &input, &authentication.tag)
            .map_err(|_| ControlTokenFailure::Authentication)
    }

    pub fn digest(&self, purpose: &[u8], payload: &[u8]) -> Result<[u8; 32], ControlTokenFailure> {
        let input = control_input(purpose, payload)?;
        DataProtection::hash(&input).map_err(|_| ControlTokenFailure::Authentication)
    }

    /// Starts the narrow streaming authenticator for one logical Query Result Batch.
    ///
    /// This capability is intentionally distinct from bounded control-token payload
    /// authentication: callers may stream a budget-bounded result without materializing it.
    pub fn query_result_digest(&self) -> Result<QueryResultDigest, ControlTokenFailure> {
        let secret = self
            .secret
            .lock()
            .map_err(|_| ControlTokenFailure::Custody)?;
        let mut state =
            <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(secret.marker_key.expose_to_backend())
                .map_err(|_| ControlTokenFailure::Authentication)?;
        state.update(CONTROL_TOKEN_DOMAIN);
        state.update(
            &u16::try_from(QUERY_RESULT_DIGEST_PURPOSE.len())
                .map_err(|_| ControlTokenFailure::LimitExceeded)?
                .to_be_bytes(),
        );
        state.update(QUERY_RESULT_DIGEST_PURPOSE);
        Ok(QueryResultDigest { state })
    }
}

/// Non-cloneable, non-debug streaming state for one authenticated Query Result Batch digest.
pub struct QueryResultDigest {
    state: Hmac<Sha256>,
}

impl QueryResultDigest {
    /// Adds the next canonical logical-output bytes without retaining caller data.
    pub fn update(&mut self, bytes: &[u8]) {
        self.state.update(bytes);
    }

    /// Finalizes exactly once and consumes the secret-bearing state.
    pub fn finalize(self) -> Result<[u8; 32], ControlTokenFailure> {
        Ok(self.state.finalize().into_bytes().into())
    }
}

fn control_input(
    purpose: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ControlTokenFailure> {
    if purpose.is_empty() || purpose.len() > MAX_PURPOSE_BYTES || payload.len() > MAX_PAYLOAD_BYTES
    {
        return Err(ControlTokenFailure::LimitExceeded);
    }
    let mut input = Zeroizing::new(Vec::with_capacity(
        CONTROL_TOKEN_DOMAIN.len() + 2 + purpose.len() + payload.len(),
    ));
    input.extend_from_slice(CONTROL_TOKEN_DOMAIN);
    input.extend_from_slice(
        &u16::try_from(purpose.len())
            .map_err(|_| ControlTokenFailure::LimitExceeded)?
            .to_be_bytes(),
    );
    input.extend_from_slice(purpose);
    input.extend_from_slice(payload);
    Ok(input)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlTokenFailure {
    InvalidInput,
    LimitExceeded,
    Authentication,
    Custody,
}

impl Display for ControlTokenFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("authenticated control token operation failed")
    }
}

impl std::error::Error for ControlTokenFailure {}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::ControlTokenProtector;
    use crate::catalog::CatalogSecret;

    #[test]
    fn query_result_digest_is_chunk_independent_and_uses_stable_authenticated_framing() {
        let secret = Mutex::new(CatalogSecret::from_owned(
            Box::new([0x21; 32]),
            Box::new([0x31; 32]),
        ));
        let protector = ControlTokenProtector::new(&secret);
        let mut whole = protector.query_result_digest().expect("digest context");
        whole.update(b"bounded logical output");
        let whole = whole.finalize().expect("digest finalization");

        let mut chunked = protector.query_result_digest().expect("digest context");
        chunked.update(b"bounded ");
        chunked.update(b"logical ");
        chunked.update(b"output");

        assert_eq!(whole, chunked.finalize().expect("digest finalization"));
        assert_eq!(
            whole,
            [
                0x0d, 0x41, 0xf4, 0xe7, 0x4d, 0xa9, 0xf9, 0x59, 0x48, 0x6c, 0x0c, 0xc0, 0xdd, 0x9b,
                0x79, 0x16, 0x8a, 0x50, 0xb2, 0x7b, 0xf5, 0x58, 0x37, 0x3f, 0xae, 0x01, 0xcc, 0x84,
                0xb0, 0xbc, 0x4e, 0x1c,
            ]
        );
    }
}
