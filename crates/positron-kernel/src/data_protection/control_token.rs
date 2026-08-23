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
pub const QUERY_CURSOR_MAX_PAYLOAD_BYTES: usize = 8_192;
const QUERY_PLAN_DIGEST_MAX_PAYLOAD_BYTES: usize = 65_536;
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
        self.authenticate_bounded(purpose, payload, MAX_PAYLOAD_BYTES)
    }

    /// Authenticates a bounded Query Cursor payload under its dedicated wire
    /// limit. Other control-token purposes remain governed by the 4 KiB
    /// generic limit.
    pub fn authenticate_query_cursor(
        &self,
        purpose: &[u8],
        payload: &[u8],
    ) -> Result<ControlTokenAuthentication, ControlTokenFailure> {
        self.authenticate_bounded(purpose, payload, QUERY_CURSOR_MAX_PAYLOAD_BYTES)
    }

    fn authenticate_bounded(
        &self,
        purpose: &[u8],
        payload: &[u8],
        maximum_payload_bytes: usize,
    ) -> Result<ControlTokenAuthentication, ControlTokenFailure> {
        let input = control_input(purpose, payload, maximum_payload_bytes)?;
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
        self.verify_bounded(purpose, payload, authentication, MAX_PAYLOAD_BYTES)
    }

    /// Verifies a Query Cursor payload under its dedicated wire limit.
    pub fn verify_query_cursor(
        &self,
        purpose: &[u8],
        payload: &[u8],
        authentication: ControlTokenAuthentication,
    ) -> Result<(), ControlTokenFailure> {
        self.verify_bounded(
            purpose,
            payload,
            authentication,
            QUERY_CURSOR_MAX_PAYLOAD_BYTES,
        )
    }

    fn verify_bounded(
        &self,
        purpose: &[u8],
        payload: &[u8],
        authentication: ControlTokenAuthentication,
        maximum_payload_bytes: usize,
    ) -> Result<(), ControlTokenFailure> {
        let input = control_input(purpose, payload, maximum_payload_bytes)?;
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
        let input = control_input(purpose, payload, MAX_PAYLOAD_BYTES)?;
        DataProtection::hash(&input).map_err(|_| ControlTokenFailure::Authentication)
    }

    /// Hashes a Query Cursor plan payload under the dedicated cursor bound.
    pub fn digest_query_cursor(
        &self,
        purpose: &[u8],
        payload: &[u8],
    ) -> Result<[u8; 32], ControlTokenFailure> {
        let input = control_input(purpose, payload, QUERY_CURSOR_MAX_PAYLOAD_BYTES)?;
        DataProtection::hash(&input).map_err(|_| ControlTokenFailure::Authentication)
    }

    /// Hashes one bounded canonical LogicalPlan without changing the
    /// authenticated cursor wire-payload ceiling. This purpose-specific
    /// opening is used only for the semantic plan digest.
    pub fn digest_query_plan(
        &self,
        purpose: &[u8],
        payload: &[u8],
    ) -> Result<[u8; 32], ControlTokenFailure> {
        let input = control_input(purpose, payload, QUERY_PLAN_DIGEST_MAX_PAYLOAD_BYTES)?;
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

/// Returns a deterministic authenticator for the bounded fuzz adapters.
///
/// The key is process-local fuzz fixture data and is only compiled into fuzz
/// builds; production callers can obtain a protector only through Catalog
/// custody.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_control_token_protector() -> ControlTokenProtector<'static> {
    static SECRET: std::sync::OnceLock<Mutex<CatalogSecret>> = std::sync::OnceLock::new();
    let secret = SECRET.get_or_init(|| {
        Mutex::new(CatalogSecret::from_owned(
            Box::new([0x21; 32]),
            Box::new([0x31; 32]),
        ))
    });
    ControlTokenProtector::new(secret)
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
    maximum_payload_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, ControlTokenFailure> {
    if purpose.is_empty()
        || purpose.len() > MAX_PURPOSE_BYTES
        || payload.len() > maximum_payload_bytes
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

    use super::{ControlTokenAuthentication, ControlTokenProtector, MAX_PAYLOAD_BYTES};
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

    #[test]
    fn query_cursor_payload_has_a_dedicated_limit_without_widening_generic_tokens() {
        assert_eq!(
            ControlTokenAuthentication::new(0, [0; 32]).expect_err("zero epochs are invalid"),
            super::ControlTokenFailure::InvalidInput
        );
        let secret = Mutex::new(CatalogSecret::from_owned(
            Box::new([0x41; 32]),
            Box::new([0x51; 32]),
        ));
        let protector = ControlTokenProtector::new(&secret);
        assert!(
            protector
                .authenticate(b"generic", &vec![0; MAX_PAYLOAD_BYTES])
                .is_ok()
        );
        let authentication = protector
            .authenticate(b"generic", b"stable")
            .expect("generic authentication must produce a token");
        assert!(
            protector
                .verify(b"generic", b"stable", authentication)
                .is_ok()
        );
        let stale =
            ControlTokenAuthentication::new(authentication.epoch() + 1, authentication.tag())
                .expect("non-zero epoch is a valid authentication shape");
        assert_eq!(
            protector
                .verify(b"generic", b"stable", stale)
                .expect_err("stale epochs must fail closed"),
            super::ControlTokenFailure::Authentication
        );
        let mut wrong_tag = authentication.tag();
        wrong_tag[0] ^= 1;
        let wrong_tag = ControlTokenAuthentication::new(authentication.epoch(), wrong_tag)
            .expect("non-zero epoch is a valid authentication shape");
        assert_eq!(
            protector
                .verify(b"generic", b"stable", wrong_tag)
                .expect_err("tampered tags must fail closed"),
            super::ControlTokenFailure::Authentication
        );
        assert_eq!(
            protector
                .authenticate(b"generic", &vec![0; MAX_PAYLOAD_BYTES + 1])
                .expect_err("generic payload growth must remain bounded"),
            super::ControlTokenFailure::LimitExceeded
        );
        assert!(
            protector
                .authenticate_query_cursor(
                    b"query-cursor-v1",
                    &vec![0; super::QUERY_CURSOR_MAX_PAYLOAD_BYTES]
                )
                .is_ok()
        );
        assert_eq!(
            protector
                .authenticate_query_cursor(
                    b"query-cursor-v1",
                    &vec![0; super::QUERY_CURSOR_MAX_PAYLOAD_BYTES + 1]
                )
                .expect_err("query cursor payload growth must remain bounded"),
            super::ControlTokenFailure::LimitExceeded
        );
        assert_eq!(
            super::ControlTokenFailure::Authentication.to_string(),
            "authenticated control token operation failed"
        );
    }
}
