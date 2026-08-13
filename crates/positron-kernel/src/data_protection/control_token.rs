use std::fmt::{Display, Formatter};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::catalog::CatalogSecret;

use super::DataProtection;

const CONTROL_TOKEN_DOMAIN: &[u8] = b"positron-authenticated-control-token-v1\0";
const MAX_PURPOSE_BYTES: usize = 64;
const MAX_PAYLOAD_BYTES: usize = 4_096;

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
