use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use std::fmt::Formatter;

use super::{DataProtection, FrameFailure, FrameObjectContext};

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::rc::Rc;

pub(super) struct SecretKeyBytes {
    bytes: Box<[u8; 32]>,
    #[cfg(test)]
    zeroized_before_release: Option<Rc<Cell<bool>>>,
}

impl SecretKeyBytes {
    pub(super) fn from_owned(bytes: Box<[u8; 32]>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            zeroized_before_release: None,
        }
    }

    #[cfg(test)]
    pub(super) fn from_owned_with_observer(
        bytes: Box<[u8; 32]>,
        zeroized_before_release: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            bytes,
            zeroized_before_release: Some(zeroized_before_release),
        }
    }

    pub(super) fn expose_to_backend(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    pub(super) fn expose_to_backend_mut(&mut self) -> &mut [u8] {
        self.bytes.as_mut()
    }
}

impl Drop for SecretKeyBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.zeroized_before_release {
            observer.set(self.bytes.iter().all(|byte| *byte == 0));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CryptoBackendFailure {
    InvalidKey,
    SealFailed,
    AuthenticationFailed,
    EntropyUnavailable,
    HashFailed,
    OpenFailed,
}

pub(super) trait CryptoBackend {
    fn seal_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure>;

    fn open_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecretPlaintext, CryptoBackendFailure>;

    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], CryptoBackendFailure>;

    fn fill_random(&self, destination: &mut [u8]) -> Result<(), CryptoBackendFailure>;
}

pub(super) struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    fn seal_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
        let cipher = Aes256Gcm::new_from_slice(key.expose_to_backend())
            .map_err(|_| CryptoBackendFailure::InvalidKey)?;
        cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoBackendFailure::SealFailed)
    }

    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], CryptoBackendFailure> {
        Ok(Sha256::digest(bytes).into())
    }

    fn open_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecretPlaintext, CryptoBackendFailure> {
        let cipher = Aes256Gcm::new_from_slice(key.expose_to_backend())
            .map_err(|_| CryptoBackendFailure::InvalidKey)?;
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map(SecretPlaintext::new)
            .map_err(|_| CryptoBackendFailure::AuthenticationFailed)
    }

    fn fill_random(&self, destination: &mut [u8]) -> Result<(), CryptoBackendFailure> {
        getrandom::fill(destination).map_err(|_| CryptoBackendFailure::EntropyUnavailable)
    }
}

/// An explicitly secret 256-bit input transferred into an object data key.
///
/// This type intentionally implements neither `Clone`, `Debug`, nor `Display`
/// and exposes no byte accessor. Its memory is zeroized when custody ends.
pub(super) struct SecretKeyInput(pub(super) SecretKeyBytes);

impl SecretKeyInput {
    /// Takes ownership of exactly one AES-256 key buffer.
    ///
    /// Positron zeroizes this owned buffer before releasing it. This makes no
    /// claim about copies created before ownership transfer.
    #[must_use]
    pub(super) fn from_owned(bytes: Box<[u8; 32]>) -> Self {
        Self(SecretKeyBytes::from_owned(bytes))
    }

    #[cfg(test)]
    pub(super) fn from_test_bytes(bytes: [u8; 32]) -> Self {
        Self::from_owned(Box::new(bytes))
    }

    #[cfg(test)]
    pub(super) fn from_owned_for_test(
        bytes: Box<[u8; 32]>,
        zeroized_before_release: Rc<Cell<bool>>,
    ) -> Self {
        Self(SecretKeyBytes::from_owned_with_observer(
            bytes,
            zeroized_before_release,
        ))
    }
}

/// A per-object data key bound to its authoritative identity and epochs.
pub(super) struct ObjectDataKey {
    pub(super) key: SecretKeyBytes,
    pub(super) object: FrameObjectContext,
}

impl ObjectDataKey {
    /// Imports an already recovered per-object data key without exposing it.
    #[must_use]
    pub fn import(input: SecretKeyInput, object: FrameObjectContext) -> Self {
        DataProtection::release().import_object_key(input, object)
    }

    /// Generates a fresh random per-object data key through the Crypto Backend.
    pub fn generate(object: FrameObjectContext) -> Result<Self, FrameFailure> {
        DataProtection::release().generate_object_key(object)
    }
}

impl std::fmt::Debug for ObjectDataKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ObjectDataKey { <redacted> }")
    }
}

pub(super) struct SecretPlaintext {
    pub(super) bytes: Vec<u8>,
    #[cfg(test)]
    zeroized_before_release: Option<Rc<Cell<bool>>>,
}

impl SecretPlaintext {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            zeroized_before_release: None,
        }
    }

    #[cfg(test)]
    pub(super) fn new_for_test(bytes: Vec<u8>, zeroized_before_release: Rc<Cell<bool>>) -> Self {
        Self {
            bytes,
            zeroized_before_release: Some(zeroized_before_release),
        }
    }
}

impl Drop for SecretPlaintext {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.zeroized_before_release {
            observer.set(self.bytes.iter().all(|byte| *byte == 0));
        }
    }
}
