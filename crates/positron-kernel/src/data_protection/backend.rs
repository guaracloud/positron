use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use std::fmt::Formatter;

use super::{DataProtection, FrameFailure, FrameObjectContext};

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::rc::Rc;

pub(crate) struct SecretKeyBytes {
    bytes: Box<[u8; 32]>,
    #[cfg(test)]
    zeroized_before_release: Option<Rc<Cell<bool>>>,
}

impl SecretKeyBytes {
    pub(crate) fn from_owned(bytes: Box<[u8; 32]>) -> Self {
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

    pub(crate) fn expose_to_backend(&self) -> &[u8; 32] {
        self.bytes.as_ref()
    }

    pub(crate) fn expose_to_backend_mut(&mut self) -> &mut [u8; 32] {
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
    WrapFailed,
    UnwrapFailed,
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

    fn hmac_sha256(
        &self,
        key: &SecretKeyBytes,
        bytes: &[u8],
    ) -> Result<[u8; 32], CryptoBackendFailure> {
        RustCryptoBackend.hmac_sha256(key, bytes)
    }

    fn verify_hmac_sha256(
        &self,
        key: &SecretKeyBytes,
        bytes: &[u8],
        expected: &[u8; 32],
    ) -> Result<(), CryptoBackendFailure> {
        RustCryptoBackend.verify_hmac_sha256(key, bytes, expected)
    }

    fn wrap_key_aes_256_kwp(
        &self,
        key: &SecretKeyBytes,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
        RustCryptoBackend.wrap_key_aes_256_kwp(key, plaintext)
    }

    fn unwrap_key_aes_256_kwp(
        &self,
        key: &SecretKeyBytes,
        wrapped: &[u8],
    ) -> Result<SecretPlaintext, CryptoBackendFailure> {
        RustCryptoBackend.unwrap_key_aes_256_kwp(key, wrapped)
    }
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
        // The pinned sha2 `zeroize` feature makes the concrete SHA-256
        // context zeroize its internal state, length, and private block-buffer
        // bytes and position on drop. This does not make a claim about caller
        // input custody or copies outside that reviewed context.
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

    fn hmac_sha256(
        &self,
        key: &SecretKeyBytes,
        bytes: &[u8],
    ) -> Result<[u8; 32], CryptoBackendFailure> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.expose_to_backend())
            .map_err(|_| CryptoBackendFailure::InvalidKey)?;
        mac.update(bytes);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_hmac_sha256(
        &self,
        key: &SecretKeyBytes,
        bytes: &[u8],
        expected: &[u8; 32],
    ) -> Result<(), CryptoBackendFailure> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.expose_to_backend())
            .map_err(|_| CryptoBackendFailure::InvalidKey)?;
        mac.update(bytes);
        mac.verify_slice(expected)
            .map_err(|_| CryptoBackendFailure::AuthenticationFailed)
    }

    fn wrap_key_aes_256_kwp(
        &self,
        key: &SecretKeyBytes,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
        aes_kwp_wrap(key, plaintext)
    }

    fn unwrap_key_aes_256_kwp(
        &self,
        key: &SecretKeyBytes,
        wrapped: &[u8],
    ) -> Result<SecretPlaintext, CryptoBackendFailure> {
        aes_kwp_unwrap(key, wrapped)
    }
}

const KWP_AIV_PREFIX: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];
const MAX_KWP_PLAINTEXT_BYTES: usize = 4_096;

fn aes_kwp_wrap(
    wrapping_key: &SecretKeyBytes,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoBackendFailure> {
    let plaintext_bytes = u32::try_from(plaintext.len())
        .ok()
        .filter(|length| *length != 0 && plaintext.len() <= MAX_KWP_PLAINTEXT_BYTES)
        .ok_or(CryptoBackendFailure::WrapFailed)?;
    let block_count = plaintext
        .len()
        .checked_add(7)
        .map(|length| length / 8)
        .ok_or(CryptoBackendFailure::WrapFailed)?;
    let cipher = Aes256::new_from_slice(wrapping_key.expose_to_backend())
        .map_err(|_| CryptoBackendFailure::InvalidKey)?;
    let mut a = [0_u8; 8];
    a[..4].copy_from_slice(&KWP_AIV_PREFIX);
    a[4..].copy_from_slice(&plaintext_bytes.to_be_bytes());
    let mut r = Zeroizing::new(vec![[0_u8; 8]; block_count]);
    for (slot, chunk) in r.iter_mut().zip(plaintext.chunks(8)) {
        slot[..chunk.len()].copy_from_slice(chunk);
    }
    if block_count == 1 {
        let mut block = aes::Block::default();
        block[..8].copy_from_slice(&a);
        block[8..].copy_from_slice(&r[0]);
        cipher.encrypt_block(&mut block);
        let wrapped = block.to_vec();
        block.zeroize();
        return Ok(wrapped);
    }
    for round in 0_u64..6 {
        for (index, chunk) in r.iter_mut().enumerate() {
            let mut block = aes::Block::default();
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            let step = round
                .checked_mul(block_count as u64)
                .and_then(|value| value.checked_add(index as u64 + 1))
                .ok_or(CryptoBackendFailure::WrapFailed)?;
            a.copy_from_slice(&block[..8]);
            for (byte, mask) in a.iter_mut().zip(step.to_be_bytes()) {
                *byte ^= mask;
            }
            chunk.copy_from_slice(&block[8..]);
            block.zeroize();
        }
    }
    let capacity = block_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(8))
        .ok_or(CryptoBackendFailure::WrapFailed)?;
    let mut wrapped = Vec::with_capacity(capacity);
    wrapped.extend_from_slice(&a);
    for source in r.iter() {
        wrapped.extend_from_slice(source);
    }
    Ok(wrapped)
}

fn aes_kwp_unwrap(
    wrapping_key: &SecretKeyBytes,
    wrapped: &[u8],
) -> Result<SecretPlaintext, CryptoBackendFailure> {
    if wrapped.len() < 16
        || !wrapped.len().is_multiple_of(8)
        || wrapped.len() > MAX_KWP_PLAINTEXT_BYTES + 8
    {
        return Err(CryptoBackendFailure::UnwrapFailed);
    }
    let block_count = wrapped.len() / 8 - 1;
    let cipher = Aes256::new_from_slice(wrapping_key.expose_to_backend())
        .map_err(|_| CryptoBackendFailure::InvalidKey)?;
    let (mut a, mut r) = if block_count == 1 {
        let mut block = aes::Block::clone_from_slice(wrapped);
        cipher.decrypt_block(&mut block);
        let a: [u8; 8] = block[..8]
            .try_into()
            .map_err(|_| CryptoBackendFailure::UnwrapFailed)?;
        let mut r = Zeroizing::new(vec![[0_u8; 8]; 1]);
        r[0].copy_from_slice(&block[8..]);
        block.zeroize();
        (a, r)
    } else {
        let a: [u8; 8] = wrapped[..8]
            .try_into()
            .map_err(|_| CryptoBackendFailure::UnwrapFailed)?;
        let mut r = Zeroizing::new(vec![[0_u8; 8]; block_count]);
        for (slot, chunk) in r.iter_mut().zip(wrapped[8..].chunks_exact(8)) {
            slot.copy_from_slice(chunk);
        }
        (a, r)
    };
    if block_count != 1 {
        for round in (0_u64..6).rev() {
            for (index, chunk) in r.iter_mut().enumerate().rev() {
                let step = round
                    .checked_mul(block_count as u64)
                    .and_then(|value| value.checked_add(index as u64 + 1))
                    .ok_or(CryptoBackendFailure::UnwrapFailed)?;
                let mut block = aes::Block::default();
                for ((destination, byte), mask) in
                    block[..8].iter_mut().zip(a).zip(step.to_be_bytes())
                {
                    *destination = byte ^ mask;
                }
                block[8..].copy_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                a.copy_from_slice(&block[..8]);
                chunk.copy_from_slice(&block[8..]);
                block.zeroize();
            }
        }
    }
    let mut expected_aiv = [0_u8; 8];
    expected_aiv[..4].copy_from_slice(&KWP_AIV_PREFIX);
    let plaintext_bytes = u32::from_be_bytes(
        a[4..]
            .try_into()
            .map_err(|_| CryptoBackendFailure::UnwrapFailed)?,
    );
    expected_aiv[4..].copy_from_slice(&plaintext_bytes.to_be_bytes());
    let plaintext_bytes =
        usize::try_from(plaintext_bytes).map_err(|_| CryptoBackendFailure::UnwrapFailed)?;
    let padded_bytes = block_count
        .checked_mul(8)
        .ok_or(CryptoBackendFailure::UnwrapFailed)?;
    let minimum_bytes = padded_bytes.saturating_sub(7);
    let padding_difference = r
        .iter()
        .flatten()
        .skip(plaintext_bytes)
        .fold(0_u8, |difference, byte| difference | *byte);
    if a.ct_eq(&expected_aiv).unwrap_u8() != 1
        || plaintext_bytes < minimum_bytes
        || plaintext_bytes > padded_bytes
        || padding_difference != 0
    {
        return Err(CryptoBackendFailure::UnwrapFailed);
    }
    let mut plaintext = Vec::with_capacity(padded_bytes);
    for source in r.iter() {
        plaintext.extend_from_slice(source);
    }
    plaintext.truncate(plaintext_bytes);
    Ok(SecretPlaintext::new(plaintext))
}

/// An explicitly secret 256-bit input transferred into an object data key.
///
/// This type intentionally implements neither `Clone`, `Debug`, nor `Display`
/// and exposes no byte accessor. Its memory is zeroized when custody ends.
pub(crate) struct SecretKeyInput(pub(super) SecretKeyBytes);

impl SecretKeyInput {
    /// Takes ownership of exactly one AES-256 key buffer.
    ///
    /// Positron zeroizes this owned buffer before releasing it. This makes no
    /// claim about copies created before ownership transfer.
    #[must_use]
    pub(crate) fn from_owned(bytes: Box<[u8; 32]>) -> Self {
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
pub(crate) struct ObjectDataKey {
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

    pub(super) fn len(&self) -> usize {
        self.bytes.len()
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
