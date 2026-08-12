use std::error::Error;
use std::fmt::{Display, Formatter};

use super::SecretPlaintext;

/// An authenticated encrypted frame ready for persistent storage.
pub(crate) struct EncryptedFrame(pub(super) Vec<u8>);

impl EncryptedFrame {
    /// Returns the stable encrypted frame-v1 artifact bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for EncryptedFrame {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedFrame")
            .field("encoded_bytes", &self.0.len())
            .finish()
    }
}

/// Plaintext from a frame that passed structural, checksum, and AEAD checks.
pub(crate) struct VerifiedFrame(pub(super) SecretPlaintext);

impl VerifiedFrame {
    /// Returns authenticated plaintext to the owning decoder.
    #[must_use]
    pub fn as_plaintext(&self) -> &[u8] {
        &self.0.bytes
    }
}

impl std::fmt::Debug for VerifiedFrame {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedFrame")
            .field("plaintext_bytes", &self.0.bytes.len())
            .finish()
    }
}

/// The stable class of a frame protection or authentication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameFailureCode {
    /// The caller supplied an invalid identity or context.
    InvalidContext,
    /// The caller supplied an invalid finite limit.
    InvalidLimit,
    /// The plaintext or resulting frame exceeded the caller's policy.
    LimitExceeded,
    /// The reviewed cryptographic backend refused frame sealing.
    SealFailed,
    /// The reviewed cryptographic backend refused checksum hashing.
    HashFailed,
    /// The reviewed cryptographic backend could not perform frame opening.
    OpenFailed,
    /// The frame could not be authenticated under the expected key and context.
    AuthenticationFailed,
    /// The frame is truncated or structurally inconsistent.
    MalformedFrame,
    /// The frame names a format version this release cannot read.
    UnsupportedVersion,
    /// The frame names an algorithm this release cannot read.
    UnsupportedAlgorithm,
    /// The keyless ciphertext checksum did not match the stored bytes.
    ChecksumMismatch,
    /// The operating-system entropy source refused fresh key generation.
    EntropyUnavailable,
}

/// A bounded secret-free frame failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameFailure {
    pub(super) code: FrameFailureCode,
}

impl FrameFailure {
    pub(super) const fn new(code: FrameFailureCode) -> Self {
        Self { code }
    }

    /// Returns the stable code intended for caller control flow.
    #[must_use]
    pub const fn code(self) -> FrameFailureCode {
        self.code
    }
}

impl Display for FrameFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("encrypted frame operation failed")
    }
}

impl Error for FrameFailure {}
