//! Authenticated encrypted-frame ownership for the Storage Kernel.
//!
//! Frame v1 is `20-byte authenticated header || 32-byte SHA-256 checksum ||
//! ciphertext || 16-byte AES-GCM tag`. The authenticated header contains the
//! magic, frame version, algorithm identifier, frame sequence, and the length
//! of `ciphertext || tag`. The checksum also covers `ciphertext || tag`; it is
//! useful for keyless corruption detection, while the AES-GCM tag remains the
//! authority for authenticity. AEAD associated data additionally binds the
//! tenant or system scope, object class, signal and Virtual Shard when
//! applicable, object identity, Key Epoch, Format Epoch, and payload purpose.
//!
//! The 96-bit nonce is an injective v1 domain prefix plus the big-endian frame
//! sequence. Consequently, sequence values must never repeat under one object
//! data key. A legitimate immutable frame is intentionally rereadable at its
//! exact authoritative address. Rejecting duplicate sequence admission and
//! persisting the next sequence belong to the Active Segment Ledger.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use std::error::Error;
use std::fmt::{Display, Formatter};

const FRAME_MAGIC: [u8; 4] = *b"PFRM";
const FRAME_VERSION: u16 = 1;
const AES_256_GCM_ALGORITHM: u16 = 1;
const AES_256_GCM_TAG_BYTES: u32 = 16;
const FRAME_HEADER_BYTES: u32 = 52;
const MINIMUM_ENCODED_FRAME_BYTES: u32 = FRAME_HEADER_BYTES + AES_256_GCM_TAG_BYTES;
const FRAME_AAD_DOMAIN: &[u8] = b"positron-frame-aad-v1";
const FRAME_NONCE_DOMAIN: [u8; 4] = [0x50, 0x46, 0x52, 0x01];

struct SecretKeyBytes(Zeroizing<[u8; 32]>);

impl SecretKeyBytes {
    fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn expose_to_backend(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn expose_to_backend_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CryptoBackendFailure {
    InvalidKey,
    EncryptionFailed,
    EntropyUnavailable,
}

trait CryptoBackend {
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
    ) -> Result<Vec<u8>, CryptoBackendFailure>;

    fn sha256(&self, bytes: &[u8]) -> [u8; 32];

    fn fill_random(&self, destination: &mut [u8]) -> Result<(), CryptoBackendFailure>;
}

struct RustCryptoBackend;

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
            .map_err(|_| CryptoBackendFailure::EncryptionFailed)
    }

    fn sha256(&self, bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn open_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
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
            .map_err(|_| CryptoBackendFailure::EncryptionFailed)
    }

    fn fill_random(&self, destination: &mut [u8]) -> Result<(), CryptoBackendFailure> {
        getrandom::fill(destination).map_err(|_| CryptoBackendFailure::EntropyUnavailable)
    }
}

/// An explicitly secret 256-bit input transferred into an object data key.
///
/// This type intentionally implements neither `Clone`, `Debug`, nor `Display`
/// and exposes no byte accessor. Its memory is zeroized when custody ends.
pub struct SecretKeyInput(SecretKeyBytes);

impl SecretKeyInput {
    /// Takes custody of exactly one AES-256 key.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(SecretKeyBytes::new(bytes))
    }
}

/// The immutable identity of one encrypted persistent object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameObjectId([u8; 16]);

impl FrameObjectId {
    /// Creates a non-sentinel persistent object identity.
    pub fn new(bytes: [u8; 16]) -> Result<Self, FrameFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(FrameFailure::new(FrameFailureCode::InvalidContext))
        } else {
            Ok(Self(bytes))
        }
    }
}

/// The immutable generation of key material protecting an object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyEpoch(u64);

impl KeyEpoch {
    /// Creates an exact immutable key epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// The independently versioned persistent format generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatEpoch(u32);

impl FormatEpoch {
    /// Creates a non-zero Format Epoch.
    pub const fn new(value: u32) -> Result<Self, FrameFailure> {
        if value == 0 {
            Err(FrameFailure::new(FrameFailureCode::InvalidContext))
        } else {
            Ok(Self(value))
        }
    }
}

/// The immutable sequence of one frame under its object data key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameSequence(u64);

impl FrameSequence {
    /// Creates an exact frame sequence selected by the object's sequence owner.
    ///
    /// This constructor does not allocate or persist sequence values. The
    /// caller must never reuse a sequence under the same object data key.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// The segment payload purpose authenticated with one frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentFramePurpose {
    /// A canonical Signal Store block.
    StoreBlock,
    /// A Signal Store index extent.
    Index,
    /// Signal Store statistics.
    Statistics,
    /// Segment metadata.
    SegmentMetadata,
}

impl SegmentFramePurpose {
    const fn tag(self) -> u8 {
        match self {
            Self::StoreBlock => 1,
            Self::Index => 2,
            Self::Statistics => 3,
            Self::SegmentMetadata => 4,
        }
    }
}

/// The kernel-owned non-telemetry persistent object protected by one DEK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemObjectKind {
    /// An immutable Catalog Object.
    Catalog,
    /// An immutable manifest.
    Manifest,
    /// Governance Audit Store content.
    GovernanceAudit,
    /// Backup snapshot metadata.
    BackupMetadata,
}

impl SystemObjectKind {
    const fn class_tag(self) -> u8 {
        match self {
            Self::Catalog => 2,
            Self::Manifest => 3,
            Self::GovernanceAudit => 4,
            Self::BackupMetadata => 5,
        }
    }

    const fn purpose_tag(self) -> u8 {
        match self {
            Self::Catalog => 5,
            Self::Manifest => 6,
            Self::GovernanceAudit => 7,
            Self::BackupMetadata => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameScope {
    Tenant(TenantId),
    System,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameObjectClass {
    Segment {
        signal: SignalKind,
        shard: VirtualShardId,
    },
    System(SystemObjectKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FramePurpose {
    Segment(SegmentFramePurpose),
    System(SystemObjectKind),
}

impl FramePurpose {
    const fn tag(self) -> u8 {
        match self {
            Self::Segment(purpose) => purpose.tag(),
            Self::System(kind) => kind.purpose_tag(),
        }
    }
}

/// The authoritative identity and epoch binding for one encrypted object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameObjectContext {
    scope: FrameScope,
    class: FrameObjectClass,
    object_id: FrameObjectId,
    key_epoch: KeyEpoch,
    format_epoch: FormatEpoch,
}

impl FrameObjectContext {
    /// Binds one segment object to an exact tenant, signal, and Virtual Shard.
    #[must_use]
    pub const fn tenant_segment(
        tenant: TenantId,
        signal: SignalKind,
        shard: VirtualShardId,
        object_id: FrameObjectId,
        key_epoch: KeyEpoch,
        format_epoch: FormatEpoch,
    ) -> Self {
        Self {
            scope: FrameScope::Tenant(tenant),
            class: FrameObjectClass::Segment { signal, shard },
            object_id,
            key_epoch,
            format_epoch,
        }
    }

    /// Binds one kernel-owned system object to its exact kind and epochs.
    #[must_use]
    pub const fn system(
        kind: SystemObjectKind,
        object_id: FrameObjectId,
        key_epoch: KeyEpoch,
        format_epoch: FormatEpoch,
    ) -> Self {
        Self {
            scope: FrameScope::System,
            class: FrameObjectClass::System(kind),
            object_id,
            key_epoch,
            format_epoch,
        }
    }

    /// Creates the authoritative context for one segment frame.
    pub const fn frame(
        self,
        purpose: SegmentFramePurpose,
        sequence: FrameSequence,
    ) -> Result<FrameContext, FrameFailure> {
        match self.class {
            FrameObjectClass::Segment { .. } => Ok(FrameContext {
                object: self,
                purpose: FramePurpose::Segment(purpose),
                sequence,
            }),
            FrameObjectClass::System(_) => Err(FrameFailure::new(FrameFailureCode::InvalidContext)),
        }
    }

    /// Creates the authoritative frame context for one system object extent.
    pub const fn system_frame(self, sequence: FrameSequence) -> Result<FrameContext, FrameFailure> {
        match self.class {
            FrameObjectClass::System(kind) => Ok(FrameContext {
                object: self,
                purpose: FramePurpose::System(kind),
                sequence,
            }),
            FrameObjectClass::Segment { .. } => {
                Err(FrameFailure::new(FrameFailureCode::InvalidContext))
            },
        }
    }

    fn encode(self, purpose: FramePurpose, destination: &mut Vec<u8>) {
        match self.scope {
            FrameScope::Tenant(tenant) => {
                destination.push(1);
                destination.extend_from_slice(&tenant.to_bytes());
            },
            FrameScope::System => {
                destination.push(2);
                destination.extend_from_slice(&[0_u8; 16]);
            },
        }
        match self.class {
            FrameObjectClass::Segment { signal, shard } => {
                destination.push(1);
                destination.push(match signal {
                    SignalKind::Logs => 1,
                    SignalKind::Traces => 2,
                });
                destination.extend_from_slice(&shard.value().to_be_bytes());
            },
            FrameObjectClass::System(kind) => {
                destination.push(kind.class_tag());
                destination.push(0);
                destination.extend_from_slice(&0_u32.to_be_bytes());
            },
        }
        destination.extend_from_slice(&self.object_id.0);
        destination.extend_from_slice(&self.key_epoch.0.to_be_bytes());
        destination.extend_from_slice(&self.format_epoch.0.to_be_bytes());
        destination.push(purpose.tag());
    }
}

/// The complete authoritative context for one independently encrypted frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameContext {
    object: FrameObjectContext,
    purpose: FramePurpose,
    sequence: FrameSequence,
}

/// A finite caller-owned encoded-frame policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameLimits {
    max_encoded_bytes: u32,
}

impl FrameLimits {
    /// Creates a finite policy large enough to hold the fixed header and tag.
    pub const fn new(max_encoded_bytes: u32) -> Result<Self, FrameFailure> {
        if max_encoded_bytes < MINIMUM_ENCODED_FRAME_BYTES {
            Err(FrameFailure::new(FrameFailureCode::InvalidLimit))
        } else {
            Ok(Self { max_encoded_bytes })
        }
    }
}

/// A per-object data key bound to its authoritative identity and epochs.
pub struct ObjectDataKey {
    key: SecretKeyBytes,
    object: FrameObjectContext,
}

impl ObjectDataKey {
    /// Imports an already recovered per-object data key without exposing it.
    #[must_use]
    pub fn import(input: SecretKeyInput, object: FrameObjectContext) -> Self {
        Self {
            key: input.0,
            object,
        }
    }

    /// Generates a fresh random per-object data key through the Crypto Backend.
    pub fn generate(object: FrameObjectContext) -> Result<Self, FrameFailure> {
        let backend = RustCryptoBackend;
        let mut key = SecretKeyBytes::new([0_u8; 32]);
        backend
            .fill_random(key.expose_to_backend_mut())
            .map_err(|_| FrameFailure::new(FrameFailureCode::EntropyUnavailable))?;
        Ok(Self { key, object })
    }
}

impl std::fmt::Debug for ObjectDataKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ObjectDataKey { <redacted> }")
    }
}

/// An authenticated encrypted frame ready for persistent storage.
pub struct EncryptedFrame(Vec<u8>);

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
pub struct VerifiedFrame(Zeroizing<Vec<u8>>);

impl VerifiedFrame {
    /// Returns authenticated plaintext to the owning decoder.
    #[must_use]
    pub fn as_plaintext(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Debug for VerifiedFrame {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedFrame")
            .field("plaintext_bytes", &self.0.len())
            .finish()
    }
}

/// The stable class of a frame protection or authentication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameFailureCode {
    /// The caller supplied an invalid identity or context.
    InvalidContext,
    /// The caller supplied an invalid finite limit.
    InvalidLimit,
    /// The plaintext or resulting frame exceeded the caller's policy.
    LimitExceeded,
    /// The reviewed cryptographic backend refused the operation.
    CryptoBackendFailure,
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
pub struct FrameFailure {
    code: FrameFailureCode,
}

impl FrameFailure {
    const fn new(code: FrameFailureCode) -> Self {
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

/// The Storage Kernel's authenticated encrypted-frame entry point.
pub enum DataProtection {}

impl DataProtection {
    /// Protects plaintext as one independently authenticated frame-v1 artifact.
    pub fn protect_frame(
        key: &ObjectDataKey,
        context: FrameContext,
        plaintext: &[u8],
        limits: FrameLimits,
    ) -> Result<EncryptedFrame, FrameFailure> {
        if key.object != context.object {
            return Err(FrameFailure::new(FrameFailureCode::InvalidContext));
        }
        let ciphertext_bytes = plaintext
            .len()
            .checked_add(AES_256_GCM_TAG_BYTES as usize)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        let encoded_bytes = FRAME_HEADER_BYTES
            .checked_add(ciphertext_bytes)
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        if encoded_bytes > limits.max_encoded_bytes {
            return Err(FrameFailure::new(FrameFailureCode::LimitExceeded));
        }

        let header = encode_authenticated_header(context.sequence, ciphertext_bytes);
        let associated_data = encode_associated_data(&header, context);
        let backend = RustCryptoBackend;
        let ciphertext = backend
            .seal_aes_256_gcm(
                &key.key,
                nonce_for(context.sequence),
                &associated_data,
                plaintext,
            )
            .map_err(|_| FrameFailure::new(FrameFailureCode::CryptoBackendFailure))?;
        let checksum = backend.sha256(&ciphertext);
        let capacity = usize::try_from(encoded_bytes)
            .map_err(|_| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(&header);
        encoded.extend_from_slice(&checksum);
        encoded.extend_from_slice(&ciphertext);
        Ok(EncryptedFrame(encoded))
    }

    /// Authenticates a bounded frame before exposing its plaintext.
    pub fn open_frame(
        key: &ObjectDataKey,
        expected_context: FrameContext,
        encoded: &[u8],
        limits: FrameLimits,
    ) -> Result<VerifiedFrame, FrameFailure> {
        if key.object != expected_context.object {
            return Err(FrameFailure::new(FrameFailureCode::AuthenticationFailed));
        }
        let encoded_bytes = u32::try_from(encoded.len())
            .map_err(|_| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        if encoded_bytes > limits.max_encoded_bytes {
            return Err(FrameFailure::new(FrameFailureCode::LimitExceeded));
        }
        let parsed = parse_frame(encoded, limits)?;
        if parsed.sequence != expected_context.sequence {
            return Err(FrameFailure::new(FrameFailureCode::AuthenticationFailed));
        }
        let backend = RustCryptoBackend;
        if backend.sha256(parsed.ciphertext) != parsed.checksum {
            return Err(FrameFailure::new(FrameFailureCode::ChecksumMismatch));
        }
        let associated_data = encode_associated_data(parsed.authenticated_header, expected_context);
        let plaintext = backend
            .open_aes_256_gcm(
                &key.key,
                nonce_for(expected_context.sequence),
                &associated_data,
                parsed.ciphertext,
            )
            .map_err(|_| FrameFailure::new(FrameFailureCode::AuthenticationFailed))?;
        Ok(VerifiedFrame(Zeroizing::new(plaintext)))
    }
}

struct ParsedFrame<'a> {
    authenticated_header: &'a [u8],
    sequence: FrameSequence,
    checksum: [u8; 32],
    ciphertext: &'a [u8],
}

fn parse_frame(encoded: &[u8], limits: FrameLimits) -> Result<ParsedFrame<'_>, FrameFailure> {
    let header: &[u8; 20] = encoded
        .get(..20)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| FrameFailure::new(FrameFailureCode::MalformedFrame))?;
    let [
        magic_a,
        magic_b,
        magic_c,
        magic_d,
        version_a,
        version_b,
        algorithm_a,
        algorithm_b,
        sequence_a,
        sequence_b,
        sequence_c,
        sequence_d,
        sequence_e,
        sequence_f,
        sequence_g,
        sequence_h,
        length_a,
        length_b,
        length_c,
        length_d,
    ] = *header;
    if [magic_a, magic_b, magic_c, magic_d] != FRAME_MAGIC {
        return Err(FrameFailure::new(FrameFailureCode::MalformedFrame));
    }
    if u16::from_be_bytes([version_a, version_b]) != FRAME_VERSION {
        return Err(FrameFailure::new(FrameFailureCode::UnsupportedVersion));
    }
    if u16::from_be_bytes([algorithm_a, algorithm_b]) != AES_256_GCM_ALGORITHM {
        return Err(FrameFailure::new(FrameFailureCode::UnsupportedAlgorithm));
    }
    let sequence = FrameSequence::new(u64::from_be_bytes([
        sequence_a, sequence_b, sequence_c, sequence_d, sequence_e, sequence_f, sequence_g,
        sequence_h,
    ]));
    let declared_ciphertext_bytes = u32::from_be_bytes([length_a, length_b, length_c, length_d]);
    if declared_ciphertext_bytes < AES_256_GCM_TAG_BYTES {
        return Err(FrameFailure::new(FrameFailureCode::MalformedFrame));
    }
    let declared_encoded_bytes = FRAME_HEADER_BYTES
        .checked_add(declared_ciphertext_bytes)
        .ok_or_else(|| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
    if declared_encoded_bytes > limits.max_encoded_bytes {
        return Err(FrameFailure::new(FrameFailureCode::LimitExceeded));
    }
    let checksum: [u8; 32] = encoded
        .get(20..52)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| FrameFailure::new(FrameFailureCode::MalformedFrame))?;
    let ciphertext = encoded
        .get(52..)
        .ok_or_else(|| FrameFailure::new(FrameFailureCode::MalformedFrame))?;
    let actual_ciphertext_bytes = u32::try_from(ciphertext.len())
        .map_err(|_| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
    if actual_ciphertext_bytes != declared_ciphertext_bytes {
        return Err(FrameFailure::new(FrameFailureCode::MalformedFrame));
    }
    Ok(ParsedFrame {
        authenticated_header: header,
        sequence,
        checksum,
        ciphertext,
    })
}

fn encode_authenticated_header(sequence: FrameSequence, ciphertext_bytes: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&FRAME_MAGIC);
    header.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    header.extend_from_slice(&AES_256_GCM_ALGORITHM.to_be_bytes());
    header.extend_from_slice(&sequence.0.to_be_bytes());
    header.extend_from_slice(&ciphertext_bytes.to_be_bytes());
    header
}

fn encode_associated_data(header: &[u8], context: FrameContext) -> Vec<u8> {
    let mut associated_data = Vec::with_capacity(93);
    associated_data.extend_from_slice(header);
    associated_data.extend_from_slice(FRAME_AAD_DOMAIN);
    context.object.encode(context.purpose, &mut associated_data);
    associated_data
}

const fn nonce_for(sequence: FrameSequence) -> [u8; 12] {
    let [a, b, c, d, e, f, g, h] = sequence.0.to_be_bytes();
    let [i, j, k, l] = FRAME_NONCE_DOMAIN;
    [i, j, k, l, a, b, c, d, e, f, g, h]
}

#[cfg(test)]
mod tests;
