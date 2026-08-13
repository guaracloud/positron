//! Authenticated encrypted-frame ownership for the Storage Kernel.
//!
//! Frame v1 is `20-byte authenticated header || 32-byte SHA-256 checksum ||
//! ciphertext || 16-byte AES-GCM tag`. The authenticated header contains the
//! magic, frame version, algorithm identifier, frame sequence, and the length
//! of `ciphertext || tag`. The checksum supports keyless corruption detection;
//! the AES-GCM tag remains the authority for authenticity. Associated data
//! binds the authoritative object address and payload purpose.
//!
//! The 96-bit nonce is an injective v1 domain prefix plus the big-endian frame
//! sequence. Sequence admission and persistence belong to the Active Segment
//! Ledger; this module protects or opens one already-authorized frame.

mod backend;
mod codec;
mod context;
mod control_token;
mod frame;
mod key_envelope;
mod local_key;
mod service;

#[cfg(any(test, fuzzing))]
mod fuzzing;

use backend::{CryptoBackend, CryptoBackendFailure, RustCryptoBackend, SecretPlaintext};
pub(crate) use backend::{ObjectDataKey, SecretKeyBytes, SecretKeyInput};
use codec::{encode_associated_data, encode_authenticated_header, nonce_for, parse_frame};
pub(crate) use context::{
    FormatEpoch as FrameFormatEpoch, FrameContext, FrameLimits, FrameObjectClass,
    FrameObjectContext, FrameObjectId, FrameScope, FrameSequence, KeyEpoch, SegmentFramePurpose,
    SystemObjectKind,
};
pub use control_token::{ControlTokenAuthentication, ControlTokenFailure, ControlTokenProtector};
pub(crate) use frame::{EncryptedFrame, FrameFailure, FrameFailureCode, VerifiedFrame};
pub(crate) use key_envelope::{SegmentEnvelopeRoute, WrappedKeyContext};
#[cfg(test)]
use key_envelope::{encode_segment_wrapped_key_payload, segment_context_encoding};
use key_envelope::{
    encode_segment_wrapped_key_payload_with_route, encode_wrapped_key_payload,
    segment_context_encoding_with_route, verify_segment_wrapped_key_payload_with_route,
    verify_wrapped_key_payload,
};
pub use local_key::{
    BootstrapIntegrityIdentity, BootstrapKeyCustody, BootstrapKeyFailure, BootstrapKeyIdentity,
    BootstrapObjectPurpose,
};
pub(crate) use service::DataProtection;

#[cfg(any(test, fuzzing))]
use context::FormatEpoch;

const FRAME_MAGIC: [u8; 4] = *b"PFRM";
const FRAME_VERSION: u16 = 1;
const AES_256_GCM_ALGORITHM: u16 = 1;
const AES_256_GCM_TAG_BYTES: u32 = 16;
const FRAME_HEADER_BYTES: u32 = 52;
const MINIMUM_ENCODED_FRAME_BYTES: u32 = FRAME_HEADER_BYTES + AES_256_GCM_TAG_BYTES;
const FRAME_AAD_DOMAIN: &[u8] = b"positron-frame-aad-v1";
const FRAME_NONCE_DOMAIN: [u8; 4] = [0x50, 0x46, 0x52, 0x01];

#[cfg(fuzzing)]
#[doc(hidden)]
pub use fuzzing::fuzz_authenticated_frame;

#[cfg(fuzzing)]
#[doc(hidden)]
pub use local_key::fuzz_local_root_key_file;

#[cfg(test)]
mod tests;
