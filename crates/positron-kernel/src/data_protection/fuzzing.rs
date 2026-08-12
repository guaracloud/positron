use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::{
    DataProtection, FormatEpoch, FrameContext, FrameFailure, FrameFailureCode, FrameLimits,
    FrameObjectContext, FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey, SecretKeyInput,
    SegmentFramePurpose, VerifiedFrame,
};

#[cfg(fuzzing)]
use super::{CryptoBackend, RustCryptoBackend};

const MAX_ENCODED_BYTES: u32 = 2048;
const VALID_EMPTY_FRAME: &[u8; 68] =
    include_bytes!("../../../../fuzz/corpus/encrypted_frame_open/valid_empty_frame");

fn frame_fixture() -> Option<(ObjectDataKey, FrameContext, FrameObjectContext, FrameLimits)> {
    let tenant = TenantId::from_bytes([0x11; 16]).ok()?;
    let shard = VirtualShardId::new(1).ok()?;
    let object_id = FrameObjectId::new([0x22; 16]).ok()?;
    let format_epoch = FormatEpoch::new(1).ok()?;
    let limits = FrameLimits::new(MAX_ENCODED_BYTES).ok()?;
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        object_id,
        KeyEpoch::new(1),
        format_epoch,
    );
    let context = object
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1))
        .ok()?;
    let key = ObjectDataKey::import(SecretKeyInput::from_owned(Box::new([0x33; 32])), object);
    Some((key, context, object, limits))
}

pub(super) fn open_bounded_raw_frame(data: &[u8]) -> Result<VerifiedFrame, FrameFailure> {
    let (key, context, _, limits) =
        frame_fixture().ok_or_else(|| FrameFailure::new(FrameFailureCode::InvalidContext))?;
    let bounded_end = data.len().min(
        usize::try_from(MAX_ENCODED_BYTES)
            .unwrap_or(usize::MAX)
            .saturating_add(1),
    );
    let bounded = data.get(..bounded_end).unwrap_or_default();
    DataProtection::open_frame(&key, context, bounded, limits)
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_authenticated_frame(data: &[u8]) {
    // The corpus is itself an encoded-frame input. This directly exercises the
    // bounded structural/checksum/AEAD decoder, including retained seeds.
    if let Ok(verified) = open_bounded_raw_frame(data) {
        assert!(verified.as_plaintext().len() <= MAX_ENCODED_BYTES as usize);
    }

    // Keep a deterministic valid frame as the structured mutation oracle.
    // It was generated independently and is never resealed by a fuzz callback.
    let Some((key, context, object, limits)) = frame_fixture() else {
        return;
    };
    let Ok(verified) = DataProtection::open_frame(&key, context, VALID_EMPTY_FRAME, limits) else {
        panic!("the committed valid frame must authenticate");
    };
    assert!(verified.as_plaintext().is_empty());

    let selector = data.first().copied().unwrap_or_default() % 6;
    let mut hostile = VALID_EMPTY_FRAME.to_vec();
    let expected = match selector {
        0 => {
            if let Some(version) = hostile.get_mut(4..6) {
                version.copy_from_slice(&2_u16.to_be_bytes());
            }
            FrameFailureCode::UnsupportedVersion
        },
        1 => {
            if let Some(algorithm) = hostile.get_mut(6..8) {
                algorithm.copy_from_slice(&2_u16.to_be_bytes());
            }
            FrameFailureCode::UnsupportedAlgorithm
        },
        2 => {
            if let Some(checksum) = hostile.get_mut(20) {
                *checksum ^= 1;
            }
            FrameFailureCode::ChecksumMismatch
        },
        3 | 4 => {
            let offset = if selector == 3 {
                52
            } else {
                hostile.len().saturating_sub(1)
            };
            if let Some(byte) = hostile.get_mut(offset) {
                *byte ^= 1;
            }
            let checksum = RustCryptoBackend.sha256(hostile.get(52..).unwrap_or_default());
            if let (Ok(checksum), Some(stored)) = (checksum, hostile.get_mut(20..52)) {
                stored.copy_from_slice(&checksum);
            }
            FrameFailureCode::AuthenticationFailed
        },
        _ => {
            let Ok(other_context) =
                object.frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(2))
            else {
                return;
            };
            let failure = DataProtection::open_frame(&key, other_context, &hostile, limits)
                .expect_err("a substituted frame address must not expose plaintext");
            assert_eq!(failure.code(), FrameFailureCode::AuthenticationFailed);
            return;
        },
    };
    let failure = DataProtection::open_frame(&key, context, &hostile, limits)
        .expect_err("a structured frame mutation must not expose plaintext");
    assert_eq!(failure.code(), expected);
}
