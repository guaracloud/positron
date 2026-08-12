use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::{
    CryptoBackend, DataProtection, FormatEpoch, FrameContext, FrameFailure, FrameFailureCode,
    FrameLimits, FrameObjectContext, FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey,
    RustCryptoBackend, SecretKeyInput, SegmentFramePurpose, VerifiedFrame,
};

const MAX_ENCODED_BYTES: u32 = 2048;
pub(super) const AUTHENTIC_PLAINTEXT: &[u8; 18] = b"vector-store-block";

// Independently derived with Node.js v24.18.0/OpenSSL 3.5.7 from the
// documented frame-v1 byte contract. This is also the canonical Store Block
// vector asserted by the platform-independent vector suite.
pub(super) const AUTHENTIC_FRAME: &[u8; 86] =
    include_bytes!("../../../../fuzz/corpus/encrypted_frame_open/valid_non_empty_frame");

fn frame_fixture() -> Option<(ObjectDataKey, FrameContext, FrameObjectContext, FrameLimits)> {
    let tenant =
        TenantId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).ok()?;
    let shard = VirtualShardId::new(7).ok()?;
    let object_id = FrameObjectId::new([0x11; 16]).ok()?;
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
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(9))
        .ok()?;
    let mut key_bytes = [0_u8; 32];
    for (value, byte) in (0_u8..32).zip(&mut key_bytes) {
        *byte = value;
    }
    let key = ObjectDataKey::import(SecretKeyInput::from_owned(Box::new(key_bytes)), object);
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

pub(super) fn raw_open_result_matches_oracle(
    data: &[u8],
    result: Result<VerifiedFrame, FrameFailure>,
) -> bool {
    match (data == AUTHENTIC_FRAME.as_slice(), result) {
        (true, Ok(verified)) => verified.as_plaintext() == AUTHENTIC_PLAINTEXT,
        (false, Err(_)) => true,
        (true, Err(_)) | (false, Ok(_)) => false,
    }
}

pub(super) fn structured_mutation(selector: u8) -> Option<(Vec<u8>, FrameFailureCode)> {
    let mut hostile = AUTHENTIC_FRAME.to_vec();
    let expected = match selector {
        0 => {
            hostile.get_mut(4..6)?.copy_from_slice(&2_u16.to_be_bytes());
            FrameFailureCode::UnsupportedVersion
        },
        1 => {
            hostile.get_mut(6..8)?.copy_from_slice(&2_u16.to_be_bytes());
            FrameFailureCode::UnsupportedAlgorithm
        },
        2 => {
            *hostile.get_mut(20)? ^= 1;
            FrameFailureCode::ChecksumMismatch
        },
        3 | 4 => {
            let offset = if selector == 3 {
                52
            } else {
                hostile.len().checked_sub(1)?
            };
            *hostile.get_mut(offset)? ^= 1;
            let checksum = RustCryptoBackend.sha256(hostile.get(52..)?).ok()?;
            hostile.get_mut(20..52)?.copy_from_slice(&checksum);
            FrameFailureCode::AuthenticationFailed
        },
        _ => return None,
    };
    Some((hostile, expected))
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_authenticated_frame(data: &[u8]) {
    // The corpus is itself an encoded-frame input. This directly exercises the
    // bounded structural/checksum/AEAD decoder. Success is accepted only for
    // the independently committed authentic artifact and known plaintext.
    assert!(raw_open_result_matches_oracle(
        data,
        open_bounded_raw_frame(data),
    ));

    // Keep a deterministic non-empty valid frame as the structured mutation
    // seed. It was generated independently and is never resealed here.
    let Some((key, context, object, limits)) = frame_fixture() else {
        return;
    };
    let Ok(verified) = DataProtection::open_frame(&key, context, AUTHENTIC_FRAME, limits) else {
        panic!("the committed valid frame must authenticate");
    };
    assert_eq!(verified.as_plaintext(), AUTHENTIC_PLAINTEXT);

    let selector = data.first().copied().unwrap_or_default() % 6;
    if selector == 5 {
        let Ok(other_context) =
            object.frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(10))
        else {
            return;
        };
        let failure = DataProtection::open_frame(&key, other_context, AUTHENTIC_FRAME, limits)
            .expect_err("a substituted frame address must not expose plaintext");
        assert_eq!(failure.code(), FrameFailureCode::AuthenticationFailed);
        return;
    }
    let Some((hostile, expected)) = structured_mutation(selector) else {
        return;
    };
    let failure = DataProtection::open_frame(&key, context, &hostile, limits)
        .expect_err("a structured frame mutation must not expose plaintext");
    assert_eq!(failure.code(), expected);
}
