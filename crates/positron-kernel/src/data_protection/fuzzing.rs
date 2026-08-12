#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_authenticated_frame(data: &[u8]) {
    use positron_domain::identity::TenantId;
    use positron_domain::routing::{SignalKind, VirtualShardId};

    use super::{
        CryptoBackend, DataProtection, FormatEpoch, FrameFailureCode, FrameLimits,
        FrameObjectContext, FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey,
        RustCryptoBackend, SecretKeyInput, SegmentFramePurpose,
    };
    const MAX_PLAINTEXT_BYTES: usize = 1024;
    const MAX_ENCODED_BYTES: u32 = 2048;

    let tenant = TenantId::from_bytes([0x11; 16]);
    let shard = VirtualShardId::new(1);
    let object_id = FrameObjectId::new([0x22; 16]);
    let format_epoch = FormatEpoch::new(1);
    let limits = FrameLimits::new(MAX_ENCODED_BYTES);
    let (Ok(tenant), Ok(shard), Ok(object_id), Ok(format_epoch), Ok(limits)) =
        (tenant, shard, object_id, format_epoch, limits)
    else {
        return;
    };
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        object_id,
        KeyEpoch::new(1),
        format_epoch,
    );
    let Ok(context) = object.frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1)) else {
        return;
    };
    let key = ObjectDataKey::import(SecretKeyInput::from_owned(Box::new([0x33; 32])), object);
    let plaintext_end = data.len().min(MAX_PLAINTEXT_BYTES);
    let plaintext = data.get(..plaintext_end).unwrap_or_default();
    let Ok(frame) = DataProtection::protect_frame(&key, context, plaintext, limits) else {
        return;
    };
    let Ok(verified) = DataProtection::open_frame(&key, context, frame.as_bytes(), limits) else {
        panic!("a freshly protected bounded frame must authenticate");
    };
    assert_eq!(verified.as_plaintext(), plaintext);

    let selector = data.first().copied().unwrap_or_default() % 6;
    let mut hostile = frame.as_bytes().to_vec();
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
