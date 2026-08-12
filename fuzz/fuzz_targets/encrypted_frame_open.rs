#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    DataProtection, FormatEpoch, FrameLimits, FrameObjectContext, FrameObjectId, FrameSequence,
    KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose,
};

const MAX_FUZZ_ENCODED_BYTES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let tenant = TenantId::from_bytes([0x11; 16]);
    let shard = VirtualShardId::new(1);
    let object_id = FrameObjectId::new([0x22; 16]);
    let format_epoch = FormatEpoch::new(1);
    let limits = FrameLimits::new(MAX_FUZZ_ENCODED_BYTES as u32);
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
    let key = ObjectDataKey::import(SecretKeyInput::new([0x33; 32]), object);

    let bounded_end = data.len().min(MAX_FUZZ_ENCODED_BYTES + 1);
    let bounded = data.get(..bounded_end).unwrap_or_default();
    if let Ok(verified) = DataProtection::open_frame(&key, context, bounded, limits) {
        let second = DataProtection::open_frame(&key, context, bounded, limits);
        assert!(second.is_ok());
        assert!(verified.as_plaintext().len() <= MAX_FUZZ_ENCODED_BYTES);
    }
});
