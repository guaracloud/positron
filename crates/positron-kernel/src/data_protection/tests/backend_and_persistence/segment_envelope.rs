use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::super::{
    DataProtection, FormatEpoch, FrameFailureCode, FrameObjectContext, FrameObjectId, KeyEpoch,
    ObjectDataKey, SecretKeyBytes, SecretKeyInput, SegmentEnvelopeRoute, SystemObjectKind,
    encode_segment_wrapped_key_payload_with_route, segment_context_encoding_with_route,
};

#[test]
fn segment_wrapped_keys_bind_every_physical_scope_dimension() -> Result<(), &'static str> {
    let instance = [0x81; 16];
    let route = SegmentEnvelopeRoute::new(1, [0x80; 16], 7).map_err(|_| "invalid segment route")?;
    let wrapping_key = SecretKeyBytes::from_owned(Box::new([0x82; 32]));
    let system_object = FrameObjectContext::system(
        SystemObjectKind::Catalog,
        FrameObjectId::new([0x83; 16]).map_err(|_| "invalid system object")?,
        KeyEpoch::new(1),
        FormatEpoch::new(1).map_err(|_| "invalid format epoch")?,
    );
    let system_key =
        ObjectDataKey::import(SecretKeyInput::from_test_bytes([0x84; 32]), system_object);
    for failure in [
        segment_context_encoding_with_route(instance, system_object, route)
            .expect_err("system objects have no segment envelope context"),
        encode_segment_wrapped_key_payload_with_route(&system_key, instance, [0x85; 32], route)
            .err()
            .expect("system keys cannot use the segment envelope format"),
    ] {
        if failure.code() != FrameFailureCode::InvalidContext {
            return Err("invalid segment envelope context was misclassified");
        }
    }

    let tenant = TenantId::from_bytes([0x86; 16]).map_err(|_| "invalid tenant")?;
    let shard = VirtualShardId::new(7).map_err(|_| "invalid shard")?;
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Traces,
        shard,
        FrameObjectId::new([0x87; 16]).map_err(|_| "invalid segment object")?,
        KeyEpoch::new(3),
        FormatEpoch::new(4).map_err(|_| "invalid segment format")?,
    );
    let object_key =
        ObjectDataKey::generate(object).map_err(|_| "segment object key generation failed")?;
    if format!("{object_key:?}") != "ObjectDataKey { <redacted> }" {
        return Err("segment object key debug output was not redacted");
    }
    let wrapped =
        DataProtection::wrap_segment_key_with_route(&wrapping_key, &object_key, instance, route)
            .map_err(|_| "segment key wrap failed")?;
    let opened = DataProtection::unwrap_segment_key_with_route(
        &wrapping_key,
        &wrapped,
        instance,
        object,
        route,
    )
    .map_err(|_| "segment key unwrap failed")?;
    if opened.key.expose_to_backend() != object_key.key.expose_to_backend() {
        return Err("segment key round trip differed");
    }

    let substituted = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        FrameObjectId::new([0x87; 16]).map_err(|_| "invalid segment object")?,
        KeyEpoch::new(3),
        FormatEpoch::new(4).map_err(|_| "invalid segment format")?,
    );
    if DataProtection::unwrap_segment_key_with_route(
        &wrapping_key,
        &wrapped,
        instance,
        substituted,
        route,
    )
    .is_ok()
    {
        return Err("segment envelope accepted a substituted signal");
    }
    if DataProtection::unwrap_segment_key_with_route(
        &wrapping_key,
        &wrapped,
        [0x89; 16],
        object,
        route,
    )
    .is_ok()
    {
        return Err("segment envelope accepted a substituted instance");
    }
    let substituted_route =
        SegmentEnvelopeRoute::new(1, [0x90; 16], 7).map_err(|_| "invalid substituted route")?;
    if DataProtection::unwrap_segment_key_with_route(
        &wrapping_key,
        &wrapped,
        instance,
        object,
        substituted_route,
    )
    .is_ok()
    {
        return Err("segment envelope accepted a substituted provider route");
    }
    Ok(())
}
