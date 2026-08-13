use super::{
    FrameFailure, FrameFailureCode, FrameObjectClass, FrameObjectContext, FrameScope,
    ObjectDataKey, SecretKeyBytes, SecretPlaintext, SystemObjectKind,
};
use zeroize::Zeroizing;

const PAYLOAD_VERSION: u64 = 1;
const SYSTEM_SCOPE: u64 = 1;
const SEGMENT_SCOPE: u64 = 2;
const KEY_BYTES_OFFSET: usize = 4;
const KEY_BYTES: usize = 32;

/// The non-secret provider route bound inside a segment's wrapped-key authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SegmentEnvelopeRoute {
    pub(crate) provider_family: u16,
    pub(crate) provider_reference: [u8; 16],
    pub(crate) provider_key_epoch: u64,
}

impl SegmentEnvelopeRoute {
    pub(crate) fn new(
        provider_family: u16,
        provider_reference: [u8; 16],
        provider_key_epoch: u64,
    ) -> Result<Self, FrameFailure> {
        if provider_family == 0
            || provider_reference.iter().all(|byte| *byte == 0)
            || provider_key_epoch == 0
        {
            return Err(FrameFailure::new(FrameFailureCode::InvalidContext));
        }
        Ok(Self {
            provider_family,
            provider_reference,
            provider_key_epoch,
        })
    }
}

/// The authoritative, caller-independent binding embedded inside one wrapped key payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WrappedKeyContext {
    instance: [u8; 16],
    kind: SystemObjectKind,
    key_id: [u8; 32],
    key_epoch: u64,
    context_digest: [u8; 32],
}

impl WrappedKeyContext {
    pub(crate) fn system(
        instance: [u8; 16],
        kind: SystemObjectKind,
        key_id: [u8; 32],
        key_epoch: u64,
        context_digest: [u8; 32],
    ) -> Result<Self, FrameFailure> {
        if instance.iter().all(|byte| *byte == 0)
            || key_id.iter().all(|byte| *byte == 0)
            || key_epoch == 0
            || context_digest.iter().all(|byte| *byte == 0)
        {
            return Err(FrameFailure::new(FrameFailureCode::InvalidContext));
        }
        Ok(Self {
            instance,
            kind,
            key_id,
            key_epoch,
            context_digest,
        })
    }
}

pub(super) fn encode_wrapped_key_payload(
    key: &ObjectDataKey,
    context: WrappedKeyContext,
) -> SecretPlaintext {
    encode_payload(key.key.expose_to_backend(), context)
}

pub(super) fn verify_wrapped_key_payload(
    payload: SecretPlaintext,
    expected: WrappedKeyContext,
) -> Result<SecretKeyBytes, FrameFailure> {
    let key_bytes = Zeroizing::new(
        payload
            .bytes
            .get(KEY_BYTES_OFFSET..KEY_BYTES_OFFSET + KEY_BYTES)
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::AuthenticationFailed))?
            .try_into()
            .map_err(|_| FrameFailure::new(FrameFailureCode::AuthenticationFailed))?,
    );
    let expected_payload = encode_payload(&key_bytes, expected);
    let difference = payload.bytes.iter().zip(&expected_payload.bytes).fold(
        (payload.bytes.len() ^ expected_payload.bytes.len()) as u8,
        |difference, (actual, expected)| difference | (*actual ^ *expected),
    );
    if difference != 0 || payload.bytes.len() != expected_payload.bytes.len() {
        return Err(FrameFailure::new(FrameFailureCode::AuthenticationFailed));
    }
    Ok(SecretKeyBytes::from_owned(Box::new(*key_bytes)))
}

fn encode_payload(key: &[u8; KEY_BYTES], context: WrappedKeyContext) -> SecretPlaintext {
    let mut encoded = Vec::with_capacity(128);
    encode_varint_field(1, PAYLOAD_VERSION, &mut encoded);
    encode_bytes_field(2, key, &mut encoded);
    encode_bytes_field(3, &context.instance, &mut encoded);
    encode_varint_field(4, key_kind(context.kind), &mut encoded);
    encode_bytes_field(5, &context.key_id, &mut encoded);
    encode_varint_field(6, context.key_epoch, &mut encoded);
    encode_varint_field(7, SYSTEM_SCOPE, &mut encoded);
    encode_bytes_field(8, &context.context_digest, &mut encoded);
    SecretPlaintext::new(encoded)
}

pub(crate) fn segment_context_encoding(
    instance: [u8; 16],
    object: FrameObjectContext,
) -> Result<Vec<u8>, FrameFailure> {
    segment_context_encoding_with_route(instance, object, default_segment_route())
}

pub(crate) fn segment_context_encoding_with_route(
    instance: [u8; 16],
    object: FrameObjectContext,
    route: SegmentEnvelopeRoute,
) -> Result<Vec<u8>, FrameFailure> {
    let (tenant, signal, shard) = match (object.scope, object.class) {
        (FrameScope::Tenant(tenant), FrameObjectClass::Segment { signal, shard }) => {
            (tenant, signal, shard)
        },
        _ => return Err(FrameFailure::new(FrameFailureCode::InvalidContext)),
    };
    let mut encoded = Vec::with_capacity(96);
    encoded.extend_from_slice(b"positron-segment-envelope-context-v2\0");
    encoded.extend_from_slice(&instance);
    encoded.extend_from_slice(&tenant.to_bytes());
    encoded.push(match signal {
        positron_domain::routing::SignalKind::Logs => 1,
        positron_domain::routing::SignalKind::Traces => 2,
    });
    encoded.extend_from_slice(&shard.value().to_be_bytes());
    encoded.extend_from_slice(&object.object_id.0);
    encoded.extend_from_slice(&object.key_epoch.0.to_be_bytes());
    encoded.extend_from_slice(&object.format_epoch.0.to_be_bytes());
    encoded.extend_from_slice(&route.provider_family.to_be_bytes());
    encoded.extend_from_slice(&route.provider_reference);
    encoded.extend_from_slice(&route.provider_key_epoch.to_be_bytes());
    Ok(encoded)
}

pub(crate) fn encode_segment_wrapped_key_payload(
    key: &ObjectDataKey,
    instance: [u8; 16],
    context_digest: [u8; 32],
) -> Result<SecretPlaintext, FrameFailure> {
    encode_segment_wrapped_key_payload_with_route(
        key,
        instance,
        context_digest,
        default_segment_route(),
    )
}

pub(crate) fn encode_segment_wrapped_key_payload_with_route(
    key: &ObjectDataKey,
    instance: [u8; 16],
    context_digest: [u8; 32],
    route: SegmentEnvelopeRoute,
) -> Result<SecretPlaintext, FrameFailure> {
    let (tenant, signal, shard) = match (key.object.scope, key.object.class) {
        (FrameScope::Tenant(tenant), FrameObjectClass::Segment { signal, shard }) => {
            (tenant, signal, shard)
        },
        _ => return Err(FrameFailure::new(FrameFailureCode::InvalidContext)),
    };
    let mut encoded = Vec::with_capacity(176);
    encode_varint_field(1, PAYLOAD_VERSION, &mut encoded);
    encode_bytes_field(2, key.key.expose_to_backend(), &mut encoded);
    encode_bytes_field(3, &instance, &mut encoded);
    encode_varint_field(4, 5, &mut encoded);
    encode_bytes_field(5, &key.object.object_id.0, &mut encoded);
    encode_varint_field(6, key.object.key_epoch.0, &mut encoded);
    encode_varint_field(7, SEGMENT_SCOPE, &mut encoded);
    encode_bytes_field(8, &context_digest, &mut encoded);
    encode_bytes_field(9, &tenant.to_bytes(), &mut encoded);
    encode_varint_field(
        10,
        match signal {
            positron_domain::routing::SignalKind::Logs => 1,
            positron_domain::routing::SignalKind::Traces => 2,
        },
        &mut encoded,
    );
    encode_varint_field(11, u64::from(shard.value()), &mut encoded);
    encode_varint_field(12, u64::from(key.object.format_epoch.0), &mut encoded);
    encode_varint_field(13, u64::from(route.provider_family), &mut encoded);
    encode_bytes_field(14, &route.provider_reference, &mut encoded);
    encode_varint_field(15, route.provider_key_epoch, &mut encoded);
    Ok(SecretPlaintext::new(encoded))
}

pub(crate) fn verify_segment_wrapped_key_payload_with_route(
    payload: SecretPlaintext,
    instance: [u8; 16],
    object: FrameObjectContext,
    context_digest: [u8; 32],
    route: SegmentEnvelopeRoute,
) -> Result<SecretKeyBytes, FrameFailure> {
    let key_bytes = Zeroizing::new(
        payload
            .bytes
            .get(KEY_BYTES_OFFSET..KEY_BYTES_OFFSET + KEY_BYTES)
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::AuthenticationFailed))?
            .try_into()
            .map_err(|_| FrameFailure::new(FrameFailureCode::AuthenticationFailed))?,
    );
    let candidate = ObjectDataKey {
        key: SecretKeyBytes::from_owned(Box::new(*key_bytes)),
        object,
    };
    let expected =
        encode_segment_wrapped_key_payload_with_route(&candidate, instance, context_digest, route)?;
    let difference = payload.bytes.iter().zip(&expected.bytes).fold(
        (payload.bytes.len() ^ expected.bytes.len()) as u8,
        |difference, (actual, expected)| difference | (*actual ^ *expected),
    );
    if difference != 0 || payload.bytes.len() != expected.bytes.len() {
        return Err(FrameFailure::new(FrameFailureCode::AuthenticationFailed));
    }
    Ok(candidate.key)
}

const fn default_segment_route() -> SegmentEnvelopeRoute {
    SegmentEnvelopeRoute {
        provider_family: 1,
        provider_reference: [1; 16],
        provider_key_epoch: 1,
    }
}

fn encode_varint_field(field: u8, value: u64, destination: &mut Vec<u8>) {
    destination.push(field << 3);
    encode_varint(value, destination);
}

fn encode_bytes_field(field: u8, bytes: &[u8], destination: &mut Vec<u8>) {
    destination.push((field << 3) | 2);
    encode_varint(bytes.len() as u64, destination);
    destination.extend_from_slice(bytes);
}

fn encode_varint(mut value: u64, destination: &mut Vec<u8>) {
    while value >= 0x80 {
        destination.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    destination.push(value as u8);
}

const fn key_kind(kind: SystemObjectKind) -> u64 {
    match kind {
        SystemObjectKind::Catalog => 1,
        SystemObjectKind::Manifest => 2,
        SystemObjectKind::GovernanceAudit => 3,
        SystemObjectKind::BackupMetadata => 4,
        SystemObjectKind::InstanceBootstrap => 5,
    }
}
