use super::{
    FrameFailure, FrameFailureCode, ObjectDataKey, SecretKeyBytes, SecretPlaintext,
    SystemObjectKind,
};
use zeroize::Zeroizing;

const PAYLOAD_VERSION: u64 = 1;
const SYSTEM_SCOPE: u64 = 1;
const KEY_BYTES_OFFSET: usize = 4;
const KEY_BYTES: usize = 32;

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
    }
}
