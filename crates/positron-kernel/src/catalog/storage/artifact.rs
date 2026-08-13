use crate::data_protection::{
    DataProtection, FrameFailure, FrameFailureCode, FrameFormatEpoch, FrameLimits,
    FrameObjectContext, FrameObjectId, FrameSequence, KeyEpoch, SecretKeyBytes, SystemObjectKind,
    WrappedKeyContext,
};

use super::super::types::{
    CatalogFailure, CatalogFailureCode, CatalogSecret, CatalogWrappingKey, FormatEpoch, InstanceId,
};

const ARTIFACT_MAGIC: [u8; 8] = *b"PARTV003";
const ARTIFACT_VERSION: u16 = 3;
const LOCAL_PROVIDER: u16 = 1;
const AES_256_KWP_ALGORITHM: u16 = 1;
const ARTIFACT_HEADER_BYTES: usize = 247;
const FRAME_OVERHEAD_BYTES: usize = 68;
const WRAPPED_PAYLOAD_BYTES: usize = 136;
const DATA_KEY_EPOCH: u64 = 1;
const ENVELOPE_CONTEXT_DOMAIN: &[u8] = b"positron-catalog-key-envelope-context-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ArtifactKind {
    Object,
    Audit,
    Commit,
}

impl ArtifactKind {
    pub(super) const fn tag(self) -> u8 {
        match self {
            Self::Object => 1,
            Self::Audit => 2,
            Self::Commit => 3,
        }
    }

    const fn system_kind(self) -> SystemObjectKind {
        match self {
            Self::Object | Self::Commit => SystemObjectKind::Catalog,
            Self::Audit => SystemObjectKind::GovernanceAudit,
        }
    }
}

pub(super) fn protect_artifact(
    secret: &CatalogSecret,
    instance: InstanceId,
    kind: ArtifactKind,
    content_identity: [u8; 32],
    format_epoch: FormatEpoch,
    plaintext: &[u8],
) -> Result<Vec<u8>, CatalogFailure> {
    let key_id = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let context_digest = envelope_context_digest(
        instance,
        kind,
        content_identity,
        format_epoch,
        key_id,
        DATA_KEY_EPOCH,
    )?;
    let object = artifact_context(kind, context_digest, format_epoch)?;
    let key = DataProtection::random_key(object).map_err(map_frame_failure)?;
    let wrapping_key = contextual_wrapping_key(&secret.wrapping, context_digest)?;
    let key_context = wrapped_key_context(instance, kind, key_id, DATA_KEY_EPOCH, context_digest)?;
    let wrapped_payload = DataProtection::wrap_key_payload(&wrapping_key, &key, key_context)
        .map_err(map_frame_failure)?;
    if wrapped_payload.len() != WRAPPED_PAYLOAD_BYTES {
        return Err(CatalogFailure::new(CatalogFailureCode::StorageUnavailable));
    }
    let encoded_limit = plaintext
        .len()
        .checked_add(FRAME_OVERHEAD_BYTES)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let limits = FrameLimits::new(encoded_limit).map_err(map_frame_failure)?;
    let frame = DataProtection::protect_frame(
        &key,
        object
            .system_frame(FrameSequence::new(0))
            .map_err(map_frame_failure)?,
        plaintext,
        limits,
    )
    .map_err(map_frame_failure)?;
    let capacity = ARTIFACT_HEADER_BYTES
        .checked_add(frame.as_bytes().len())
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&ARTIFACT_MAGIC);
    encoded.extend_from_slice(&ARTIFACT_VERSION.to_be_bytes());
    encoded.push(kind.tag());
    encoded.extend_from_slice(&LOCAL_PROVIDER.to_be_bytes());
    encoded.extend_from_slice(&AES_256_KWP_ALGORITHM.to_be_bytes());
    encoded.extend_from_slice(&secret.wrapping.provider_key_reference);
    encoded.extend_from_slice(&secret.wrapping.key_epoch.to_be_bytes());
    encoded.extend_from_slice(&key_id);
    encoded.extend_from_slice(&DATA_KEY_EPOCH.to_be_bytes());
    encoded.extend_from_slice(&context_digest);
    encoded.extend_from_slice(&wrapped_payload);
    encoded.extend_from_slice(frame.as_bytes());
    Ok(encoded)
}

pub(super) fn open_artifact(
    secret: &CatalogSecret,
    instance: InstanceId,
    kind: ArtifactKind,
    content_identity: [u8; 32],
    format_epoch: FormatEpoch,
    encoded: &[u8],
) -> Result<Vec<u8>, CatalogFailure> {
    let (header, frame) = encoded
        .split_at_checked(ARTIFACT_HEADER_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let decoded = decode_header(header, kind)?;
    let wrapping = wrapping_key_for_header(secret, &decoded)?;
    if decoded.key_epoch != DATA_KEY_EPOCH {
        return Err(CatalogFailure::new(
            CatalogFailureCode::AuthenticationFailed,
        ));
    }
    let expected_context = envelope_context_digest(
        instance,
        kind,
        content_identity,
        format_epoch,
        decoded.key_id,
        decoded.key_epoch,
    )?;
    if decoded.context_digest != expected_context {
        return Err(CatalogFailure::new(
            CatalogFailureCode::AuthenticationFailed,
        ));
    }
    let object = artifact_context(kind, expected_context, format_epoch)?;
    let wrapping_key = contextual_wrapping_key(wrapping, expected_context)?;
    let key_context = wrapped_key_context(
        instance,
        kind,
        decoded.key_id,
        decoded.key_epoch,
        expected_context,
    )?;
    let key = DataProtection::unwrap_key_payload(
        &wrapping_key,
        &decoded.wrapped_payload,
        key_context,
        object,
    )
    .map_err(map_frame_failure)?;
    let encoded_limit = u32::try_from(frame.len())
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let limits = FrameLimits::new(encoded_limit).map_err(map_frame_failure)?;
    DataProtection::open_frame(
        &key,
        object
            .system_frame(FrameSequence::new(0))
            .map_err(map_frame_failure)?,
        frame,
        limits,
    )
    .map(|frame| frame.as_plaintext().to_vec())
    .map_err(map_frame_failure)
}

struct DecodedHeader {
    provider_key_reference: [u8; 16],
    root_key_epoch: u64,
    key_id: [u8; 32],
    key_epoch: u64,
    context_digest: [u8; 32],
    wrapped_payload: [u8; WRAPPED_PAYLOAD_BYTES],
}

fn decode_header(header: &[u8], kind: ArtifactKind) -> Result<DecodedHeader, CatalogFailure> {
    if header.get(..8) != Some(ARTIFACT_MAGIC.as_slice()) || header.get(10) != Some(&kind.tag()) {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    if header.get(8..10) != Some(ARTIFACT_VERSION.to_be_bytes().as_slice())
        || header.get(11..13) != Some(LOCAL_PROVIDER.to_be_bytes().as_slice())
        || header.get(13..15) != Some(AES_256_KWP_ALGORITHM.to_be_bytes().as_slice())
    {
        return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
    }
    Ok(DecodedHeader {
        provider_key_reference: array(header, 15, 31)?,
        root_key_epoch: u64::from_be_bytes(array(header, 31, 39)?),
        key_id: array(header, 39, 71)?,
        key_epoch: u64::from_be_bytes(array(header, 71, 79)?),
        context_digest: array(header, 79, 111)?,
        wrapped_payload: array(header, 111, 247)?,
    })
}

fn array<const N: usize>(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<[u8; N], CatalogFailure> {
    bytes
        .get(start..end)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?
        .try_into()
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
}

fn envelope_context_digest(
    instance: InstanceId,
    kind: ArtifactKind,
    content_identity: [u8; 32],
    format_epoch: FormatEpoch,
    key_id: [u8; 32],
    key_epoch: u64,
) -> Result<[u8; 32], CatalogFailure> {
    let mut context = Vec::with_capacity(ENVELOPE_CONTEXT_DOMAIN.len() + 93);
    context.extend_from_slice(ENVELOPE_CONTEXT_DOMAIN);
    context.extend_from_slice(&instance.0);
    context.push(2);
    context.push(kind.tag());
    context.extend_from_slice(&content_identity);
    context.extend_from_slice(&format_epoch.0.to_be_bytes());
    context.extend_from_slice(&key_id);
    context.extend_from_slice(&key_epoch.to_be_bytes());
    DataProtection::hash(&context)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))
}

fn wrapped_key_context(
    instance: InstanceId,
    kind: ArtifactKind,
    key_id: [u8; 32],
    key_epoch: u64,
    context_digest: [u8; 32],
) -> Result<WrappedKeyContext, CatalogFailure> {
    WrappedKeyContext::system(
        instance.0,
        kind.system_kind(),
        key_id,
        key_epoch,
        context_digest,
    )
    .map_err(map_frame_failure)
}

fn contextual_wrapping_key(
    secret: &CatalogWrappingKey,
    context_digest: [u8; 32],
) -> Result<SecretKeyBytes, CatalogFailure> {
    DataProtection::authenticate(&secret.key, &context_digest)
        .map(|bytes| SecretKeyBytes::from_owned(Box::new(bytes)))
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::AuthenticationFailed))
}

fn wrapping_key_for_header<'secret>(
    secret: &'secret CatalogSecret,
    decoded: &DecodedHeader,
) -> Result<&'secret CatalogWrappingKey, CatalogFailure> {
    if decoded.provider_key_reference == secret.wrapping.provider_key_reference
        && decoded.root_key_epoch == secret.wrapping.key_epoch
    {
        return Ok(&secret.wrapping);
    }
    if let Some(predecessor) = secret.predecessor.as_ref()
        && decoded.provider_key_reference == predecessor.provider_key_reference
        && decoded.root_key_epoch == predecessor.key_epoch
    {
        return Ok(predecessor);
    }
    Err(CatalogFailure::new(
        CatalogFailureCode::AuthenticationFailed,
    ))
}

fn artifact_context(
    kind: ArtifactKind,
    context_digest: [u8; 32],
    format_epoch: FormatEpoch,
) -> Result<FrameObjectContext, CatalogFailure> {
    let object_id = FrameObjectId::new(
        context_digest
            .get(..16)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?
            .try_into()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::InvalidInput))?,
    )
    .map_err(map_frame_failure)?;
    let epoch = FrameFormatEpoch::new(format_epoch.0).map_err(map_frame_failure)?;
    Ok(FrameObjectContext::system(
        kind.system_kind(),
        object_id,
        KeyEpoch::new(1),
        epoch,
    ))
}

pub(super) fn rewrap_artifact_envelope(
    current: &CatalogWrappingKey,
    replacement: &CatalogWrappingKey,
    instance: InstanceId,
    kind: ArtifactKind,
    content_identity: [u8; 32],
    format_epoch: FormatEpoch,
    encoded: &[u8],
) -> Result<Vec<u8>, CatalogFailure> {
    let (header, ciphertext) = encoded
        .split_at_checked(ARTIFACT_HEADER_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let decoded = decode_header(header, kind)?;
    if decoded.provider_key_reference != current.provider_key_reference
        || decoded.root_key_epoch != current.key_epoch
        || decoded.key_epoch != DATA_KEY_EPOCH
    {
        return Err(CatalogFailure::new(
            CatalogFailureCode::AuthenticationFailed,
        ));
    }
    let context = envelope_context_digest(
        instance,
        kind,
        content_identity,
        format_epoch,
        decoded.key_id,
        decoded.key_epoch,
    )?;
    if decoded.context_digest != context {
        return Err(CatalogFailure::new(
            CatalogFailureCode::AuthenticationFailed,
        ));
    }
    let object = artifact_context(kind, context, format_epoch)?;
    let key_context =
        wrapped_key_context(instance, kind, decoded.key_id, decoded.key_epoch, context)?;
    let current_wrapping_key = contextual_wrapping_key(current, context)?;
    let object_key = DataProtection::unwrap_key_payload(
        &current_wrapping_key,
        &decoded.wrapped_payload,
        key_context,
        object,
    )
    .map_err(map_frame_failure)?;
    let replacement_wrapping_key = contextual_wrapping_key(replacement, context)?;
    let replacement_envelope =
        DataProtection::wrap_key_payload(&replacement_wrapping_key, &object_key, key_context)
            .map_err(map_frame_failure)?;
    let mut rewrapped = Vec::with_capacity(encoded.len());
    rewrapped.extend_from_slice(&ARTIFACT_MAGIC);
    rewrapped.extend_from_slice(&ARTIFACT_VERSION.to_be_bytes());
    rewrapped.push(kind.tag());
    rewrapped.extend_from_slice(&LOCAL_PROVIDER.to_be_bytes());
    rewrapped.extend_from_slice(&AES_256_KWP_ALGORITHM.to_be_bytes());
    rewrapped.extend_from_slice(&replacement.provider_key_reference);
    rewrapped.extend_from_slice(&replacement.key_epoch.to_be_bytes());
    rewrapped.extend_from_slice(&decoded.key_id);
    rewrapped.extend_from_slice(&decoded.key_epoch.to_be_bytes());
    rewrapped.extend_from_slice(&context);
    rewrapped.extend_from_slice(&replacement_envelope);
    rewrapped.extend_from_slice(ciphertext);
    Ok(rewrapped)
}

fn map_frame_failure(failure: FrameFailure) -> CatalogFailure {
    let code = match failure.code() {
        FrameFailureCode::LimitExceeded | FrameFailureCode::InvalidLimit => {
            CatalogFailureCode::LimitExceeded
        },
        FrameFailureCode::AuthenticationFailed | FrameFailureCode::OpenFailed => {
            CatalogFailureCode::AuthenticationFailed
        },
        FrameFailureCode::EntropyUnavailable
        | FrameFailureCode::HashFailed
        | FrameFailureCode::SealFailed => CatalogFailureCode::StorageUnavailable,
        FrameFailureCode::InvalidContext
        | FrameFailureCode::MalformedFrame
        | FrameFailureCode::UnsupportedVersion
        | FrameFailureCode::UnsupportedAlgorithm
        | FrameFailureCode::ChecksumMismatch => CatalogFailureCode::IntegrityCorruption,
    };
    CatalogFailure::new(code)
}
