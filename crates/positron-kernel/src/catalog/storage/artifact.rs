use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::data_protection::{
    DataProtection, FrameFailure, FrameFailureCode, FrameFormatEpoch, FrameLimits,
    FrameObjectContext, FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey, SecretKeyInput,
    SystemObjectKind,
};

use super::super::types::{CatalogFailure, CatalogFailureCode, CatalogSecret, FormatEpoch};

const ARTIFACT_MAGIC: [u8; 8] = *b"PARTV001";
const ARTIFACT_HEADER_BYTES: usize = 25;
const FRAME_OVERHEAD_BYTES: usize = 68;
const ARTIFACT_KEY_DOMAIN: &[u8] = b"positron-catalog-artifact-key-v1";
const ARTIFACT_OBJECT_DOMAIN: &[u8] = b"positron-catalog-frame-object-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ArtifactKind {
    Object,
    Audit,
    Commit,
}

impl ArtifactKind {
    const fn tag(self) -> u8 {
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
    kind: ArtifactKind,
    content_identity: [u8; 32],
    format_epoch: FormatEpoch,
    plaintext: &[u8],
) -> Result<Vec<u8>, CatalogFailure> {
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
    let object = artifact_context(kind, content_identity, salt, format_epoch)?;
    let key = ObjectDataKey::import(
        SecretKeyInput::from_owned(Box::new(derive_key(secret, kind, content_identity, salt)?)),
        object,
    );
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
    encoded.push(kind.tag());
    encoded.extend_from_slice(&salt);
    encoded.extend_from_slice(frame.as_bytes());
    Ok(encoded)
}

pub(super) fn open_artifact(
    secret: &CatalogSecret,
    kind: ArtifactKind,
    content_identity: [u8; 32],
    format_epoch: FormatEpoch,
    encoded: &[u8],
) -> Result<Vec<u8>, CatalogFailure> {
    let (header, frame) = encoded
        .split_at_checked(ARTIFACT_HEADER_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    if header.get(..8) != Some(ARTIFACT_MAGIC.as_slice()) || header.get(8) != Some(&kind.tag()) {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    let salt: [u8; 16] = header
        .get(9..25)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?
        .try_into()
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let object = artifact_context(kind, content_identity, salt, format_epoch)?;
    let key = ObjectDataKey::import(
        SecretKeyInput::from_owned(Box::new(derive_key(secret, kind, content_identity, salt)?)),
        object,
    );
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

fn artifact_context(
    kind: ArtifactKind,
    content_identity: [u8; 32],
    salt: [u8; 16],
    format_epoch: FormatEpoch,
) -> Result<FrameObjectContext, CatalogFailure> {
    let mut digest = Sha256::new();
    digest.update(ARTIFACT_OBJECT_DOMAIN);
    digest.update([kind.tag()]);
    digest.update(content_identity);
    digest.update(salt);
    let identity: [u8; 32] = digest.finalize().into();
    let object_id = FrameObjectId::new(
        identity
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

fn derive_key(
    secret: &CatalogSecret,
    kind: ArtifactKind,
    content_identity: [u8; 32],
    salt: [u8; 16],
) -> Result<[u8; 32], CatalogFailure> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(secret.0.expose_to_backend())
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::AuthenticationFailed))?;
    mac.update(ARTIFACT_KEY_DOMAIN);
    mac.update(&[kind.tag()]);
    mac.update(&content_identity);
    mac.update(&salt);
    Ok(mac.finalize().into_bytes().into())
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
