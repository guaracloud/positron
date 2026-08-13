use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;

use zeroize::Zeroizing;

use crate::catalog::{CatalogSecret, InstanceId};
use crate::data_protection::{
    DataProtection, FrameLimits, FrameSequence, ObjectDataKey, SecretKeyBytes, SecretKeyInput,
};
use crate::{SegmentProtectionKey, SegmentScope};
use positron_domain::identity::TenantId;

use super::bootstrap::initialize_local_key;
use super::persistence::open_existing_local_key;
use super::security_directory::FreshInitializationRootProof;
use super::{LocalKeyFailure, VerifiedLocalKey};

const ENVELOPE_MAGIC: [u8; 8] = *b"POSBOOT1";
const ENVELOPE_BYTES_LIMIT: u32 = 1_048_960;
const ENVELOPE_HEADER_BYTES: usize = 49;

mod derivation;
mod directory;
use derivation::{derive_child, object_context, tenant_object_id, wrapped_context};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapObjectPurpose {
    Pending,
    Initialized,
    Claim,
}

impl BootstrapObjectPurpose {
    const fn tag(self) -> u8 {
        match self {
            Self::Pending => 1,
            Self::Initialized => 2,
            Self::Claim => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapKeyIdentity {
    key_id: [u8; 16],
    fingerprint: [u8; 32],
    created_at_unix_seconds: u64,
}

impl BootstrapKeyIdentity {
    pub fn from_parts(
        key_id: [u8; 16],
        fingerprint: [u8; 32],
        created_at_unix_seconds: u64,
    ) -> Result<Self, BootstrapKeyFailure> {
        if key_id.iter().all(|byte| *byte == 0) || fingerprint.iter().all(|byte| *byte == 0) {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        Ok(Self {
            key_id,
            fingerprint,
            created_at_unix_seconds,
        })
    }

    #[must_use]
    pub const fn key_id(self) -> [u8; 16] {
        self.key_id
    }

    #[must_use]
    pub const fn fingerprint(self) -> [u8; 32] {
        self.fingerprint
    }

    #[must_use]
    pub const fn created_at_unix_seconds(self) -> u64 {
        self.created_at_unix_seconds
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapKeyFailure {
    Custody,
    Entropy,
    Authentication,
    InvalidInput,
    LimitExceeded,
}

impl Display for BootstrapKeyFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("instance bootstrap key operation failed")
    }
}

impl Error for BootstrapKeyFailure {}

pub struct BootstrapKeyCustody {
    key: VerifiedLocalKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapIntegrityIdentity {
    public_key: [u8; 32],
    fingerprint: [u8; 32],
}

impl BootstrapIntegrityIdentity {
    #[must_use]
    pub const fn public_key(self) -> [u8; 32] {
        self.public_key
    }

    #[must_use]
    pub const fn fingerprint(self) -> [u8; 32] {
        self.fingerprint
    }
}

impl std::fmt::Debug for BootstrapKeyCustody {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BootstrapKeyCustody { <redacted> }")
    }
}

impl BootstrapKeyCustody {
    pub fn initialize(secrets_root: &Path) -> Result<Self, BootstrapKeyFailure> {
        let proof = FreshInitializationRootProof::new(secrets_root).map_err(map_local)?;
        initialize_local_key(proof)
            .map(|key| Self { key })
            .map_err(map_local)
    }

    pub fn open(secrets_root: &Path) -> Result<Self, BootstrapKeyFailure> {
        open_existing_local_key(secrets_root)
            .map(|key| Self { key })
            .map_err(map_local)
    }

    #[must_use]
    pub const fn identity(&self) -> BootstrapKeyIdentity {
        BootstrapKeyIdentity {
            key_id: self.key.evidence.key_id.0,
            fingerprint: self.key.evidence.fingerprint.0,
            created_at_unix_seconds: self.key.evidence.creation_time.0,
        }
    }

    pub fn random_identifier(&self) -> Result<[u8; 16], BootstrapKeyFailure> {
        let bytes =
            DataProtection::random_identifier().map_err(|_| BootstrapKeyFailure::Entropy)?;
        let mut identifier = [0_u8; 16];
        identifier.copy_from_slice(bytes.get(..16).ok_or(BootstrapKeyFailure::Entropy)?);
        if identifier.iter().all(|byte| *byte == 0) {
            Err(BootstrapKeyFailure::Entropy)
        } else {
            Ok(identifier)
        }
    }

    pub fn random_secret(&self) -> Result<Box<[u8; 32]>, BootstrapKeyFailure> {
        DataProtection::random_identifier()
            .map(Box::new)
            .map_err(|_| BootstrapKeyFailure::Entropy)
    }

    pub fn catalog_secret(
        &self,
        instance: InstanceId,
    ) -> Result<CatalogSecret, BootstrapKeyFailure> {
        let system = self.system_kek(instance)?;
        let marker = derive_child(&system, instance, b"catalog-marker", &[])?;
        let wrapping = derive_child(&system, instance, b"catalog-wrapping-kek", &[])?;
        Ok(CatalogSecret::from_owned(marker, wrapping))
    }

    pub fn segment_key(
        &self,
        instance: InstanceId,
        scope: SegmentScope,
    ) -> Result<SegmentProtectionKey, BootstrapKeyFailure> {
        let system = self.system_kek(instance)?;
        let tenant = derive_child(
            &system,
            instance,
            b"tenant-kek",
            &scope.tenant_id().to_bytes(),
        )?;
        let tenant = SecretKeyBytes::from_owned(tenant);
        let mut context = Zeroizing::new(Vec::with_capacity(23));
        context.extend_from_slice(&scope.tenant_id().to_bytes());
        context.push(match scope.signal_kind() {
            positron_domain::routing::SignalKind::Logs => 1,
            positron_domain::routing::SignalKind::Traces => 2,
        });
        context.extend_from_slice(&scope.shard_id().value().to_be_bytes());
        derive_child(&tenant, instance, b"active-segment-wrapping-kek", &context)
            .map(SegmentProtectionKey::from_owned)
    }

    pub fn tenant_key_envelope(
        &self,
        instance: InstanceId,
        tenant: TenantId,
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        let system = self.system_kek(instance)?;
        let tenant_key = derive_child(&system, instance, b"tenant-kek", &tenant.to_bytes())?;
        let object_id = tenant_object_id(tenant)?;
        let context = object_context(object_id)?;
        let object_key = ObjectDataKey::import(SecretKeyInput::from_owned(tenant_key), context);
        DataProtection::wrap_key_payload(
            &system,
            &object_key,
            wrapped_context(instance, BootstrapObjectPurpose::Initialized, object_id)?,
        )
        .map_err(map_frame)
    }

    pub fn protect(
        &self,
        instance: InstanceId,
        purpose: BootstrapObjectPurpose,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        if plaintext.is_empty() {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        let object_id = self.random_identifier()?;
        self.protect_with_object(instance, purpose, object_id, plaintext)
    }

    pub fn protect_instance_integrity_key(
        &self,
        instance: InstanceId,
        plaintext: &[u8; 32],
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        let system = self.system_kek(instance)?;
        let derived = derive_child(&system, instance, b"instance-integrity-object", &[])?;
        let mut object_id = [0_u8; 16];
        object_id.copy_from_slice(derived.get(..16).ok_or(BootstrapKeyFailure::InvalidInput)?);
        if object_id.iter().all(|byte| *byte == 0) {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        self.protect_with_object(
            instance,
            BootstrapObjectPurpose::Initialized,
            object_id,
            plaintext,
        )
    }

    fn protect_with_object(
        &self,
        instance: InstanceId,
        purpose: BootstrapObjectPurpose,
        object_id: [u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        let context = object_context(object_id)?;
        let system = self.system_kek(instance)?;
        let key = self.object_key(&system, instance, purpose, object_id)?;
        let wrapped_context = wrapped_context(instance, purpose, object_id)?;
        let wrapped =
            DataProtection::wrap_key_payload(&system, &key, wrapped_context).map_err(map_frame)?;
        let frame = DataProtection::protect_frame(
            &key,
            context
                .system_frame(FrameSequence::new(0))
                .map_err(map_frame)?,
            plaintext,
            FrameLimits::new(ENVELOPE_BYTES_LIMIT).map_err(map_frame)?,
        )
        .map_err(map_frame)?;
        let frame_bytes = frame.as_bytes();
        let wrapped_length =
            u32::try_from(wrapped.len()).map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let frame_length =
            u32::try_from(frame_bytes.len()).map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let mut encoded = Vec::with_capacity(
            ENVELOPE_HEADER_BYTES
                .saturating_add(wrapped.len())
                .saturating_add(frame_bytes.len()),
        );
        encoded.extend_from_slice(&ENVELOPE_MAGIC);
        encoded.push(purpose.tag());
        encoded.extend_from_slice(&instance.to_bytes());
        encoded.extend_from_slice(&object_id);
        encoded.extend_from_slice(&wrapped_length.to_be_bytes());
        encoded.extend_from_slice(&frame_length.to_be_bytes());
        encoded.extend_from_slice(&wrapped);
        encoded.extend_from_slice(frame_bytes);
        Ok(encoded)
    }

    pub fn open_object(
        &self,
        instance: InstanceId,
        purpose: BootstrapObjectPurpose,
        encoded: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, BootstrapKeyFailure> {
        if encoded.get(..8) != Some(ENVELOPE_MAGIC.as_slice())
            || encoded.get(8).copied() != Some(purpose.tag())
        {
            return Err(BootstrapKeyFailure::Authentication);
        }
        if encoded.get(9..25) != Some(instance.to_bytes().as_slice()) {
            return Err(BootstrapKeyFailure::Authentication);
        }
        let object_id: [u8; 16] = encoded
            .get(25..41)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let wrapped_length = encoded
            .get(41..45)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let frame_length = encoded
            .get(45..49)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let wrapped_end = ENVELOPE_HEADER_BYTES
            .checked_add(
                usize::try_from(wrapped_length).map_err(|_| BootstrapKeyFailure::Authentication)?,
            )
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let wrapped = encoded
            .get(ENVELOPE_HEADER_BYTES..wrapped_end)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let frame = encoded
            .get(wrapped_end..)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        if usize::try_from(frame_length).ok() != Some(frame.len()) {
            return Err(BootstrapKeyFailure::Authentication);
        }
        let system = self.system_kek(instance)?;
        let context = object_context(object_id)?;
        let key = DataProtection::unwrap_key_payload(
            &system,
            wrapped,
            wrapped_context(instance, purpose, object_id)?,
            context,
        )
        .map_err(map_frame)?;
        DataProtection::open_frame(
            &key,
            context
                .system_frame(FrameSequence::new(0))
                .map_err(map_frame)?,
            frame,
            FrameLimits::new(ENVELOPE_BYTES_LIMIT).map_err(map_frame)?,
        )
        .map(|verified| Zeroizing::new(verified.as_plaintext().to_vec()))
        .map_err(map_frame)
    }

    pub fn integrity_identity(
        &self,
        private_seed: &[u8; 32],
    ) -> Result<BootstrapIntegrityIdentity, BootstrapKeyFailure> {
        let public_key =
            DataProtection::ed25519_public_key(SecretKeyInput::from_owned(Box::new(*private_seed)))
                .map_err(map_frame)?;
        let mut input = Vec::with_capacity(72);
        input.extend_from_slice(b"positron-instance-integrity-key-fingerprint-v1\0");
        input.extend_from_slice(&public_key);
        let fingerprint = DataProtection::hash(&input).map_err(map_frame)?;
        Ok(BootstrapIntegrityIdentity {
            public_key,
            fingerprint,
        })
    }
}

fn map_local(_failure: LocalKeyFailure) -> BootstrapKeyFailure {
    BootstrapKeyFailure::Custody
}

fn map_frame(_failure: crate::data_protection::FrameFailure) -> BootstrapKeyFailure {
    BootstrapKeyFailure::Authentication
}
