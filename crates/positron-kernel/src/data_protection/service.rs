use super::{
    AES_256_GCM_TAG_BYTES, CryptoBackend, CryptoBackendFailure, EncryptedFrame, FRAME_HEADER_BYTES,
    FrameContext, FrameFailure, FrameFailureCode, FrameLimits, FrameObjectContext, ObjectDataKey,
    RustCryptoBackend, SecretKeyBytes, SecretKeyInput, SegmentEnvelopeRoute, VerifiedFrame,
    WrappedKeyContext, encode_associated_data, encode_authenticated_header,
    encode_segment_wrapped_key_payload_with_route, encode_wrapped_key_payload, nonce_for,
    parse_frame, segment_context_encoding_with_route,
    verify_segment_wrapped_key_payload_with_route, verify_wrapped_key_payload,
};

/// The Storage Kernel's authenticated encrypted-frame entry point.
pub(crate) enum DataProtection {}

impl DataProtection {
    pub(super) fn release() -> BackendDataProtection<RustCryptoBackend> {
        BackendDataProtection {
            backend: RustCryptoBackend,
        }
    }

    #[cfg(test)]
    pub(super) fn with_backend<B: CryptoBackend>(backend: B) -> BackendDataProtection<B> {
        BackendDataProtection { backend }
    }

    /// Protects plaintext as one independently authenticated frame-v1 artifact.
    pub fn protect_frame(
        key: &ObjectDataKey,
        context: FrameContext,
        plaintext: &[u8],
        limits: FrameLimits,
    ) -> Result<EncryptedFrame, FrameFailure> {
        Self::release().protect_frame(key, context, plaintext, limits)
    }

    pub(crate) fn protected_frame_length(
        plaintext_bytes: usize,
        limits: FrameLimits,
    ) -> Result<u32, FrameFailure> {
        BackendDataProtection::<RustCryptoBackend>::protected_frame_length(plaintext_bytes, limits)
    }

    /// Authenticates a bounded frame before exposing its plaintext.
    pub fn open_frame(
        key: &ObjectDataKey,
        expected_context: FrameContext,
        encoded: &[u8],
        limits: FrameLimits,
    ) -> Result<VerifiedFrame, FrameFailure> {
        Self::release().open_frame(key, expected_context, encoded, limits)
    }

    pub(crate) fn hash(bytes: &[u8]) -> Result<[u8; 32], FrameFailure> {
        Self::release()
            .backend
            .sha256(bytes)
            .map_err(|_| FrameFailure::new(FrameFailureCode::HashFailed))
    }

    pub(crate) fn authenticate(
        key: &SecretKeyBytes,
        bytes: &[u8],
    ) -> Result<[u8; 32], FrameFailure> {
        Self::release()
            .backend
            .hmac_sha256(key, bytes)
            .map_err(|_| FrameFailure::new(FrameFailureCode::AuthenticationFailed))
    }

    pub(crate) fn authenticate_object_key(
        key: &ObjectDataKey,
        bytes: &[u8],
    ) -> Result<[u8; 32], FrameFailure> {
        Self::authenticate(&key.key, bytes)
    }

    pub(crate) fn verify_object_authentication(
        key: &ObjectDataKey,
        bytes: &[u8],
        expected: &[u8; 32],
    ) -> Result<(), FrameFailure> {
        Self::verify_authentication(&key.key, bytes, expected)
    }

    pub(crate) fn verify_authentication(
        key: &SecretKeyBytes,
        bytes: &[u8],
        expected: &[u8; 32],
    ) -> Result<(), FrameFailure> {
        Self::release()
            .backend
            .verify_hmac_sha256(key, bytes, expected)
            .map_err(|_| FrameFailure::new(FrameFailureCode::AuthenticationFailed))
    }

    pub(crate) fn random_key(object: FrameObjectContext) -> Result<ObjectDataKey, FrameFailure> {
        Self::release().generate_object_key(object)
    }

    pub(crate) fn random_identifier() -> Result<[u8; 32], FrameFailure> {
        Self::random_identifier_with_backend(&Self::release().backend)
    }

    pub(crate) fn ed25519_public_key(
        private_seed: SecretKeyInput,
    ) -> Result<[u8; 32], FrameFailure> {
        Self::release().ed25519_public_key(private_seed)
    }

    #[cfg(test)]
    pub(super) fn with_backend_random_identifier<B: CryptoBackend>(
        backend: B,
    ) -> Result<[u8; 32], FrameFailure> {
        Self::random_identifier_with_backend(&backend)
    }

    fn random_identifier_with_backend<B: CryptoBackend>(
        backend: &B,
    ) -> Result<[u8; 32], FrameFailure> {
        let mut identifier = [0_u8; 32];
        backend
            .fill_random(&mut identifier)
            .map_err(|_| FrameFailure::new(FrameFailureCode::EntropyUnavailable))?;
        if identifier.iter().all(|byte| *byte == 0) {
            return Err(FrameFailure::new(FrameFailureCode::EntropyUnavailable));
        }
        Ok(identifier)
    }

    pub(crate) fn wrap_key_payload(
        wrapping_key: &SecretKeyBytes,
        object_key: &ObjectDataKey,
        context: WrappedKeyContext,
    ) -> Result<Vec<u8>, FrameFailure> {
        let payload = encode_wrapped_key_payload(object_key, context);
        Self::release()
            .backend
            .wrap_key_aes_256_kwp(wrapping_key, &payload.bytes)
            .map_err(|_| FrameFailure::new(FrameFailureCode::SealFailed))
    }

    pub(crate) fn unwrap_key_payload(
        wrapping_key: &SecretKeyBytes,
        wrapped_payload: &[u8],
        context: WrappedKeyContext,
        object: FrameObjectContext,
    ) -> Result<ObjectDataKey, FrameFailure> {
        let payload = Self::release()
            .backend
            .unwrap_key_aes_256_kwp(wrapping_key, wrapped_payload)
            .map_err(|_| FrameFailure::new(FrameFailureCode::AuthenticationFailed))?;
        let key = verify_wrapped_key_payload(payload, context)?;
        Ok(ObjectDataKey { key, object })
    }

    pub(crate) fn wrap_segment_key(
        wrapping_key: &SecretKeyBytes,
        object_key: &ObjectDataKey,
        instance: [u8; 16],
    ) -> Result<Vec<u8>, FrameFailure> {
        Self::wrap_segment_key_with_route(
            wrapping_key,
            object_key,
            instance,
            SegmentEnvelopeRoute {
                provider_family: 1,
                provider_reference: [1; 16],
                provider_key_epoch: 1,
            },
        )
    }

    pub(crate) fn wrap_segment_key_with_route(
        wrapping_key: &SecretKeyBytes,
        object_key: &ObjectDataKey,
        instance: [u8; 16],
        route: SegmentEnvelopeRoute,
    ) -> Result<Vec<u8>, FrameFailure> {
        let context = segment_context_encoding_with_route(instance, object_key.object, route)?;
        let digest = Self::hash(&context)?;
        let payload =
            encode_segment_wrapped_key_payload_with_route(object_key, instance, digest, route)?;
        Self::release()
            .backend
            .wrap_key_aes_256_kwp(wrapping_key, &payload.bytes)
            .map_err(|_| FrameFailure::new(FrameFailureCode::SealFailed))
    }

    pub(crate) fn unwrap_segment_key(
        wrapping_key: &SecretKeyBytes,
        wrapped_payload: &[u8],
        instance: [u8; 16],
        object: FrameObjectContext,
    ) -> Result<ObjectDataKey, FrameFailure> {
        Self::unwrap_segment_key_with_route(
            wrapping_key,
            wrapped_payload,
            instance,
            object,
            SegmentEnvelopeRoute {
                provider_family: 1,
                provider_reference: [1; 16],
                provider_key_epoch: 1,
            },
        )
    }

    pub(crate) fn unwrap_segment_key_with_route(
        wrapping_key: &SecretKeyBytes,
        wrapped_payload: &[u8],
        instance: [u8; 16],
        object: FrameObjectContext,
        route: SegmentEnvelopeRoute,
    ) -> Result<ObjectDataKey, FrameFailure> {
        let context = segment_context_encoding_with_route(instance, object, route)?;
        let digest = Self::hash(&context)?;
        let payload = Self::release()
            .backend
            .unwrap_key_aes_256_kwp(wrapping_key, wrapped_payload)
            .map_err(|_| FrameFailure::new(FrameFailureCode::AuthenticationFailed))?;
        let key = verify_segment_wrapped_key_payload_with_route(
            payload, instance, object, digest, route,
        )?;
        Ok(ObjectDataKey { key, object })
    }
}

pub(super) struct BackendDataProtection<B> {
    pub(super) backend: B,
}

impl<B: CryptoBackend> BackendDataProtection<B> {
    pub(super) fn ed25519_public_key(
        &self,
        private_seed: SecretKeyInput,
    ) -> Result<[u8; 32], FrameFailure> {
        self.backend
            .ed25519_public_key(&private_seed.0)
            .map_err(|_| FrameFailure::new(FrameFailureCode::SealFailed))
    }

    fn protected_frame_length(
        plaintext_bytes: usize,
        limits: FrameLimits,
    ) -> Result<u32, FrameFailure> {
        let ciphertext_bytes = plaintext_bytes
            .checked_add(AES_256_GCM_TAG_BYTES as usize)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        let encoded_bytes = FRAME_HEADER_BYTES
            .checked_add(ciphertext_bytes)
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        if encoded_bytes > limits.max_encoded_bytes {
            return Err(FrameFailure::new(FrameFailureCode::LimitExceeded));
        }
        Ok(encoded_bytes)
    }

    pub(super) fn import_object_key(
        &self,
        input: SecretKeyInput,
        object: FrameObjectContext,
    ) -> ObjectDataKey {
        ObjectDataKey {
            key: input.0,
            object,
        }
    }

    pub(super) fn generate_object_key(
        &self,
        object: FrameObjectContext,
    ) -> Result<ObjectDataKey, FrameFailure> {
        let mut key = SecretKeyBytes::from_owned(Box::new([0_u8; 32]));
        self.backend
            .fill_random(key.expose_to_backend_mut())
            .map_err(|_| FrameFailure::new(FrameFailureCode::EntropyUnavailable))?;
        Ok(ObjectDataKey { key, object })
    }

    pub(super) fn protect_frame(
        &self,
        key: &ObjectDataKey,
        context: FrameContext,
        plaintext: &[u8],
        limits: FrameLimits,
    ) -> Result<EncryptedFrame, FrameFailure> {
        if key.object != context.object {
            return Err(FrameFailure::new(FrameFailureCode::InvalidContext));
        }
        let encoded_bytes = Self::protected_frame_length(plaintext.len(), limits)?;
        let ciphertext_bytes = encoded_bytes
            .checked_sub(FRAME_HEADER_BYTES)
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::LimitExceeded))?;

        let header = encode_authenticated_header(context.sequence, ciphertext_bytes);
        let associated_data = encode_associated_data(&header, context);
        #[cfg(test)]
        record_test_protection_authority(key, nonce_for(context.sequence));
        let ciphertext = self
            .backend
            .seal_aes_256_gcm(
                &key.key,
                nonce_for(context.sequence),
                &associated_data,
                plaintext,
            )
            .map_err(|_| FrameFailure::new(FrameFailureCode::SealFailed))?;
        if ciphertext.len() != ciphertext_bytes as usize {
            return Err(FrameFailure::new(FrameFailureCode::SealFailed));
        }
        let checksum = self
            .backend
            .sha256(&ciphertext)
            .map_err(|_| FrameFailure::new(FrameFailureCode::HashFailed))?;
        let capacity = usize::try_from(encoded_bytes)
            .map_err(|_| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(&header);
        encoded.extend_from_slice(&checksum);
        encoded.extend_from_slice(&ciphertext);
        Ok(EncryptedFrame(encoded))
    }

    pub(super) fn open_frame(
        &self,
        key: &ObjectDataKey,
        expected_context: FrameContext,
        encoded: &[u8],
        limits: FrameLimits,
    ) -> Result<VerifiedFrame, FrameFailure> {
        if key.object != expected_context.object {
            return Err(FrameFailure::new(FrameFailureCode::AuthenticationFailed));
        }
        let encoded_bytes = u32::try_from(encoded.len())
            .map_err(|_| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        if encoded_bytes > limits.max_encoded_bytes {
            return Err(FrameFailure::new(FrameFailureCode::LimitExceeded));
        }
        let parsed = parse_frame(encoded, limits)?;
        if parsed.sequence != expected_context.sequence {
            return Err(FrameFailure::new(FrameFailureCode::AuthenticationFailed));
        }
        if self
            .backend
            .sha256(parsed.ciphertext)
            .map_err(|_| FrameFailure::new(FrameFailureCode::HashFailed))?
            != parsed.checksum
        {
            return Err(FrameFailure::new(FrameFailureCode::ChecksumMismatch));
        }
        let associated_data = encode_associated_data(parsed.authenticated_header, expected_context);
        let plaintext = self
            .backend
            .open_aes_256_gcm(
                &key.key,
                nonce_for(expected_context.sequence),
                &associated_data,
                parsed.ciphertext,
            )
            .map_err(|failure| match failure {
                CryptoBackendFailure::OpenFailed => FrameFailure::new(FrameFailureCode::OpenFailed),
                _ => FrameFailure::new(FrameFailureCode::AuthenticationFailed),
            })?;
        let expected_plaintext_bytes = parsed
            .ciphertext
            .len()
            .checked_sub(AES_256_GCM_TAG_BYTES as usize)
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::MalformedFrame))?;
        if plaintext.len() != expected_plaintext_bytes {
            return Err(FrameFailure::new(FrameFailureCode::OpenFailed));
        }
        Ok(VerifiedFrame(plaintext))
    }
}

#[cfg(test)]
fn record_test_protection_authority(key: &ObjectDataKey, nonce: [u8; 12]) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};

    use sha2::{Digest, Sha256};

    type ProtectionAuthority = ([u8; 32], [u8; 12]);
    static USED: OnceLock<Mutex<HashSet<ProtectionAuthority>>> = OnceLock::new();
    let digest: [u8; 32] = Sha256::digest(key.key.expose_to_backend()).into();
    let unique = USED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((digest, nonce));
    assert!(
        unique,
        "test attempted duplicate protection under one DEK and sequence"
    );
}
