use super::{
    AES_256_GCM_TAG_BYTES, CryptoBackend, CryptoBackendFailure, EncryptedFrame, FRAME_HEADER_BYTES,
    FrameContext, FrameFailure, FrameFailureCode, FrameLimits, FrameObjectContext, ObjectDataKey,
    RustCryptoBackend, SecretKeyBytes, SecretKeyInput, VerifiedFrame, encode_associated_data,
    encode_authenticated_header, nonce_for, parse_frame,
};

/// The Storage Kernel's authenticated encrypted-frame entry point.
pub(super) enum DataProtection {}

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

    /// Authenticates a bounded frame before exposing its plaintext.
    pub fn open_frame(
        key: &ObjectDataKey,
        expected_context: FrameContext,
        encoded: &[u8],
        limits: FrameLimits,
    ) -> Result<VerifiedFrame, FrameFailure> {
        Self::release().open_frame(key, expected_context, encoded, limits)
    }
}

pub(super) struct BackendDataProtection<B> {
    pub(super) backend: B,
}

impl<B: CryptoBackend> BackendDataProtection<B> {
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
        let ciphertext_bytes = plaintext
            .len()
            .checked_add(AES_256_GCM_TAG_BYTES as usize)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        let encoded_bytes = FRAME_HEADER_BYTES
            .checked_add(ciphertext_bytes)
            .ok_or_else(|| FrameFailure::new(FrameFailureCode::LimitExceeded))?;
        if encoded_bytes > limits.max_encoded_bytes {
            return Err(FrameFailure::new(FrameFailureCode::LimitExceeded));
        }

        let header = encode_authenticated_header(context.sequence, ciphertext_bytes);
        let associated_data = encode_associated_data(&header, context);
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
