//! Domain-separated Instance Integrity Key signatures for durable Query exports.

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::BootstrapIntegrityIdentity;

const DOMAIN: &[u8] = b"positron-query-export-manifest-signature-v1\0";
const MAX_PAYLOAD_BYTES: usize = 42_496;
const SIGNATURE_BYTES: usize = 64;

/// Opaque custody of the Instance Integrity Key for Query export manifests.
pub struct ExportManifestSigner {
    seed: Zeroizing<[u8; 32]>,
    identity: BootstrapIntegrityIdentity,
}

impl ExportManifestSigner {
    /// Takes already-authorized Instance Integrity Key material into export-only custody.
    pub(crate) fn from_seed(
        mut seed: Box<[u8; 32]>,
    ) -> Result<Self, ExportManifestSignatureFailure> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| ExportManifestSignatureFailure::AuthenticationFailed)?;
        let public_key: [u8; 32] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| ExportManifestSignatureFailure::AuthenticationFailed)?;
        let identity = integrity_identity(public_key)?;
        let retained = Zeroizing::new(*seed);
        seed.zeroize();
        Ok(Self {
            seed: retained,
            identity,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> BootstrapIntegrityIdentity {
        self.identity
    }

    /// Signs one bounded canonical Query export manifest under its dedicated domain.
    pub fn sign(
        &self,
        payload: &[u8],
    ) -> Result<ExportManifestSignature, ExportManifestSignatureFailure> {
        let message = signing_message(self.identity, payload)?;
        let pair = Ed25519KeyPair::from_seed_unchecked(self.seed.as_ref())
            .map_err(|_| ExportManifestSignatureFailure::AuthenticationFailed)?;
        let signature: [u8; SIGNATURE_BYTES] = pair
            .sign(&message)
            .as_ref()
            .try_into()
            .map_err(|_| ExportManifestSignatureFailure::AuthenticationFailed)?;
        ExportManifestSignature::new(self.identity, signature)
    }
}

impl std::fmt::Debug for ExportManifestSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExportManifestSigner { <redacted> }")
    }
}

/// One Instance Integrity Key signature over a canonical durable export manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportManifestSignature {
    identity: BootstrapIntegrityIdentity,
    signature: [u8; SIGNATURE_BYTES],
}

impl ExportManifestSignature {
    /// Reconstructs received signature evidence after the caller has already
    /// validated its claimed Instance Integrity identity against pinned trust.
    pub fn new(
        identity: BootstrapIntegrityIdentity,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, ExportManifestSignatureFailure> {
        if signature.iter().all(|byte| *byte == 0) {
            return Err(ExportManifestSignatureFailure::AuthenticationFailed);
        }
        Ok(Self {
            identity,
            signature,
        })
    }

    #[must_use]
    pub const fn integrity_identity(self) -> BootstrapIntegrityIdentity {
        self.identity
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; SIGNATURE_BYTES] {
        self.signature
    }

    /// Verifies against an externally pinned Instance Integrity identity.
    ///
    /// The embedded identity is evidence only; it is never trusted by itself.
    pub fn verify(
        self,
        expected: BootstrapIntegrityIdentity,
        payload: &[u8],
    ) -> Result<(), ExportManifestSignatureFailure> {
        if self.identity != expected {
            return Err(ExportManifestSignatureFailure::AuthenticationFailed);
        }
        let message = signing_message(expected, payload)?;
        UnparsedPublicKey::new(&ED25519, expected.public_key())
            .verify(&message, &self.signature)
            .map_err(|_| ExportManifestSignatureFailure::AuthenticationFailed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportManifestSignatureFailure {
    LimitExceeded,
    AuthenticationFailed,
}

impl std::fmt::Display for ExportManifestSignatureFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("export manifest signature operation failed")
    }
}
impl std::error::Error for ExportManifestSignatureFailure {}

fn integrity_identity(
    public_key: [u8; 32],
) -> Result<BootstrapIntegrityIdentity, ExportManifestSignatureFailure> {
    let mut input = Vec::new();
    input
        .try_reserve_exact(48)
        .map_err(|_| ExportManifestSignatureFailure::LimitExceeded)?;
    input.extend_from_slice(b"positron-instance-integrity-key-fingerprint-v1\0");
    input.extend_from_slice(&public_key);
    let fingerprint: [u8; 32] = Sha256::digest(input).into();
    Ok(BootstrapIntegrityIdentity::new_for_integrity_signing(
        public_key,
        fingerprint,
    ))
}
fn signing_message(
    identity: BootstrapIntegrityIdentity,
    payload: &[u8],
) -> Result<Vec<u8>, ExportManifestSignatureFailure> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ExportManifestSignatureFailure::LimitExceeded);
    }
    let mut message = Vec::new();
    message
        .try_reserve_exact(DOMAIN.len() + 32 + 32 + 4 + payload.len())
        .map_err(|_| ExportManifestSignatureFailure::LimitExceeded)?;
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&identity.public_key());
    message.extend_from_slice(&identity.fingerprint());
    message.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| ExportManifestSignatureFailure::LimitExceeded)?
            .to_be_bytes(),
    );
    message.extend_from_slice(payload);
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_requires_the_externally_pinned_integrity_identity() {
        let signer =
            ExportManifestSigner::from_seed(Box::new([0x51; 32])).expect("fixture integrity key");
        let signature = signer.sign(&vec![0x61; MAX_PAYLOAD_BYTES]).expect("sign");
        let pinned = BootstrapIntegrityIdentity::from_pinned(
            signer.identity().public_key(),
            signer.identity().fingerprint(),
        )
        .expect("pinned IKI identity validates");
        let decoded = ExportManifestSignature::new(pinned, signature.bytes())
            .expect("received fixed-size signature evidence validates");
        decoded
            .verify(pinned, &vec![0x61; MAX_PAYLOAD_BYTES])
            .expect("correct pinned IKI verifies");
        assert!(
            BootstrapIntegrityIdentity::from_pinned(signer.identity().public_key(), [0x01; 32],)
                .is_err()
        );
        let other = ExportManifestSigner::from_seed(Box::new([0x52; 32]))
            .expect("other fixture integrity key");
        assert_eq!(
            signature
                .verify(other.identity(), &vec![0x61; MAX_PAYLOAD_BYTES])
                .expect_err("signature must not trust embedded key"),
            ExportManifestSignatureFailure::AuthenticationFailed
        );
        assert_eq!(
            signer
                .sign(&vec![0; MAX_PAYLOAD_BYTES + 1])
                .expect_err("manifest size remains bounded"),
            ExportManifestSignatureFailure::LimitExceeded
        );
    }
}
