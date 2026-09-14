use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use zeroize::{Zeroize, Zeroizing};

use super::{CatalogFailure, CatalogFailureCode, GovernanceAuditRecord, InstanceId};

const MAGIC: [u8; 8] = *b"POSAUDP1";
const VERSION: u16 = 1;
const SIGNATURE_BYTES: usize = 64;
const ENCODED_BYTES: usize = 8 + 2 + 16 + 8 + 32 + 32 + SIGNATURE_BYTES;
const SIGNING_DOMAIN: &[u8] = b"positron-governance-audit-checkpoint-v1\0";

/// Opaque custody of an Instance Integrity Key for Governance Audit checkpoints.
///
/// The signer retains only the Ed25519 seed needed for checkpoint signatures and
/// zeroizes it when custody ends. Its public key is safe to retain for offline
/// verification.
pub struct AuditCheckpointSigner {
    seed: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
}

impl AuditCheckpointSigner {
    /// Takes ownership of one already-authorized Instance Integrity Key seed.
    pub fn from_seed(mut seed: Box<[u8; 32]>) -> Result<Self, CatalogFailure> {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::AuthenticationFailed))?;
        let public_key = key_pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::AuthenticationFailed))?;
        let retained = Zeroizing::new(*seed);
        seed.zeroize();
        Ok(Self {
            seed: retained,
            public_key,
        })
    }

    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], CatalogFailure> {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(self.seed.as_ref())
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::AuthenticationFailed))?;
        key_pair
            .sign(message)
            .as_ref()
            .try_into()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::AuthenticationFailed))
    }
}

impl std::fmt::Debug for AuditCheckpointSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditCheckpointSigner { <redacted> }")
    }
}

/// A signed, durable anchor for the visible Governance Audit hash chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceAuditCheckpoint {
    instance: InstanceId,
    position: u64,
    record_hash: [u8; 32],
    public_key: [u8; 32],
    signature: [u8; SIGNATURE_BYTES],
}

impl GovernanceAuditCheckpoint {
    pub(super) fn create(
        signer: &AuditCheckpointSigner,
        instance: InstanceId,
        record: &GovernanceAuditRecord,
    ) -> Result<Self, CatalogFailure> {
        let public_key = signer.public_key();
        let message = signing_message(instance, record.position, record.hash, public_key)?;
        let signature = signer.sign(&message)?;
        Ok(Self {
            instance,
            position: record.position,
            record_hash: record.hash,
            public_key,
            signature,
        })
    }

    #[must_use]
    pub const fn instance(&self) -> InstanceId {
        self.instance
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn record_hash(&self) -> [u8; 32] {
        self.record_hash
    }

    /// Verifies this checkpoint against the trusted Instance Integrity public key.
    pub fn verify(&self, trusted_public_key: [u8; 32]) -> Result<(), CatalogFailure> {
        if self.public_key != trusted_public_key {
            return Err(CatalogFailure::new(
                CatalogFailureCode::AuthenticationFailed,
            ));
        }
        let message = signing_message(
            self.instance,
            self.position,
            self.record_hash,
            self.public_key,
        )?;
        UnparsedPublicKey::new(&ED25519, trusted_public_key)
            .verify(&message, &self.signature)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::AuthenticationFailed))
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(ENCODED_BYTES);
        encoded.extend_from_slice(&MAGIC);
        encoded.extend_from_slice(&VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.instance.0);
        encoded.extend_from_slice(&self.position.to_be_bytes());
        encoded.extend_from_slice(&self.record_hash);
        encoded.extend_from_slice(&self.public_key);
        encoded.extend_from_slice(&self.signature);
        encoded
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, CatalogFailure> {
        if encoded.len() != ENCODED_BYTES
            || encoded.get(..8) != Some(MAGIC.as_slice())
            || encoded.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let instance = encoded
            .get(10..26)
            .and_then(|bytes| bytes.try_into().ok())
            .and_then(|bytes| InstanceId::new(bytes).ok())
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        let position = encoded
            .get(26..34)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .filter(|position| *position != 0)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        let record_hash = array(encoded, 34, 66)?;
        let public_key = array(encoded, 66, 98)?;
        let signature = array(encoded, 98, ENCODED_BYTES)?;
        if record_hash.iter().all(|byte| *byte == 0) || public_key.iter().all(|byte| *byte == 0) {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        Ok(Self {
            instance,
            position,
            record_hash,
            public_key,
            signature,
        })
    }
}

pub(super) fn verify_chain(
    records: &[GovernanceAuditRecord],
    trusted_public_key: [u8; 32],
    checkpoint: Option<&GovernanceAuditCheckpoint>,
) -> Result<(), CatalogFailure> {
    let mut predecessor = [0_u8; 32];
    for (offset, record) in records.iter().enumerate() {
        let expected_position = u64::try_from(offset)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        if record.position != expected_position
            || record.predecessor_hash != predecessor
            || record.hash
                != super::codec::audit_hash(
                    record.position,
                    record.predecessor_hash,
                    record.transaction,
                    &record.intent,
                )?
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        predecessor = record.hash;
    }
    if let Some(checkpoint) = checkpoint {
        checkpoint.verify(trusted_public_key)?;
        let offset = checkpoint
            .position
            .checked_sub(1)
            .and_then(|position| usize::try_from(position).ok())
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        if records.get(offset).map(GovernanceAuditRecord::record_hash)
            != Some(checkpoint.record_hash)
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
    }
    Ok(())
}

fn signing_message(
    instance: InstanceId,
    position: u64,
    record_hash: [u8; 32],
    public_key: [u8; 32],
) -> Result<Vec<u8>, CatalogFailure> {
    if position == 0 || record_hash.iter().all(|byte| *byte == 0) {
        return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
    }
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + 88);
    message
        .try_reserve_exact(SIGNING_DOMAIN.len() + 88)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(&instance.0);
    message.extend_from_slice(&position.to_be_bytes());
    message.extend_from_slice(&record_hash);
    message.extend_from_slice(&public_key);
    Ok(message)
}

fn array<const N: usize>(
    encoded: &[u8],
    start: usize,
    end: usize,
) -> Result<[u8; N], CatalogFailure> {
    encoded
        .get(start..end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
}
