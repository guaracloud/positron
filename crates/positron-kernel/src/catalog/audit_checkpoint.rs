use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use zeroize::{Zeroize, Zeroizing};

use super::{CatalogFailure, CatalogFailureCode, CatalogObject, GovernanceAuditRecord, InstanceId};

const MAGIC: [u8; 8] = *b"POSAUDP1";
const VERSION: u16 = 1;
const SIGNATURE_BYTES: usize = 64;
const ENCODED_BYTES: usize = 8 + 2 + 16 + 8 + 32 + 32 + SIGNATURE_BYTES;
const SIGNING_DOMAIN: &[u8] = b"positron-governance-audit-checkpoint-v1\0";
const RETENTION_MAGIC: [u8; 8] = *b"POSAUDR1";
const RETENTION_VERSION: u16 = 1;
const RETENTION_ENCODED_BYTES: usize = 8 + 2 + 16 + 32 + 8 + 8 + 32 + 32 + SIGNATURE_BYTES;
const RETENTION_SIGNING_DOMAIN: &[u8] = b"positron-governance-audit-retention-anchor-v1\0";
const RETENTION_POLICY_MAGIC: [u8; 8] = *b"POSAUP01";
const RETENTION_POLICY_VERSION: u16 = 1;
const RETENTION_POLICY_ENCODED_BYTES: usize = 8 + 2 + 16 + 8;

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

/// Trusted system policy and Instance Integrity Key material required to
/// authorize a retained Governance Audit suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditRetentionTrust {
    instance: InstanceId,
    integrity_public_key: [u8; 32],
    integrity_key_fingerprint: [u8; 32],
    system_policy_generation: u64,
}

impl AuditRetentionTrust {
    pub fn new(
        instance: InstanceId,
        integrity_public_key: [u8; 32],
        integrity_key_fingerprint: [u8; 32],
        system_policy_generation: u64,
    ) -> Result<Self, CatalogFailure> {
        if integrity_public_key.iter().all(|byte| *byte == 0)
            || integrity_key_fingerprint.iter().all(|byte| *byte == 0)
            || system_policy_generation == 0
        {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        Ok(Self {
            instance,
            integrity_public_key,
            integrity_key_fingerprint,
            system_policy_generation,
        })
    }

    #[must_use]
    pub const fn instance(self) -> InstanceId {
        self.instance
    }

    #[must_use]
    pub const fn integrity_public_key(self) -> [u8; 32] {
        self.integrity_public_key
    }

    #[must_use]
    pub const fn integrity_key_fingerprint(self) -> [u8; 32] {
        self.integrity_key_fingerprint
    }

    #[must_use]
    pub const fn system_policy_generation(self) -> u64 {
        self.system_policy_generation
    }
}

/// The Administration-owned system policy generation that authorizes
/// Governance Audit retention. Tenant signal-retention policy is deliberately
/// not an input to this object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemAuditRetentionPolicy {
    instance: InstanceId,
    generation: u64,
}

impl SystemAuditRetentionPolicy {
    pub fn new(instance: InstanceId, generation: u64) -> Result<Self, CatalogFailure> {
        if generation == 0 {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        Ok(Self {
            instance,
            generation,
        })
    }

    #[must_use]
    pub const fn instance(self) -> InstanceId {
        self.instance
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Produces the immutable Catalog object that Administration includes in
    /// its audited system-policy transaction.
    pub fn into_catalog_object(self) -> Result<CatalogObject, CatalogFailure> {
        CatalogObject::new(self.encode())
    }

    fn encode(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(RETENTION_POLICY_ENCODED_BYTES);
        encoded.extend_from_slice(&RETENTION_POLICY_MAGIC);
        encoded.extend_from_slice(&RETENTION_POLICY_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.instance.0);
        encoded.extend_from_slice(&self.generation.to_be_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, CatalogFailure> {
        if encoded.len() != RETENTION_POLICY_ENCODED_BYTES
            || encoded.get(..8) != Some(RETENTION_POLICY_MAGIC.as_slice())
            || encoded.get(8..10) != Some(RETENTION_POLICY_VERSION.to_be_bytes().as_slice())
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let instance = array(encoded, 10, 26).and_then(|bytes| {
            InstanceId::new(bytes)
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
        })?;
        let generation = encoded
            .get(26..34)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .filter(|generation| *generation != 0)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        Ok(Self {
            instance,
            generation,
        })
    }

    pub(super) fn is_encoded(bytes: &[u8]) -> bool {
        bytes.starts_with(&RETENTION_POLICY_MAGIC)
    }
}

/// A signed Catalog-reachable boundary immediately preceding a retained audit
/// suffix. It does not itself reclaim any audit artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRetentionAnchor {
    instance: InstanceId,
    integrity_key_fingerprint: [u8; 32],
    system_policy_generation: u64,
    position: u64,
    record_hash: [u8; 32],
    public_key: [u8; 32],
    signature: [u8; SIGNATURE_BYTES],
}

impl AuditRetentionAnchor {
    pub(super) fn create(
        signer: &AuditCheckpointSigner,
        trust: AuditRetentionTrust,
        record: &GovernanceAuditRecord,
    ) -> Result<Self, CatalogFailure> {
        if signer.public_key() != trust.integrity_public_key {
            return Err(CatalogFailure::new(
                CatalogFailureCode::AuthenticationFailed,
            ));
        }
        let message =
            retention_signing_message(trust, record.position, record.hash, signer.public_key())?;
        Ok(Self {
            instance: trust.instance,
            integrity_key_fingerprint: trust.integrity_key_fingerprint,
            system_policy_generation: trust.system_policy_generation,
            position: record.position,
            record_hash: record.hash,
            public_key: signer.public_key(),
            signature: signer.sign(&message)?,
        })
    }

    #[must_use]
    pub const fn instance(&self) -> InstanceId {
        self.instance
    }

    #[must_use]
    pub const fn system_policy_generation(&self) -> u64 {
        self.system_policy_generation
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn record_hash(&self) -> [u8; 32] {
        self.record_hash
    }

    /// Verifies the exact trusted instance, integrity identity, and policy
    /// generation before accepting this anchor.
    pub fn verify(&self, trust: AuditRetentionTrust) -> Result<(), CatalogFailure> {
        if self.instance != trust.instance
            || self.integrity_key_fingerprint != trust.integrity_key_fingerprint
            || self.system_policy_generation != trust.system_policy_generation
            || self.public_key != trust.integrity_public_key
        {
            return Err(CatalogFailure::new(
                CatalogFailureCode::AuthenticationFailed,
            ));
        }
        let message =
            retention_signing_message(trust, self.position, self.record_hash, self.public_key)?;
        UnparsedPublicKey::new(&ED25519, trust.integrity_public_key)
            .verify(&message, &self.signature)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::AuthenticationFailed))
    }

    /// Verifies a suffix after its physically retained predecessor boundary.
    /// Callers must supply the Catalog-reachable signed anchor; no unanchored
    /// suffix is accepted.
    pub fn verify_retained_suffix(
        records: &[GovernanceAuditRecord],
        anchor: Option<&Self>,
        trust: AuditRetentionTrust,
    ) -> Result<(), CatalogFailure> {
        let anchor =
            anchor.ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        anchor.verify(trust)?;
        let mut predecessor = anchor.record_hash;
        let mut expected = anchor
            .position
            .checked_add(1)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        for record in records {
            if record.position != expected
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
            expected = expected
                .checked_add(1)
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        }
        Ok(())
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(RETENTION_ENCODED_BYTES);
        encoded.extend_from_slice(&RETENTION_MAGIC);
        encoded.extend_from_slice(&RETENTION_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.instance.0);
        encoded.extend_from_slice(&self.integrity_key_fingerprint);
        encoded.extend_from_slice(&self.system_policy_generation.to_be_bytes());
        encoded.extend_from_slice(&self.position.to_be_bytes());
        encoded.extend_from_slice(&self.record_hash);
        encoded.extend_from_slice(&self.public_key);
        encoded.extend_from_slice(&self.signature);
        encoded
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, CatalogFailure> {
        if encoded.len() != RETENTION_ENCODED_BYTES
            || encoded.get(..8) != Some(RETENTION_MAGIC.as_slice())
            || encoded.get(8..10) != Some(RETENTION_VERSION.to_be_bytes().as_slice())
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let instance = array(encoded, 10, 26).and_then(|bytes| {
            InstanceId::new(bytes)
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
        })?;
        let integrity_key_fingerprint = array(encoded, 26, 58)?;
        let system_policy_generation = encoded
            .get(58..66)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .filter(|generation| *generation != 0)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        let position = encoded
            .get(66..74)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .filter(|position| *position != 0)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        let record_hash = array(encoded, 74, 106)?;
        let public_key = array(encoded, 106, 138)?;
        let signature = array(encoded, 138, RETENTION_ENCODED_BYTES)?;
        if integrity_key_fingerprint.iter().all(|byte| *byte == 0)
            || record_hash.iter().all(|byte| *byte == 0)
            || public_key.iter().all(|byte| *byte == 0)
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        Ok(Self {
            instance,
            integrity_key_fingerprint,
            system_policy_generation,
            position,
            record_hash,
            public_key,
            signature,
        })
    }

    pub(super) fn is_encoded(bytes: &[u8]) -> bool {
        bytes.starts_with(&RETENTION_MAGIC)
    }
}

pub(super) fn retention_anchor(
    snapshot: &super::CatalogSnapshot,
) -> Result<Option<AuditRetentionAnchor>, CatalogFailure> {
    let mut found = None;
    for object in snapshot.plaintext_objects() {
        if !AuditRetentionAnchor::is_encoded(object) {
            continue;
        }
        let anchor = AuditRetentionAnchor::decode(object)?;
        if found.replace(anchor).is_some() {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
    }
    Ok(found)
}

pub(super) fn retention_trust(
    snapshot: &super::CatalogSnapshot,
    instance: InstanceId,
) -> Result<AuditRetentionTrust, CatalogFailure> {
    let policy = retention_policy(snapshot)?
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    retention_trust_for_policy(snapshot, instance, policy)
}

pub(super) fn retention_trust_for_policy(
    snapshot: &super::CatalogSnapshot,
    instance: InstanceId,
    policy: SystemAuditRetentionPolicy,
) -> Result<AuditRetentionTrust, CatalogFailure> {
    let (_, governance) = snapshot.governance_object()?;
    if governance.instance() != instance.0 {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    if policy.instance() != instance {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    AuditRetentionTrust::new(
        instance,
        governance.integrity_public_key(),
        governance.integrity_key_fingerprint(),
        policy.generation(),
    )
}

pub(super) fn retention_policy(
    snapshot: &super::CatalogSnapshot,
) -> Result<Option<SystemAuditRetentionPolicy>, CatalogFailure> {
    let mut found = None;
    for object in snapshot.plaintext_objects() {
        if !SystemAuditRetentionPolicy::is_encoded(object) {
            continue;
        }
        let policy = SystemAuditRetentionPolicy::decode(object)?;
        if found.replace(policy).is_some() {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
    }
    Ok(found)
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

fn retention_signing_message(
    trust: AuditRetentionTrust,
    position: u64,
    record_hash: [u8; 32],
    public_key: [u8; 32],
) -> Result<Vec<u8>, CatalogFailure> {
    if position == 0 || record_hash.iter().all(|byte| *byte == 0) {
        return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
    }
    let mut message = Vec::with_capacity(RETENTION_SIGNING_DOMAIN.len() + 128);
    message
        .try_reserve_exact(RETENTION_SIGNING_DOMAIN.len() + 128)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    message.extend_from_slice(RETENTION_SIGNING_DOMAIN);
    message.extend_from_slice(&trust.instance.0);
    message.extend_from_slice(&trust.integrity_key_fingerprint);
    message.extend_from_slice(&trust.system_policy_generation.to_be_bytes());
    message.extend_from_slice(&position.to_be_bytes());
    message.extend_from_slice(&record_hash);
    message.extend_from_slice(&public_key);
    Ok(message)
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
