use std::collections::BTreeMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::types::{
    AuditFrontier, CatalogFailure, CatalogFailureCode, CatalogGenerationId, CatalogObjectId,
    CatalogSnapshot, FormatEpoch, GovernanceAuditRecord, InstanceId, MAX_AUDIT_INTENT_BYTES,
    MAX_CATALOG_OBJECTS, SnapshotData, TransactionId,
};

const COMMIT_MAGIC: [u8; 8] = *b"PCOMV001";
const AUDIT_MAGIC: [u8; 8] = *b"PAUDV001";
const CODEC_VERSION: u16 = 1;
const COMMIT_FIXED_BYTES: usize = 194;
const AUDIT_FIXED_BYTES: usize = 102;
pub(super) const MAX_AUDIT_RECORD_BYTES: usize = AUDIT_FIXED_BYTES + MAX_AUDIT_INTENT_BYTES;
const AUDIT_HASH_DOMAIN: &[u8] = b"positron-governance-audit-record-v1";
const TRANSACTION_DIGEST_DOMAIN: &[u8] = b"positron-catalog-transaction-v1";
const OBJECT_SET_DIGEST_DOMAIN: &[u8] = b"positron-catalog-object-set-v1";

#[derive(Clone)]
pub(super) struct CommitRecord {
    pub(super) generation: CatalogGenerationId,
    pub(super) number: u64,
    pub(super) predecessor: CatalogGenerationId,
    pub(super) instance: InstanceId,
    pub(super) format_epoch: FormatEpoch,
    pub(super) transaction: TransactionId,
    pub(super) transaction_digest: [u8; 32],
    pub(super) object_set_digest: [u8; 32],
    pub(super) audit_frontier: AuditFrontier,
    pub(super) objects: Vec<CatalogObjectId>,
}

pub(super) fn object_set_digest(objects: &[CatalogObjectId]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(OBJECT_SET_DIGEST_DOMAIN);
    digest.update((objects.len() as u64).to_be_bytes());
    for object in objects {
        digest.update(object.0);
    }
    digest.finalize().into()
}

pub(super) fn transaction_digest(
    format_epoch: FormatEpoch,
    objects: &[CatalogObjectId],
    audit: Option<&[u8]>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DIGEST_DOMAIN);
    digest.update(format_epoch.0.to_be_bytes());
    digest.update(object_set_digest(objects));
    match audit {
        Some(intent) => {
            digest.update([1]);
            digest.update((intent.len() as u64).to_be_bytes());
            digest.update(intent);
        },
        None => digest.update([0]),
    }
    digest.finalize().into()
}

pub(super) fn prepare_audit(
    predecessor: AuditFrontier,
    transaction: TransactionId,
    intent: &[u8],
) -> Result<(GovernanceAuditRecord, Vec<u8>), CatalogFailure> {
    if intent.is_empty() || intent.len() > MAX_AUDIT_INTENT_BYTES {
        return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
    }
    let position = predecessor
        .position
        .checked_add(1)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let hash = audit_hash(position, predecessor.hash, transaction, intent);
    let record = GovernanceAuditRecord {
        position,
        predecessor_hash: predecessor.hash,
        hash,
        transaction,
        intent: Arc::from(intent),
    };
    Ok((record.clone(), encode_audit(&record)))
}

fn audit_hash(
    position: u64,
    predecessor_hash: [u8; 32],
    transaction: TransactionId,
    intent: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AUDIT_HASH_DOMAIN);
    digest.update(position.to_be_bytes());
    digest.update(predecessor_hash);
    digest.update(transaction.0);
    digest.update((intent.len() as u64).to_be_bytes());
    digest.update(intent);
    digest.finalize().into()
}

fn encode_audit(record: &GovernanceAuditRecord) -> Vec<u8> {
    let intent_bytes = record.intent.len() as u32;
    let mut encoded = Vec::with_capacity(AUDIT_FIXED_BYTES + record.intent.len());
    encoded.extend_from_slice(&AUDIT_MAGIC);
    encoded.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    encoded.extend_from_slice(&record.position.to_be_bytes());
    encoded.extend_from_slice(&record.predecessor_hash);
    encoded.extend_from_slice(&record.transaction.0);
    encoded.extend_from_slice(&intent_bytes.to_be_bytes());
    encoded.extend_from_slice(&record.intent);
    encoded.extend_from_slice(&record.hash);
    encoded
}

pub(super) fn decode_audit(encoded: &[u8]) -> Result<GovernanceAuditRecord, CatalogFailure> {
    let mut decoder = Decoder::new(encoded);
    if decoder.take_array::<8>()? != AUDIT_MAGIC || decoder.u16()? != CODEC_VERSION {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    let position = decoder.u64()?;
    if position == 0 {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    let predecessor_hash = decoder.take_array::<32>()?;
    let transaction = TransactionId::new(decoder.take_array::<16>()?)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let intent_length = decoder.u32()? as usize;
    if intent_length == 0 || intent_length > MAX_AUDIT_INTENT_BYTES {
        return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
    }
    let intent: Arc<[u8]> = Arc::from(decoder.take(intent_length)?);
    let stored_hash = decoder.take_array::<32>()?;
    decoder.finish()?;
    if stored_hash != audit_hash(position, predecessor_hash, transaction, &intent) {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    Ok(GovernanceAuditRecord {
        position,
        predecessor_hash,
        hash: stored_hash,
        transaction,
        intent,
    })
}

pub(super) fn encode_commit(record: &CommitRecord) -> Vec<u8> {
    let object_count = record.objects.len() as u32;
    let mut encoded = Vec::with_capacity(COMMIT_FIXED_BYTES + record.objects.len() * 32);
    encoded.extend_from_slice(&COMMIT_MAGIC);
    encoded.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    encoded.extend_from_slice(&record.number.to_be_bytes());
    encoded.extend_from_slice(&record.predecessor.0);
    encoded.extend_from_slice(&record.instance.0);
    encoded.extend_from_slice(&record.format_epoch.0.to_be_bytes());
    encoded.extend_from_slice(&record.transaction.0);
    encoded.extend_from_slice(&record.transaction_digest);
    encoded.extend_from_slice(&record.object_set_digest);
    encoded.extend_from_slice(&record.audit_frontier.position.to_be_bytes());
    encoded.extend_from_slice(&record.audit_frontier.hash);
    encoded.extend_from_slice(&object_count.to_be_bytes());
    for object in &record.objects {
        encoded.extend_from_slice(&object.0);
    }
    encoded
}

pub(super) fn decode_commit(
    generation: CatalogGenerationId,
    encoded: &[u8],
) -> Result<CommitRecord, CatalogFailure> {
    if CatalogGenerationId(Sha256::digest(encoded).into()) != generation {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    let mut decoder = Decoder::new(encoded);
    if decoder.take_array::<8>()? != COMMIT_MAGIC || decoder.u16()? != CODEC_VERSION {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    let number = decoder.u64()?;
    if number == 0 {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    let predecessor = CatalogGenerationId(decoder.take_array::<32>()?);
    let instance = InstanceId::new(decoder.take_array::<16>()?)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let format_epoch = FormatEpoch::new(decoder.u32()?)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let transaction = TransactionId::new(decoder.take_array::<16>()?)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let transaction_digest = decoder.take_array::<32>()?;
    let stored_object_set_digest = decoder.take_array::<32>()?;
    let audit_frontier = AuditFrontier {
        position: decoder.u64()?,
        hash: decoder.take_array::<32>()?,
    };
    let object_count = decoder.u32()? as usize;
    if object_count == 0 || object_count > MAX_CATALOG_OBJECTS {
        return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
    }
    let mut objects = Vec::with_capacity(object_count);
    for _ in 0..object_count {
        objects.push(CatalogObjectId(decoder.take_array::<32>()?));
    }
    decoder.finish()?;
    if objects
        .iter()
        .zip(objects.iter().skip(1))
        .any(|(first, second)| first >= second)
        || object_set_digest(&objects) != stored_object_set_digest
    {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    Ok(CommitRecord {
        generation,
        number,
        predecessor,
        instance,
        format_epoch,
        transaction,
        transaction_digest,
        object_set_digest: stored_object_set_digest,
        audit_frontier,
        objects,
    })
}

pub(super) fn generation_identity(encoded_commit: &[u8]) -> CatalogGenerationId {
    CatalogGenerationId(Sha256::digest(encoded_commit).into())
}

pub(super) fn snapshot_from_record(
    record: &CommitRecord,
    objects: BTreeMap<CatalogObjectId, Arc<[u8]>>,
) -> CatalogSnapshot {
    CatalogSnapshot(Arc::new(SnapshotData {
        identity: record.generation,
        number: record.number,
        format_epoch: Some(record.format_epoch),
        objects,
        audit_frontier: record.audit_frontier,
    }))
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CatalogFailure> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        self.remaining = remaining;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CatalogFailure> {
        let mut value = [0_u8; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, CatalogFailure> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn u32(&mut self) -> Result<u32, CatalogFailure> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn u64(&mut self) -> Result<u64, CatalogFailure> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn finish(self) -> Result<(), CatalogFailure> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
        }
    }
}
