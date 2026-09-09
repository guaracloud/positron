use super::codec::{
    CommitRecord, decode_audit, decode_commit, generation_identity, transaction_digest,
};
use super::types::{CatalogFailure, CatalogFailureCode, GovernanceAuditRecord, TransactionId};

const PREPARED_MAGIC: [u8; 8] = *b"PPRE0001";
const PREPARED_VERSION: u16 = 1;
pub(super) const MAX_PREPARED_BYTES: usize = 400_000;

/// Exact, encrypted transaction-owned evidence needed to complete a
/// pre-marker administrative retry without recreating entropy-derived state.
#[derive(Clone)]
pub(super) struct PreparedCommit {
    pub(super) request_digest: [u8; 32],
    pub(super) record: CommitRecord,
    pub(super) encoded_commit: Vec<u8>,
    pub(super) audit: GovernanceAuditRecord,
    pub(super) encoded_audit: Vec<u8>,
}

impl PreparedCommit {
    pub(super) fn new(
        request_digest: [u8; 32],
        record: CommitRecord,
        encoded_commit: Vec<u8>,
        audit: GovernanceAuditRecord,
        encoded_audit: Vec<u8>,
    ) -> Result<Self, CatalogFailure> {
        let prepared = Self {
            request_digest,
            record,
            encoded_commit,
            audit,
            encoded_audit,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, CatalogFailure> {
        self.validate()?;
        let capacity = PREPARED_MAGIC
            .len()
            .checked_add(2)
            .and_then(|value| value.checked_add(32))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(self.encoded_commit.len()))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(self.encoded_audit.len()))
            .filter(|value| *value <= MAX_PREPARED_BYTES)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(&PREPARED_MAGIC);
        encoded.extend_from_slice(&PREPARED_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.request_digest);
        encoded.extend_from_slice(
            &u32::try_from(self.encoded_commit.len())
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&self.encoded_commit);
        encoded.extend_from_slice(
            &u32::try_from(self.encoded_audit.len())
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&self.encoded_audit);
        Ok(encoded)
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, CatalogFailure> {
        if encoded.len() > MAX_PREPARED_BYTES {
            return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
        }
        let mut decoder = Decoder::new(encoded);
        if decoder.array::<8>()? != PREPARED_MAGIC {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        if decoder.u16()? != PREPARED_VERSION {
            return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
        }
        let request_digest = decoder.array::<32>()?;
        let encoded_commit = decoder.length_prefixed()?;
        let encoded_audit = decoder.length_prefixed()?;
        decoder.finish()?;
        let generation = generation_identity(&encoded_commit)?;
        let record = decode_commit(generation, &encoded_commit)?;
        let audit = decode_audit(&encoded_audit)?;
        Self::new(request_digest, record, encoded_commit, audit, encoded_audit)
    }

    fn validate(&self) -> Result<(), CatalogFailure> {
        let decoded_commit = decode_commit(self.record.generation, &self.encoded_commit)?;
        let decoded_audit = decode_audit(&self.encoded_audit)?;
        if decoded_commit != self.record
            || decoded_audit != self.audit
            || self.record.transaction != self.audit.transaction
            || self.record.audit_frontier.position != self.audit.position
            || self.record.audit_frontier.hash != self.audit.hash
            || generation_identity(&self.encoded_commit)? != self.record.generation
            || transaction_digest(
                self.record.format_epoch,
                &self.record.objects,
                Some(self.audit.intent()),
            )? != self.record.transaction_digest
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        Ok(())
    }

    pub(super) fn transaction(&self) -> TransactionId {
        self.record.transaction
    }
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CatalogFailure> {
        let bytes = self
            .remaining
            .get(..length)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        self.remaining = self
            .remaining
            .get(length..)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CatalogFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
    }

    fn u16(&mut self) -> Result<u16, CatalogFailure> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn length_prefixed(&mut self) -> Result<Vec<u8>, CatalogFailure> {
        let length = usize::try_from(u32::from_be_bytes(self.array::<4>()?))
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        if length == 0 || length > MAX_PREPARED_BYTES {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        Ok(self.take(length)?.to_vec())
    }

    fn finish(self) -> Result<(), CatalogFailure> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
        }
    }
}
