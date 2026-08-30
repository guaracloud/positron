use crate::ResourceReservation;
use crate::data_protection::DataProtection;
use std::sync::OnceLock;

use super::{IngestTime, LedgerFailure, LedgerFailureCode, SegmentScope, StoreBlockIdentity};
use crate::active_segment_ledger::MAX_STORE_BLOCK_BYTES;

/// Opaque canonical Store Block bytes and their caller-owned stable identity.
pub struct PreparedStoreBlock<'capacity> {
    pub(in crate::active_segment_ledger) scope: SegmentScope,
    pub(in crate::active_segment_ledger) identity: StoreBlockIdentity,
    pub(in crate::active_segment_ledger) payload: Vec<u8>,
    pub(in crate::active_segment_ledger) content_digest: OnceLock<[u8; 32]>,
    pub(in crate::active_segment_ledger) preparation_capacity:
        Option<ResourceReservation<'capacity>>,
    pub(in crate::active_segment_ledger) retention_ingest_time: Option<IngestTime>,
}

impl PreparedStoreBlock<'static> {
    pub fn new(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
    ) -> Result<Self, LedgerFailure> {
        Self::checked(scope, identity, bytes, None, None)
    }
}

impl<'capacity> PreparedStoreBlock<'capacity> {
    /// Computes the stable digest used to reconcile this canonical payload.
    pub fn content_digest(&self) -> Result<[u8; 32], LedgerFailure> {
        if let Some(digest) = self.content_digest.get() {
            return Ok(*digest);
        }
        let digest = DataProtection::hash(&self.payload)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        Ok(publish_digest(&self.content_digest, digest))
    }

    pub fn new_with_preparation_capacity(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
        capacity: ResourceReservation<'capacity>,
    ) -> Result<Self, LedgerFailure> {
        Self::checked(scope, identity, bytes, Some(capacity), None)
    }

    /// Carries Signal Store-derived lifecycle metadata into the authenticated
    /// durability frontier without exposing it as a deletion selector.
    pub fn new_with_preparation_capacity_and_ingest_time(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
        capacity: ResourceReservation<'capacity>,
        latest_ingest_time: IngestTime,
    ) -> Result<Self, LedgerFailure> {
        Self::checked(
            scope,
            identity,
            bytes,
            Some(capacity),
            Some(latest_ingest_time),
        )
    }

    fn checked(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
        preparation_capacity: Option<ResourceReservation<'capacity>>,
        retention_ingest_time: Option<IngestTime>,
    ) -> Result<Self, LedgerFailure> {
        if bytes.is_empty() || bytes.len() > MAX_STORE_BLOCK_BYTES {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        Ok(Self {
            scope,
            identity,
            payload: bytes,
            content_digest: OnceLock::new(),
            preparation_capacity,
            retention_ingest_time,
        })
    }
}

fn publish_digest(content_digest: &OnceLock<[u8; 32]>, digest: [u8; 32]) -> [u8; 32] {
    match content_digest.set(digest) {
        Ok(()) => digest,
        Err(existing) => content_digest
            .get()
            .copied()
            .map_or(existing, |stored| stored),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::publish_digest;

    #[test]
    fn competing_digest_publication_keeps_the_first_value() {
        let content_digest = OnceLock::new();
        assert_eq!(publish_digest(&content_digest, [0x11; 32]), [0x11; 32]);
        assert_eq!(publish_digest(&content_digest, [0x22; 32]), [0x11; 32]);
    }
}
