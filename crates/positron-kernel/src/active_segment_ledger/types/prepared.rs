use crate::ResourceReservation;
use crate::data_protection::DataProtection;
use std::sync::OnceLock;

use super::{LedgerFailure, LedgerFailureCode, SegmentScope, StoreBlockIdentity};
use crate::active_segment_ledger::MAX_STORE_BLOCK_BYTES;

/// Opaque canonical Store Block bytes and their caller-owned stable identity.
pub struct PreparedStoreBlock<'capacity> {
    pub(in crate::active_segment_ledger) scope: SegmentScope,
    pub(in crate::active_segment_ledger) identity: StoreBlockIdentity,
    pub(in crate::active_segment_ledger) payload: Vec<u8>,
    pub(in crate::active_segment_ledger) content_digest: OnceLock<[u8; 32]>,
    pub(in crate::active_segment_ledger) preparation_capacity:
        Option<ResourceReservation<'capacity>>,
}

impl PreparedStoreBlock<'static> {
    pub fn new(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
    ) -> Result<Self, LedgerFailure> {
        Self::checked(scope, identity, bytes, None)
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
        match self.content_digest.set(digest) {
            Ok(()) => Ok(digest),
            Err(existing) => match self.content_digest.get() {
                Some(stored) => Ok(*stored),
                None => Ok(existing),
            },
        }
    }

    pub fn new_with_preparation_capacity(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
        capacity: ResourceReservation<'capacity>,
    ) -> Result<Self, LedgerFailure> {
        Self::checked(scope, identity, bytes, Some(capacity))
    }

    fn checked(
        scope: SegmentScope,
        identity: StoreBlockIdentity,
        bytes: Vec<u8>,
        preparation_capacity: Option<ResourceReservation<'capacity>>,
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
        })
    }
}
