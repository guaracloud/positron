use crate::ResourceReservation;

use super::{LedgerFailure, LedgerFailureCode, SegmentScope, StoreBlockIdentity};
use crate::active_segment_ledger::MAX_STORE_BLOCK_BYTES;

/// Opaque canonical Store Block bytes and their caller-owned stable identity.
pub struct PreparedStoreBlock<'capacity> {
    pub(in crate::active_segment_ledger) scope: SegmentScope,
    pub(in crate::active_segment_ledger) identity: StoreBlockIdentity,
    pub(in crate::active_segment_ledger) payload: Vec<u8>,
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
            preparation_capacity,
        })
    }
}
