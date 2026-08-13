use positron_domain::routing::CommitPosition;

use crate::data_protection::{DataProtection, ObjectDataKey};

use super::{LedgerFailure, map_frame_failure};

const RECEIPT_AUTHENTICATOR_DOMAIN: &[u8] = b"positron-ledger-receipt-v1\0";

pub(super) fn receipt_authenticator(
    key: &ObjectDataKey,
    durable_bytes: u64,
    next_sequence: u64,
    position: CommitPosition,
) -> Result<[u8; 32], LedgerFailure> {
    let mut evidence = Vec::with_capacity(RECEIPT_AUTHENTICATOR_DOMAIN.len() + 24);
    evidence.extend_from_slice(RECEIPT_AUTHENTICATOR_DOMAIN);
    evidence.extend_from_slice(&durable_bytes.to_be_bytes());
    evidence.extend_from_slice(&next_sequence.to_be_bytes());
    evidence.extend_from_slice(&position.value().to_be_bytes());
    DataProtection::authenticate_object_key(key, &evidence).map_err(map_frame_failure)
}
