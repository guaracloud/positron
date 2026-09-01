use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;

use crate::catalog::{Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, FormatEpoch};
use crate::data_protection::DataProtection;
use crate::{CatalogSnapshot, IngestTime, TransactionId};

use super::{FORMAT_EPOCH, LedgerFailure, LedgerFailureCode, SegmentScope, map_frame_failure};

const MAGIC: &[u8; 8] = b"PRETFR01";
const VERSION: u16 = 1;
const RECORD_BYTES: usize = 8 + 2 + 16 + 1 + 4 + 8;

pub(super) fn recover(
    snapshot: &CatalogSnapshot,
    scope: SegmentScope,
) -> Result<Option<IngestTime>, LedgerFailure> {
    let mut recovered = None;
    for bytes in snapshot.plaintext_objects() {
        let Some((candidate_scope, instant)) = decode(bytes)? else {
            continue;
        };
        if candidate_scope == scope && recovered.replace(instant).is_some() {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
    }
    Ok(recovered)
}

pub(super) fn publish(
    catalog: &Catalog<'_>,
    basis: &CatalogSnapshot,
    scope: SegmentScope,
    frontier: IngestTime,
) -> Result<(), LedgerFailure> {
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(basis.plaintext_object_count().saturating_add(1))
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in basis.plaintext_objects() {
        objects.push(CatalogObject::new(bytes.to_vec())?);
    }
    objects.push(CatalogObject::new(encode(scope, frontier))?);
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let mut transaction = [0_u8; 16];
    transaction.copy_from_slice(
        random
            .get(..16)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?,
    );
    let result = catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::new(FORMAT_EPOCH)?,
            objects,
        )?,
        None,
    );
    match result {
        Ok(_) => Ok(()),
        Err(failure) if failure.code() == CatalogFailureCode::StorageUnavailable => {
            #[cfg(any(test, fuzzing, feature = "test-support"))]
            super::fault::emit_event(
                super::fault::LedgerFileEvent::BeforeRetentionFrontierReconciliation,
            )?;
            catalog.refresh_state().map_err(ambiguous_catalog)?;
            let latest = catalog.pin().map_err(ambiguous_catalog)?;
            let recovered = recover(&latest, scope)
                .map_err(|recovery| LedgerFailure::ambiguous(recovery.code()))?;
            if recovered.is_some_and(|durable| durable >= frontier) {
                Ok(())
            } else if latest.identity() == basis.identity() {
                Err(failure.into())
            } else {
                let failure = LedgerFailure::from(failure);
                Err(LedgerFailure::ambiguous(failure.code()))
            }
        },
        Err(failure) => Err(failure.into()),
    }
}

fn ambiguous_catalog(failure: crate::CatalogFailure) -> LedgerFailure {
    let failure = LedgerFailure::from(failure);
    LedgerFailure::ambiguous(failure.code())
}

pub(super) fn encode(scope: SegmentScope, frontier: IngestTime) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RECORD_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&scope.tenant_id().to_bytes());
    bytes.push(match scope.signal_kind() {
        SignalKind::Logs => 1,
        SignalKind::Traces => 2,
    });
    bytes.extend_from_slice(&scope.shard_id().value().to_be_bytes());
    bytes.extend_from_slice(&frontier.instant().value().to_be_bytes());
    bytes
}

pub(super) fn decode(bytes: &[u8]) -> Result<Option<(SegmentScope, IngestTime)>, LedgerFailure> {
    if !bytes.starts_with(MAGIC) {
        return Ok(None);
    }
    if bytes.len() != RECORD_BYTES || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice()) {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    let tenant = TenantId::from_bytes(exact(bytes, 10)?)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    let signal = match bytes.get(26).copied() {
        Some(1) => SignalKind::Logs,
        Some(2) => SignalKind::Traces,
        _ => return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    };
    let shard = VirtualShardId::new(u32::from_be_bytes(exact(bytes, 27)?))
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    let instant = i64::from_be_bytes(exact(bytes, 31)?);
    Ok(Some((
        SegmentScope::new(tenant, signal, shard),
        IngestTime::from_authenticated_durable(UnixNanoseconds::new(instant)),
    )))
}

fn exact<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], LedgerFailure> {
    bytes
        .get(start..start.saturating_add(N))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}
