use positron_domain::routing::CommitPosition;

use crate::IngestTime;
use crate::catalog::{
    Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, FormatEpoch, TransactionId,
};
use crate::data_protection::DataProtection;

use super::format::{SegmentMetadata, SegmentState};
use super::storage::LedgerStorage;
use super::{
    FORMAT_EPOCH, LedgerFailure, LedgerFailureCode, SegmentId, SegmentScope, map_frame_failure,
};

pub(super) fn fresh_metadata(
    scope: SegmentScope,
    base_position: CommitPosition,
) -> Result<SegmentMetadata, LedgerFailure> {
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(
        random
            .get(..16)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?,
    );
    Ok(SegmentMetadata {
        scope,
        id: SegmentId::new(bytes)?,
        state: SegmentState::Active,
        base_position,
    })
}

pub(super) fn publish_segments(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_scope(catalog, basis, storage, scope, metadata, None, false)
}

pub(super) fn publish_exact_scope_segments(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_scope(catalog, basis, storage, scope, metadata, None, true)
}

pub(super) fn publish_segments_with_frontier(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
    frontier: IngestTime,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_scope(
        catalog,
        basis,
        storage,
        scope,
        metadata,
        Some(frontier),
        false,
    )
}

fn publish_scope(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
    frontier: Option<IngestTime>,
    exact_scope: bool,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(
            basis
                .plaintext_object_count()
                .saturating_add(metadata.len()),
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in basis.plaintext_objects() {
        if storage.is_scope_metadata(bytes, scope) {
            continue;
        }
        if frontier.is_some()
            && super::retention_frontier::decode(bytes)?
                .is_some_and(|(candidate, _)| candidate == scope)
        {
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec())?);
    }
    for segment in metadata {
        objects.push(CatalogObject::new(storage.metadata_object(*segment))?);
    }
    if let Some(frontier) = frontier {
        objects.push(CatalogObject::new(super::retention_frontier::encode(
            scope, frontier,
        ))?);
    }
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let mut transaction = [0_u8; 16];
    transaction.copy_from_slice(
        random
            .get(..16)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?,
    );
    let publication = catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::new(FORMAT_EPOCH)?,
            objects,
        )?,
        None,
    );
    match publication {
        Ok(commit) => Ok(commit.snapshot().clone()),
        Err(failure) => {
            // A generation marker rename may have made the proposal durable
            // before its directory synchronization reported failure. Reconcile
            // the catalog authority before exposing an ordinary rejection to
            // callers whose live ledger still reflects the prior generation.
            if failure.code() != CatalogFailureCode::StorageUnavailable {
                return Err(failure.into());
            }
            catalog
                .refresh_state()
                .map_err(|failure| LedgerFailure::ambiguous(LedgerFailure::from(failure).code()))?;
            let snapshot = catalog
                .pin()
                .map_err(|failure| LedgerFailure::ambiguous(LedgerFailure::from(failure).code()))?;
            if snapshot.identity() == basis.identity() {
                return Err(failure.into());
            }
            let segments = storage.catalog_segments(&snapshot, scope)?;
            let segments_subsume = metadata.iter().all(|expected| segments.contains(expected))
                && (!exact_scope || segments.len() == metadata.len());
            let frontier_subsumed = match frontier {
                Some(expected) => super::retention_frontier::recover(&snapshot, scope)?
                    .is_some_and(|published| published >= expected),
                None => true,
            };
            if snapshot.number() > basis.number() && segments_subsume && frontier_subsumed {
                Ok(snapshot)
            } else {
                Err(LedgerFailure::ambiguous(LedgerFailureCode::StaleGeneration))
            }
        },
    }
}
