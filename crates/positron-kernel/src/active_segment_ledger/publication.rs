use positron_domain::routing::CommitPosition;

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
) -> Result<(), LedgerFailure> {
    let mut objects = basis
        .plaintext_objects()
        .filter(|bytes| !storage.is_scope_metadata(bytes, scope))
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    for segment in metadata {
        objects.push(CatalogObject::new(storage.metadata_object(*segment))?);
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
        Ok(_) => Ok(()),
        Err(failure) => {
            // A generation marker rename may have made the proposal durable
            // before its directory synchronization reported failure. Reconcile
            // the catalog authority before exposing an ordinary rejection to
            // callers whose live ledger still reflects the prior generation.
            if failure.code() == CatalogFailureCode::StorageUnavailable
                && catalog.refresh_state().is_ok()
                && catalog.pin().ok().is_some_and(|snapshot| {
                    basis.number().checked_add(1) == Some(snapshot.number())
                        && storage.catalog_segments(&snapshot, scope).ok().is_some_and(
                            |published| {
                                published.len() == metadata.len()
                                    && metadata.iter().all(|expected| published.contains(expected))
                            },
                        )
                })
            {
                Ok(())
            } else {
                Err(failure.into())
            }
        },
    }
}
