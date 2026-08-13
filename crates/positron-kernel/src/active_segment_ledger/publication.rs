use positron_domain::routing::CommitPosition;

use crate::catalog::{Catalog, CatalogObject, CatalogProposal, FormatEpoch, TransactionId};
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
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::new(FORMAT_EPOCH)?,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
