use super::{Catalog, SnapshotLeaseId};
use crate::{CatalogObject, CatalogProposal, FormatEpoch, TransactionId};

/// Publishes a benign marker update for one unrelated lease in test-support builds.
pub fn publish_snapshot_lease_marker_for_test(
    catalog: &Catalog<'_>,
    identity: SnapshotLeaseId,
    transaction: u8,
) -> Result<(), crate::CatalogFailure> {
    let basis = catalog.pin()?;
    let mut found = false;
    let objects = basis
        .plaintext_objects()
        .map(|bytes| {
            let mut bytes = bytes.to_vec();
            if bytes.starts_with(b"PSLEASE1")
                && bytes.get(10..26) == Some(identity.to_bytes().as_slice())
            {
                let repeats = bytes
                    .get(119..127)
                    .and_then(|value| value.try_into().ok())
                    .map(u64::from_be_bytes)
                    .ok_or_else(|| {
                        crate::CatalogFailure::new(crate::CatalogFailureCode::IntegrityCorruption)
                    })?
                    .checked_add(1)
                    .ok_or_else(|| {
                        crate::CatalogFailure::new(crate::CatalogFailureCode::LimitExceeded)
                    })?;
                bytes
                    .get_mut(119..127)
                    .ok_or_else(|| {
                        crate::CatalogFailure::new(crate::CatalogFailureCode::IntegrityCorruption)
                    })?
                    .copy_from_slice(&repeats.to_be_bytes());
                found = true;
            }
            CatalogObject::new(bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !found {
        return Err(crate::CatalogFailure::new(
            crate::CatalogFailureCode::IntegrityCorruption,
        ));
    }
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction; 16]).map_err(|_| {
                crate::CatalogFailure::new(crate::CatalogFailureCode::LimitExceeded)
            })?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
