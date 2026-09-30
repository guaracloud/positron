use std::collections::BTreeSet;

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

struct PublicationOptions<'clock> {
    frontier: Option<IngestTime>,
    lifecycle_clock: Option<&'clock crate::retention_time::StagedCatalogAnchor<'clock>>,
    exact_scope: bool,
    additional: Vec<CatalogObject>,
    replaced_tasks: BTreeSet<crate::MaintenanceTaskId>,
}

pub(super) struct RetentionPublication<'clock, 'authority, 'metadata> {
    pub(super) lifecycle_clock: &'clock crate::retention_time::StagedCatalogAnchor<'authority>,
    pub(super) scope: SegmentScope,
    pub(super) metadata: &'metadata [SegmentMetadata],
    pub(super) frontier: IngestTime,
    pub(super) additional: Vec<CatalogObject>,
    pub(super) replaced_tasks: BTreeSet<crate::MaintenanceTaskId>,
}

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
    publish_scope(
        catalog,
        basis,
        storage,
        scope,
        metadata,
        PublicationOptions {
            frontier: None,
            lifecycle_clock: None,
            exact_scope: false,
            additional: Vec::new(),
            replaced_tasks: BTreeSet::new(),
        },
    )
}

pub(super) fn publish_exact_scope_segments(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_scope(
        catalog,
        basis,
        storage,
        scope,
        metadata,
        PublicationOptions {
            frontier: None,
            lifecycle_clock: None,
            exact_scope: true,
            additional: Vec::new(),
            replaced_tasks: BTreeSet::new(),
        },
    )
}

pub(super) fn publish_segments_with_frontier(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    lifecycle_clock: &crate::retention_time::StagedCatalogAnchor<'_>,
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
        PublicationOptions {
            frontier: Some(frontier),
            lifecycle_clock: Some(lifecycle_clock),
            exact_scope: false,
            additional: Vec::new(),
            replaced_tasks: BTreeSet::new(),
        },
    )
}

pub(super) fn publish_retention_with_tasks(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    publication: RetentionPublication<'_, '_, '_>,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_scope(
        catalog,
        basis,
        storage,
        publication.scope,
        publication.metadata,
        PublicationOptions {
            frontier: Some(publication.frontier),
            lifecycle_clock: Some(publication.lifecycle_clock),
            exact_scope: false,
            additional: publication.additional,
            replaced_tasks: publication.replaced_tasks,
        },
    )
}

fn publish_scope(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
    options: PublicationOptions<'_>,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    let PublicationOptions {
        frontier,
        lifecycle_clock,
        exact_scope,
        additional,
        replaced_tasks,
    } = options;
    let mut objects = Vec::new();
    let frontier_objects = usize::from(frontier.is_some());
    let clock_objects = usize::from(lifecycle_clock.is_some());
    let object_capacity = basis
        .plaintext_object_count()
        .checked_add(metadata.len())
        .and_then(|count| count.checked_add(frontier_objects))
        .and_then(|count| count.checked_add(clock_objects))
        .and_then(|count| count.checked_add(additional.len()))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    objects
        .try_reserve_exact(object_capacity)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    let mut lifecycle_anchor_seen = false;
    for bytes in basis.plaintext_objects() {
        if storage.is_scope_metadata(bytes, scope) {
            continue;
        }
        if crate::maintenance::durable_task_record_identity(bytes)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
            .is_some_and(|identity| replaced_tasks.contains(&identity))
        {
            continue;
        }
        if frontier.is_some()
            && super::retention_frontier::decode(bytes)?
                .is_some_and(|(candidate, _)| candidate == scope)
        {
            continue;
        }
        let lifecycle_anchor = crate::retention_time::validate_catalog_anchor_singleton(
            bytes,
            &mut lifecycle_anchor_seen,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        if lifecycle_clock.is_some() && lifecycle_anchor {
            continue;
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        retained.extend_from_slice(bytes);
        objects.push(CatalogObject::new(retained)?);
    }
    for segment in metadata {
        objects.push(CatalogObject::new(storage.metadata_object(*segment))?);
    }
    if let Some(frontier) = frontier {
        objects.push(CatalogObject::new(super::retention_frontier::encode(
            scope, frontier,
        ))?);
    }
    if let (Some(clock), Some(frontier)) = (lifecycle_clock, frontier) {
        objects.push(CatalogObject::new(
            clock
                .catalog_anchor_record(frontier)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?,
        )?);
    }
    let additional_ids = additional
        .iter()
        .map(CatalogObject::identity)
        .collect::<Vec<_>>();
    objects.extend(additional);
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
            basis
                .format_epoch()
                .unwrap_or(FormatEpoch::new(FORMAT_EPOCH)?),
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
            let anchor_subsumed = lifecycle_clock.map_or(Ok(true), |clock| {
                clock
                    .catalog_anchor_subsumed(&snapshot)
                    .map_err(|_| LedgerFailure::ambiguous(LedgerFailureCode::StorageUnavailable))
            })?;
            let tasks_subsumed = additional_ids.iter().try_fold(true, |visible, identity| {
                Ok::<_, LedgerFailure>(visible && snapshot.object(*identity)?.is_some())
            })?;
            if snapshot.number() > basis.number()
                && segments_subsume
                && frontier_subsumed
                && anchor_subsumed
                && tasks_subsumed
            {
                Ok(snapshot)
            } else {
                Err(LedgerFailure::ambiguous(LedgerFailureCode::StaleGeneration))
            }
        },
    }
}
