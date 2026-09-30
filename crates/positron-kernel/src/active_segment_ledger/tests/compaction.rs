use std::cell::Cell;
use std::error::Error;
use std::fs;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;

use super::support::{TemporaryRoot, establish_authority};
use crate::active_segment_ledger::SegmentRetention;
use crate::active_segment_ledger::fault::{
    LedgerFileEvent, with_ledger_fault, with_ledger_faults_after,
};
use crate::active_segment_ledger::format::{SegmentMetadata, SegmentState};
use crate::active_segment_ledger::publication::publish_segments;
use crate::active_segment_ledger::recovery::{frontier_name, segment_name};
use crate::catalog::{CatalogFileEvent, with_catalog_fault};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret, CommittedBlock,
    CompactionBlock, FormatEpoch, IngestTime, InstanceId, LedgerCompletionState, LedgerFailureCode,
    MaintenanceCoordinator, MaintenanceTaskId, MountQualification, PrimaryDataVolume,
    RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, ResourceDimension, RetentionBucket,
    RetentionTimeAuthority, SegmentId, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
    TransactionId, WorkClaim, WorkKind,
};

#[cfg(feature = "test-support")]
use crate::{
    CatalogPublicationFault, with_catalog_publication_ambiguity_hook_after,
    with_catalog_publication_fault_after, with_catalog_publication_fault_sequence_after,
};

fn preparation_capacity<'authority>(
    authority: &'authority crate::StorageKernelResourceAuthority,
    tenant: TenantId,
) -> Result<crate::ResourceReservation<'authority>, Box<dyn Error>> {
    Ok(authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?)
}

fn compaction_block(
    scope: SegmentScope,
    block: &CommittedBlock,
) -> Result<CompactionBlock, Box<dyn Error>> {
    let ingest_time = match block.block_retention {
        SegmentRetention::Complete(ingest_time) => ingest_time,
        SegmentRetention::Empty | SegmentRetention::Unavailable => {
            return Err("compaction fixture block lacks authenticated ingest time".into());
        },
    };
    Ok(CompactionBlock::new(
        scope,
        block.segment_id(),
        block.identity(),
        block.position(),
        block.payload().to_vec(),
        block.content_digest()?,
        ingest_time,
    )?)
}

#[test]
fn compaction_rejects_invalid_inputs_and_repairs_after_output_seal_ambiguity()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let foreign_tenant = TenantId::from_bytes([0x65; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(4)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xb5; 32]));
    let governor_before_binding = authority.governor().inspect()?;
    let tenant_compaction = authority.recovery().reserve(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::EmergencyCompaction,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    assert!(!tenant_compaction.authorizes_compaction(foreign_tenant));
    drop(tenant_compaction);
    assert_eq!(authority.governor().inspect()?, governor_before_binding);
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    ledger.append(
        ledger
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0xb6; 16])?,
            )?
            .finish(b"first-source".to_vec())?,
    )?;
    ledger.append(
        ledger
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0xb7; 16])?,
            )?
            .finish(b"second-source".to_vec())?,
    )?;
    let active_snapshot = ledger.snapshot()?;
    let foreign_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(5)?);
    let foreign_ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        foreign_scope,
        key(),
    )?;
    foreign_ledger.append(
        foreign_ledger
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0xc2; 16])?,
            )?
            .finish(b"first-source".to_vec())?,
    )?;
    foreign_ledger.append(
        foreign_ledger
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0xc3; 16])?,
            )?
            .finish(b"second-source".to_vec())?,
    )?;
    foreign_ledger.seal()?;
    let foreign_ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        foreign_scope,
        key(),
    )?;
    let foreign_snapshot = foreign_ledger.snapshot()?;
    drop(active_snapshot);
    let active_snapshot = ledger.snapshot()?;
    let foreign_preparation_failure = match ledger.prepare_compaction(&foreign_snapshot) {
        Ok(_) => return Err("a preparation crossed physical scopes".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        foreign_preparation_failure.code(),
        LedgerFailureCode::PhysicalScopeMismatch
    );
    let foreign_blocks = foreign_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(foreign_scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let preparation = ledger.prepare_compaction(&active_snapshot)?;
    let foreign_execution_failure = foreign_ledger
        .compact_sealed_with_cancellation(foreign_blocks.clone(), preparation, || false)
        .expect_err("a preparation cannot execute against another ledger scope");
    assert_eq!(
        foreign_execution_failure.code(),
        LedgerFailureCode::PhysicalScopeMismatch
    );
    drop(active_snapshot);
    drop(foreign_snapshot);
    let stale_snapshot = foreign_ledger.snapshot()?;
    let stale_preparation = foreign_ledger.prepare_compaction(&stale_snapshot)?;
    foreign_ledger.append(
        foreign_ledger
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0xc4; 16])?,
            )?
            .finish(b"foreign-third".to_vec())?,
    )?;
    let catalog_before_stale = catalog.pin()?.identity();
    let stale_execution_failure = foreign_ledger
        .compact_sealed_with_cancellation(foreign_blocks, stale_preparation, || false)
        .expect_err("a prepared snapshot cannot execute after the ledger advances");
    assert_eq!(
        stale_execution_failure.code(),
        LedgerFailureCode::StaleGeneration
    );
    assert_eq!(catalog.pin()?.identity(), catalog_before_stale);
    drop(stale_snapshot);
    drop(foreign_ledger);
    let active_snapshot = ledger.snapshot()?;
    let active_blocks = active_snapshot.blocks();
    let active_first = active_blocks
        .first()
        .ok_or_else(|| -> Box<dyn Error> { "active compaction fixture block missing".into() })?;
    let valid_first = compaction_block(scope, active_first)?;
    assert_eq!(
        CompactionBlock::new(
            scope,
            valid_first.source_segment,
            valid_first.identity,
            valid_first.position,
            Vec::new(),
            valid_first.content_digest,
            valid_first.ingest_time,
        )
        .expect_err("empty compaction payload must be refused")
        .code(),
        LedgerFailureCode::InvalidInput
    );
    assert_eq!(
        CompactionBlock::new(
            scope,
            valid_first.source_segment,
            valid_first.identity,
            valid_first.position,
            b"not authenticated".to_vec(),
            valid_first.content_digest,
            IngestTime::from_unretained_observation(valid_first.ingest_time.instant()),
        )
        .expect_err("unauthenticated compaction time must be refused")
        .code(),
        LedgerFailureCode::InvalidInput
    );

    assert_eq!(
        ledger
            .compact_sealed(Vec::new())
            .expect_err("empty compaction must be bounded")
            .code(),
        LedgerFailureCode::LimitExceeded
    );
    let empty_preparation = ledger.prepare_compaction(&active_snapshot)?;
    assert_eq!(
        ledger
            .compact_sealed_with_cancellation(Vec::new(), empty_preparation, || false)
            .expect_err("an empty prepared compaction must be bounded")
            .code(),
        LedgerFailureCode::LimitExceeded
    );
    let mut foreign = valid_first.clone();
    foreign.scope = SegmentScope::new(
        TenantId::from_bytes([0x65; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(4)?,
    );
    assert_eq!(
        ledger
            .compact_sealed(vec![foreign])
            .expect_err("cross-scope compaction must be refused")
            .code(),
        LedgerFailureCode::PhysicalScopeMismatch
    );
    assert_eq!(
        ledger
            .compact_sealed(vec![valid_first.clone(), valid_first.clone()])
            .expect_err("duplicate positions must be refused")
            .code(),
        LedgerFailureCode::InvalidInput
    );
    let mut wrong_payload = valid_first.clone();
    if let Some(byte) = wrong_payload.payload.first_mut() {
        *byte ^= 1;
    }
    assert_eq!(
        ledger
            .compact_sealed(vec![wrong_payload])
            .expect_err("changed source bytes must be refused")
            .code(),
        LedgerFailureCode::StaleGeneration
    );
    let mut wrong_digest = valid_first.clone();
    if let Some(byte) = wrong_digest.content_digest.first_mut() {
        *byte ^= 1;
    }
    assert_eq!(
        ledger
            .compact_sealed(vec![wrong_digest])
            .expect_err("changed source digest must be refused")
            .code(),
        LedgerFailureCode::StaleGeneration
    );
    let mut missing_source = valid_first.clone();
    missing_source.source_segment = SegmentId::new([0xc1; 16])?;
    assert_eq!(
        ledger
            .compact_sealed(vec![missing_source])
            .expect_err("unknown source identity must be refused")
            .code(),
        LedgerFailureCode::StaleGeneration
    );
    let mut unretained = valid_first.clone();
    unretained.ingest_time = IngestTime::from_unretained_observation(
        valid_first
            .ingest_time
            .instant()
            .value()
            .checked_add(1)
            .map(positron_domain::time::UnixNanoseconds::new)
            .ok_or("compaction test ingest time overflow")?,
    );
    assert_eq!(
        ledger
            .compact_sealed(vec![unretained])
            .expect_err("unauthenticated source time must be refused")
            .code(),
        LedgerFailureCode::IntegrityCorruption
    );
    assert_eq!(
        ledger
            .compact_sealed(vec![valid_first.clone()])
            .expect_err("active segments are not compaction inputs")
            .code(),
        LedgerFailureCode::InvalidInput
    );

    ledger.seal()?;
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let source_snapshot = reopened.snapshot()?;
    let source_blocks = source_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(source_blocks.len(), 2);
    let mut too_many_blocks = source_blocks.clone();
    let mut extra = source_blocks
        .get(1)
        .ok_or("second source block missing")?
        .clone();
    extra.identity = StoreBlockIdentity::new([0xc0; 16])?;
    extra.position = extra.position.next()?;
    too_many_blocks.push(extra);
    let prepared_capacity = reopened.prepare_compaction(&source_snapshot)?;
    assert_eq!(
        reopened
            .compact_sealed_with_cancellation(too_many_blocks, prepared_capacity, || false)
            .expect_err("prepared compaction must reject blocks beyond its admitted bound")
            .code(),
        LedgerFailureCode::LimitExceeded
    );
    let mut too_large_payload = source_blocks.clone();
    too_large_payload
        .first_mut()
        .ok_or("prepared compaction payload fixture missing")?
        .payload
        .extend_from_slice(&[0; 256]);
    let prepared_capacity = reopened.prepare_compaction(&source_snapshot)?;
    assert_eq!(
        reopened
            .compact_sealed_with_cancellation(too_large_payload, prepared_capacity, || false)
            .expect_err("prepared compaction must reject payload beyond its admitted bound")
            .code(),
        LedgerFailureCode::LimitExceeded
    );
    assert_eq!(
        reopened
            .compact_sealed(vec![source_blocks[0].clone()])
            .expect_err("partial source segment must be refused")
            .code(),
        LedgerFailureCode::StaleGeneration
    );
    assert_eq!(
        with_ledger_fault(LedgerFileEvent::CreateSegment, || {
            reopened.compact_sealed(source_blocks.clone())
        })
        .expect_err("output creation failure must not publish")
        .code(),
        LedgerFailureCode::StorageUnavailable
    );
    assert_eq!(
        with_ledger_fault(LedgerFileEvent::WriteFrame, || {
            reopened.compact_sealed(source_blocks.clone())
        })
        .expect_err("output write failure must not publish")
        .code(),
        LedgerFailureCode::StorageUnavailable
    );
    let header_cleanup_failure = with_ledger_faults_after(
        &[
            (LedgerFileEvent::WriteSegmentHeader, 0),
            (LedgerFileEvent::DiscardUnpublishedOutput, 0),
        ],
        || reopened.compact_sealed(source_blocks.clone()),
    )
    .expect_err("header failure cleanup must fence a partial output");
    assert_eq!(
        header_cleanup_failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    assert_eq!(
        reopened
            .compact_sealed(source_blocks.clone())
            .expect_err("a cleanup-fenced ledger must reject follow-up work")
            .code(),
        LedgerFailureCode::RecoveryRequired
    );
    drop(source_snapshot);
    drop(reopened);

    let sealed_fault = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let sealed_fault_snapshot = sealed_fault.snapshot()?;
    let sealed_fault_blocks = sealed_fault_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let failure = with_ledger_fault(LedgerFileEvent::RenameSealSegment, || {
        sealed_fault.compact_sealed(sealed_fault_blocks)
    })
    .expect_err("post-publication sealing failure must be ambiguous");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    drop(sealed_fault_snapshot);
    drop(sealed_fault);

    let retry = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let retry_snapshot = retry.snapshot()?;
    let retry_blocks = retry_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let partial_failure = with_ledger_fault(LedgerFileEvent::RenameSealFrontier, || {
        retry.compact_sealed(retry_blocks)
    })
    .expect_err("frontier sealing failure must be ambiguous after segment rename");
    assert_eq!(
        partial_failure.code(),
        LedgerFailureCode::StorageUnavailable
    );
    assert_eq!(
        partial_failure.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    drop(retry_snapshot);
    drop(retry);

    let repaired = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let repaired_snapshot = repaired.snapshot()?;
    assert_eq!(repaired_snapshot.blocks().len(), 2);
    assert_eq!(repaired_snapshot.blocks()[0].payload(), b"first-source");
    assert_eq!(repaired_snapshot.blocks()[1].payload(), b"second-source");

    let missing_metadata_block = compaction_block(
        scope,
        repaired_snapshot
            .blocks()
            .first()
            .ok_or("repaired compaction block missing")?,
    )?;
    let basis = catalog.pin()?;
    let metadata = repaired.storage.catalog_segments(&basis, scope)?;
    let source_metadata = metadata
        .iter()
        .find(|candidate| candidate.id == missing_metadata_block.source_segment)
        .copied()
        .ok_or("repaired source metadata missing")?;
    assert_eq!(
        repaired
            .storage
            .retired_recovery_encoded_bytes(source_metadata)
            .expect_err("sealed metadata cannot request retired recovery bytes")
            .code(),
        LedgerFailureCode::InvalidInput
    );
    assert_eq!(
        repaired
            .storage
            .reclaim_retired(source_metadata)
            .expect_err("sealed metadata cannot request retired reclamation")
            .code(),
        LedgerFailureCode::InvalidInput
    );

    let active_directory = root.path().join("segments/active");
    let first_cleanup_probe = SegmentMetadata {
        id: SegmentId::new([0xc4; 16])?,
        state: SegmentState::Active,
        ..source_metadata
    };
    fs::create_dir(active_directory.join(segment_name(first_cleanup_probe.id)))?;
    assert_eq!(
        repaired
            .storage
            .discard_unpublished(first_cleanup_probe)
            .expect_err("an output directory cannot be unlinked as a file")
            .code(),
        LedgerFailureCode::StorageUnavailable
    );
    let second_cleanup_probe = SegmentMetadata {
        id: SegmentId::new([0xc5; 16])?,
        state: SegmentState::Active,
        ..source_metadata
    };
    fs::write(
        active_directory.join(segment_name(second_cleanup_probe.id)),
        b"output",
    )?;
    fs::create_dir(active_directory.join(frontier_name(second_cleanup_probe.id)))?;
    let cleanup_failure = repaired
        .storage
        .discard_unpublished(second_cleanup_probe)
        .expect_err("a partially removed output must be reported as post-mutation");
    assert_eq!(
        cleanup_failure.code(),
        LedgerFailureCode::StorageUnavailable
    );
    assert_eq!(
        cleanup_failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    fs::remove_dir(active_directory.join(segment_name(first_cleanup_probe.id)))?;
    fs::remove_dir(active_directory.join(frontier_name(second_cleanup_probe.id)))?;
    repaired.storage.discard_unpublished(SegmentMetadata {
        id: SegmentId::new([0xc6; 16])?,
        state: SegmentState::Active,
        ..source_metadata
    })?;
    let source_bytes = repaired.storage.metadata_object(source_metadata);
    let retired_metadata = SegmentMetadata {
        state: SegmentState::Retired,
        ..source_metadata
    };
    let retired_bytes = repaired.storage.metadata_object(retired_metadata);
    let objects = basis
        .object_identities()
        .filter_map(|identity| {
            let bytes = basis.object(identity).ok().flatten()?.to_vec();
            if bytes == source_bytes {
                return CatalogObject::new(retired_bytes.clone()).ok();
            }
            CatalogObject::new(bytes).ok()
        })
        .collect::<Vec<_>>();
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xc2; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    repaired.storage.reclaim_retired(retired_metadata)?;
    let basis = catalog.pin()?;
    let objects = basis
        .object_identities()
        .filter_map(|identity| {
            let bytes = basis.object(identity).ok().flatten()?.to_vec();
            (bytes != retired_bytes).then(|| CatalogObject::new(bytes).ok())?
        })
        .collect::<Vec<_>>();
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xc3; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    assert_eq!(
        repaired
            .compact_sealed(vec![missing_metadata_block])
            .expect_err("a source omitted from the current Catalog is stale")
            .code(),
        LedgerFailureCode::StaleGeneration
    );
    Ok(())
}

#[test]
fn compaction_cleanup_failures_fence_each_prepublication_mutation() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xc6; 16])?,
        CatalogSecret::from_owned(Box::new([0xc7; 32]), Box::new([0xc8; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(5)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xc9; 32]));

    for (identity, payload) in [
        ([0xca; 16], b"cleanup-first".as_slice()),
        ([0xcb; 16], b"cleanup-middle".as_slice()),
        ([0xcc; 16], b"cleanup-last".as_slice()),
    ] {
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        ledger.append(
            ledger
                .begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new(identity)?,
                )?
                .finish(payload.to_vec())?,
        )?;
        ledger.seal()?;
    }

    let first_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let first_snapshot = first_attempt.snapshot()?;
    let first_blocks = first_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(first_blocks.len(), 3);
    let before_cancellation = catalog.pin()?.identity();
    let preparation = first_attempt.prepare_compaction(&first_snapshot)?;
    let cancelled = first_attempt
        .compact_sealed_with_cancellation(first_blocks.clone(), preparation, || true)
        .expect_err("cancellation before output creation must not mutate");
    assert_eq!(cancelled.code(), LedgerFailureCode::Cancelled);
    assert_eq!(
        cancelled.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );
    assert_eq!(catalog.pin()?.identity(), before_cancellation);
    let polls = Cell::new(0_u8);
    let preparation = first_attempt.prepare_compaction(&first_snapshot)?;
    let cancelled_at_output_boundary = first_attempt
        .compact_sealed_with_cancellation(first_blocks.clone(), preparation, || {
            let current = polls.get();
            polls.set(current.saturating_add(1));
            current >= 1
        })
        .expect_err("cancellation at the first output boundary must not mutate");
    assert_eq!(
        cancelled_at_output_boundary.code(),
        LedgerFailureCode::Cancelled
    );
    assert_eq!(
        cancelled_at_output_boundary.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );
    let first_failure = with_ledger_faults_after(
        &[
            (LedgerFileEvent::CreateSegment, 1),
            (LedgerFileEvent::DiscardUnpublishedOutput, 0),
        ],
        || first_attempt.compact_sealed(vec![first_blocks[0].clone(), first_blocks[2].clone()]),
    )
    .expect_err("failed cleanup after output creation must fence the ledger");
    assert_eq!(first_failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        first_failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    drop(first_snapshot);
    drop(first_attempt);

    let second_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let second_snapshot = second_attempt.snapshot()?;
    let second_blocks = second_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let polls = Cell::new(0_u8);
    let preparation = second_attempt.prepare_compaction(&second_snapshot)?;
    let cancelled_before_later_output = second_attempt
        .compact_sealed_with_cancellation(
            vec![second_blocks[0].clone(), second_blocks[2].clone()],
            preparation,
            || {
                let current = polls.get();
                polls.set(current.saturating_add(1));
                current >= 4
            },
        )
        .expect_err("cancellation before a later output must require recovery");
    assert_eq!(
        cancelled_before_later_output.code(),
        LedgerFailureCode::Cancelled
    );
    assert_eq!(
        cancelled_before_later_output.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );
    drop(second_snapshot);
    drop(second_attempt);
    let cleanup_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let cleanup_snapshot = cleanup_attempt.snapshot()?;
    let cleanup_blocks = cleanup_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let cleanup_polls = Cell::new(0_u8);
    let cleanup_preparation = cleanup_attempt.prepare_compaction(&cleanup_snapshot)?;
    let cleanup_failure = with_ledger_fault(LedgerFileEvent::DiscardUnpublishedOutput, || {
        cleanup_attempt.compact_sealed_with_cancellation(
            vec![cleanup_blocks[0].clone(), cleanup_blocks[2].clone()],
            cleanup_preparation,
            || {
                let current = cleanup_polls.get();
                cleanup_polls.set(current.saturating_add(1));
                current >= 4
            },
        )
    })
    .expect_err("failed cleanup at a later output boundary must fence recovery");
    assert_eq!(
        cleanup_failure.code(),
        LedgerFailureCode::StorageUnavailable
    );
    assert_eq!(
        cleanup_failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    drop(cleanup_snapshot);
    drop(cleanup_attempt);
    let second_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let second_snapshot = second_attempt.snapshot()?;
    let second_blocks = second_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let polls = Cell::new(0_u8);
    let preparation = second_attempt.prepare_compaction(&second_snapshot)?;
    let cancelled_after_append = second_attempt
        .compact_sealed_with_cancellation(second_blocks.clone(), preparation, || {
            let current = polls.get();
            polls.set(current.saturating_add(1));
            current >= 3
        })
        .expect_err("cancellation after a committed output frame must require recovery");
    assert_eq!(cancelled_after_append.code(), LedgerFailureCode::Cancelled);
    assert_eq!(
        cancelled_after_append.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );
    drop(second_snapshot);
    drop(second_attempt);

    let second_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let second_snapshot = second_attempt.snapshot()?;
    let second_blocks = second_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let polls = Cell::new(0_u8);
    let preparation = second_attempt.prepare_compaction(&second_snapshot)?;
    let cancelled_after_first_output = second_attempt
        .compact_sealed_with_cancellation(second_blocks.clone(), preparation, || {
            let current = polls.get();
            polls.set(current.saturating_add(1));
            current >= 4
        })
        .expect_err("cancellation before a later output must require recovery");
    assert_eq!(
        cancelled_after_first_output.code(),
        LedgerFailureCode::Cancelled
    );
    assert_eq!(
        cancelled_after_first_output.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );
    drop(second_snapshot);
    drop(second_attempt);

    let second_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let second_snapshot = second_attempt.snapshot()?;
    let second_blocks = second_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let second_failure = with_ledger_faults_after(
        &[
            (LedgerFileEvent::WriteFrame, 1),
            (LedgerFileEvent::DiscardUnpublishedOutput, 0),
        ],
        || second_attempt.compact_sealed(vec![second_blocks[0].clone(), second_blocks[2].clone()]),
    )
    .expect_err("failed cleanup after output writing must fence the ledger");
    assert_eq!(second_failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        second_failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    drop(second_snapshot);
    drop(second_attempt);

    let third_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let third_snapshot = third_attempt.snapshot()?;
    let third_blocks = third_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let polls = Cell::new(0_u8);
    let preparation = third_attempt.prepare_compaction(&third_snapshot)?;
    let cancelled_before_publish =
        with_ledger_fault(LedgerFileEvent::DiscardUnpublishedOutput, || {
            third_attempt.compact_sealed_with_cancellation(
                vec![third_blocks[0].clone(), third_blocks[2].clone()],
                preparation,
                || {
                    let current = polls.get();
                    polls.set(current.saturating_add(1));
                    current >= 7
                },
            )
        })
        .expect_err("failed cleanup after cancellation before publication must fence recovery");
    assert_eq!(
        cancelled_before_publish.code(),
        LedgerFailureCode::StorageUnavailable
    );
    assert_eq!(
        cancelled_before_publish.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    drop(third_snapshot);
    drop(third_attempt);

    let fifth_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let fifth_snapshot = fifth_attempt.snapshot()?;
    let fifth_blocks = fifth_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let polls = Cell::new(0_u8);
    let preparation = fifth_attempt.prepare_compaction(&fifth_snapshot)?;
    let cancelled_before_publish = fifth_attempt
        .compact_sealed_with_cancellation(
            vec![fifth_blocks[0].clone(), fifth_blocks[2].clone()],
            preparation,
            || {
                let current = polls.get();
                polls.set(current.saturating_add(1));
                current >= 7
            },
        )
        .expect_err("cancellation before publication must clean outputs and remain retryable");
    assert_eq!(
        cancelled_before_publish.code(),
        LedgerFailureCode::Cancelled
    );
    assert_eq!(
        cancelled_before_publish.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );
    drop(fifth_snapshot);
    drop(fifth_attempt);

    let fourth_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let fourth_snapshot = fourth_attempt.snapshot()?;
    let fourth_blocks = fourth_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let polls = Cell::new(0_u8);
    let preparation = fourth_attempt.prepare_compaction(&fourth_snapshot)?;
    let cancelled_after_seal = fourth_attempt
        .compact_sealed_with_cancellation(fourth_blocks, preparation, || {
            let current = polls.get();
            polls.set(current.saturating_add(1));
            current >= 10
        })
        .expect_err("cancellation after output sealing must remain ambiguous");
    assert_eq!(cancelled_after_seal.code(), LedgerFailureCode::Cancelled);
    assert_eq!(
        cancelled_after_seal.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    drop(fourth_snapshot);
    drop(fourth_attempt);

    let third_attempt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let third_snapshot = third_attempt.snapshot()?;
    let third_blocks = third_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let third_failure = with_ledger_fault(LedgerFileEvent::DiscardUnpublishedOutput, || {
        with_catalog_fault(CatalogFileEvent::SynchronizeCommit, || {
            third_attempt.compact_sealed(third_blocks)
        })
    })
    .expect_err("failed cleanup after Catalog refusal must fence the ledger");
    assert_eq!(third_failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        third_failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    drop(third_snapshot);
    drop(third_attempt);

    #[cfg(feature = "test-support")]
    {
        let ambiguous_attempt = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        let ambiguous_snapshot = ambiguous_attempt.snapshot()?;
        let ambiguous_blocks = ambiguous_snapshot
            .blocks()
            .iter()
            .map(|block| compaction_block(scope, block))
            .collect::<Result<Vec<_>, _>>()?;
        let ambiguous_failure = with_catalog_publication_ambiguity_hook_after(
            CatalogPublicationFault::SynchronizeCommit,
            0,
            |catalog| {
                catalog
                    .refresh_after_ambiguous_publication_for_test()
                    .expect("pre-rename failure leaves the previous basis recoverable");
                let basis = catalog.pin().expect("pin the previous Catalog basis");
                let mut objects = basis
                    .object_identities()
                    .map(|identity| {
                        CatalogObject::new(
                            basis
                                .object(identity)
                                .expect("read the previous Catalog object")
                                .expect("previous Catalog object exists")
                                .to_vec(),
                        )
                        .expect("copy the previous Catalog object")
                    })
                    .collect::<Vec<_>>();
                objects.push(
                    CatalogObject::new(b"compaction unrelated successor".to_vec())
                        .expect("unrelated successor object"),
                );
                catalog
                    .commit(
                        basis.identity(),
                        CatalogProposal::new(
                            TransactionId::new([0xcd; 16]).expect("successor transaction"),
                            FormatEpoch::CATALOG_V1,
                            objects,
                        )
                        .expect("successor proposal"),
                        None,
                    )
                    .expect("publish unrelated successor");
            },
            || ambiguous_attempt.compact_sealed(ambiguous_blocks),
        )
        .expect_err("an unresolved Catalog successor must remain ambiguous");
        assert_eq!(
            ambiguous_failure.completion_state(),
            LedgerCompletionState::CommitAmbiguous
        );
        drop(ambiguous_snapshot);
        drop(ambiguous_attempt);
    }
    Ok(())
}

#[test]
fn cancellation_after_publication_before_output_seal_is_ambiguous() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd1; 16])?,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(6)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = SegmentProtectionKey::from_owned(Box::new([0xd5; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key,
    )?;
    ledger.append(
        ledger
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0xd6; 16])?,
            )?
            .finish(b"publication-boundary-first".to_vec())?,
    )?;
    ledger.seal()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xd5; 32])),
    )?;
    let snapshot = ledger.snapshot()?;
    let blocks = snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let preparation = ledger.prepare_compaction(&snapshot)?;
    let polls = Cell::new(0_u8);
    let failure = ledger
        .compact_sealed_with_cancellation(blocks, preparation, || {
            let current = polls.get();
            polls.set(current.saturating_add(1));
            current >= 5
        })
        .expect_err("publication before output sealing must remain ambiguous");
    assert_eq!(failure.code(), LedgerFailureCode::Cancelled);
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    Ok(())
}

#[test]
fn ambiguous_output_append_is_reported_without_catalog_mutation() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd7; 16])?,
        CatalogSecret::from_owned(Box::new([0xd8; 32]), Box::new([0xd9; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(8)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xda; 32]));
    for (identity, payload) in [
        ([0xdb; 16], b"ambiguous-first".as_slice()),
        ([0xdc; 16], b"ambiguous-second".as_slice()),
    ] {
        let source = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        source.append(
            source
                .begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new(identity)?,
                )?
                .finish(payload.to_vec())?,
        )?;
        source.seal()?;
    }
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let generation_before = catalog.pin()?.identity();
    let governor_before = authority.governor().inspect()?;
    let snapshot = ledger.snapshot()?;
    let blocks = snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let preparation = ledger.prepare_compaction(&snapshot)?;
    let failure = with_ledger_fault(LedgerFileEvent::SynchronizeFrontierDirectory, || {
        ledger.compact_sealed_with_cancellation(blocks, preparation, || false)
    })
    .expect_err("ambiguous output append must be surfaced");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    assert_eq!(catalog.pin()?.identity(), generation_before);
    drop(snapshot);
    assert_eq!(authority.governor().inspect()?, governor_before);
    drop(ledger);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(reopened.snapshot()?.blocks().len(), 2);
    Ok(())
}

#[test]
fn large_catalog_compaction_admits_before_copy_and_recovers_without_drift()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xdb; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xdc; 32]), Box::new([0xdd; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(9)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xde; 32]));
    let basis = catalog.pin()?;
    let objects = (0_u8..1)
        .map(|marker| {
            let mut bytes = vec![marker; 524_288];
            if let Some(first) = bytes.first_mut() {
                *first = marker.saturating_add(1);
            }
            CatalogObject::new(bytes).map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xdf; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    for (identity, payload) in [
        ([0xe0; 16], b"large-catalog-first".as_slice()),
        ([0xe1; 16], b"large-catalog-second".as_slice()),
    ] {
        let source = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        source.append(
            source
                .begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new(identity)?,
                )?
                .finish(payload.to_vec())?,
        )?;
        source.seal()?;
    }
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let ledger_baseline = authority.governor().inspect()?;
    let snapshot = ledger.snapshot()?;
    let baseline = authority.governor().inspect()?;
    let probe = ledger.prepare_compaction(&snapshot)?;
    let admitted = authority.governor().inspect()?;
    let required_memory = admitted
        .recovery_shared_usage(ResourceDimension::MemoryBytes)
        .checked_sub(baseline.recovery_shared_usage(ResourceDimension::MemoryBytes))
        .ok_or("compaction probe did not report a memory charge")?;
    drop(probe);
    assert_eq!(authority.governor().inspect()?, baseline);
    let available_memory = baseline
        .recovery_shared_capacity(ResourceDimension::MemoryBytes)
        .checked_sub(baseline.recovery_shared_usage(ResourceDimension::MemoryBytes))
        .ok_or("compaction fixture has no shared recovery memory")?;
    let blocker_memory = available_memory
        .checked_sub(required_memory)
        .and_then(|available| available.checked_add(1))
        .ok_or("large Catalog compaction unexpectedly exceeds shared capacity")?;
    let blocker = authority.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::EmergencyCompaction,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, blocker_memory)?,
    )?)?;
    assert!(!blocker.authorizes_tenant_schema_session(tenant, 1));
    let generation_before_refusal = catalog.pin()?.identity();
    let refusal = match ledger.prepare_compaction(&snapshot) {
        Ok(_) => return Err("large Catalog compaction copied before admission".into()),
        Err(failure) => failure,
    };
    assert_eq!(refusal.code(), LedgerFailureCode::ResourceAdmissionRefused);
    assert_eq!(catalog.pin()?.identity(), generation_before_refusal);
    drop(blocker);
    let after_refusal = authority.governor().inspect()?;
    assert_eq!(
        after_refusal.outstanding_total(),
        baseline.outstanding_total()
    );
    for dimension in ResourceDimension::ALL {
        assert_eq!(after_refusal.usage(dimension), baseline.usage(dimension));
        assert_eq!(
            after_refusal.recovery_shared_usage(dimension),
            baseline.recovery_shared_usage(dimension)
        );
        assert_eq!(
            after_refusal.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension),
            baseline.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension)
        );
    }

    let blocks = snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let generation_before_fault = catalog.pin()?.identity();
    let fault = with_catalog_fault(CatalogFileEvent::SynchronizeCommit, || {
        ledger.compact_sealed(blocks)
    })
    .expect_err("Catalog publication fault must not publish large-catalog compaction");
    assert_eq!(fault.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        fault.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );
    assert_eq!(catalog.pin()?.identity(), generation_before_fault);
    drop(snapshot);
    let after_fault = authority.governor().inspect()?;
    assert_eq!(
        after_fault.outstanding_total(),
        ledger_baseline.outstanding_total()
    );
    for dimension in ResourceDimension::ALL {
        assert_eq!(
            after_fault.usage(dimension),
            ledger_baseline.usage(dimension)
        );
        assert_eq!(
            after_fault.recovery_shared_usage(dimension),
            ledger_baseline.recovery_shared_usage(dimension)
        );
        assert_eq!(
            after_fault.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension),
            ledger_baseline.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension)
        );
    }
    drop(ledger);

    let retry = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let retry_snapshot = retry.snapshot()?;
    let retry_blocks = retry_snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let publication = retry.compact_sealed(retry_blocks)?;
    assert_eq!(publication.input_segments(), 2);
    assert_eq!(publication.output_segments(), 1);
    drop(retry_snapshot);
    drop(retry);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(reopened.snapshot()?.blocks().len(), 2);
    Ok(())
}

#[test]
fn trace_compaction_uses_the_same_checked_source_binding() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe2; 16])?,
        CatalogSecret::from_owned(Box::new([0xe3; 32]), Box::new([0xe4; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(10)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xe5; 32]));
    for (identity, payload) in [
        ([0xe6; 16], b"trace-first".as_slice()),
        ([0xe7; 16], b"trace-second".as_slice()),
    ] {
        let source = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        source.append(
            source
                .begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new(identity)?,
                )?
                .finish(payload.to_vec())?,
        )?;
        source.seal()?;
    }
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let publication = ledger.compact_sealed(
        ledger
            .snapshot()?
            .blocks()
            .iter()
            .map(|block| compaction_block(scope, block))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    assert_eq!(publication.input_segments(), 2);
    assert_eq!(publication.output_segments(), 1);
    Ok(())
}

#[test]
fn successful_compaction_replaces_sealed_sources_and_survives_reopen() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd6; 16])?,
        CatalogSecret::from_owned(Box::new([0xd7; 32]), Box::new([0xd8; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(6)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xd9; 32]));

    for (identity, payload) in [
        ([0xda; 16], b"successful-first".as_slice()),
        ([0xdb; 16], b"successful-second".as_slice()),
    ] {
        let source = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        source.append(
            source
                .begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new(identity)?,
                )?
                .finish(payload.to_vec())?,
        )?;
        source.seal()?;
    }

    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let before = ledger.snapshot()?;
    let blocks = before
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(blocks.len(), 2);
    let payload_bytes = blocks.iter().try_fold(0_u64, |total, block| {
        total
            .checked_add(
                u64::try_from(block.payload.len())
                    .map_err(|_| "compaction payload does not fit in u64")?,
            )
            .ok_or("compaction payload accounting overflow")
    })?;
    let governor_before = authority.governor().inspect()?;
    let preparation = ledger.prepare_compaction(&before)?;
    let governor_during = authority.governor().inspect()?;
    let catalog_snapshot = catalog.pin()?;
    let catalog_bytes = catalog_snapshot
        .plaintext_objects()
        .try_fold(0_u64, |total, bytes| {
            total
                .checked_add(u64::try_from(bytes.len()).map_err(|_| "Catalog bytes overflow")?)
                .ok_or("Catalog capacity accounting overflow")
        })?;
    let catalog_objects = u64::try_from(catalog_snapshot.plaintext_object_count())?;
    let expected = |dimension| match dimension {
        ResourceDimension::MemoryBytes => {
            payload_bytes * 5 + 2 * 256 + catalog_bytes + catalog_objects * 64
        },
        ResourceDimension::QueueSlots | ResourceDimension::TaskSlots => 1,
        ResourceDimension::BufferCacheBytes => payload_bytes * 2 + 2 * (384 + 1_024),
        ResourceDimension::BatchItems => 9 + catalog_objects,
        ResourceDimension::LeaseSlots => 0,
        ResourceDimension::RetrySlots | ResourceDimension::IoPermits => 1,
        ResourceDimension::CpuWorkUnits => 1,
        ResourceDimension::FileDescriptors => 6,
        ResourceDimension::DiskHeadroomBytes => payload_bytes * 2 + 2 * (384 + 1_024),
    };
    for dimension in ResourceDimension::ALL {
        let before_usage = governor_before
            .recovery_shared_usage(dimension)
            .checked_add(
                governor_before
                    .recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension),
            )
            .ok_or("compaction baseline accounting overflow")?;
        let during_usage = governor_during
            .recovery_shared_usage(dimension)
            .checked_add(
                governor_during
                    .recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension),
            )
            .ok_or("compaction peak accounting overflow")?;
        assert_eq!(during_usage - before_usage, expected(dimension));
    }
    drop(preparation);
    let governor_after = authority.governor().inspect()?;
    for dimension in ResourceDimension::ALL {
        assert_eq!(
            governor_after.recovery_shared_usage(dimension),
            governor_before.recovery_shared_usage(dimension)
        );
        assert_eq!(
            governor_after.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension),
            governor_before.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension)
        );
    }
    let publication = ledger.compact_sealed(blocks)?;
    assert_eq!(publication.input_segments(), 2);
    assert_eq!(publication.output_segments(), 1);
    let after = ledger.snapshot()?;
    assert_eq!(after.blocks().len(), 2);
    assert_eq!(after.blocks()[0].payload(), b"successful-first");
    assert_eq!(after.blocks()[1].payload(), b"successful-second");
    drop(before);
    drop(after);
    drop(ledger);

    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let recovered = reopened.snapshot()?;
    assert_eq!(recovered.blocks().len(), 2);
    assert_eq!(recovered.blocks()[0].payload(), b"successful-first");
    assert_eq!(recovered.blocks()[1].payload(), b"successful-second");
    Ok(())
}

#[test]
fn typed_compaction_task_couples_the_exact_manifest_and_terminal_record()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xe1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    super::retention_frontier::install_governance_policy(&catalog, instance, tenant, 60, 0xe4)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(61)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xe5; 32]));
    for (identity, payload) in [
        ([0xe6; 16], b"bound-first".as_slice()),
        ([0xe7; 16], b"bound-second".as_slice()),
    ] {
        let source = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        source.append(
            source
                .begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new(identity)?,
                )?
                .finish(payload.to_vec())?,
        )?;
        source.seal()?;
    }
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let snapshot = ledger.snapshot()?;
    let blocks = snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let policy = catalog.pin()?.retention_policy(SignalKind::Logs)?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Logs,
        blocks[0].ingest_time,
        policy.retention_seconds(),
    )?;
    let generation_before_binding_refusals = catalog.pin()?.number();
    let foreign_bucket = RetentionBucket::for_ingest_time(
        TenantId::from_bytes([0x65; 16])?,
        SignalKind::Logs,
        blocks[0].ingest_time,
        policy.retention_seconds(),
    )?;
    let wrong_scope_failure = match ledger.prepare_compaction_task(
        foreign_bucket,
        MaintenanceTaskId::new([0xa1; 16]).expect("wrong-scope task identity"),
    ) {
        Ok(_) => return Err("a Compaction descriptor bound a foreign physical scope".into()),
        Err(failure) => failure,
    };
    assert_eq!(wrong_scope_failure.code(), LedgerFailureCode::InvalidInput);
    let outside_bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Logs,
        IngestTime::from_authenticated_durable(UnixNanoseconds::new(
            blocks[0]
                .ingest_time
                .instant()
                .value()
                .checked_add(120_000_000_000)
                .ok_or("bucket fixture overflow")?,
        )),
        policy.retention_seconds(),
    )?;
    assert_eq!(catalog.pin()?.number(), generation_before_binding_refusals);
    let source_segments = snapshot
        .blocks()
        .iter()
        .map(CommittedBlock::segment_id)
        .collect::<std::collections::BTreeSet<_>>();
    let empty_identity = MaintenanceTaskId::new([0xa2; 16]).expect("empty-bucket task identity");
    let empty_task = ledger.prepare_compaction_task(outside_bucket, empty_identity)?;
    let empty_coordinator = MaintenanceCoordinator::new();
    empty_task.submit_and_persist(&empty_coordinator, &catalog, 1)?;
    let empty_execution = empty_coordinator
        .start_compaction_task_with_reservation_and_persist(
            &catalog,
            &authority,
            1,
            false,
            empty_identity,
        )
        .map_err(|failure| format!("empty-bucket task admission: {failure:?}"))?
        .expect("empty-bucket compaction dispatch");
    let empty_preparation =
        ledger.prepare_compaction_payload_for_maintenance(&snapshot, &empty_execution)?;
    let empty_generation = catalog.pin()?.number();
    let empty_publication = ledger.compact_sealed_with_maintenance(
        Vec::new(),
        empty_preparation,
        &empty_coordinator,
        &empty_execution,
        || false,
    )?;
    assert_eq!(empty_publication.input_segments(), 0);
    assert_eq!(empty_publication.output_segments(), 0);
    assert_eq!(
        catalog.pin()?.number(),
        empty_generation + 1,
        "an empty bucket terminalizes only its PMTC record"
    );
    assert_eq!(
        empty_coordinator
            .status(empty_identity)
            .expect("empty-bucket terminal task")
            .phase(),
        crate::MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        ledger
            .snapshot()?
            .blocks()
            .iter()
            .map(CommittedBlock::segment_id)
            .collect::<std::collections::BTreeSet<_>>(),
        source_segments,
        "an empty bucket leaves the source manifest current"
    );
    assert_eq!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .map_err(|failure| format!("restore empty-bucket task: {failure:?}"))?
            .status(empty_identity)
            .expect("restored empty-bucket task")
            .phase(),
        crate::MaintenanceTaskPhase::Succeeded
    );
    let identity = MaintenanceTaskId::new([0xe8; 16]).expect("task identity");
    let task = ledger
        .prepare_compaction_task(bucket, identity)
        .map_err(|failure| format!("typed task planning: {failure:?}"))?;
    let coordinator = MaintenanceCoordinator::new();
    task.submit_and_persist(&coordinator, &catalog, 1)
        .map_err(|failure| format!("typed task persistence: {failure:?}"))?;
    let execution = coordinator
        .start_compaction_task_with_reservation_and_persist(
            &catalog, &authority, 1, false, identity,
        )
        .map_err(|failure| format!("typed task admission: {failure:?}"))?
        .expect("typed task dispatches");
    let unrelated_bytes = vec![0xa5; 1_048_576];
    let adding_basis = catalog.pin()?;
    let mut grown_objects = adding_basis
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    grown_objects.push(CatalogObject::new(unrelated_bytes.clone())?);
    catalog.commit(
        adding_basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xa5; 16])?,
            FormatEpoch::CATALOG_V1,
            grown_objects,
        )?,
        None,
    )?;
    let generation_before_growth_refusal = catalog.pin()?.number();
    let growth_refusal = match ledger.prepare_compaction_for_maintenance(&execution) {
        Ok(_) => return Err("current Catalog growth made an immutable grant underclaim".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        growth_refusal.code(),
        LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(catalog.pin()?.number(), generation_before_growth_refusal);
    assert_eq!(
        coordinator.status(identity).expect("running task").phase(),
        crate::MaintenanceTaskPhase::Running
    );
    let removing_basis = catalog.pin()?;
    let restored_objects = removing_basis
        .plaintext_objects()
        .filter(|bytes| *bytes != unrelated_bytes.as_slice())
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    catalog.commit(
        removing_basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xa6; 16])?,
            FormatEpoch::CATALOG_V1,
            restored_objects,
        )?,
        None,
    )?;
    let mut rewritten_source = blocks.clone();
    rewritten_source[0].source_segment = rewritten_source[1].source_segment;
    let refusal_preparation = ledger
        .prepare_compaction_payload_for_maintenance(&snapshot, &execution)
        .map_err(|failure| format!("rewritten-source preparation: {failure:?}"))?;
    let generation_before_refusal = catalog.pin()?.number();
    let refusal = ledger
        .compact_sealed_with_maintenance(
            rewritten_source,
            refusal_preparation,
            &coordinator,
            &execution,
            || false,
        )
        .expect_err("a running task cannot rewrite its immutable sealed-source binding");
    assert_eq!(refusal.code(), LedgerFailureCode::StaleGeneration);
    assert_eq!(catalog.pin()?.number(), generation_before_refusal);
    assert_eq!(
        coordinator.status(identity).expect("running task").phase(),
        crate::MaintenanceTaskPhase::Running
    );
    super::retention_frontier::install_governance_policy(&catalog, instance, tenant, 120, 0xa3)?;
    let generation_before_policy_refusal = catalog.pin()?.number();
    let policy_refusal = match ledger.prepare_compaction_for_maintenance(&execution) {
        Ok(_) => return Err("a running task substituted a later retention policy object".into()),
        Err(failure) => failure,
    };
    assert_eq!(policy_refusal.code(), LedgerFailureCode::StaleGeneration);
    assert_eq!(catalog.pin()?.number(), generation_before_policy_refusal);
    assert_eq!(
        coordinator.status(identity).expect("running task").phase(),
        crate::MaintenanceTaskPhase::Running
    );
    super::retention_frontier::install_governance_policy(&catalog, instance, tenant, 60, 0xa4)?;
    let preparation = ledger
        .prepare_compaction_payload_for_maintenance(&snapshot, &execution)
        .map_err(|failure| format!("execution preparation: {failure:?}"))?;
    let generation = catalog.pin()?.number();
    let mut reversed_blocks = blocks;
    reversed_blocks.reverse();
    ledger
        .compact_sealed_with_maintenance(
            reversed_blocks,
            preparation,
            &coordinator,
            &execution,
            || false,
        )
        .map_err(|failure| format!("typed execution: {failure:?}"))?;
    assert_eq!(
        coordinator.status(identity).expect("terminal task").phase(),
        crate::MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        catalog.pin()?.number(),
        generation + 1,
        "output metadata and terminal PMTC share one Catalog generation"
    );
    assert_eq!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("restore")
            .status(identity)
            .expect("restored task")
            .phase(),
        crate::MaintenanceTaskPhase::Succeeded
    );
    drop(snapshot);
    drop(ledger);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(
        reopened.snapshot()?.blocks().len(),
        2,
        "reopen observes the one canonical post-compaction source replacement"
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn typed_compaction_recovers_the_exact_output_and_terminal_pair_after_lost_ack()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xe9; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xea; 32]), Box::new([0xeb; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    super::retention_frontier::install_governance_policy(&catalog, instance, tenant, 60, 0xec)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(62)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xed; 32]));
    for (identity, payload) in [
        ([0xee; 16], b"lost-ack-first".as_slice()),
        ([0xef; 16], b"lost-ack-second".as_slice()),
    ] {
        let source = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        source.append(
            source
                .begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new(identity)?,
                )?
                .finish(payload.to_vec())?,
        )?;
        source.seal()?;
    }
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let snapshot = ledger.snapshot()?;
    let blocks = snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let policy = catalog.pin()?.retention_policy(SignalKind::Logs)?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Logs,
        blocks[0].ingest_time,
        policy.retention_seconds(),
    )?;
    let identity = MaintenanceTaskId::new([0xf0; 16]).expect("task identity");
    let task = ledger.prepare_compaction_task(bucket, identity)?;
    let coordinator = MaintenanceCoordinator::new();
    task.submit_and_persist(&coordinator, &catalog, 1)?;
    let execution = coordinator
        .start_compaction_task_with_reservation_and_persist(
            &catalog, &authority, 1, false, identity,
        )
        .expect("typed compaction starts")
        .ok_or("typed compaction dispatch")?;
    let preparation = ledger.prepare_compaction_payload_for_maintenance(&snapshot, &execution)?;
    let generation = catalog.pin()?.number();
    let publication = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || {
            ledger.compact_sealed_with_maintenance(
                blocks.clone(),
                preparation,
                &coordinator,
                &execution,
                || false,
            )
        },
    )?;
    assert_eq!(publication.input_segments(), 2);
    assert_eq!(publication.output_segments(), 1);
    assert_eq!(
        coordinator
            .status(identity)
            .expect("succeeded task")
            .phase(),
        crate::MaintenanceTaskPhase::Succeeded,
        "the original coordinator installs success only after proving the exact durable pair"
    );
    catalog.refresh_state()?;
    assert_eq!(catalog.pin()?.number(), generation + 1);
    let output_segments = ledger
        .snapshot()?
        .blocks()
        .iter()
        .map(CommittedBlock::segment_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        output_segments.len(),
        1,
        "one exact output manifest is current"
    );
    let recovered = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore");
    assert_eq!(
        recovered.status(identity).expect("restored task").phase(),
        crate::MaintenanceTaskPhase::Succeeded,
        "the one durable terminal PMTC record is restored with the output generation"
    );
    drop(snapshot);
    drop(ledger);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let output = reopened.snapshot()?;
    assert_eq!(
        output.blocks().len(),
        2,
        "recovery must not duplicate output blocks"
    );
    assert_eq!(
        output
            .blocks()
            .iter()
            .map(CommittedBlock::segment_id)
            .collect::<std::collections::BTreeSet<_>>(),
        output_segments,
        "reopened Catalog reachability is the exact same output manifest"
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn typed_compaction_reconciles_a_two_fault_lost_ack_with_the_original_execution()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xf1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xf2; 32]), Box::new([0xf3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    super::retention_frontier::install_governance_policy(&catalog, instance, tenant, 60, 0xf4)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(63)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xf5; 32]));
    for (identity, payload) in [
        ([0xf6; 16], b"two-fault-first".as_slice()),
        ([0xf7; 16], b"two-fault-second".as_slice()),
    ] {
        let source = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        source.append(
            source
                .begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new(identity)?,
                )?
                .finish(payload.to_vec())?,
        )?;
        source.seal()?;
    }
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let snapshot = ledger.snapshot()?;
    let blocks = snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let policy = catalog.pin()?.retention_policy(SignalKind::Logs)?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Logs,
        blocks[0].ingest_time,
        policy.retention_seconds(),
    )?;
    let identity = MaintenanceTaskId::new([0xf8; 16]).expect("task identity");
    let task = ledger.prepare_compaction_task(bucket, identity)?;
    let coordinator = MaintenanceCoordinator::new();
    task.submit_and_persist(&coordinator, &catalog, 1)?;
    let execution = coordinator
        .start_compaction_task_with_reservation_and_persist(
            &catalog, &authority, 1, false, identity,
        )
        .expect("typed compaction starts")
        .ok_or("typed compaction dispatch")?;
    let preparation = ledger.prepare_compaction_payload_for_maintenance(&snapshot, &execution)?;
    let generation = catalog.pin()?.number();
    let first = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeGenerationDirectory, 0),
            (CatalogPublicationFault::ReadGenerationDirectory, 0),
        ],
        || {
            ledger.compact_sealed_with_maintenance(
                blocks.clone(),
                preparation,
                &coordinator,
                &execution,
                || false,
            )
        },
    )
    .expect_err("a missing immediate successor proof leaves the original task running");
    assert_eq!(first.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        coordinator.status(identity).expect("running task").phase(),
        crate::MaintenanceTaskPhase::Running
    );
    catalog.refresh_state()?;
    assert_eq!(catalog.pin()?.number(), generation + 1);
    assert_eq!(
        coordinator
            .cancel_and_persist(&catalog, identity)
            .expect_err("a durable Compaction terminal must not be overwritten by cancellation"),
        crate::MaintenanceFailure::PreconditionFailed
    );
    ledger.reconcile_ambiguous_compaction_completion(&blocks, &coordinator, &execution)?;
    assert_eq!(
        coordinator
            .status(identity)
            .expect("succeeded task")
            .phase(),
        crate::MaintenanceTaskPhase::Succeeded,
        "one bounded same-dispatch retry installs only the proven terminal pair"
    );
    assert_eq!(
        catalog.pin()?.number(),
        generation + 1,
        "reconciliation never republishes output metadata"
    );
    let output = ledger.snapshot()?;
    let manifest = output
        .blocks()
        .iter()
        .map(CommittedBlock::segment_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(manifest.len(), 1);
    assert_eq!(output.blocks().len(), 2);
    assert_eq!(output.blocks()[0].payload(), b"two-fault-first");
    assert_eq!(output.blocks()[1].payload(), b"two-fault-second");
    drop(output);
    drop(snapshot);
    drop(ledger);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let reopened_output = reopened.snapshot()?;
    assert_eq!(
        reopened_output
            .blocks()
            .iter()
            .map(CommittedBlock::segment_id)
            .collect::<std::collections::BTreeSet<_>>(),
        manifest,
        "reopen observes the exact durable output manifest"
    );
    assert_eq!(reopened_output.blocks().len(), 2);
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn typed_compaction_refuses_an_altered_valid_terminal_record_after_lost_ack()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xf9; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xfa; 32]), Box::new([0xfb; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    super::retention_frontier::install_governance_policy(&catalog, instance, tenant, 60, 0xfc)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(64)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xfd; 32]));
    let source = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    source.append(
        source
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0xfe; 16])?,
            )?
            .finish(b"altered-terminal-source".to_vec())?,
    )?;
    source.seal()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let snapshot = ledger.snapshot()?;
    let blocks = snapshot
        .blocks()
        .iter()
        .map(|block| compaction_block(scope, block))
        .collect::<Result<Vec<_>, _>>()?;
    let policy = catalog.pin()?.retention_policy(SignalKind::Logs)?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Logs,
        blocks[0].ingest_time,
        policy.retention_seconds(),
    )?;
    let identity = MaintenanceTaskId::new([0xff; 16]).expect("task identity");
    let task = ledger.prepare_compaction_task(bucket, identity)?;
    let coordinator = MaintenanceCoordinator::new();
    task.submit_and_persist(&coordinator, &catalog, 1)?;
    let execution = coordinator
        .start_compaction_task_with_reservation_and_persist(
            &catalog, &authority, 1, false, identity,
        )
        .expect("typed compaction starts")
        .ok_or("typed compaction dispatch")?;
    let preparation = ledger.prepare_compaction_payload_for_maintenance(&snapshot, &execution)?;
    let first = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeGenerationDirectory, 0),
            (CatalogPublicationFault::ReadGenerationDirectory, 0),
        ],
        || {
            ledger.compact_sealed_with_maintenance(
                blocks.clone(),
                preparation,
                &coordinator,
                &execution,
                || false,
            )
        },
    )
    .expect_err("a durable pair without immediate proof is ambiguous");
    assert_eq!(first.code(), LedgerFailureCode::StorageUnavailable);
    catalog.refresh_state()?;
    let basis = catalog.pin()?;
    let mut altered = false;
    let objects = basis
        .plaintext_objects()
        .map(|bytes| {
            let record_identity = crate::maintenance::durable_task_record_identity(bytes)
                .map_err(|failure| format!("durable task identity: {failure:?}"))?;
            let replacement = if record_identity == Some(identity) {
                altered = true;
                crate::maintenance::rewrite_durable_task_record_dispatches_for_test(bytes, 2)
                    .map_err(|failure| format!("rewrite durable terminal: {failure:?}"))?
            } else {
                bytes.to_vec()
            };
            CatalogObject::new(replacement).map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    assert!(
        altered,
        "the terminal PMTC must be durable before it can be altered"
    );
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xab; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let failure = ledger
        .reconcile_ambiguous_compaction_completion(&blocks, &coordinator, &execution)
        .expect_err("a same-identity but altered terminal PMTC must fail closed");
    assert_eq!(failure.code(), LedgerFailureCode::RecoveryRequired);
    assert_eq!(
        coordinator.status(identity).expect("live task").phase(),
        crate::MaintenanceTaskPhase::Running,
        "the terminal cannot be faked from object identity alone"
    );
    Ok(())
}

#[test]
fn compaction_preparation_rejects_a_stale_catalog_snapshot_without_reservation_drift()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xee; 16])?,
        CatalogSecret::from_owned(Box::new([0xef; 32]), Box::new([0xf0; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(7)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xf1; 32])),
    )?;
    ledger.append(
        ledger
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0xf2; 16])?,
            )?
            .finish(b"stale-preparation".to_vec())?,
    )?;
    let snapshot = ledger.snapshot()?;
    let basis = catalog.pin()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf3; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(
                b"unrelated-catalog-generation".to_vec(),
            )?],
        )?,
        None,
    )?;
    let before = authority.governor().inspect()?;
    let failure = match ledger.prepare_compaction(&snapshot) {
        Ok(_) => return Err("a stale Catalog snapshot was admitted".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::StaleGeneration);
    let after = authority.governor().inspect()?;
    assert_eq!(after.outstanding_total(), before.outstanding_total());
    for dimension in ResourceDimension::ALL {
        assert_eq!(
            after.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension),
            before.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension)
        );
    }
    Ok(())
}

#[test]
fn repair_moves_a_catalog_published_active_compaction_output_to_sealed_namespace()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let protection = SegmentProtectionKey::from_owned(Box::new([0xa5; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection.clone(),
    )?;
    let capacity = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?;
    let preparation = ledger.begin_store_block(capacity, StoreBlockIdentity::new([0xa6; 16])?)?;
    ledger.append(preparation.finish(b"crash-output".to_vec())?)?;
    let current = ledger.storage.current_metadata()?;
    let basis = catalog.pin()?;
    let mut metadata = ledger.storage.catalog_segments(&basis, scope)?;
    let published = metadata
        .iter_mut()
        .find(|candidate| candidate.id == current.id)
        .ok_or("active segment missing from Catalog")?;
    published.state = SegmentState::Sealed;
    publish_segments(&catalog, &basis, &ledger.storage, scope, &metadata)?;
    drop(ledger);

    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let snapshot = reopened.snapshot()?;
    assert_eq!(snapshot.blocks().len(), 1);
    assert_eq!(snapshot.blocks()[0].payload(), b"crash-output");
    Ok(())
}
