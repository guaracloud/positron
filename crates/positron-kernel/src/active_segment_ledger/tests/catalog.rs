use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use super::support::{TemporaryRoot, establish_authority};
use crate::active_segment_ledger::format::{SegmentMetadata, SegmentState};
use crate::active_segment_ledger::storage::LedgerStorage;
use crate::active_segment_ledger::{
    ActiveSegmentLedger, LedgerFailureCode, SegmentId, SegmentProtectionKey, SegmentScope,
    publish_segments,
};
use crate::catalog::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSecret,
    FormatEpoch, InstanceId, TransactionId,
};
use crate::{MountQualification, PrimaryDataVolume};

#[test]
fn catalog_continuity_gaps_and_multiple_active_segments_fail_closed() -> Result<(), Box<dyn Error>>
{
    with_fixture(0xa1, |authority, catalog, scope| {
        let ledger = open(authority, catalog, scope)?;
        assert_eq!(
            format!("{ledger:?}"),
            "ActiveSegmentLedger { <storage-and-key-redacted> }"
        );
        let original = ledger.storage.current_metadata()?;
        drop(ledger);
        publish_metadata(
            catalog,
            authority,
            scope,
            &[SegmentMetadata {
                base_position: CommitPosition::origin().next()?,
                ..original
            }],
            0xb1,
        )?;
        let failure = open(authority, catalog, scope)
            .expect_err("a catalog range cannot start after the durable origin");
        assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
        Ok(())
    })?;

    with_fixture(0xa2, |authority, catalog, scope| {
        let ledger = open(authority, catalog, scope)?;
        let first = ledger.storage.current_metadata()?;
        drop(ledger);
        let second = SegmentMetadata {
            id: SegmentId::new([0xc2; 16])?,
            ..first
        };
        publish_metadata(catalog, authority, scope, &[first, second], 0xb2)?;
        let failure = open(authority, catalog, scope)
            .expect_err("one scope cannot publish two active segments");
        assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
        Ok(())
    })
}

#[test]
fn duplicate_segment_publication_is_rejected_by_the_catalog_contract() -> Result<(), Box<dyn Error>>
{
    with_fixture(0xa3, |authority, catalog, scope| {
        let storage = LedgerStorage::open(
            authority
                .primary_data_volume()
                .expect("fixture retains the volume"),
        )?;
        let metadata = SegmentMetadata {
            scope,
            id: SegmentId::new([0xc3; 16])?,
            state: SegmentState::Active,
            base_position: CommitPosition::origin(),
        };
        let failure = publish_segments(
            catalog,
            &catalog.pin()?,
            &storage,
            scope,
            &[metadata, metadata],
        )
        .expect_err("duplicate metadata objects cannot form a catalog proposal");
        assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);
        Ok(())
    })
}

#[test]
fn ledger_catalog_publication_preserves_stale_and_idempotency_conflict_fencing()
-> Result<(), Box<dyn Error>> {
    with_fixture(0xa4, |authority, catalog, scope| {
        let stale = catalog.pin()?.identity();
        drop(open(authority, catalog, scope)?);
        let proposal = |transaction, payload| -> Result<CatalogProposal, Box<dyn Error>> {
            Ok(CatalogProposal::new(
                TransactionId::new([transaction; 16])?,
                FormatEpoch::new(1)?,
                vec![CatalogObject::new(vec![payload])?],
            )?)
        };
        let failure = catalog
            .commit(stale, proposal(0xb4, 1)?, None)
            .expect_err("an earlier ledger generation cannot publish over its successor");
        assert_eq!(failure.code(), CatalogFailureCode::StaleGeneration);

        let transaction = 0xb5;
        catalog.commit(catalog.pin()?.identity(), proposal(transaction, 2)?, None)?;
        catalog.commit(catalog.pin()?.identity(), proposal(transaction, 2)?, None)?;
        let failure = catalog
            .commit(catalog.pin()?.identity(), proposal(transaction, 3)?, None)
            .expect_err("one transaction identity cannot name different object sets");
        assert_eq!(failure.code(), CatalogFailureCode::IdempotencyConflict);

        let audited = catalog.commit(
            catalog.pin()?.identity(),
            proposal(0xb6, 4)?,
            Some(AuditIntent::new(b"ledger-catalog-publication".to_vec())?),
        )?;
        assert_eq!(
            audited
                .governance_audit_record()
                .expect("the accepted audit intent is visible")
                .intent(),
            b"ledger-catalog-publication"
        );
        Ok(())
    })
}

#[test]
fn segment_publication_uses_one_exact_catalog_generation_as_proposal_and_precondition()
-> Result<(), Box<dyn Error>> {
    with_fixture(0xa5, |authority, catalog, scope| {
        drop(open(authority, catalog, scope)?);
        let basis = catalog.pin()?;
        let storage = LedgerStorage::open(
            authority
                .primary_data_volume()
                .expect("fixture retains volume"),
        )?;
        let metadata = storage.catalog_segments(&basis, scope)?;
        let unrelated = CatalogObject::new(b"unrelated-control-state".to_vec())?;
        let unrelated_id = unrelated.identity();
        let mut objects = basis
            .plaintext_objects()
            .map(|bytes| CatalogObject::new(bytes.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        objects.push(unrelated);
        catalog.commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new([0xb7; 16])?,
                FormatEpoch::new(1)?,
                objects,
            )?,
            Some(AuditIntent::new(b"unrelated-audit".to_vec())?),
        )?;

        let failure = publish_segments(catalog, &basis, &storage, scope, &metadata)
            .expect_err("a segment proposal cannot overwrite an intervening generation");
        assert_eq!(failure.code(), LedgerFailureCode::StaleGeneration);
        let current = catalog.pin()?;
        assert_eq!(
            current.object(unrelated_id)?,
            Some(b"unrelated-control-state".as_slice())
        );
        assert_eq!(catalog.governance_audit_records()?.len(), 1);
        Ok(())
    })
}

fn open<'authority, 'catalog>(
    authority: &'authority crate::StorageKernelResourceAuthority,
    catalog: &'catalog Catalog<'authority>,
    scope: SegmentScope,
) -> Result<ActiveSegmentLedger<'authority, 'catalog>, crate::LedgerFailure> {
    ActiveSegmentLedger::open(
        authority,
        catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xd1; 32])),
    )
}

fn publish_metadata(
    catalog: &Catalog<'_>,
    authority: &crate::StorageKernelResourceAuthority,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
    transaction: u8,
) -> Result<(), Box<dyn Error>> {
    let storage = LedgerStorage::open(
        authority
            .primary_data_volume()
            .expect("fixture retains the volume"),
    )?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .filter(|bytes| !storage.is_scope_metadata(bytes, scope))
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    for segment in metadata {
        objects.push(CatalogObject::new(storage.metadata_object(*segment))?);
    }
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction; 16])?,
            FormatEpoch::new(1)?,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

fn with_fixture<T>(
    seed: u8,
    action: impl FnOnce(
        &crate::StorageKernelResourceAuthority,
        &Catalog<'_>,
        SegmentScope,
    ) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([seed; 16])?,
        CatalogSecret::from_owned(Box::new([seed + 1; 32]), Box::new([seed + 2; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(u32::from(seed))?,
    );
    action(&authority, &catalog, scope)
}
