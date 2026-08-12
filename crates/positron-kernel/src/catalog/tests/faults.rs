use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_kernel::{MountQualification, PrimaryDataVolume};

use super::super::storage::fault::CatalogFileEvent;
use super::super::storage::with_catalog_fault;
use super::super::{
    AuditIntent, Catalog, CatalogFailure, CatalogFailureCode, CatalogObject, CatalogProposal,
    CatalogSecret, FormatEpoch, InstanceId, TransactionId,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-catalog-fault-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove catalog fault root: {error}");
        }
    }
}

fn id(last: u8) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[15] = last;
    bytes
}

fn secret() -> CatalogSecret {
    CatalogSecret::from_owned(Box::new([0xe1; 32]))
}

fn proposal(transaction: u8, value: u8) -> Result<CatalogProposal, CatalogFailure> {
    CatalogProposal::new(
        TransactionId::new(id(transaction))?,
        FormatEpoch::new(1)?,
        vec![CatalogObject::new(vec![value])?],
    )
}

#[test]
fn every_pre_marker_fault_recovers_only_the_predecessor() -> Result<(), Box<dyn std::error::Error>>
{
    for (offset, event) in [
        CatalogFileEvent::WriteObject,
        CatalogFileEvent::PartialObjectWrite,
        CatalogFileEvent::SynchronizeObject,
        CatalogFileEvent::SynchronizeObjectDirectory,
        CatalogFileEvent::ReserveAudit,
        CatalogFileEvent::WriteAudit,
        CatalogFileEvent::PartialAuditWrite,
        CatalogFileEvent::SynchronizeAudit,
        CatalogFileEvent::SynchronizeAuditDirectory,
        CatalogFileEvent::WriteCommit,
        CatalogFileEvent::PartialCommitWrite,
        CatalogFileEvent::SynchronizeCommit,
        CatalogFileEvent::SynchronizeCommitDirectory,
        CatalogFileEvent::WriteMarker,
        CatalogFileEvent::PartialMarkerWrite,
        CatalogFileEvent::SynchronizeMarker,
        CatalogFileEvent::RenameMarker,
    ]
    .into_iter()
    .enumerate()
    {
        let root = TemporaryRoot::new()?;
        let instance = InstanceId::new(id(51))?;
        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let catalog = Catalog::open(volume, instance, secret())?;
        let expected = catalog.pin()?.identity();
        let failure = with_catalog_fault(event, || {
            let value = 80_u8.saturating_add(offset as u8);
            catalog.commit(
                expected,
                proposal(value, value)?,
                Some(AuditIntent::new(vec![offset as u8 + 1])?),
            )
        })
        .expect_err("injected publication fault must fail");
        assert_eq!(
            failure.code(),
            CatalogFailureCode::StorageUnavailable,
            "{event:?}"
        );
        drop(catalog);

        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let recovered = Catalog::open(volume, instance, secret())?;
        assert_eq!(recovered.pin()?.number(), 0, "{event:?}");
        assert!(
            recovered.governance_audit_records()?.is_empty(),
            "{event:?}"
        );
    }
    Ok(())
}

#[test]
fn post_rename_directory_sync_fault_recovers_only_the_complete_successor()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(71))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let catalog = Catalog::open(volume, instance, secret())?;
    let expected = catalog.pin()?.identity();

    let failure = with_catalog_fault(CatalogFileEvent::SynchronizeGenerationDirectory, || {
        catalog.commit(
            expected,
            proposal(72, 1)?,
            Some(AuditIntent::new(b"directory sync unknown".to_vec())?),
        )
    })
    .expect_err("post-rename synchronization fault must return unknown completion");
    assert_eq!(failure.code(), CatalogFailureCode::StorageUnavailable);
    let retried = catalog.commit(
        expected,
        proposal(72, 1)?,
        Some(AuditIntent::new(b"directory sync unknown".to_vec())?),
    )?;
    assert_eq!(retried.number(), 1);
    assert_eq!(
        retried
            .governance_audit_record()
            .map(|record| record.position()),
        Some(1)
    );
    drop(catalog);

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let recovered = Catalog::open(volume, instance, secret())?;
    assert_eq!(recovered.pin()?.number(), 1);
    assert_eq!(recovered.governance_audit_records()?.len(), 1);
    Ok(())
}

#[test]
fn failed_audited_successor_releases_its_chain_position() -> Result<(), Box<dyn std::error::Error>>
{
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(91))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let catalog = Catalog::open(volume, instance, secret())?;
    let first = catalog.commit(
        catalog.pin()?.identity(),
        proposal(92, 2)?,
        Some(AuditIntent::new(b"first".to_vec())?),
    )?;

    let failure = with_catalog_fault(CatalogFileEvent::WriteCommit, || {
        catalog.commit(
            first.identity(),
            proposal(93, 3)?,
            Some(AuditIntent::new(b"unpublished".to_vec())?),
        )
    })
    .expect_err("commit-record fault must keep successor unpublished");
    assert_eq!(failure.code(), CatalogFailureCode::StorageUnavailable);

    let successor = catalog.commit(
        first.identity(),
        proposal(94, 4)?,
        Some(AuditIntent::new(b"successor".to_vec())?),
    )?;
    assert_eq!(successor.number(), 2);
    let audit = catalog.governance_audit_records()?;
    assert_eq!(
        audit
            .iter()
            .map(|record| record.position())
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(audit[1].predecessor_hash(), audit[0].record_hash());
    assert_eq!(audit[1].intent(), b"successor");
    Ok(())
}

#[test]
fn partial_staging_write_can_be_retried_idempotently() -> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(101))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let catalog = Catalog::open(volume, instance, secret())?;
    let expected = catalog.pin()?.identity();

    let failure = with_catalog_fault(CatalogFileEvent::PartialObjectWrite, || {
        catalog.commit(
            expected,
            proposal(102, 9)?,
            Some(AuditIntent::new(b"retry".to_vec())?),
        )
    })
    .expect_err("partial object write must fail before publication");
    assert_eq!(failure.code(), CatalogFailureCode::StorageUnavailable);

    let retried = catalog.commit(
        expected,
        proposal(102, 9)?,
        Some(AuditIntent::new(b"retry".to_vec())?),
    )?;
    assert_eq!(retried.number(), 1);
    assert_eq!(catalog.governance_audit_records()?.len(), 1);
    Ok(())
}
