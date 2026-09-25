use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_kernel::{MountQualification, PrimaryDataVolume, RecoveryWorkClaim, RecoveryWorkKind};

use super::super::storage::fault::CatalogFileEvent;
use super::super::storage::{with_catalog_fault, with_catalog_fault_after};
use super::super::{
    AuditCheckpointSigner, AuditIntent, Catalog, CatalogFailure, CatalogFailureCode, CatalogObject,
    CatalogProposal, CatalogSecret, CatalogWrappingKey, FormatEpoch, InstanceId,
    PreparedTransactionInspection, TransactionId,
};
#[cfg(feature = "test-support")]
use super::super::{GovernanceFixtureObject, GovernanceFixtureTarget};
use super::support::{establish_catalog_authority, establish_catalog_authority_with_repair_memory};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "test-support")]
#[test]
fn governance_fixture_object_checks_its_bound_before_copying() {
    assert_eq!(
        GovernanceFixtureObject::from_bytes(&[])
            .map(|_| ())
            .expect_err("empty fixture object must be rejected")
            .code(),
        CatalogFailureCode::LimitExceeded
    );
    let oversized = vec![0_u8; 1_048_577];
    assert_eq!(
        GovernanceFixtureObject::from_bytes(&oversized)
            .map(|_| ())
            .expect_err("oversized fixture object must be rejected")
            .code(),
        CatalogFailureCode::LimitExceeded
    );
    assert!(GovernanceFixtureObject::from_bytes(b"POSGOV03").is_ok());
}

#[cfg(feature = "test-support")]
#[test]
fn default_governance_fixture_target_delegates_installation() {
    struct DelegatingTarget(AtomicU64);

    impl GovernanceFixtureTarget for DelegatingTarget {
        fn install_governance_fixture(
            &self,
            _fixture: &GovernanceFixtureObject,
        ) -> Result<(), CatalogFailure> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let target = DelegatingTarget(AtomicU64::new(0));
    let fixture = GovernanceFixtureObject::from_bytes(b"POSGOV03")
        .expect("the bounded test fixture must be accepted");
    target
        .replace_governance_fixture(&fixture)
        .expect("the default replacement must delegate installation");
    assert_eq!(target.0.load(Ordering::Relaxed), 1);
}

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
    CatalogSecret::from_owned(Box::new([0xd1; 32]), Box::new([0xe1; 32]))
}

#[test]
fn catalog_open_is_refused_while_a_same_authority_repair_claim_is_held_then_recovers()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(1))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority_with_repair_memory(volume, 90_000_000)?;
    let claim = RecoveryWorkClaim::system(
        RecoveryWorkKind::Repair,
        super::super::recovery_resource_claim(),
    )?;
    let reservation = authority.recovery().reserve(claim)?;
    let failure = Catalog::open(&authority, instance, secret())
        .expect_err("one 70 MB repair claim must exclude a second claim from a 90 MB pool");
    assert_eq!(failure.code(), CatalogFailureCode::ResourceAdmissionRefused);
    drop(reservation);
    drop(Catalog::open(&authority, instance, secret())?);
    Ok(())
}

fn rotating_secret(
    wrapping_byte: u8,
    provider: u8,
    epoch: u64,
) -> Result<CatalogSecret, CatalogFailure> {
    CatalogSecret::from_owned_at_epoch(
        Box::new([0xa7; 32]),
        Box::new([wrapping_byte; 32]),
        [provider; 16],
        epoch,
    )
}

fn wrapping_key(
    wrapping_byte: u8,
    provider: u8,
    epoch: u64,
) -> Result<CatalogWrappingKey, CatalogFailure> {
    CatalogWrappingKey::from_owned_at_epoch(Box::new([wrapping_byte; 32]), [provider; 16], epoch)
}

fn proposal(transaction: u8, value: u8) -> Result<CatalogProposal, CatalogFailure> {
    CatalogProposal::new(
        TransactionId::new(id(transaction))?,
        FormatEpoch::new(1)?,
        vec![CatalogObject::new(vec![value])?],
    )
}

fn proposal_at_epoch(
    transaction: u8,
    value: u8,
    epoch: u32,
) -> Result<CatalogProposal, CatalogFailure> {
    CatalogProposal::new(
        TransactionId::new(id(transaction))?,
        FormatEpoch::new(epoch)?,
        vec![CatalogObject::new(vec![value])?],
    )
}

#[test]
fn prepared_inspection_rejects_changed_digest_and_never_publishes()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(39))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    let transaction = TransactionId::new(id(40))?;
    let digest = [0x41; 32];
    let failure = with_catalog_fault(CatalogFileEvent::WriteMarker, || {
        catalog.commit_prepared(
            catalog.pin().expect("snapshot").identity(),
            CatalogProposal::new(
                transaction,
                FormatEpoch::CATALOG_V1,
                vec![CatalogObject::new(vec![7]).expect("object")],
            )
            .expect("proposal"),
            AuditIntent::new(b"prepared inspection".to_vec()).expect("audit"),
            digest,
        )
    })
    .expect_err("pre-marker fault retains only a prepared proposal");
    assert_eq!(failure.code(), CatalogFailureCode::StorageUnavailable);
    assert_eq!(catalog.pin()?.number(), 0);
    let wrong = catalog
        .inspect_prepared(transaction, [0x42; 32])
        .expect_err("a changed request digest must not inspect the proposal");
    assert_eq!(wrong.code(), CatalogFailureCode::IdempotencyConflict);
    assert_eq!(catalog.pin()?.number(), 0);
    assert!(matches!(
        catalog.inspect_prepared(transaction, digest)?,
        PreparedTransactionInspection::Inspected(_)
    ));
    assert_eq!(catalog.pin()?.number(), 0);
    Ok(())
}

#[test]
fn prepared_inspection_refuses_an_advanced_predecessor_without_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(43))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    let transaction = TransactionId::new(id(44))?;
    let digest = [0x45; 32];
    with_catalog_fault(CatalogFileEvent::WriteMarker, || {
        catalog.commit_prepared(
            catalog.pin().expect("snapshot").identity(),
            CatalogProposal::new(
                transaction,
                FormatEpoch::CATALOG_V1,
                vec![CatalogObject::new(vec![8]).expect("object")],
            )
            .expect("proposal"),
            AuditIntent::new(b"prepared predecessor".to_vec()).expect("audit"),
            digest,
        )
    })
    .expect_err("pre-marker fault retains a prepared proposal");
    catalog.commit(
        catalog.pin()?.identity(),
        proposal(46, 9)?,
        Some(AuditIntent::new(b"independent successor".to_vec())?),
    )?;
    assert_eq!(catalog.pin()?.number(), 1);
    assert!(matches!(
        catalog.inspect_prepared(transaction, digest)?,
        PreparedTransactionInspection::Unavailable
    ));
    assert_eq!(catalog.pin()?.number(), 1);
    Ok(())
}

#[test]
fn prepared_inspection_refuses_a_missing_staged_object_without_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(47))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    let transaction = TransactionId::new(id(48))?;
    let digest = [0x49; 32];
    with_catalog_fault(CatalogFileEvent::WriteMarker, || {
        catalog.commit_prepared(
            catalog.pin().expect("snapshot").identity(),
            CatalogProposal::new(
                transaction,
                FormatEpoch::CATALOG_V1,
                vec![CatalogObject::new(vec![10]).expect("object")],
            )
            .expect("proposal"),
            AuditIntent::new(b"prepared object".to_vec()).expect("audit"),
            digest,
        )
    })
    .expect_err("pre-marker fault retains a prepared proposal");
    let object = fs::read_dir(root.0.join("catalog/objects"))?
        .next()
        .ok_or("prepared object")??
        .path();
    fs::remove_file(object)?;
    let failure = catalog
        .inspect_prepared(transaction, digest)
        .expect_err("missing staged objects must fail closed");
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    assert_eq!(catalog.pin()?.number(), 0);
    Ok(())
}

#[test]
fn prepared_inspection_refuses_an_altered_staged_object_without_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(50))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    let transaction = TransactionId::new(id(51))?;
    let digest = [0x52; 32];
    with_catalog_fault(CatalogFileEvent::WriteMarker, || {
        catalog.commit_prepared(
            catalog.pin().expect("snapshot").identity(),
            CatalogProposal::new(
                transaction,
                FormatEpoch::CATALOG_V1,
                vec![CatalogObject::new(vec![11]).expect("object")],
            )
            .expect("proposal"),
            AuditIntent::new(b"altered prepared object".to_vec()).expect("audit"),
            digest,
        )
    })
    .expect_err("pre-marker fault retains a prepared proposal");
    let object = fs::read_dir(root.0.join("catalog/objects"))?
        .next()
        .ok_or("prepared object")??
        .path();
    fs::write(object, [0_u8])?;
    let failure = catalog
        .inspect_prepared(transaction, digest)
        .expect_err("altered staged objects must fail closed");
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    assert_eq!(catalog.pin()?.number(), 0);
    Ok(())
}

#[test]
fn current_reader_recovers_a_published_catalog_epoch_two_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(30))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;

    let committed = catalog.commit(
        catalog.pin()?.identity(),
        proposal_at_epoch(31, 7, 2)?,
        Some(AuditIntent::new(b"epoch two publication".to_vec())?),
    )?;
    assert_eq!(
        committed.snapshot().format_epoch(),
        Some(FormatEpoch::new(2)?)
    );
    drop(catalog);
    drop(authority);

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let reopened = Catalog::open(&authority, instance, secret())?;
    assert_eq!(reopened.pin()?.format_epoch(), Some(FormatEpoch::new(2)?));
    assert_eq!(reopened.governance_audit_records()?.len(), 1);
    Ok(())
}

#[test]
fn epoch_two_pre_marker_fault_leaves_the_epoch_one_predecessor_current()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(32))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;

    catalog.commit(
        catalog.pin()?.identity(),
        proposal(33, 1)?,
        Some(AuditIntent::new(b"epoch one predecessor".to_vec())?),
    )?;
    let failure = with_catalog_fault(CatalogFileEvent::WriteMarker, || {
        catalog.commit(
            catalog.pin()?.identity(),
            proposal_at_epoch(34, 2, FormatEpoch::CATALOG_V2.value())?,
            Some(AuditIntent::new(b"epoch two migration candidate".to_vec())?),
        )
    })
    .expect_err("pre-marker epoch-two publication must not become visible");
    assert_eq!(failure.code(), CatalogFailureCode::StorageUnavailable);
    drop(catalog);
    drop(authority);

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let reopened = Catalog::open(&authority, instance, secret())?;
    assert_eq!(reopened.pin()?.number(), 1);
    assert_eq!(
        reopened.pin()?.format_epoch(),
        Some(FormatEpoch::CATALOG_V1)
    );
    assert_eq!(reopened.governance_audit_records()?.len(), 1);
    Ok(())
}

#[test]
fn transaction_identity_file_and_directory_sync_faults_restart_and_retry_idempotently()
-> Result<(), Box<dyn std::error::Error>> {
    for event in [
        CatalogFileEvent::SynchronizeTransactionDigest,
        CatalogFileEvent::SynchronizeTransactionDirectory,
    ] {
        let root = TemporaryRoot::new()?;
        let instance = InstanceId::new(id(31))?;
        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let catalog = Catalog::open(&authority, instance, secret())?;
        let expected = catalog.pin()?.identity();
        let failure = with_catalog_fault(event, || {
            catalog.commit(
                expected,
                proposal(32, 7)?,
                Some(AuditIntent::new(b"durable transaction identity".to_vec())?),
            )
        })
        .expect_err("transaction identity durability fault must precede publication");
        assert_eq!(failure.code(), CatalogFailureCode::StorageUnavailable);
        drop(catalog);
        drop(authority);

        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let reopened = Catalog::open(&authority, instance, secret())?;
        assert_eq!(reopened.pin()?.number(), 0);
        let committed = reopened.commit(
            expected,
            proposal(32, 7)?,
            Some(AuditIntent::new(b"durable transaction identity".to_vec())?),
        )?;
        assert_eq!(committed.number(), 1, "{event:?}");
    }
    Ok(())
}

#[test]
fn read_only_current_snapshot_does_not_require_the_catalog_writer()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(37))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(catalog.pin()?.identity(), proposal(38, 9)?, None)?;

    let snapshot = Catalog::read_current_snapshot(&authority, instance, secret())?;

    assert_eq!(snapshot.number(), catalog.pin()?.number());
    assert_eq!(snapshot.identity(), catalog.pin()?.identity());
    Ok(())
}

#[test]
fn read_only_view_binds_one_immutable_snapshot_and_audit_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(39))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    let first = catalog.commit(
        catalog.pin()?.identity(),
        proposal(40, 10)?,
        Some(AuditIntent::new(b"first visible audit".to_vec())?),
    )?;

    let view = Catalog::read_current_view(&authority, instance, secret())?;
    assert_eq!(view.snapshot().identity(), first.identity());
    assert_eq!(view.governance_audit_records().len(), 1);

    catalog.commit(
        catalog.pin()?.identity(),
        proposal(41, 11)?,
        Some(AuditIntent::new(b"second visible audit".to_vec())?),
    )?;
    assert_eq!(view.snapshot().identity(), first.identity());
    assert_eq!(view.governance_audit_records().len(), 1);
    Ok(())
}

#[test]
fn interrupted_root_rewrap_restarts_with_predecessor_and_retries_idempotently()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(41))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, rotating_secret(0x31, 0x41, 7)?)?;
    catalog.commit(
        catalog.pin()?.identity(),
        proposal(42, 9)?,
        Some(AuditIntent::new(b"root rotation".to_vec())?),
    )?;

    let failure = with_catalog_fault(CatalogFileEvent::SynchronizeRewrapDirectory, || {
        catalog.rewrap(
            TransactionId::new(id(43))?,
            wrapping_key(0x32, 0x42, 8)?,
            AuditIntent::new(b"root rotation operation".to_vec())?,
        )
    })
    .expect_err("post-rename rewrap fault must return unknown completion");
    assert_eq!(failure.code(), CatalogFailureCode::StorageUnavailable);
    drop(catalog);
    drop(authority);

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let predecessor = wrapping_key(0x31, 0x41, 7)?;
    let resumed_secret = rotating_secret(0x32, 0x42, 8)?.with_predecessor(predecessor)?;
    let resumed = Catalog::open(&authority, instance, resumed_secret)?;
    assert_eq!(resumed.pin()?.number(), 2);
    for event in [
        CatalogFileEvent::SynchronizeRewrap,
        CatalogFileEvent::SynchronizeRewrapDirectory,
    ] {
        for _ in 0..3 {
            let repeated = with_catalog_fault(event, || {
                resumed.rewrap(
                    TransactionId::new(id(43))?,
                    wrapping_key(0x32, 0x42, 8)?,
                    AuditIntent::new(b"root rotation operation".to_vec())?,
                )
            })
            .expect_err("every successor envelope must repeat both durability barriers");
            assert_eq!(repeated.code(), CatalogFailureCode::StorageUnavailable);
            assert_eq!(resumed.pin()?.number(), 2, "{event:?}");
            assert_eq!(resumed.governance_audit_records()?.len(), 2, "{event:?}");
        }
    }
    resumed.rewrap(
        TransactionId::new(id(43))?,
        wrapping_key(0x32, 0x42, 8)?,
        AuditIntent::new(b"root rotation operation".to_vec())?,
    )?;
    drop(resumed);
    drop(authority);

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let reopened = Catalog::open(&authority, instance, rotating_secret(0x32, 0x42, 8)?)?;
    assert_eq!(reopened.pin()?.number(), 4);
    assert_eq!(reopened.governance_audit_records()?.len(), 4);
    Ok(())
}

#[test]
fn completion_publication_fault_never_advances_or_retires_before_verified_progress()
-> Result<(), Box<dyn std::error::Error>> {
    for event in [
        CatalogFileEvent::WriteMarker,
        CatalogFileEvent::SynchronizeGenerationDirectory,
    ] {
        let root = TemporaryRoot::new()?;
        let instance = InstanceId::new(id(44))?;
        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let catalog = Catalog::open(&authority, instance, rotating_secret(0x33, 0x43, 7)?)?;
        catalog.commit(
            catalog.pin()?.identity(),
            proposal(45, 10)?,
            Some(AuditIntent::new(b"initial mutation".to_vec())?),
        )?;
        let failure = with_catalog_fault_after(event, 2, || {
            catalog.rewrap(
                TransactionId::new(id(46))?,
                wrapping_key(0x34, 0x44, 8)?,
                AuditIntent::new(b"governed completion fault".to_vec())?,
            )
        })
        .expect_err("the selected completion publication barrier must fail");
        assert_eq!(failure.code(), CatalogFailureCode::StorageUnavailable);
        assert_eq!(catalog.pin()?.number(), 3, "{event:?}");
        assert_eq!(catalog.governance_audit_records()?.len(), 3, "{event:?}");
        if event == CatalogFileEvent::SynchronizeGenerationDirectory {
            let acknowledged = catalog.rewrap(
                TransactionId::new(id(46))?,
                wrapping_key(0x34, 0x44, 8)?,
                AuditIntent::new(b"governed completion fault".to_vec())?,
            )?;
            assert_eq!(acknowledged.completed().number(), 4);
            assert_eq!(catalog.governance_audit_records()?.len(), 4);
        }
        drop(catalog);
        drop(authority);

        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let resumed = Catalog::open(
            &authority,
            instance,
            rotating_secret(0x34, 0x44, 8)?.with_predecessor(wrapping_key(0x33, 0x43, 7)?)?,
        )?;
        let recovered_number = resumed.pin()?.number();
        assert!(matches!(recovered_number, 3 | 4), "{event:?}");
        let completed = resumed.rewrap(
            TransactionId::new(id(46))?,
            wrapping_key(0x34, 0x44, 8)?,
            AuditIntent::new(b"governed completion fault".to_vec())?,
        )?;
        assert_eq!(completed.completed().number(), 4, "{event:?}");
        assert_eq!(resumed.governance_audit_records()?.len(), 4, "{event:?}");
    }
    Ok(())
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
        let authority = establish_catalog_authority(volume)?;
        let catalog = Catalog::open(&authority, instance, secret())?;
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
        drop(authority);

        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let recovered = Catalog::open(&authority, instance, secret())?;
        assert_eq!(recovered.pin()?.number(), 0, "{event:?}");
        assert!(
            recovered.governance_audit_records()?.is_empty(),
            "{event:?}"
        );
    }
    Ok(())
}

#[test]
fn audit_checkpoint_faults_expose_no_partial_anchor_and_remain_retryable()
-> Result<(), Box<dyn std::error::Error>> {
    for event in [
        CatalogFileEvent::PartialAuditCheckpointWrite,
        CatalogFileEvent::SynchronizeAuditCheckpoint,
        CatalogFileEvent::SynchronizeAuditCheckpointDirectory,
    ] {
        let root = TemporaryRoot::new()?;
        let instance = InstanceId::new(id(82))?;
        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let catalog = Catalog::open(&authority, instance, secret())?;
        catalog.commit(
            catalog.pin()?.identity(),
            proposal(83, 84)?,
            Some(AuditIntent::new(b"action=governed-change".to_vec())?),
        )?;
        let signer = AuditCheckpointSigner::from_seed(Box::new([0x85; 32]))?;
        let failure = with_catalog_fault(event, || catalog.publish_audit_checkpoint(&signer))
            .expect_err("injected checkpoint persistence failure must fail closed");
        assert_eq!(
            failure.code(),
            CatalogFailureCode::StorageUnavailable,
            "{event:?}"
        );
        drop(catalog);

        let view = Catalog::read_current_view(&authority, instance, secret())?;
        let recovered = view.latest_audit_checkpoint()?;
        if let Some(checkpoint) = recovered.as_ref() {
            checkpoint.verify(signer.public_key())?;
            assert_eq!(checkpoint.position(), 1, "{event:?}");
        }
        view.verify_audit_chain(signer.public_key(), recovered.as_ref())?;

        let catalog = Catalog::open(&authority, instance, secret())?;
        let checkpoint = catalog.publish_audit_checkpoint(&signer)?;
        assert_eq!(checkpoint.position(), 1, "{event:?}");
    }
    Ok(())
}

#[test]
fn tampered_audit_checkpoint_fences_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(86))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(
        catalog.pin()?.identity(),
        proposal(87, 88)?,
        Some(AuditIntent::new(b"action=governed-change".to_vec())?),
    )?;
    let signer = AuditCheckpointSigner::from_seed(Box::new([0x89; 32]))?;
    catalog.publish_audit_checkpoint(&signer)?;
    drop(catalog);

    let checkpoints = root.0.join("catalog/governance-audit-checkpoints");
    let checkpoint = fs::read_dir(checkpoints)?
        .next()
        .ok_or("checkpoint artifact")??
        .path();
    let mut bytes = fs::read(&checkpoint)?;
    let byte = bytes
        .first_mut()
        .ok_or("checkpoint artifact must be nonempty")?;
    *byte ^= 1;
    fs::write(checkpoint, bytes)?;

    let failure = match Catalog::read_current_view(&authority, instance, secret()) {
        Ok(_) => return Err("tampered checkpoint must fence recovery".into()),
        Err(failure) => failure,
    };
    assert!(matches!(
        failure.code(),
        CatalogFailureCode::AuthenticationFailed | CatalogFailureCode::IntegrityCorruption
    ));
    Ok(())
}

#[test]
fn post_rename_directory_sync_fault_recovers_only_the_complete_successor()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(71))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
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
    drop(authority);

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let recovered = Catalog::open(&authority, instance, secret())?;
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
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
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
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
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

#[test]
fn every_existing_artifact_is_resynchronized_before_retry_acknowledgement()
-> Result<(), Box<dyn std::error::Error>> {
    for (offset, event) in [
        CatalogFileEvent::SynchronizeObjectDirectory,
        CatalogFileEvent::SynchronizeAuditDirectory,
        CatalogFileEvent::SynchronizeCommitDirectory,
        CatalogFileEvent::SynchronizeGenerationDirectory,
    ]
    .into_iter()
    .enumerate()
    {
        let root = TemporaryRoot::new()?;
        let instance = InstanceId::new(id(111))?;
        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let catalog = Catalog::open(&authority, instance, secret())?;
        let expected = catalog.pin()?.identity();
        let transaction = 112_u8.saturating_add(offset as u8);
        let attempt = || {
            catalog.commit(
                expected,
                proposal(transaction, transaction)?,
                Some(AuditIntent::new(b"resynchronize".to_vec())?),
            )
        };
        assert_eq!(
            with_catalog_fault(event, attempt)
                .expect_err("first directory synchronization must fail")
                .code(),
            CatalogFailureCode::StorageUnavailable
        );
        assert_eq!(
            with_catalog_fault(event, attempt)
                .expect_err("retry must repeat the same durability barrier")
                .code(),
            CatalogFailureCode::StorageUnavailable,
            "{event:?}"
        );
        assert_eq!(attempt()?.number(), 1, "{event:?}");
    }
    Ok(())
}
