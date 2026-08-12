use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use positron_kernel::{
    AdmissionFailureCode, AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal,
    CatalogSecret, FormatEpoch, InstanceId, MountQualification, PrimaryDataVolume,
    RecoveryWorkClaim, RecoveryWorkKind, ResourceDimension, TransactionId,
};

use super::support::{catalog_recovery_claim, establish_catalog_authority};

static NEXT_TEMPORARY_ROOT: AtomicU64 = AtomicU64::new(0);

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_TEMPORARY_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-catalog-generation-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

#[test]
fn stale_and_concurrent_proposals_publish_at_most_one_successor() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Arc::new(Catalog::open(
        &authority,
        InstanceId::new(id(21))?,
        CatalogSecret::from_owned(Box::new([0xb1; 32])),
    )?);
    let predecessor = catalog.pin()?.identity();
    let outcomes = thread::scope(|scope| {
        let mut handles = Vec::new();
        for value in [22_u8, 23] {
            let writer = Arc::clone(&catalog);
            handles.push(scope.spawn(move || {
                writer.commit(
                    predecessor,
                    CatalogProposal::new(
                        TransactionId::new(id(value))?,
                        FormatEpoch::new(1)?,
                        vec![CatalogObject::new(vec![value])?],
                    )?,
                    None,
                )
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| "catalog writer thread panicked"))
            .collect::<Result<Vec<_>, _>>()
    })?;

    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    let failure = outcomes
        .iter()
        .find_map(|outcome| outcome.as_ref().err())
        .ok_or("one proposal must fail")?;
    assert_eq!(failure.code(), CatalogFailureCode::StaleGeneration);
    assert_eq!(
        failure.current_generation(),
        Some(catalog.pin()?.identity())
    );
    assert_eq!(catalog.pin()?.number(), 1);
    Ok(())
}

#[test]
fn retry_with_same_transaction_is_idempotent_and_changed_content_conflicts()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(id(31))?,
        CatalogSecret::from_owned(Box::new([0xc1; 32])),
    )?;
    let transaction = TransactionId::new(id(32))?;
    let expected = catalog.pin()?.identity();
    let proposal = || {
        CatalogProposal::new(
            transaction,
            FormatEpoch::new(1)?,
            vec![CatalogObject::new(b"same proposal".to_vec())?],
        )
    };
    let first = catalog.commit(expected, proposal()?, None)?;
    let retry = catalog.commit(expected, proposal()?, None)?;
    assert_eq!(retry.identity(), first.identity());
    assert_eq!(catalog.pin()?.number(), 1);

    let conflict = catalog
        .commit(
            expected,
            CatalogProposal::new(
                transaction,
                FormatEpoch::new(1)?,
                vec![CatalogObject::new(b"different proposal".to_vec())?],
            )?,
            None,
        )
        .expect_err("changed transaction content must conflict");
    assert_eq!(conflict.code(), CatalogFailureCode::IdempotencyConflict);
    assert_eq!(catalog.pin()?.identity(), first.identity());
    Ok(())
}

#[test]
fn governance_sensitive_generation_and_audit_record_publish_jointly() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(id(11))?,
        CatalogSecret::from_owned(Box::new([0xa1; 32])),
    )?;
    let object = CatalogObject::new(b"tenant lifecycle: read-only".to_vec())?;
    let object_id = object.identity();

    let published = catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(id(12))?,
            FormatEpoch::new(1)?,
            vec![object],
        )?,
        Some(AuditIntent::new(
            b"principal=system; action=tenant.read-only; outcome=succeeded".to_vec(),
        )?),
    )?;

    assert_eq!(
        published
            .governance_audit_record()
            .map(|record| record.position()),
        Some(1)
    );
    assert_eq!(catalog.pin()?.governance_audit_frontier(), 1);
    assert_eq!(
        catalog.pin()?.object(object_id)?,
        Some(b"tenant lifecycle: read-only".as_slice())
    );
    let audit = catalog.governance_audit_records()?;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].predecessor_hash(), [0; 32]);
    assert_eq!(
        audit[0].intent(),
        b"principal=system; action=tenant.read-only; outcome=succeeded"
    );
    Ok(())
}

#[test]
fn catalog_recovery_admission_is_typed_and_released_for_retry() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let blocker = authority.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::Repair,
        catalog_recovery_claim(),
    )?)?;

    let failure = Catalog::open(
        &authority,
        InstanceId::new(id(61))?,
        CatalogSecret::from_owned(Box::new([0xc2; 32])),
    )
    .expect_err("recovery without its bounded reservation must fail closed");
    assert_eq!(failure.code(), CatalogFailureCode::ResourceAdmissionRefused);
    assert_eq!(
        failure.admission_failure().map(|failure| failure.code()),
        Some(AdmissionFailureCode::ProtectedCapacityUnavailable)
    );

    drop(blocker);
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(id(61))?,
        CatalogSecret::from_owned(Box::new([0xc2; 32])),
    )?;
    assert_eq!(catalog.pin()?.number(), 0);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .recovery_pool_usage(RecoveryWorkKind::Repair, ResourceDimension::MemoryBytes),
        0
    );
    Ok(())
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove test root: {error}");
        }
    }
}

fn id(last: u8) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[15] = last;
    bytes
}

#[test]
fn public_catalog_values_enforce_bounds_and_keep_secrets_out_of_diagnostics()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        InstanceId::new([0; 16])
            .expect_err("zero instance identifier must fail")
            .code(),
        CatalogFailureCode::InvalidInput
    );
    assert_eq!(
        TransactionId::new([0; 16])
            .expect_err("zero transaction identifier must fail")
            .code(),
        CatalogFailureCode::InvalidInput
    );
    let instance = InstanceId::new(id(1))?;
    let transaction = TransactionId::new(id(2))?;
    assert_eq!(instance.to_bytes(), id(1));
    assert_eq!(transaction.to_bytes(), id(2));
    assert_eq!(
        FormatEpoch::new(0)
            .expect_err("zero format epoch must fail")
            .code(),
        CatalogFailureCode::InvalidInput
    );
    assert_eq!(FormatEpoch::new(7)?.value(), 7);

    for plaintext in [Vec::new(), vec![0; 1_048_577]] {
        assert_eq!(
            CatalogObject::new(plaintext)
                .expect_err("invalid object size must fail")
                .code(),
            CatalogFailureCode::LimitExceeded
        );
    }
    for intent in [Vec::new(), vec![0; 65_537]] {
        assert_eq!(
            AuditIntent::new(intent)
                .expect_err("invalid audit size must fail")
                .code(),
            CatalogFailureCode::LimitExceeded
        );
    }

    let epoch = FormatEpoch::new(1)?;
    assert_eq!(
        CatalogProposal::new(transaction, epoch, Vec::new())
            .expect_err("empty proposal must fail")
            .code(),
        CatalogFailureCode::LimitExceeded
    );
    assert_eq!(
        CatalogProposal::new(
            transaction,
            epoch,
            vec![
                CatalogObject::new(b"duplicate".to_vec())?,
                CatalogObject::new(b"duplicate".to_vec())?,
            ],
        )
        .expect_err("duplicate identities must fail")
        .code(),
        CatalogFailureCode::InvalidInput
    );

    let too_many = (0_u16..1_025)
        .map(|value| CatalogObject::new(value.to_be_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        CatalogProposal::new(transaction, epoch, too_many)
            .expect_err("proposal object-count limit must fail")
            .code(),
        CatalogFailureCode::LimitExceeded
    );
    let too_large = (0_u8..17)
        .map(|value| CatalogObject::new(vec![value; 1_048_576]))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        CatalogProposal::new(transaction, epoch, too_large)
            .expect_err("proposal byte limit must fail")
            .code(),
        CatalogFailureCode::LimitExceeded
    );

    let object = CatalogObject::new(b"safe diagnostics".to_vec())?;
    assert_eq!(object.identity().to_bytes().len(), 32);
    let object_diagnostic = format!("{object:?}");
    assert!(object_diagnostic.contains("plaintext_bytes: 16"));
    assert!(!object_diagnostic.contains("safe diagnostics"));
    let proposal = CatalogProposal::new(transaction, epoch, vec![object])?;
    assert!(format!("{proposal:?}").contains("object_count: 1"));
    let audit = AuditIntent::new(b"redacted action".to_vec())?;
    assert_eq!(format!("{audit:?}"), "AuditIntent { encoded_bytes: 15 }");
    let secret = CatalogSecret::from_owned(Box::new([0x7d; 32]));
    let diagnostic = format!("{secret:?}");
    assert_eq!(diagnostic, "CatalogSecret { <redacted> }");
    assert!(!diagnostic.contains("125"));

    let failure = CatalogObject::new(Vec::new()).expect_err("empty object must fail");
    assert_eq!(failure.to_string(), "catalog operation failed");
    assert!(failure.source().is_none());
    assert_eq!(failure.current_generation(), None);
    Ok(())
}

#[test]
fn catalog_writer_publishes_an_externally_readable_immutable_generation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(id(1))?,
        CatalogSecret::from_owned(Box::new([0x91; 32])),
    )?;
    let predecessor = catalog.pin()?;
    assert_eq!(predecessor.number(), 0);
    let object = CatalogObject::new(b"tenant configuration v1".to_vec())?;
    let object_id = object.identity();

    let published = catalog.commit(
        predecessor.identity(),
        CatalogProposal::new(
            TransactionId::new(id(2))?,
            FormatEpoch::new(1)?,
            vec![object],
        )?,
        None,
    )?;

    assert_eq!(published.number(), 1);
    assert_eq!(published.snapshot().number(), 1);
    assert_eq!(
        published.snapshot().format_epoch(),
        Some(FormatEpoch::new(1)?)
    );
    assert!(published.governance_audit_record().is_none());
    assert_eq!(published.identity().to_bytes().len(), 32);
    let pinned = catalog.pin()?;
    assert_eq!(pinned.identity(), published.identity());
    assert_eq!(
        pinned.object(object_id)?,
        Some(b"tenant configuration v1".as_slice())
    );
    assert_eq!(predecessor.object(object_id)?, None);
    assert!(format!("{pinned:?}").contains("object_count: 1"));
    assert_eq!(
        format!("{catalog:?}"),
        "Catalog { <storage-and-key-redacted> }"
    );
    Ok(())
}
