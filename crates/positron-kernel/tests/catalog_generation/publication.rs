use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::thread;

use positron_kernel::{
    AdmissionFailureCode, AuditCheckpointSigner, AuditIntent, Catalog, CatalogFailureCode,
    CatalogObject, CatalogProposal, CatalogSecret, CatalogWrappingKey, FormatEpoch,
    GovernanceFixtureObject, GovernanceFixtureTarget, InstanceId, MountQualification,
    PrimaryDataVolume, RecoveryWorkClaim, RecoveryWorkKind, ResourceDimension,
    SystemAuditRetentionPolicy, TransactionId,
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
        CatalogSecret::from_owned(Box::new([0xa1; 32]), Box::new([0xb1; 32])),
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
    match failure.code() {
        CatalogFailureCode::StaleGeneration => assert_eq!(
            failure.current_generation(),
            Some(catalog.pin()?.identity())
        ),
        CatalogFailureCode::ResourceAdmissionRefused => assert!(matches!(
            failure.admission_failure().map(|failure| failure.code()),
            Some(
                AdmissionFailureCode::GovernorContended
                    | AdmissionFailureCode::ProtectedCapacityUnavailable
            )
        )),
        other => return Err(format!("unexpected concurrent outcome: {other:?}").into()),
    }
    assert_eq!(catalog.pin()?.number(), 1);
    let resources = authority.governor().inspect()?;
    for dimension in ResourceDimension::ALL {
        assert_eq!(
            resources.recovery_pool_usage(RecoveryWorkKind::DurabilityCompletion, dimension),
            0,
            "{dimension:?} reservation leaked"
        );
    }
    Ok(())
}

#[test]
fn authority_owns_exactly_one_catalog_writer_during_concurrent_open_and_commit()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let instance = InstanceId::new(id(24))?;
    let (opened_sender, opened_receiver) = mpsc::channel();
    let release = Arc::new(Barrier::new(3));

    let outcomes = thread::scope(|scope| {
        let mut handles = Vec::new();
        for value in [25_u8, 26] {
            let opened_sender = opened_sender.clone();
            let release = Arc::clone(&release);
            let authority = &authority;
            handles.push(scope.spawn(move || {
                let opened = Catalog::open(
                    authority,
                    instance,
                    CatalogSecret::from_owned(Box::new([0xc1; 32]), Box::new([0xd1; 32])),
                );
                opened_sender
                    .send(opened.is_ok())
                    .expect("main test thread retains the open-report receiver");
                release.wait();
                match opened {
                    Ok(catalog) => catalog.commit(
                        catalog.pin()?.identity(),
                        CatalogProposal::new(
                            TransactionId::new(id(value))?,
                            FormatEpoch::new(1)?,
                            vec![CatalogObject::new(vec![value])?],
                        )?,
                        Some(AuditIntent::new(vec![value])?),
                    ),
                    Err(failure) => Err(failure),
                }
            }));
        }
        drop(opened_sender);
        let opened = opened_receiver.iter().take(2).collect::<Vec<_>>();
        release.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| "catalog thread panicked"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, Box<dyn Error>>((opened, outcomes))
    })?;

    assert_eq!(outcomes.0.iter().filter(|opened| **opened).count(), 1);
    assert_eq!(
        outcomes.1.iter().filter(|outcome| outcome.is_ok()).count(),
        1
    );
    let failure = outcomes
        .1
        .iter()
        .find_map(|outcome| outcome.as_ref().err())
        .ok_or("one open must fail")?;
    assert_eq!(failure.code(), CatalogFailureCode::ConcurrentWriter);
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
        CatalogSecret::from_owned(Box::new([0xb1; 32]), Box::new([0xc1; 32])),
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
        CatalogSecret::from_owned(Box::new([0x91; 32]), Box::new([0xa1; 32])),
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
fn signed_audit_checkpoint_binds_the_visible_chain_frontier() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let instance = InstanceId::new(id(13))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x93; 32]), Box::new([0xa3; 32])),
    )?;
    let signer = AuditCheckpointSigner::from_seed(Box::new([0xb3; 32]))?;
    let public_key = signer.public_key();

    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(id(14))?,
            FormatEpoch::new(1)?,
            vec![CatalogObject::new(b"governed change".to_vec())?],
        )?,
        Some(AuditIntent::new(b"action=tenant.suspend".to_vec())?),
    )?;

    let checkpoint = catalog.publish_audit_checkpoint(&signer)?;
    assert_eq!(checkpoint.instance(), instance);
    assert_eq!(checkpoint.position(), 1);
    assert_eq!(
        checkpoint.record_hash(),
        catalog.governance_audit_records()?[0].record_hash()
    );
    checkpoint.verify(public_key)?;

    drop(catalog);
    let view = Catalog::read_current_view(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x93; 32]), Box::new([0xa3; 32])),
    )?;
    assert_eq!(view.latest_audit_checkpoint()?.as_ref(), Some(&checkpoint));
    view.verify_audit_chain(public_key, Some(&checkpoint))?;
    Ok(())
}

#[test]
fn signed_retention_anchor_authorizes_only_its_contiguous_audit_suffix()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let instance = InstanceId::new([0x79; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    )?;
    let signer = AuditCheckpointSigner::from_seed(Box::new([0x39; 32]))?;
    catalog.install_governance_fixture(&governance_fixture(
        instance,
        signer.public_key(),
        [0x95; 32],
        7,
    )?)?;
    let basis = catalog.pin()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x50; 16])?,
            FormatEpoch::CATALOG_V1,
            catalog_objects_with(
                &basis,
                SystemAuditRetentionPolicy::new(instance, 7)?.into_catalog_object()?,
            )?,
        )?,
        None,
    )?;

    for (transaction, action) in [
        (51, b"action=one".as_slice()),
        (52, b"action=two"),
        (53, b"action=three"),
    ] {
        let basis = catalog.pin()?;
        catalog.commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new([transaction; 16])?,
                FormatEpoch::CATALOG_V1,
                catalog_objects_with(&basis, CatalogObject::new(vec![transaction])?)?,
            )?,
            Some(AuditIntent::new(action.to_vec())?),
        )?;
    }
    let records = catalog.governance_audit_records()?;
    let unanchored_view = Catalog::read_current_view(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    )?;
    assert!(
        unanchored_view
            .verify_retained_audit_suffix(&records[2..])
            .is_err()
    );
    let other_signer = AuditCheckpointSigner::from_seed(Box::new([0x49; 32]))?;
    let failure = catalog
        .publish_audit_retention_anchor(TransactionId::new([0x55; 16])?, &other_signer, &records[1])
        .expect_err("a signer outside the authenticated integrity-key history must be rejected");
    assert_eq!(failure.code(), CatalogFailureCode::AuthenticationFailed);
    let anchor = catalog.publish_audit_retention_anchor(
        TransactionId::new([0x56; 16])?,
        &signer,
        &records[1],
    )?;

    let view = Catalog::read_current_view(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    )?;
    assert_eq!(view.audit_retention_anchor(), Some(&anchor));
    view.verify_retained_audit_suffix(&records[2..])?;
    assert!(view.verify_retained_audit_suffix(&records[1..]).is_err());
    assert!(view.verify_retained_audit_suffix(&[]).is_err());

    let legacy_view = Catalog::read_current_view(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    )?;
    legacy_view.verify_audit_chain(signer.public_key(), None)?;

    catalog.replace_governance_fixture(&governance_fixture(
        instance,
        signer.public_key(),
        [0x95; 32],
        8,
    )?)?;
    let view = Catalog::read_current_view(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    )?;
    view.verify_retained_audit_suffix(&records[2..])?;

    let successor = catalog.publish_system_audit_retention_policy(
        TransactionId::new([0x57; 16])?,
        &signer,
        SystemAuditRetentionPolicy::new(instance, 8)?,
        &records[1],
        AuditIntent::new(b"action=update-system-audit-retention".to_vec())?,
    )?;
    assert_eq!(successor.system_policy_generation(), 8);
    let records = catalog.governance_audit_records()?;
    let view = Catalog::read_current_view(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    )?;
    assert_eq!(view.audit_retention_anchor(), Some(&successor));
    view.verify_retained_audit_suffix(&records[2..])?;
    let wrong_instance = catalog
        .publish_system_audit_retention_policy(
            TransactionId::new([0x59; 16])?,
            &signer,
            SystemAuditRetentionPolicy::new(InstanceId::new([0x78; 16])?, 9)?,
            &records[2],
            AuditIntent::new(b"action=invalid-instance".to_vec())?,
        )
        .expect_err("an anchor policy for another instance must be rejected");
    assert_eq!(
        wrong_instance.code(),
        CatalogFailureCode::IntegrityCorruption
    );

    drop(view);
    drop(unanchored_view);
    drop(legacy_view);
    drop(catalog);
    drop(authority);
    let mut expired_frames = Vec::new();
    for position in [1_u64, 2] {
        let prefix = format!("{position:020}-");
        let frame = fs::read_dir(root.path().join("catalog/governance-audit"))?
            .find_map(|entry| {
                let entry = entry.ok()?;
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&prefix)
                    .then_some(entry.path())
            })
            .ok_or("published audit frame")?;
        expired_frames.push(frame);
    }
    let first = expired_frames.first().ok_or("first expired audit frame")?;
    fs::remove_file(first)?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let failure = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    )
    .expect_err("a partially missing anchored prefix must fence recovery");
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    drop(authority);
    for frame in expired_frames.iter().skip(1) {
        fs::remove_file(frame)?;
    }
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    )?;
    let retained = catalog.governance_audit_records()?;
    assert_eq!(retained, records[2..]);
    let view = Catalog::read_current_view(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    )?;
    view.verify_retained_audit_suffix(&retained)?;

    // A policy object written outside the atomic policy-and-anchor transition
    // becomes incompatible with the previous signature and fences recovery.
    replace_system_audit_retention_policy(&catalog, instance, 9, 0x58)?;
    let failure = match Catalog::read_current_view(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0xd3; 32])),
    ) {
        Ok(_) => {
            return Err("recovery accepted an unpaired system audit policy update".into());
        },
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), CatalogFailureCode::AuthenticationFailed);
    Ok(())
}

fn replace_system_audit_retention_policy(
    catalog: &Catalog<'_>,
    instance: InstanceId,
    generation: u64,
    transaction: u8,
) -> Result<(), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut objects = Vec::new();
    for identity in basis.object_identities() {
        let object = basis.object(identity)?.ok_or("catalog object")?;
        if !object.starts_with(b"POSAUP01") {
            objects.push(CatalogObject::new(object.to_vec())?);
        }
    }
    objects.push(SystemAuditRetentionPolicy::new(instance, generation)?.into_catalog_object()?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

fn catalog_objects_with(
    snapshot: &positron_kernel::CatalogSnapshot,
    appended: CatalogObject,
) -> Result<Vec<CatalogObject>, Box<dyn Error>> {
    let mut objects = Vec::new();
    for identity in snapshot.object_identities() {
        let object = snapshot.object(identity)?.ok_or("catalog object")?;
        objects.push(CatalogObject::new(object.to_vec())?);
    }
    objects.push(appended);
    Ok(objects)
}

fn governance_fixture(
    instance: InstanceId,
    integrity_public_key: [u8; 32],
    integrity_key_fingerprint: [u8; 32],
    retention_generation: u64,
) -> Result<GovernanceFixtureObject, Box<dyn Error>> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"POSGOV08");
    encoded.extend_from_slice(&instance.to_bytes());
    encoded.extend_from_slice(&[2; 16]);
    encoded.push(7);
    encoded.extend_from_slice(b"default");
    encoded.push(1);
    encoded.push(14);
    encoded.extend_from_slice(b"trace-external");
    encoded.push(7);
    encoded.extend_from_slice(b"Default");
    encoded.extend_from_slice(&[3; 16]);
    encoded.extend_from_slice(&[4; 32]);
    encoded.extend_from_slice(&[5; 32]);
    for (principal, salt, hash) in [([6; 16], [7; 32], [8; 32]), ([9; 16], [10; 32], [11; 32])] {
        encoded.extend_from_slice(&principal);
        encoded.extend_from_slice(&salt);
        encoded.extend_from_slice(&hash);
    }
    encoded.extend_from_slice(&integrity_public_key);
    encoded.extend_from_slice(&integrity_key_fingerprint);
    encoded.extend_from_slice(&2_u16.to_be_bytes());
    encoded.extend_from_slice(&[14; 2]);
    encoded.extend_from_slice(&2_u16.to_be_bytes());
    encoded.extend_from_slice(&[15; 2]);
    encoded.extend_from_slice(&86_400_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    for _ in 0..11 {
        encoded.extend_from_slice(&10_u64.to_be_bytes());
    }
    encoded.extend_from_slice(&[1, 4, 0, 1, 1]);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&retention_generation.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&3_u16.to_be_bytes());
    for (principal, scope, salt, hash) in [
        ([3; 16], 4_u8, [4; 32], [5; 32]),
        ([6; 16], 1, [7; 32], [8; 32]),
        ([9; 16], 2, [10; 32], [11; 32]),
    ] {
        encoded.extend_from_slice(&principal);
        encoded.push(scope);
        encoded.push(1);
        encoded.extend_from_slice(&0_u64.to_be_bytes());
        encoded.extend_from_slice(&salt);
        encoded.extend_from_slice(&hash);
    }
    Ok(GovernanceFixtureObject::from_bytes(&encoded)?)
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
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xc2; 32])),
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
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xc2; 32])),
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

#[test]
fn catalog_commit_admission_refuses_before_work_and_releases_every_dimension_for_retry()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(id(65))?,
        CatalogSecret::from_owned(Box::new([0xb5; 32]), Box::new([0xc5; 32])),
    )?;
    let blocker = authority.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        catalog_recovery_claim(),
    )?)?;
    let expected = catalog.pin()?.identity();
    let proposal = || {
        CatalogProposal::new(
            TransactionId::new(id(66))?,
            FormatEpoch::new(1)?,
            vec![CatalogObject::new(b"governed commit".to_vec())?],
        )
    };

    let failure = catalog
        .commit(expected, proposal()?, None)
        .expect_err("commit without its complete reservation must fail before mutation");
    assert_eq!(failure.code(), CatalogFailureCode::ResourceAdmissionRefused);
    assert_eq!(catalog.pin()?.number(), 0);

    drop(blocker);
    assert_eq!(catalog.commit(expected, proposal()?, None)?.number(), 1);
    let resources = authority.governor().inspect()?;
    for dimension in ResourceDimension::ALL {
        assert_eq!(
            resources.recovery_pool_usage(RecoveryWorkKind::DurabilityCompletion, dimension),
            0,
            "{dimension:?} reservation leaked"
        );
    }
    Ok(())
}

#[test]
fn catalog_rejects_unsupported_epochs_before_admission_and_writes_v1_and_v2()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        FormatEpoch::new(0)
            .expect_err("zero is not a Format Epoch")
            .code(),
        CatalogFailureCode::InvalidInput
    );
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(id(67))?,
        CatalogSecret::from_owned(Box::new([0xb6; 32]), Box::new([0xc6; 32])),
    )?;
    let blocker = authority.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        catalog_recovery_claim(),
    )?)?;
    let expected = catalog.pin()?.identity();
    for (transaction, epoch) in [(68_u8, 3_u32), (69, u32::MAX)] {
        let failure = catalog
            .commit(
                expected,
                CatalogProposal::new(
                    TransactionId::new(id(transaction))?,
                    FormatEpoch::new(epoch)?,
                    vec![CatalogObject::new(vec![transaction])?],
                )?,
                None,
            )
            .expect_err("an unsupported writable epoch must precede admission and mutation");
        assert_eq!(failure.code(), CatalogFailureCode::UnsupportedFormat);
        assert_eq!(catalog.pin()?.number(), 0);
    }
    drop(blocker);
    assert_eq!(
        catalog
            .commit(
                expected,
                CatalogProposal::new(
                    TransactionId::new(id(70))?,
                    FormatEpoch::CATALOG_V1,
                    vec![CatalogObject::new(b"epoch one".to_vec())?],
                )?,
                None,
            )?
            .number(),
        1
    );
    let epoch_one = catalog.pin()?;
    assert_eq!(epoch_one.format_epoch(), Some(FormatEpoch::CATALOG_V1));
    assert_eq!(
        catalog
            .commit(
                epoch_one.identity(),
                CatalogProposal::new(
                    TransactionId::new(id(71))?,
                    FormatEpoch::CATALOG_V2,
                    vec![CatalogObject::new(b"epoch two".to_vec())?],
                )?,
                None,
            )?
            .number(),
        2
    );
    assert_eq!(catalog.pin()?.format_epoch(), Some(FormatEpoch::CATALOG_V2));
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
    let secret = CatalogSecret::from_owned(Box::new([0x6d; 32]), Box::new([0x7d; 32]));
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
        CatalogSecret::from_owned(Box::new([0x81; 32]), Box::new([0x91; 32])),
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

#[test]
fn governed_root_rewrap_publishes_audited_start_verification_and_completion()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(81))?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned_at_epoch(
            Box::new([0xa7; 32]),
            Box::new([0xb7; 32]),
            [0xc7; 16],
            7,
        )?,
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(id(82))?,
            FormatEpoch::new(1)?,
            vec![CatalogObject::new(b"stable content identity".to_vec())?],
        )?,
        Some(AuditIntent::new(b"rotate wrapping root".to_vec())?),
    )?;
    for (transaction, provider, epoch) in [(84_u8, 0xc7_u8, 7_u64), (85, 0xc6, 6)] {
        let failure = catalog
            .rewrap(
                TransactionId::new(id(transaction))?,
                CatalogWrappingKey::from_owned_at_epoch(
                    Box::new([0xb6; 32]),
                    [provider; 16],
                    epoch,
                )?,
                AuditIntent::new(b"invalid root rotation".to_vec())?,
            )
            .expect_err("a non-successor route must fail before an audited start");
        assert_eq!(failure.code(), CatalogFailureCode::InvalidInput);
        assert_eq!(catalog.pin()?.number(), 1);
        assert_eq!(catalog.governance_audit_records()?.len(), 1);
    }
    let rotation = catalog.rewrap(
        TransactionId::new(id(83))?,
        CatalogWrappingKey::from_owned_at_epoch(Box::new([0xb8; 32]), [0xc8; 16], 8)?,
        AuditIntent::new(b"operator approved root rotation".to_vec())?,
    )?;
    assert_eq!(rotation.started().number(), 2);
    assert_eq!(rotation.verified().number(), 3);
    assert_eq!(rotation.completed().number(), 4);
    let records = catalog.governance_audit_records()?;
    assert_eq!(records.len(), 4);
    assert!(
        records[1]
            .intent()
            .starts_with(b"catalog-root-rotation-v1\0started\0")
    );
    assert!(
        records[2]
            .intent()
            .starts_with(b"catalog-root-rotation-v1\0verified\0")
    );
    assert!(
        records[3]
            .intent()
            .starts_with(b"catalog-root-rotation-v1\0completed\0")
    );
    assert_eq!(
        catalog
            .rewrap(
                TransactionId::new(id(83))?,
                CatalogWrappingKey::from_owned_at_epoch(Box::new([0xb8; 32]), [0xc8; 16], 8)?,
                AuditIntent::new(b"operator approved root rotation".to_vec())?,
            )?
            .completed()
            .identity(),
        rotation.completed().identity()
    );
    let conflict = catalog
        .rewrap(
            TransactionId::new(id(83))?,
            CatalogWrappingKey::from_owned_at_epoch(Box::new([0xb8; 32]), [0xc8; 16], 8)?,
            AuditIntent::new(b"different rotation intent".to_vec())?,
        )
        .expect_err("one rotation transaction cannot be rebound to another intent");
    assert_eq!(conflict.code(), CatalogFailureCode::IdempotencyConflict);
    assert_eq!(catalog.governance_audit_records()?.len(), 4);
    assert_eq!(catalog.pin()?.identity(), rotation.completed().identity());
    drop(catalog);
    drop(authority);

    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned_at_epoch(
            Box::new([0xa7; 32]),
            Box::new([0xb8; 32]),
            [0xc8; 16],
            8,
        )?,
    )?;
    assert_eq!(reopened.pin()?.identity(), rotation.completed().identity());
    assert_eq!(reopened.governance_audit_records()?.len(), 4);
    assert_eq!(
        reopened
            .rewrap(
                TransactionId::new(id(83))?,
                CatalogWrappingKey::from_owned_at_epoch(Box::new([0xb8; 32]), [0xc8; 16], 8)?,
                AuditIntent::new(b"operator approved root rotation".to_vec())?,
            )?
            .completed()
            .identity(),
        rotation.completed().identity()
    );
    Ok(())
}
