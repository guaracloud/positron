use super::super::storage::{BootstrapFileEvent, with_fault};
use super::super::{BootstrapFailureCode, BootstrapState, InitializationPlan};
use super::support::Roots;
use crate::InstanceBootstrap;
use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};

#[test]
fn every_bootstrap_publication_fault_resumes_without_ambiguous_state()
-> Result<(), Box<dyn std::error::Error>> {
    for event in [
        BootstrapFileEvent::WriteInitialized,
        BootstrapFileEvent::RemovePending,
        BootstrapFileEvent::PublishInitialized,
    ] {
        let roots = Roots::new()?;
        let paths = roots.paths();
        let failure = with_fault(event, || {
            InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
        })
        .expect_err("named persistence fault must interrupt initialization");
        assert!(matches!(
            failure.code(),
            BootstrapFailureCode::StorageUnavailable
                | BootstrapFailureCode::CatalogUnavailable
                | BootstrapFailureCode::LedgerUnavailable
        ));
        assert_eq!(
            InstanceBootstrap::classify(&paths)?,
            BootstrapState::Incomplete
        );
        let completed =
            InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        assert!(completed.catalog_generation() >= 3);
        drop(completed);
        assert_eq!(
            InstanceBootstrap::classify(&paths)?,
            BootstrapState::Initialized
        );
    }
    Ok(())
}

#[test]
fn synchronized_pending_replacement_resumes_after_pre_rename_crash()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();

    let failure = with_fault(BootstrapFileEvent::ReplacePendingAfterSync, || {
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
    })
    .expect_err("fault after replacement sync must interrupt initialization");

    assert_eq!(failure.code(), BootstrapFailureCode::StorageUnavailable);
    assert!(
        paths
            .data_root()
            .join(".positron-bootstrap.pending.replacement")
            .is_file()
    );
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Incomplete
    );
    let completed = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(completed);
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Initialized
    );
    assert!(
        !paths
            .data_root()
            .join(".positron-bootstrap.pending.replacement")
            .exists()
    );
    Ok(())
}

#[test]
fn corrupt_pending_replacement_is_inconsistent_and_never_published()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    with_fault(BootstrapFileEvent::ReplacePendingAfterSync, || {
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
    })
    .expect_err("fault must leave synchronized replacement");
    let replacement = paths
        .data_root()
        .join(".positron-bootstrap.pending.replacement");
    let mut bytes = std::fs::read(&replacement)?;
    let last = bytes.last_mut().ok_or("replacement must not be empty")?;
    *last ^= 0x80;
    std::fs::write(&replacement, bytes)?;

    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Inconsistent
    );
    assert_eq!(
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
            .expect_err("unauthenticated replacement must not publish")
            .code(),
        BootstrapFailureCode::InconsistentRoots
    );
    assert!(replacement.is_file());
    Ok(())
}

#[test]
fn claim_removal_failure_returns_no_secret_and_remains_claimable()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let failure = with_fault(BootstrapFileEvent::RemoveClaim, || {
        InstanceBootstrap::claim(&paths)
    })
    .expect_err("claim must not release before durable destruction");
    assert_eq!(failure.code(), BootstrapFailureCode::ClaimDestructionFailed);
    assert!(InstanceBootstrap::reopen(&paths)?.claim_available());
    assert!(!InstanceBootstrap::claim(&paths)?.secret().is_empty());
    Ok(())
}

#[test]
fn resumed_bootstrap_rejects_a_substituted_existing_claim() -> Result<(), Box<dyn std::error::Error>>
{
    let roots = Roots::new()?;
    let paths = roots.paths();
    with_fault(BootstrapFileEvent::WriteInitialized, || {
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
    })
    .expect_err("fault must leave a resumable claim");
    let key = paths
        .storage
        .inspect()
        .map_err(|failure| format!("{failure:?}"))?
        .open_key()?;
    let pending = std::fs::read(paths.data_root().join(".positron-bootstrap.pending"))?;
    let instance = BootstrapKeyCustody::routed_instance(BootstrapObjectPurpose::Pending, &pending)?;
    let plaintext = key.open_object(instance, BootstrapObjectPurpose::Pending, &pending)?;
    let record = super::super::codec::BootstrapRecord::decode(&plaintext)?;
    let ingest = record.ingest.as_ref().expect("current ingest identity");
    let substituted = super::super::codec::encode_claim(
        instance,
        record.administrator,
        &[0x44; 32],
        ingest.principal,
        &[0x45; 32],
    );
    let encrypted = key.protect(instance, BootstrapObjectPurpose::Claim, &substituted)?;
    std::fs::write(paths.secrets_root().join("bootstrap-claim.v1"), encrypted)?;

    assert_eq!(
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
            .expect_err("substituted claim must fail closed")
            .code(),
        BootstrapFailureCode::IdentityMismatch
    );
    Ok(())
}

#[test]
fn authenticated_record_rejects_substituted_routed_instance()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    with_fault(BootstrapFileEvent::WriteInitialized, || {
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
    })
    .expect_err("fault must leave pending state");
    let key = paths
        .storage
        .inspect()
        .map_err(|failure| format!("{failure:?}"))?
        .open_key()?;
    let pending_path = paths.data_root().join(".positron-bootstrap.pending");
    let pending = std::fs::read(&pending_path)?;
    let routed = BootstrapKeyCustody::routed_instance(BootstrapObjectPurpose::Pending, &pending)?;
    let plaintext = key.open_object(routed, BootstrapObjectPurpose::Pending, &pending)?;
    let mut record = super::super::codec::BootstrapRecord::decode(&plaintext)?;
    record.instance = InstanceId::new([0x55; 16])?;
    let substituted = key.protect(routed, BootstrapObjectPurpose::Pending, &record.encode())?;
    let mismatch =
        super::super::operation::decode_record(&key, BootstrapObjectPurpose::Pending, &substituted);
    assert!(matches!(
        mismatch,
        Err(failure) if failure.code() == BootstrapFailureCode::IdentityMismatch
    ));
    std::fs::write(pending_path, substituted)?;
    assert_eq!(
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
            .expect_err("record and envelope routes must agree")
            .code(),
        BootstrapFailureCode::InconsistentRoots
    );
    Ok(())
}

#[test]
fn authenticated_pending_rejects_non_record_plaintext() -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    with_fault(BootstrapFileEvent::WriteInitialized, || {
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
    })
    .expect_err("fault must leave pending state");
    let key = paths
        .storage
        .inspect()
        .map_err(|failure| format!("{failure:?}"))?
        .open_key()?;
    let pending_path = paths.data_root().join(".positron-bootstrap.pending");
    let pending = std::fs::read(&pending_path)?;
    let instance = BootstrapKeyCustody::routed_instance(BootstrapObjectPurpose::Pending, &pending)?;
    let malformed = key.protect(instance, BootstrapObjectPurpose::Pending, b"not-a-record")?;
    std::fs::write(pending_path, malformed)?;

    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Inconsistent
    );
    Ok(())
}

#[test]
fn resumed_bootstrap_rejects_integrity_identity_drift() -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    with_fault(BootstrapFileEvent::WriteInitialized, || {
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
    })
    .expect_err("fault must leave pending state");
    let key = paths
        .storage
        .inspect()
        .map_err(|failure| format!("{failure:?}"))?
        .open_key()?;
    let pending_path = paths.data_root().join(".positron-bootstrap.pending");
    let pending = std::fs::read(&pending_path)?;
    let instance = BootstrapKeyCustody::routed_instance(BootstrapObjectPurpose::Pending, &pending)?;
    let plaintext = key.open_object(instance, BootstrapObjectPurpose::Pending, &pending)?;
    let mut record = super::super::codec::BootstrapRecord::decode(&plaintext)?;
    record.integrity_fingerprint = [0x77; 32];
    let substituted = key.protect(instance, BootstrapObjectPurpose::Pending, &record.encode())?;
    std::fs::write(pending_path, substituted)?;

    assert_eq!(
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
            .expect_err("integrity identity drift must fail closed")
            .code(),
        BootstrapFailureCode::IdentityMismatch
    );
    Ok(())
}

#[test]
fn claim_rejects_a_valid_envelope_for_another_principal() -> Result<(), Box<dyn std::error::Error>>
{
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let key = paths
        .storage
        .inspect()
        .map_err(|failure| format!("{failure:?}"))?
        .open_key()?;
    let substituted = super::super::codec::encode_claim(
        initialized.instance_id(),
        positron_domain::identity::PrincipalId::from_bytes([0x33; 16])?,
        &[0x44; 32],
        positron_domain::identity::PrincipalId::from_bytes([0x34; 16])?,
        &[0x45; 32],
    );
    let encrypted = key.protect(
        initialized.instance_id(),
        BootstrapObjectPurpose::Claim,
        &substituted,
    )?;
    std::fs::write(paths.secrets_root().join("bootstrap-claim.v1"), encrypted)?;
    drop(initialized);

    assert_eq!(
        InstanceBootstrap::claim(&paths)
            .expect_err("claim principal must match bootstrap administrator")
            .code(),
        BootstrapFailureCode::IdentityMismatch
    );
    Ok(())
}
