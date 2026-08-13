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
    let key = BootstrapKeyCustody::open(paths.secrets_root())?;
    let pending = std::fs::read(paths.data_root().join(".positron-bootstrap.pending"))?;
    let instance = BootstrapKeyCustody::routed_instance(BootstrapObjectPurpose::Pending, &pending)?;
    let plaintext = key.open_object(instance, BootstrapObjectPurpose::Pending, &pending)?;
    let record = super::super::codec::BootstrapRecord::decode(&plaintext)?;
    let substituted =
        super::super::codec::encode_claim(instance, record.administrator, &[0x44; 32]);
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
    let key = BootstrapKeyCustody::open(paths.secrets_root())?;
    let pending_path = paths.data_root().join(".positron-bootstrap.pending");
    let pending = std::fs::read(&pending_path)?;
    let routed = BootstrapKeyCustody::routed_instance(BootstrapObjectPurpose::Pending, &pending)?;
    let plaintext = key.open_object(routed, BootstrapObjectPurpose::Pending, &pending)?;
    let mut record = super::super::codec::BootstrapRecord::decode(&plaintext)?;
    record.instance = InstanceId::new([0x55; 16])?;
    let substituted = key.protect(routed, BootstrapObjectPurpose::Pending, &record.encode())?;
    std::fs::write(pending_path, substituted)?;
    assert_eq!(
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
            .expect_err("record and envelope routes must agree")
            .code(),
        BootstrapFailureCode::InconsistentRoots
    );
    Ok(())
}
