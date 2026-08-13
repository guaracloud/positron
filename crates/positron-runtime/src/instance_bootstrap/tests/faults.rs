use super::super::storage::{BootstrapFileEvent, with_fault};
use super::super::{BootstrapFailureCode, BootstrapState, InitializationPlan};
use super::support::Roots;
use crate::InstanceBootstrap;

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
