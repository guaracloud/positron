use std::os::unix::fs::MetadataExt;

use zeroize::Zeroizing;

use super::bootstrap::{FreshInitializationRootProof, initialize_local_key};
use super::initialization_io::{InitializationFault, with_initialization_fault};
use super::test_support::SecurityRoot;
use super::*;

#[test]
fn partial_write_failure_retains_final_name_residue_without_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;

    let observed = with_initialization_fault(InitializationFault::PartialWrite(80), || {
        initialize_local_key(proof)
    });

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::WriteFailed))
    );
    let residue = Zeroizing::new(std::fs::read(root.path.join(LOCAL_KEY_FILE_NAME))?);
    assert_eq!(residue.len(), 80);
    assert!(residue.starts_with(&LOCAL_KEY_FILE_MAGIC));
    Ok(())
}

#[test]
fn key_file_sync_failure_retains_complete_final_name_residue()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;

    let observed = with_initialization_fault(InitializationFault::SynchronizeKeyFile, || {
        initialize_local_key(proof)
    });

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(
            LocalKeyFailureCode::SynchronizeKeyFileFailed
        ))
    );
    assert_eq!(
        std::fs::metadata(root.path.join(LOCAL_KEY_FILE_NAME))?.len(),
        LOCAL_KEY_FILE_BYTES as u64
    );
    Ok(())
}

#[test]
fn directory_sync_failure_retains_complete_final_name_residue()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;

    let observed =
        with_initialization_fault(InitializationFault::SynchronizeSecurityDirectory, || {
            initialize_local_key(proof)
        });

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(
            LocalKeyFailureCode::SynchronizeSecurityDirectoryFailed
        ))
    );
    assert_eq!(
        std::fs::metadata(root.path.join(LOCAL_KEY_FILE_NAME))?.len(),
        LOCAL_KEY_FILE_BYTES as u64
    );
    Ok(())
}

#[test]
fn entropy_failure_retains_empty_owner_only_final_name_residue()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;

    let observed =
        with_initialization_fault(InitializationFault::Entropy, || initialize_local_key(proof));

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(
            LocalKeyFailureCode::EntropyUnavailable
        ))
    );
    let metadata = std::fs::metadata(root.path.join(LOCAL_KEY_FILE_NAME))?;
    assert_eq!(metadata.len(), 0);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    Ok(())
}

#[test]
fn root_key_entropy_failure_retains_empty_owner_only_final_name_residue()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;

    let observed = with_initialization_fault(InitializationFault::RootKeyEntropy, || {
        initialize_local_key(proof)
    });

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(
            LocalKeyFailureCode::EntropyUnavailable
        ))
    );
    let metadata = std::fs::metadata(root.path.join(LOCAL_KEY_FILE_NAME))?;
    assert_eq!(metadata.len(), 0);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    Ok(())
}

#[test]
fn clock_failure_retains_empty_residue_after_zeroizing_key_custody_takes_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;

    let observed =
        with_initialization_fault(InitializationFault::Clock, || initialize_local_key(proof));

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::ClockUnavailable))
    );
    assert_eq!(
        std::fs::metadata(root.path.join(LOCAL_KEY_FILE_NAME))?.len(),
        0
    );
    Ok(())
}
