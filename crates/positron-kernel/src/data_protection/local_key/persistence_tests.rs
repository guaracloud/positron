use std::cell::RefCell;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::rc::Rc;

use zeroize::Zeroizing;

use super::bootstrap::{
    FreshInitializationRootProof, LocalKeyInitializationEvent, capture_initialization_events,
    initialize_local_key, with_initialization_event_action,
};
use super::persistence::{ExpectedLocalKeyIdentity, ExpectedSecurityDirectory, open_local_key};
use super::test_support::SecurityRoot;
use super::*;

#[test]
fn fresh_local_key_persists_and_reopens_with_exact_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;

    let initialized = initialize_local_key(proof)?;
    let expected = ExpectedLocalKeyIdentity::from_evidence(initialized.evidence());
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;
    let metadata = std::fs::symlink_metadata(root.path.join(LOCAL_KEY_FILE_NAME))?;
    let reopened = open_local_key(&root.path, expected_directory, expected)?;

    assert_eq!(reopened.evidence(), initialized.evidence());
    assert_eq!(
        initialized.evidence().warning,
        LocalCustodyWarning::FilesystemCustodyDoesNotProtectCombinedKeyAndDataTheft
    );
    assert_eq!(
        initialized.evidence().recovery,
        LocalRecoveryReadiness::IndependentRecoveryRequired
    );
    assert_eq!(
        reopened.evidence().warning,
        LocalCustodyWarning::FilesystemCustodyDoesNotProtectCombinedKeyAndDataTheft
    );
    assert_eq!(
        reopened.evidence().recovery,
        LocalRecoveryReadiness::IndependentRecoveryRequired
    );
    assert_eq!(metadata.len(), LOCAL_KEY_FILE_BYTES as u64);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert!(metadata.file_type().is_file());
    Ok(())
}

#[test]
fn stale_fresh_root_proof_refuses_without_changing_the_existing_key()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let first_proof = FreshInitializationRootProof::for_test(&root.path)?;
    let stale_proof = FreshInitializationRootProof::for_test(&root.path)?;
    let first = initialize_local_key(first_proof)?;
    let expected = ExpectedLocalKeyIdentity::from_evidence(first.evidence());
    let before = Zeroizing::new(std::fs::read(root.path.join(LOCAL_KEY_FILE_NAME))?);
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;

    let (second, events) = capture_initialization_events(|| initialize_local_key(stale_proof));
    let after = Zeroizing::new(std::fs::read(root.path.join(LOCAL_KEY_FILE_NAME))?);

    #[cfg(target_os = "macos")]
    let expected_failure = LocalKeyFailureCode::UnsafeSecurityDirectory;
    #[cfg(target_os = "linux")]
    let expected_failure = LocalKeyFailureCode::KeyAlreadyExists;
    assert_eq!(
        second.map(|_| ()),
        Err(LocalKeyFailure::new(expected_failure))
    );
    assert!(!events.contains(&LocalKeyInitializationEvent::RequestEntropy));
    assert!(
        after.as_slice() == before.as_slice(),
        "stale initialization changed the existing local key file"
    );
    assert!(
        after.len() == LOCAL_KEY_FILE_BYTES,
        "existing local key file length changed"
    );
    assert_eq!(
        open_local_key(&root.path, expected_directory, expected)?.evidence(),
        first.evidence()
    );
    Ok(())
}

#[test]
fn exclusive_creation_refuses_a_racing_final_name_before_entropy()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;
    let final_path = root.path.join(LOCAL_KEY_FILE_NAME);
    let injected_error = Rc::new(RefCell::new(None));
    let action_error = Rc::clone(&injected_error);
    let action_path = final_path.clone();

    let (observed, events) = capture_initialization_events(|| {
        with_initialization_event_action(
            move |event| {
                if event == LocalKeyInitializationEvent::CreateFinalKeyFile
                    && let Err(error) = std::fs::write(&action_path, b"racing-entry")
                {
                    action_error.replace(Some(error));
                }
            },
            || initialize_local_key(proof),
        )
    });

    if let Some(error) = injected_error.take() {
        return Err(error.into());
    }
    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::KeyAlreadyExists))
    );
    assert!(!events.contains(&LocalKeyInitializationEvent::RequestEntropy));
    let racing_bytes = Zeroizing::new(std::fs::read(final_path)?);
    assert!(
        racing_bytes.as_slice() == b"racing-entry",
        "exclusive creation changed the racing final-name entry"
    );
    Ok(())
}

#[test]
fn valid_file_with_wrong_expected_identity_is_refused_without_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let initialized = initialize_local_key(FreshInitializationRootProof::for_test(&root.path)?)?;
    let before = Zeroizing::new(std::fs::read(root.path.join(LOCAL_KEY_FILE_NAME))?);
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;
    let wrong = ExpectedLocalKeyIdentity::with_test_fingerprint(
        initialized.evidence(),
        LocalKeyFingerprint([0xA5; 32]),
    );

    let observed = open_local_key(&root.path, expected_directory, wrong);

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::IdentityMismatch))
    );
    let after = Zeroizing::new(std::fs::read(root.path.join(LOCAL_KEY_FILE_NAME))?);
    assert!(
        after.as_slice() == before.as_slice(),
        "identity mismatch handling changed the existing local key file"
    );
    Ok(())
}

#[test]
fn missing_initialized_key_is_refused_without_generating_a_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let initialized = initialize_local_key(FreshInitializationRootProof::for_test(&root.path)?)?;
    let expected = ExpectedLocalKeyIdentity::from_evidence(initialized.evidence());
    let final_path = root.path.join(LOCAL_KEY_FILE_NAME);
    std::fs::remove_file(&final_path)?;
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;

    let (observed, events) =
        capture_initialization_events(|| open_local_key(&root.path, expected_directory, expected));

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::OpenKeyFileFailed))
    );
    assert!(!events.contains(&LocalKeyInitializationEvent::RequestEntropy));
    assert!(!final_path.try_exists()?);
    Ok(())
}

#[test]
fn initialized_key_with_trailing_bytes_is_refused_as_malformed()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let root = SecurityRoot::create()?;
    let initialized = initialize_local_key(FreshInitializationRootProof::for_test(&root.path)?)?;
    let expected = ExpectedLocalKeyIdentity::from_evidence(initialized.evidence());
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;
    let mut key_file = std::fs::OpenOptions::new()
        .append(true)
        .open(root.path.join(LOCAL_KEY_FILE_NAME))?;
    key_file.write_all(&[0xA5])?;
    key_file.sync_all()?;

    let observed = open_local_key(&root.path, expected_directory, expected);

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))
    );
    Ok(())
}

#[test]
fn security_directory_permission_drift_is_refused_before_key_acceptance()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let initialized = initialize_local_key(FreshInitializationRootProof::for_test(&root.path)?)?;
    let expected_key = ExpectedLocalKeyIdentity::from_evidence(initialized.evidence());
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;
    std::fs::set_permissions(&root.path, std::fs::Permissions::from_mode(0o750))?;

    let observed = open_local_key(&root.path, expected_directory, expected_key);

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(
            LocalKeyFailureCode::UnsafeSecurityDirectory
        ))
    );
    Ok(())
}

#[test]
fn security_directory_link_count_drift_is_refused_before_key_acceptance()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let initialized = initialize_local_key(FreshInitializationRootProof::for_test(&root.path)?)?;
    let expected_key = ExpectedLocalKeyIdentity::from_evidence(initialized.evidence());
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;
    std::fs::create_dir(root.path.join("unexpected-child"))?;

    let observed = open_local_key(&root.path, expected_directory, expected_key);

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(
            LocalKeyFailureCode::UnsafeSecurityDirectory
        ))
    );
    Ok(())
}

#[test]
fn key_file_permission_drift_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let initialized = initialize_local_key(FreshInitializationRootProof::for_test(&root.path)?)?;
    let expected_key = ExpectedLocalKeyIdentity::from_evidence(initialized.evidence());
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;
    std::fs::set_permissions(
        root.path.join(LOCAL_KEY_FILE_NAME),
        std::fs::Permissions::from_mode(0o640),
    )?;

    let observed = open_local_key(&root.path, expected_directory, expected_key);

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeKeyFile))
    );
    Ok(())
}

#[test]
fn hard_linked_key_file_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let initialized = initialize_local_key(FreshInitializationRootProof::for_test(&root.path)?)?;
    let expected_key = ExpectedLocalKeyIdentity::from_evidence(initialized.evidence());
    std::fs::hard_link(
        root.path.join(LOCAL_KEY_FILE_NAME),
        root.path.join("additional-link"),
    )?;
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;

    let observed = open_local_key(&root.path, expected_directory, expected_key);

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeKeyFile))
    );
    Ok(())
}

#[test]
fn symbolic_link_at_final_name_is_never_followed() -> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let initialized = initialize_local_key(FreshInitializationRootProof::for_test(&root.path)?)?;
    let expected_key = ExpectedLocalKeyIdentity::from_evidence(initialized.evidence());
    let final_path = root.path.join(LOCAL_KEY_FILE_NAME);
    let moved_path = root.path.join("moved-key");
    std::fs::rename(&final_path, &moved_path)?;
    std::os::unix::fs::symlink(&moved_path, &final_path)?;
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;

    let observed = open_local_key(&root.path, expected_directory, expected_key);

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::OpenKeyFileFailed))
    );
    Ok(())
}

#[test]
fn local_key_diagnostics_do_not_expose_identity_or_key_material()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let initialized = initialize_local_key(FreshInitializationRootProof::for_test(&root.path)?)?;
    let expected_key = ExpectedLocalKeyIdentity::from_evidence(initialized.evidence());
    let expected_directory = ExpectedSecurityDirectory::for_test(&root.path)?;
    let diagnostics = format!(
        "key={expected_key:?};directory={expected_directory:?};verified={initialized:?};failure={:?};display={}",
        LocalKeyFailure::new(LocalKeyFailureCode::FingerprintMismatch),
        LocalKeyFailure::new(LocalKeyFailureCode::FingerprintMismatch),
    );
    let file_bytes = Zeroizing::new(std::fs::read(root.path.join(LOCAL_KEY_FILE_NAME))?);
    let secret_hex = hex_bytes(
        file_bytes
            .get(70..102)
            .ok_or("persisted Root KEK fixture was truncated")?,
    );
    let fingerprint_hex = hex_bytes(&initialized.evidence().fingerprint.0);

    assert!(!diagnostics.contains(secret_hex.as_str()));
    assert!(!diagnostics.contains(fingerprint_hex.as_str()));
    assert!(!diagnostics.contains("fingerprint"));
    assert!(!diagnostics.contains("key_id"));
    assert!(!diagnostics.contains(root.path.to_string_lossy().as_ref()));
    assert!(diagnostics.len() < 640);
    Ok(())
}

fn hex_bytes(bytes: &[u8]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Zeroizing::new(String::with_capacity(bytes.len().saturating_mul(2)));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
