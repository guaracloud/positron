#[cfg(target_os = "linux")]
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "macos")]
use std::process::Command;

use super::acl::{LinuxAclQueryOutcome, classify_linux_acl_query};
#[cfg(target_os = "linux")]
use super::acl::{verify_directory_acl, verify_file_acl};
use super::bootstrap::{
    FreshInitializationRootProof, LocalKeyInitializationEvent, capture_initialization_events,
    initialize_local_key,
};
use super::{LOCAL_KEY_FILE_NAME, LocalKeyFailure, LocalKeyFailureCode};

static NEXT_SECURITY_ROOT: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "macos")]
#[test]
fn unsafe_security_directory_is_rejected_before_entropy_or_file_creation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TestSecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;
    root.add_acl("everyone allow read")?;

    let (observed, events) = capture_initialization_events(|| initialize_local_key(proof));

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeAcl))
    );
    assert!(!events.contains(&LocalKeyInitializationEvent::RequestEntropy));
    assert!(!events.contains(&LocalKeyInitializationEvent::CreateFinalKeyFile));
    assert!(!root.path.join(LOCAL_KEY_FILE_NAME).try_exists()?);
    Ok(())
}

#[test]
fn linux_acl_query_accepts_only_absence_and_fails_closed_otherwise() {
    for (outcome, expected) in [
        (LinuxAclQueryOutcome::Absent, Ok(())),
        (
            LinuxAclQueryOutcome::Present,
            Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeAcl)),
        ),
        (
            LinuxAclQueryOutcome::BufferTooSmall,
            Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeAcl)),
        ),
        (
            LinuxAclQueryOutcome::Unsupported,
            Err(LocalKeyFailure::new(
                LocalKeyFailureCode::AclInspectionUnsupported,
            )),
        ),
        (
            LinuxAclQueryOutcome::Unexpected,
            Err(LocalKeyFailure::new(
                LocalKeyFailureCode::AclInspectionFailed,
            )),
        ),
    ] {
        assert_eq!(classify_linux_acl_query(outcome), expected);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_linux_acl_attributes_are_rejected_on_exact_descriptors()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TestSecurityRoot::create()?;
    let directory = File::open(&root.path)?;
    let key_path = root.path.join("key");
    let key = File::create(&key_path)?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    assert_eq!(verify_directory_acl(&directory), Ok(()));
    assert_eq!(verify_file_acl(&key), Ok(()));

    set_linux_acl(&key, b"system.posix_acl_access\0")?;
    assert_eq!(
        verify_file_acl(&key),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeAcl))
    );
    rustix::fs::fremovexattr(&key, b"system.posix_acl_access\0".as_slice())?;
    assert_eq!(verify_file_acl(&key), Ok(()));

    set_linux_acl(&directory, b"system.posix_acl_access\0")?;
    assert_eq!(
        verify_directory_acl(&directory),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeAcl))
    );
    rustix::fs::fremovexattr(&directory, b"system.posix_acl_access\0".as_slice())?;
    set_linux_acl(&directory, b"system.posix_acl_default\0")?;
    assert_eq!(
        verify_directory_acl(&directory),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeAcl))
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn unsafe_linux_directory_is_rejected_before_entropy_or_file_creation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TestSecurityRoot::create()?;
    let proof = FreshInitializationRootProof::for_test(&root.path)?;
    let directory = File::open(&root.path)?;
    set_linux_acl(&directory, b"system.posix_acl_default\0")?;

    let (observed, events) = capture_initialization_events(|| initialize_local_key(proof));

    assert_eq!(
        observed.map(|_| ()),
        Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeAcl))
    );
    assert!(!events.contains(&LocalKeyInitializationEvent::RequestEntropy));
    assert!(!events.contains(&LocalKeyInitializationEvent::CreateFinalKeyFile));
    assert!(!root.path.join(LOCAL_KEY_FILE_NAME).try_exists()?);
    Ok(())
}

struct TestSecurityRoot {
    path: PathBuf,
}

impl TestSecurityRoot {
    fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "positron-local-key-{}-{}",
            std::process::id(),
            NEXT_SECURITY_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self { path })
    }

    #[cfg(target_os = "macos")]
    fn add_acl(&self, acl: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path = self
            .path
            .to_str()
            .ok_or("security-root fixture path was not UTF-8")?;
        let status = Command::new("/bin/chmod")
            .args(["+a", acl, path])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("chmod fixture command failed with {status}").into())
        }
    }
}

impl Drop for TestSecurityRoot {
    fn drop(&mut self) {
        let _result = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(target_os = "linux")]
fn set_linux_acl(file: &File, name: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    const ACL: [u8; 44] = [
        2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255, 2, 0, 4, 0, 57, 48, 0, 0, 4, 0, 0, 0, 255, 255,
        255, 255, 16, 0, 0, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255,
    ];
    rustix::fs::fsetxattr(file, name, &ACL, rustix::fs::XattrFlags::empty())?;
    Ok(())
}
