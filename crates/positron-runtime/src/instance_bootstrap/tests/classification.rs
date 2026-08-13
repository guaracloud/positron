use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::storage::{BootstrapFileEvent, with_fault};
use super::super::{BootstrapPaths, BootstrapState, InitializationPlan};
use crate::InstanceBootstrap;
use positron_kernel::MountQualification;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Roots(PathBuf);

impl Roots {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "positron-bootstrap-classification-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        fs::create_dir(root.join("data"))?;
        fs::create_dir(root.join("secrets"))?;
        set_owner_only(&root.join("secrets"))?;
        Ok(Self(root))
    }

    fn paths(&self) -> BootstrapPaths {
        BootstrapPaths::new(
            &self.0.join("data"),
            &self.0.join("secrets"),
            MountQualification::LocalHost,
        )
        .expect("test roots are distinct")
    }
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

impl Drop for Roots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn unknown_state_is_inconsistent_instead_of_empty() -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    fs::write(roots.0.join("data/foreign"), b"state")?;
    assert_eq!(
        InstanceBootstrap::classify(&roots.paths())?,
        BootstrapState::Inconsistent
    );
    Ok(())
}

#[test]
fn missing_key_is_resumable_only_before_protected_data_exists()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    fs::write(
        paths.data_root().join(".positron-bootstrap.pending"),
        super::super::storage::INTENT,
    )?;
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Incomplete
    );

    fs::create_dir(paths.data_root().join("catalog"))?;
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Inconsistent
    );
    Ok(())
}

#[test]
fn published_and_staged_initialized_markers_are_inconsistent()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    fs::copy(
        paths.data_root().join(".positron-bootstrap.initialized"),
        paths
            .data_root()
            .join(".positron-bootstrap.initialized.new"),
    )?;

    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Inconsistent
    );
    let failure = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
        .expect_err("ambiguous publication must never overwrite the committed identity");
    assert_eq!(
        failure.code(),
        super::super::BootstrapFailureCode::InconsistentRoots
    );
    Ok(())
}

#[test]
fn corrupt_authenticated_pending_state_is_inconsistent() -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    with_fault(BootstrapFileEvent::WriteInitialized, || {
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
    })
    .expect_err("fault must retain authenticated pending state");
    let pending = paths.data_root().join(".positron-bootstrap.pending");
    let mut bytes = fs::read(&pending)?;
    let byte = bytes.last_mut().ok_or("pending record must not be empty")?;
    *byte ^= 0x80;
    fs::write(pending, bytes)?;

    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Inconsistent
    );
    Ok(())
}

#[test]
fn raw_intent_with_partial_local_key_staging_is_resumable() -> Result<(), Box<dyn std::error::Error>>
{
    use std::os::unix::fs::PermissionsExt;

    let roots = Roots::new()?;
    let paths = roots.paths();
    fs::write(
        paths.data_root().join(".positron-bootstrap.pending"),
        super::super::storage::INTENT,
    )?;
    let staging = paths.secrets_root().join("local-root-key.v1.new");
    fs::write(&staging, b"partial")?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o600))?;

    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Incomplete
    );
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Initialized
    );
    Ok(())
}

#[test]
fn unsafe_and_empty_storage_artifacts_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    use super::super::storage;
    use positron_kernel::BootstrapArtifact;

    let roots = Roots::new()?;
    let paths = roots.paths();
    std::os::unix::fs::symlink("missing", paths.data_root().join("foreign"))?;
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Inconsistent
    );
    fs::remove_file(paths.data_root().join("foreign"))?;
    fs::write(paths.data_root().join(".positron-bootstrap.pending"), b"")?;
    let access = paths
        .storage
        .inspect()
        .expect("test roots remain available");
    assert_eq!(
        storage::read(&access, BootstrapArtifact::Pending)
            .expect_err("empty artifact")
            .code(),
        super::super::BootstrapFailureCode::CorruptState
    );
    fs::remove_file(paths.data_root().join(".positron-bootstrap.pending"))?;
    let failure = with_fault(BootstrapFileEvent::WritePending, || {
        storage::write_new(&access, BootstrapArtifact::Pending, b"bounded")
    })
    .expect_err("directory synchronization fault");
    assert_eq!(
        failure.code(),
        super::super::BootstrapFailureCode::StorageUnavailable
    );
    Ok(())
}

#[test]
fn identical_roots_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let path = roots.0.join("data");
    assert_eq!(
        BootstrapPaths::new(&path, &path, MountQualification::LocalHost)
            .expect_err("roots must be separate")
            .code(),
        super::super::BootstrapFailureCode::InvalidRoots
    );
    Ok(())
}

#[test]
fn explicit_local_key_must_match_descriptor_relative_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let data = roots.0.join("data");
    let secrets = roots.0.join("secrets");
    let rejected = BootstrapPaths::with_local_key(
        &data,
        &secrets,
        &secrets.join("different-key"),
        MountQualification::LocalHost,
    );
    assert_eq!(
        rejected.expect_err("key path must be exact").code(),
        super::super::BootstrapFailureCode::InvalidRoots
    );
    assert!(
        BootstrapPaths::with_local_key(
            &data,
            &secrets,
            &secrets.join("local-root-key.v1"),
            MountQualification::LocalHost,
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn unbound_local_key_is_inconsistent() -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    positron_kernel::BootstrapKeyCustody::initialize(paths.secrets_root())?;
    assert_eq!(
        InstanceBootstrap::classify(&paths)?,
        BootstrapState::Inconsistent
    );
    Ok(())
}

#[test]
fn pending_authentication_fails_closed_at_key_file_and_envelope_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    for pending in [
        super::super::storage::INTENT,
        b"x".as_slice(),
        b"".as_slice(),
    ] {
        let roots = Roots::new()?;
        let paths = roots.paths();
        if pending == super::super::storage::INTENT {
            fs::write(
                paths.secrets_root().join("local-root-key.v1"),
                b"invalid-key",
            )?;
        } else {
            paths
                .storage
                .inspect()
                .map_err(|failure| format!("{failure:?}"))?
                .initialize_key()?;
        }
        fs::write(
            paths.data_root().join(".positron-bootstrap.pending"),
            pending,
        )?;
        assert_eq!(
            InstanceBootstrap::classify(&paths)?,
            BootstrapState::Inconsistent
        );
    }
    Ok(())
}
