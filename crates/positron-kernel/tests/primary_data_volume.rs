//! Public contract tests for the Primary Data Volume seam.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use positron_kernel::{
    PrimaryDataVolume, VolumeCompletionState, VolumeFailureCode, VolumeFileSystem, VolumeOperation,
    VolumeRetryClass,
};

static NEXT_TEMPORARY_ROOT: AtomicU64 = AtomicU64::new(0);

struct TemporaryRoot {
    path: PathBuf,
}

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_TEMPORARY_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-primary-volume-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            eprintln!("failed to remove test root: {error}");
        }
    }
}

#[test]
fn existing_filesystem_directory_can_be_acquired() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;

    let _volume = PrimaryDataVolume::acquire(root.path())?;

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn acquisition_reports_the_kernel_qualified_local_filesystem() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;

    let volume = PrimaryDataVolume::acquire(root.path())?;
    let first_mount_identity = volume.mount_identity();

    assert_eq!(volume.filesystem(), VolumeFileSystem::Apfs);
    drop(volume);
    let reopened = PrimaryDataVolume::acquire(root.path())?;
    assert_eq!(reopened.mount_identity(), first_mount_identity);
    Ok(())
}

#[test]
fn missing_root_is_rejected_without_creating_it() -> Result<(), Box<dyn Error>> {
    let parent = TemporaryRoot::new()?;
    let missing = parent.path().join("missing");

    let failure = PrimaryDataVolume::acquire(&missing).expect_err("missing root must fail");

    assert_eq!(failure.code(), VolumeFailureCode::Missing);
    assert_eq!(
        failure.retry_class(),
        VolumeRetryClass::AfterExternalCorrection
    );
    assert_eq!(
        failure.completion_state(),
        VolumeCompletionState::RejectedBeforeProbeMutation
    );
    assert_eq!(failure.operation(), VolumeOperation::ClassifyRoot);
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn root_identity_is_stable_across_ownership_lifetimes() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let first = PrimaryDataVolume::acquire(root.path())?;
    let first_identity = first.root_identity();
    drop(first);

    let second = PrimaryDataVolume::acquire(root.path())?;

    assert_eq!(second.root_identity(), first_identity);
    Ok(())
}

#[test]
fn a_second_writer_is_rejected_while_ownership_is_held() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let _first = PrimaryDataVolume::acquire(root.path())?;

    let failure = PrimaryDataVolume::acquire(root.path()).expect_err("second writer must fail");

    assert_eq!(failure.code(), VolumeFailureCode::Busy);
    assert_eq!(failure.retry_class(), VolumeRetryClass::AfterBackoff);
    assert_eq!(
        failure.completion_state(),
        VolumeCompletionState::RejectedBeforeProbeMutation
    );
    assert_eq!(failure.operation(), VolumeOperation::AcquireOwnershipLock);
    Ok(())
}

#[cfg(unix)]
#[test]
fn symbolic_link_ownership_artifact_is_rejected_as_unsafe() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let root = TemporaryRoot::new()?;
    let outside = TemporaryRoot::new()?;
    let outside_file = outside.path().join("foreign-lock");
    fs::write(&outside_file, b"foreign")?;
    symlink(&outside_file, root.path().join(".positron-volume.lock"))?;

    let failure = PrimaryDataVolume::acquire(root.path()).expect_err("symlink lock must fail");

    assert_eq!(failure.code(), VolumeFailureCode::Unsafe);
    assert_eq!(failure.operation(), VolumeOperation::OpenOwnershipLock);
    assert_eq!(fs::read(outside_file)?, b"foreign");
    Ok(())
}

#[cfg(unix)]
#[test]
fn dangling_symbolic_link_ownership_artifact_never_creates_its_target() -> Result<(), Box<dyn Error>>
{
    use std::os::unix::fs::symlink;

    let root = TemporaryRoot::new()?;
    let outside = TemporaryRoot::new()?;
    let outside_target = outside.path().join("must-not-be-created");
    symlink(&outside_target, root.path().join(".positron-volume.lock"))?;

    let failure =
        PrimaryDataVolume::acquire(root.path()).expect_err("dangling symlink lock must fail");

    assert_eq!(failure.code(), VolumeFailureCode::Unsafe);
    assert_eq!(failure.operation(), VolumeOperation::OpenOwnershipLock);
    assert!(!outside_target.exists());
    Ok(())
}

#[test]
fn unexpected_probe_residue_is_preserved_and_fails_closed() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let probe = root.path().join(".positron-volume-probe");
    fs::create_dir(&probe)?;
    let unexpected = probe.join("unexpected");
    fs::write(&unexpected, b"do-not-delete")?;

    let failure = PrimaryDataVolume::acquire(root.path()).expect_err("residue must fail closed");

    assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
    assert_eq!(failure.operation(), VolumeOperation::PrepareProbe);
    assert_eq!(
        failure.completion_state(),
        VolumeCompletionState::ProbeResiduePresent
    );
    assert_eq!(fs::read(unexpected)?, b"do-not-delete");
    assert!(!root.path().join(".positron-volume.lock").exists());
    let mut names = fs::read_dir(root.path())?
        .map(|entry| entry.map(|value| value.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    assert_eq!(names, [".positron-volume-probe"]);
    Ok(())
}

#[test]
fn successful_probe_leaves_only_the_stale_safe_lock_artifact() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;

    let volume = PrimaryDataVolume::acquire(root.path())?;
    let mut names = fs::read_dir(root.path())?
        .map(|entry| entry.map(|value| value.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();

    assert_eq!(names, [".positron-volume.lock"]);
    drop(volume);
    assert!(root.path().join(".positron-volume.lock").exists());
    Ok(())
}

#[test]
fn stale_lock_file_is_not_treated_as_ownership() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let first = PrimaryDataVolume::acquire(root.path())?;
    drop(first);

    let _second = PrimaryDataVolume::acquire(root.path())?;

    Ok(())
}

#[test]
fn non_directory_root_is_unsafe_and_never_gets_a_lock() -> Result<(), Box<dyn Error>> {
    let parent = TemporaryRoot::new()?;
    let root_file = parent.path().join("not-a-directory");
    fs::write(&root_file, b"foreign")?;

    let failure = PrimaryDataVolume::acquire(&root_file).expect_err("file root must fail");

    assert_eq!(failure.code(), VolumeFailureCode::Unsafe);
    assert_eq!(failure.operation(), VolumeOperation::ClassifyRoot);
    assert_eq!(fs::read(&root_file)?, b"foreign");
    assert!(!root_file.join(".positron-volume.lock").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn symbolic_link_root_is_unsafe_and_preserves_its_target() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let parent = TemporaryRoot::new()?;
    let target = TemporaryRoot::new()?;
    let root_link = parent.path().join("linked-root");
    symlink(target.path(), &root_link)?;

    let failure = PrimaryDataVolume::acquire(&root_link).expect_err("symlink root must fail");

    assert_eq!(failure.code(), VolumeFailureCode::Unsafe);
    assert_eq!(failure.operation(), VolumeOperation::ClassifyRoot);
    assert!(!target.path().join(".positron-volume.lock").exists());
    Ok(())
}

#[test]
fn different_filesystem_directories_have_distinct_root_identities() -> Result<(), Box<dyn Error>> {
    let first_root = TemporaryRoot::new()?;
    let second_root = TemporaryRoot::new()?;
    let first = PrimaryDataVolume::acquire(first_root.path())?;
    let second = PrimaryDataVolume::acquire(second_root.path())?;

    assert_ne!(first.root_identity(), second.root_identity());
    Ok(())
}

#[cfg(unix)]
#[test]
fn multiply_linked_ownership_artifact_is_unsafe() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let outside = TemporaryRoot::new()?;
    let outside_file = outside.path().join("foreign-lock");
    fs::write(&outside_file, b"foreign")?;
    fs::hard_link(&outside_file, root.path().join(".positron-volume.lock"))?;

    let failure = PrimaryDataVolume::acquire(root.path()).expect_err("hard link must fail");

    assert_eq!(failure.code(), VolumeFailureCode::Unsafe);
    assert_eq!(failure.operation(), VolumeOperation::OpenOwnershipLock);
    assert_eq!(fs::read(outside_file)?, b"foreign");
    Ok(())
}

#[test]
fn failure_diagnostics_are_bounded_and_do_not_reveal_the_root() -> Result<(), Box<dyn Error>> {
    let parent = TemporaryRoot::new()?;
    let missing = parent.path().join("secret-customer-volume");

    let failure = PrimaryDataVolume::acquire(&missing).expect_err("missing root must fail");
    let diagnostic = failure.to_string();

    assert!(!diagnostic.contains("secret-customer-volume"));
    assert!(diagnostic.len() <= 96);
    Ok(())
}

#[test]
fn owned_volume_debug_does_not_reveal_the_root_path() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path())?;

    let diagnostic = format!("{volume:?}");

    assert!(!diagnostic.contains("positron-primary-volume-test"));
    assert!(diagnostic.len() <= 96);
    Ok(())
}
