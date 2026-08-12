//! Isolated process-lifecycle conformance test for Primary Data Volume ownership.

use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use positron_kernel::{
    MountQualification, OwnedPrimaryDataVolume, PrimaryDataVolume, VolumeFailure,
    VolumeFailureCode, VolumeOperation,
};

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "positron-primary-volume-process-test-{}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove process-test root: {error}");
        }
    }
}

fn acquire_local(root: &Path) -> Result<OwnedPrimaryDataVolume, VolumeFailure> {
    PrimaryDataVolume::acquire(root, MountQualification::LocalHost)
}

fn hold_volume_in_child(root: &Path) -> Result<(), Box<dyn Error>> {
    let _volume = acquire_local(root)?;
    println!("POSITRON_PRIMARY_VOLUME_CHILD_READY");
    std::io::stdin().read_to_end(&mut Vec::new())?;
    Ok(())
}

fn verify_process_lifecycle() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let initial = acquire_local(&root.0)?;
    let initial_root_identity = initial.root_identity();
    let initial_mount_identity = initial.mount_identity();
    drop(initial);

    let mut child = Command::new(std::env::current_exe()?)
        .env("POSITRON_TEST_PRIMARY_VOLUME_CHILD_ROOT", &root.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut child_stdout = BufReader::new(
        child
            .stdout
            .take()
            .ok_or("child process stdout was not piped")?,
    );
    let mut line = String::new();
    loop {
        line.clear();
        if child_stdout.read_line(&mut line)? == 0 {
            let status = child.wait()?;
            return Err(format!("child exited before acquiring volume: {status}").into());
        }
        if line.contains("POSITRON_PRIMARY_VOLUME_CHILD_READY") {
            break;
        }
    }

    let failure = acquire_local(&root.0).expect_err("second process must fail while held");
    assert_eq!(failure.code(), VolumeFailureCode::Busy);
    assert_eq!(failure.operation(), VolumeOperation::AcquireOwnershipLock);

    drop(child.stdin.take());
    let status = child.wait()?;
    assert!(status.success(), "child process failed: {status}");
    let reacquired = acquire_local(&root.0)?;
    assert_eq!(reacquired.qualification(), MountQualification::LocalHost);
    assert_eq!(reacquired.root_identity(), initial_root_identity);
    assert_eq!(reacquired.mount_identity(), initial_mount_identity);
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    if let Some(root) = std::env::var_os("POSITRON_TEST_PRIMARY_VOLUME_CHILD_ROOT") {
        hold_volume_in_child(Path::new(&root))
    } else {
        verify_process_lifecycle()
    }
}
