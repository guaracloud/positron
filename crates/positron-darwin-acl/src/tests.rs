use std::cell::Cell;
use std::fs::File;
use std::os::fd::AsFd;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

#[cfg(target_os = "macos")]
static NEXT_NATIVE_PATH: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "macos")]
#[test]
fn clean_native_file_has_no_extended_acl() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-darwin-acl-{}-{}",
        std::process::id(),
        NEXT_NATIVE_PATH.fetch_add(1, Ordering::Relaxed)
    ));
    let file = File::create(&path)?;
    let observed = extended_acl_presence(file.as_fd())?;
    std::fs::remove_file(path)?;
    assert_eq!(observed, ExtendedAclPresence::Absent);
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn native_acl_lifecycle_is_descriptor_authoritative() -> Result<(), Box<dyn std::error::Error>> {
    let root = NativeTestRoot::create()?;
    let file_path = root.path.join("key");
    let replacement_path = root.path.join("replacement");
    let original = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file_path)?;
    assert_eq!(
        extended_acl_presence(root.directory.as_fd())?,
        ExtendedAclPresence::Absent
    );
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Absent
    );

    chmod(&["+a", "everyone allow read", path_text(&file_path)?])?;
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Present
    );
    chmod(&["600", path_text(&file_path)?])?;
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Present
    );
    chmod(&["-a#", "0", path_text(&file_path)?])?;
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Absent
    );

    chmod(&[
        "+a",
        "everyone allow read,file_inherit,directory_inherit",
        path_text(&root.path)?,
    ])?;
    assert_eq!(
        extended_acl_presence(root.directory.as_fd())?,
        ExtendedAclPresence::Present
    );
    let inherited_path = root.path.join("inherited");
    let inherited = File::create(&inherited_path)?;
    assert_eq!(
        extended_acl_presence(inherited.as_fd())?,
        ExtendedAclPresence::Present
    );
    chmod(&["-a#", "0", path_text(&root.path)?])?;

    let replacement = File::create(&replacement_path)?;
    let read_only = File::open(&replacement_path)?;
    chmod(&["+a", "everyone deny read", path_text(&replacement_path)?])?;
    std::fs::rename(&replacement_path, &file_path)?;
    assert_eq!(
        extended_acl_presence(original.as_fd())?,
        ExtendedAclPresence::Absent
    );
    assert_eq!(
        extended_acl_presence(replacement.as_fd())?,
        ExtendedAclPresence::Present
    );
    assert_eq!(
        extended_acl_presence(read_only.as_fd())?,
        ExtendedAclPresence::Present
    );
    assert_eq!(read_only.metadata()?.len(), 0);
    Ok(())
}

#[cfg(target_os = "macos")]
fn chmod(arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("/bin/chmod").args(arguments).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("chmod fixture command failed with {status}").into())
    }
}

#[cfg(target_os = "macos")]
fn path_text(path: &std::path::Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str()
        .ok_or_else(|| "native ACL fixture path was not UTF-8".into())
}

#[cfg(target_os = "macos")]
struct NativeTestRoot {
    path: std::path::PathBuf,
    directory: File,
}

#[cfg(target_os = "macos")]
impl NativeTestRoot {
    fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "positron-darwin-acl-matrix-{}-{}",
            std::process::id(),
            NEXT_NATIVE_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        let directory = File::open(&path)?;
        Ok(Self { path, directory })
    }
}

#[cfg(target_os = "macos")]
impl Drop for NativeTestRoot {
    fn drop(&mut self) {
        let _result = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn null_enoent_is_absent_without_a_release_attempt() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("/dev/null")?;
    let native = InjectedNativeAcl::null_with_errno(2);
    let observed = extended_acl_presence_with(file.as_fd(), &native)?;
    assert_eq!(observed, ExtendedAclPresence::Absent);
    assert_eq!(native.release_attempts.get(), 0);
    Ok(())
}

#[test]
fn null_retrieval_failures_retain_evidence_without_a_release_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("/dev/null")?;
    let unsupported = NonZeroI32::new(45).ok_or("unsupported errno fixture was zero")?;
    for (errno, expected) in [
        (
            9,
            AclInspectionEvidence::Errno(NonZeroI32::new(9).ok_or("bad fd")?),
        ),
        (
            22,
            AclInspectionEvidence::Errno(NonZeroI32::new(22).ok_or("invalid")?),
        ),
        (
            12,
            AclInspectionEvidence::Errno(NonZeroI32::new(12).ok_or("allocation")?),
        ),
        (45, AclInspectionEvidence::Unsupported(unsupported)),
        (0, AclInspectionEvidence::MissingErrno),
    ] {
        let native = InjectedNativeAcl::null_with_errno(errno);
        assert_eq!(
            extended_acl_presence_with(file.as_fd(), &native),
            Err(AclInspectionError::Retrieve(expected))
        );
        assert_eq!(native.release_attempts.get(), 0);
    }
    let missing_errno = InjectedNativeAcl::null_without_errno();
    assert_eq!(
        extended_acl_presence_with(file.as_fd(), &missing_errno),
        Err(AclInspectionError::Retrieve(
            AclInspectionEvidence::MissingErrno
        ))
    );
    assert_eq!(missing_errno.release_attempts.get(), 0);
    Ok(())
}

#[test]
fn retrieved_acl_is_present_only_after_one_successful_release()
-> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("/dev/null")?;
    let native = InjectedNativeAcl::allocated();
    assert_eq!(
        extended_acl_presence_with(file.as_fd(), &native)?,
        ExtendedAclPresence::Present
    );
    assert_eq!(native.release_attempts.get(), 1);
    Ok(())
}

#[test]
fn release_failure_is_typed_after_exactly_one_attempt() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("/dev/null")?;
    for (errno, expected) in [
        (
            12,
            AclInspectionEvidence::Errno(NonZeroI32::new(12).ok_or("release")?),
        ),
        (0, AclInspectionEvidence::MissingErrno),
    ] {
        let native = InjectedNativeAcl::allocated_with_release_errno(errno);
        assert_eq!(
            extended_acl_presence_with(file.as_fd(), &native),
            Err(AclInspectionError::Release(expected))
        );
        assert_eq!(native.release_attempts.get(), 1);
    }
    for (native, expected) in [
        (
            InjectedNativeAcl::allocated_with_release_errno(45),
            AclInspectionEvidence::Unsupported(
                NonZeroI32::new(45).ok_or("unsupported release errno was zero")?,
            ),
        ),
        (
            InjectedNativeAcl::allocated_with_missing_release_errno(),
            AclInspectionEvidence::MissingErrno,
        ),
    ] {
        assert_eq!(
            extended_acl_presence_with(file.as_fd(), &native),
            Err(AclInspectionError::Release(expected))
        );
        assert_eq!(native.release_attempts.get(), 1);
    }
    Ok(())
}

#[test]
fn inspection_failures_have_bounded_non_sensitive_display() {
    for failure in [
        AclInspectionError::Retrieve(AclInspectionEvidence::MissingErrno),
        AclInspectionError::Release(AclInspectionEvidence::MissingErrno),
    ] {
        assert_eq!(failure.to_string(), "descriptor ACL inspection failed");
    }
}

struct InjectedNativeAcl {
    retrieval_errno: Option<Option<i32>>,
    release_failure_errno: Option<Option<i32>>,
    release_attempts: Cell<usize>,
}

impl InjectedNativeAcl {
    const fn null_with_errno(errno: i32) -> Self {
        Self {
            retrieval_errno: Some(Some(errno)),
            release_failure_errno: None,
            release_attempts: Cell::new(0),
        }
    }

    const fn null_without_errno() -> Self {
        Self {
            retrieval_errno: Some(None),
            release_failure_errno: None,
            release_attempts: Cell::new(0),
        }
    }

    const fn allocated() -> Self {
        Self {
            retrieval_errno: None,
            release_failure_errno: None,
            release_attempts: Cell::new(0),
        }
    }

    const fn allocated_with_release_errno(errno: i32) -> Self {
        Self {
            retrieval_errno: None,
            release_failure_errno: Some(Some(errno)),
            release_attempts: Cell::new(0),
        }
    }

    const fn allocated_with_missing_release_errno() -> Self {
        Self {
            retrieval_errno: None,
            release_failure_errno: Some(None),
            release_attempts: Cell::new(0),
        }
    }
}

impl NativeAcl for InjectedNativeAcl {
    fn retrieve(&self, _fd: std::os::fd::BorrowedFd<'_>) -> NativeRetrieval {
        match self.retrieval_errno {
            None => NativeRetrieval::Allocated(NativeAllocation(std::ptr::NonNull::dangling())),
            Some(errno) => NativeRetrieval::Null { errno },
        }
    }

    fn release(&self, allocation: NativeAllocation) -> NativeRelease {
        let _opaque_pointer = allocation.0.as_ptr();
        self.release_attempts
            .set(self.release_attempts.get().saturating_add(1));
        self.release_failure_errno
            .map_or(NativeRelease::Success, |errno| NativeRelease::Failure {
                errno,
            })
    }
}
