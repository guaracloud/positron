use std::cell::Cell;
use std::fs::File;
use std::os::fd::AsFd;

use super::*;

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
