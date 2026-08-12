//! Descriptor-authoritative macOS extended-ACL inspection.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::num::NonZeroI32;
#[cfg(any(target_os = "macos", test))]
use std::os::fd::BorrowedFd;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtendedAclPresence {
    Absent,
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AclInspectionEvidence {
    Errno(NonZeroI32),
    MissingErrno,
    Unsupported(NonZeroI32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AclInspectionError {
    Retrieve(AclInspectionEvidence),
    Release(AclInspectionEvidence),
}

impl Display for AclInspectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("descriptor ACL inspection failed")
    }
}

impl Error for AclInspectionError {}

#[cfg(any(target_os = "macos", test))]
enum NativeRetrieval {
    Null { errno: Option<i32> },
    Allocated(NativeAllocation),
}

#[cfg(any(target_os = "macos", test))]
struct NativeAllocation(std::ptr::NonNull<std::ffi::c_void>);

#[cfg(any(target_os = "macos", test))]
enum NativeRelease {
    Success,
    Failure { errno: Option<i32> },
}

#[cfg(any(target_os = "macos", test))]
trait NativeAcl {
    fn retrieve(&self, fd: BorrowedFd<'_>) -> NativeRetrieval;
    fn release(&self, allocation: NativeAllocation) -> NativeRelease;
}

#[cfg(target_os = "macos")]
mod native;

#[cfg(test)]
mod tests;

#[cfg(target_os = "macos")]
pub fn extended_acl_presence(
    fd: BorrowedFd<'_>,
) -> Result<ExtendedAclPresence, AclInspectionError> {
    extended_acl_presence_with(fd, &native::SystemNativeAcl)
}

#[cfg(any(target_os = "macos", test))]
fn extended_acl_presence_with(
    fd: BorrowedFd<'_>,
    native: &impl NativeAcl,
) -> Result<ExtendedAclPresence, AclInspectionError> {
    match native.retrieve(fd) {
        NativeRetrieval::Allocated(allocation) => match native.release(allocation) {
            NativeRelease::Success => Ok(ExtendedAclPresence::Present),
            NativeRelease::Failure { errno } => {
                Err(AclInspectionError::Release(classify_failure(errno)))
            },
        },
        NativeRetrieval::Null { errno: Some(2) } => Ok(ExtendedAclPresence::Absent),
        NativeRetrieval::Null {
            errno: Some(errno @ (45 | 102)),
        } => {
            let evidence = NonZeroI32::new(errno).map_or(
                AclInspectionEvidence::MissingErrno,
                AclInspectionEvidence::Unsupported,
            );
            Err(AclInspectionError::Retrieve(evidence))
        },
        NativeRetrieval::Null { errno: Some(errno) } => {
            let evidence = NonZeroI32::new(errno).map_or(
                AclInspectionEvidence::MissingErrno,
                AclInspectionEvidence::Errno,
            );
            Err(AclInspectionError::Retrieve(evidence))
        },
        NativeRetrieval::Null { errno: None } => Err(AclInspectionError::Retrieve(
            AclInspectionEvidence::MissingErrno,
        )),
    }
}

#[cfg(any(target_os = "macos", test))]
fn classify_failure(errno: Option<i32>) -> AclInspectionEvidence {
    match errno {
        Some(errno @ (45 | 102)) => NonZeroI32::new(errno).map_or(
            AclInspectionEvidence::MissingErrno,
            AclInspectionEvidence::Unsupported,
        ),
        Some(errno) => NonZeroI32::new(errno).map_or(
            AclInspectionEvidence::MissingErrno,
            AclInspectionEvidence::Errno,
        ),
        None => AclInspectionEvidence::MissingErrno,
    }
}
