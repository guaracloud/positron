//! Descriptor-authoritative ACL policy for supported Unix targets.

use std::fs::File;

#[cfg(target_os = "linux")]
use rustix::fs as unix_fs;

use super::{LocalKeyFailure, LocalKeyFailureCode};

pub(super) const LINUX_ACCESS_ACL_XATTR_NAME: &[u8] = b"system.posix_acl_access";
pub(super) const LINUX_DEFAULT_ACL_XATTR_NAME: &[u8] = b"system.posix_acl_default";

#[cfg(target_os = "macos")]
pub(super) fn verify_directory_acl(directory: &File) -> Result<(), LocalKeyFailure> {
    verify_macos_acl(directory)
}

#[cfg(target_os = "macos")]
pub(super) fn verify_file_acl(file: &File) -> Result<(), LocalKeyFailure> {
    verify_macos_acl(file)
}

#[cfg(target_os = "macos")]
fn verify_macos_acl(file: &File) -> Result<(), LocalKeyFailure> {
    use std::os::fd::AsFd;

    match positron_darwin_acl::extended_acl_presence(file.as_fd()) {
        Ok(positron_darwin_acl::ExtendedAclPresence::Absent) => Ok(()),
        Ok(positron_darwin_acl::ExtendedAclPresence::Present) => {
            Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeAcl))
        },
        Err(positron_darwin_acl::AclInspectionError::Retrieve(
            positron_darwin_acl::AclInspectionEvidence::Unsupported(_),
        ))
        | Err(positron_darwin_acl::AclInspectionError::Release(
            positron_darwin_acl::AclInspectionEvidence::Unsupported(_),
        )) => Err(LocalKeyFailure::new(
            LocalKeyFailureCode::AclInspectionUnsupported,
        )),
        Err(_) => Err(LocalKeyFailure::new(
            LocalKeyFailureCode::AclInspectionFailed,
        )),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn verify_directory_acl(directory: &File) -> Result<(), LocalKeyFailure> {
    verify_linux_acl(directory, LINUX_ACCESS_ACL_XATTR_NAME)?;
    verify_linux_acl(directory, LINUX_DEFAULT_ACL_XATTR_NAME)
}

#[cfg(target_os = "linux")]
pub(super) fn verify_file_acl(file: &File) -> Result<(), LocalKeyFailure> {
    verify_linux_acl(file, LINUX_ACCESS_ACL_XATTR_NAME)
}

#[cfg(target_os = "linux")]
fn verify_linux_acl(file: &File, name: &[u8]) -> Result<(), LocalKeyFailure> {
    let mut probe = [0_u8; 1];
    let outcome = match unix_fs::fgetxattr(file, name, probe.as_mut_slice()) {
        Ok(_) => LinuxAclQueryOutcome::Present,
        Err(rustix::io::Errno::RANGE) => LinuxAclQueryOutcome::BufferTooSmall,
        Err(rustix::io::Errno::NODATA) => LinuxAclQueryOutcome::Absent,
        Err(rustix::io::Errno::OPNOTSUPP) => LinuxAclQueryOutcome::Unsupported,
        Err(_) => LinuxAclQueryOutcome::Unexpected,
    };
    classify_linux_acl_query(outcome)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxAclQueryOutcome {
    Absent,
    Present,
    BufferTooSmall,
    Unsupported,
    Unexpected,
}

pub(super) fn classify_linux_acl_query(
    outcome: LinuxAclQueryOutcome,
) -> Result<(), LocalKeyFailure> {
    match outcome {
        LinuxAclQueryOutcome::Absent => Ok(()),
        LinuxAclQueryOutcome::Present | LinuxAclQueryOutcome::BufferTooSmall => {
            Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeAcl))
        },
        LinuxAclQueryOutcome::Unsupported => Err(LocalKeyFailure::new(
            LocalKeyFailureCode::AclInspectionUnsupported,
        )),
        LinuxAclQueryOutcome::Unexpected => Err(LocalKeyFailure::new(
            LocalKeyFailureCode::AclInspectionFailed,
        )),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn verify_directory_acl(_directory: &File) -> Result<(), LocalKeyFailure> {
    Err(LocalKeyFailure::new(
        LocalKeyFailureCode::AclInspectionUnsupported,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn verify_file_acl(_file: &File) -> Result<(), LocalKeyFailure> {
    Err(LocalKeyFailure::new(
        LocalKeyFailureCode::AclInspectionUnsupported,
    ))
}
