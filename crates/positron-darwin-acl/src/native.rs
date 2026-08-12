//! Audited ownership wrapper around the two Apple ACL functions Positron uses.
//!
//! Safety invariants:
//! - the borrowed descriptor remains owned by the caller and is never closed or duplicated;
//! - the ACL type value is the SDK-defined `ACL_TYPE_EXTENDED` value;
//! - returned pointers remain opaque and are never dereferenced;
//! - a null pointer is never released;
//! - every non-null pointer is passed to `acl_free` exactly once;
//! - errno is captured immediately after a failed native call.

#![allow(
    unsafe_code,
    reason = "this isolated leaf is the reviewed Apple ACL FFI ownership boundary"
)]

use std::ffi::{c_int, c_uint, c_void};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;

use crate::{NativeAcl, NativeAllocation, NativeRelease, NativeRetrieval};

const ACL_TYPE_EXTENDED: c_uint = 0x0000_0100;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: c_uint) -> *mut c_void;
    fn acl_free(object: *mut c_void) -> c_int;
}

pub(crate) struct SystemNativeAcl;

impl NativeAcl for SystemNativeAcl {
    fn retrieve(&self, fd: BorrowedFd<'_>) -> NativeRetrieval {
        // SAFETY: `fd` is valid for this borrow and Apple documents that
        // `acl_get_fd_np` borrows rather than closes or duplicates it. The ACL
        // type exactly matches the SDK's `ACL_TYPE_EXTENDED` value.
        let pointer = unsafe { acl_get_fd_np(fd.as_raw_fd(), ACL_TYPE_EXTENDED) };
        NonNull::new(pointer).map_or_else(
            || NativeRetrieval::Null {
                errno: io::Error::last_os_error().raw_os_error(),
            },
            |allocation| NativeRetrieval::Allocated(NativeAllocation(allocation)),
        )
    }

    fn release(&self, allocation: NativeAllocation) -> NativeRelease {
        // SAFETY: `allocation` can only be constructed from a non-null pointer
        // returned by `acl_get_fd_np`, has never been released, and is consumed
        // here. The opaque allocation is never dereferenced.
        let result = unsafe { acl_free(allocation.0.as_ptr()) };
        if result == 0 {
            NativeRelease::Success
        } else {
            NativeRelease::Failure {
                errno: io::Error::last_os_error().raw_os_error(),
            }
        }
    }
}
