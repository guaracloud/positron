//! Audited FFI boundary for the three Apple observations Positron uses.
//!
//! Safety invariants:
//! - `sysctlbyname` writes only to an initialized `u64` with its exact size;
//! - `os_proc_available_memory` returns a value and borrows no caller memory;
//! - `proc_pidinfo` writes into a fixed, initialized array of the documented
//!   `proc_fdinfo` layout, and returned byte counts are validated before use;
//! - no pointer escapes this module and no native allocation is retained.

#![allow(
    unsafe_code,
    reason = "this isolated leaf is the reviewed Apple host-observation FFI boundary"
)]

use std::ffi::{c_char, c_int, c_void};
use std::mem::size_of;

use crate::{DarwinSystemObservationError, checked_host_available_memory_bytes};

const PROC_PIDLISTFDS: c_int = 1;
const MAX_OBSERVED_FILE_DESCRIPTORS: usize = 4_096;
const HOST_VM_INFO64: c_int = 4;
const KERNEL_SUCCESS: c_int = 0;

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct VmStatistics64RevisionZero {
    free_count: u32,
    active_count: u32,
    inactive_count: u32,
    wire_count: u32,
    zero_fill_count: u64,
    reactivations: u64,
    pageins: u64,
    pageouts: u64,
    faults: u64,
    cow_faults: u64,
    lookups: u64,
    hits: u64,
    purges: u64,
    purgeable_count: u32,
    speculative_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFdInfo {
    descriptor: c_int,
    descriptor_type: u32,
}

unsafe extern "C" {
    fn sysctlbyname(
        name: *const c_char,
        old_value: *mut c_void,
        old_length: *mut usize,
        new_value: *mut c_void,
        new_length: usize,
    ) -> c_int;
    fn os_proc_available_memory() -> usize;
    fn getpid() -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        argument: u64,
        buffer: *mut c_void,
        buffer_size: c_int,
    ) -> c_int;
    fn mach_host_self() -> u32;
    static mach_task_self_: u32;
    fn mach_port_deallocate(task: u32, name: u32) -> c_int;
    fn host_page_size(host: u32, page_size: *mut usize) -> c_int;
    fn host_statistics64(
        host: u32,
        flavor: c_int,
        statistics: *mut c_int,
        count: *mut u32,
    ) -> c_int;
}

trait MachHostApi {
    fn host_self(&self) -> u32;
    fn task_self(&self) -> u32;
    fn page_size(&self, host: u32, page_size: &mut usize) -> c_int;
    fn statistics(
        &self,
        host: u32,
        statistics: &mut VmStatistics64RevisionZero,
        count: &mut u32,
    ) -> c_int;
    fn deallocate(&self, task: u32, host: u32) -> c_int;
}

struct NativeMachHostApi;

impl MachHostApi for NativeMachHostApi {
    fn host_self(&self) -> u32 {
        // SAFETY: `mach_host_self` takes no pointers and returns a send right
        // name for the calling task.
        unsafe { mach_host_self() }
    }

    fn task_self(&self) -> u32 {
        // SAFETY: this reads the libSystem-exported current-task port name.
        unsafe { mach_task_self_ }
    }

    fn page_size(&self, host: u32, page_size: &mut usize) -> c_int {
        // SAFETY: `page_size` is writable and `host` is the acquired right.
        unsafe { host_page_size(host, page_size) }
    }

    fn statistics(
        &self,
        host: u32,
        statistics: &mut VmStatistics64RevisionZero,
        count: &mut u32,
    ) -> c_int {
        // SAFETY: `statistics` is the revision-zero prefix and `count`
        // describes its capacity in integer_t units.
        unsafe {
            host_statistics64(
                host,
                HOST_VM_INFO64,
                (statistics as *mut VmStatistics64RevisionZero).cast(),
                count,
            )
        }
    }

    fn deallocate(&self, task: u32, host: u32) -> c_int {
        // SAFETY: both arguments are Mach port names owned by this task.
        unsafe { mach_port_deallocate(task, host) }
    }
}

struct HostSendRight<'api, Api: MachHostApi> {
    api: &'api Api,
    host: u32,
    active: bool,
}

impl<'api, Api: MachHostApi> HostSendRight<'api, Api> {
    fn acquire(api: &'api Api) -> Self {
        Self {
            api,
            host: api.host_self(),
            active: true,
        }
    }

    fn name(&self) -> u32 {
        self.host
    }

    fn close(mut self) -> Result<(), DarwinSystemObservationError> {
        let status = self.api.deallocate(self.api.task_self(), self.host);
        self.active = false;
        if status == KERNEL_SUCCESS {
            Ok(())
        } else {
            Err(DarwinSystemObservationError::HostPortDeallocationUnavailable)
        }
    }
}

impl<Api: MachHostApi> Drop for HostSendRight<'_, Api> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.api.deallocate(self.api.task_self(), self.host);
            self.active = false;
        }
    }
}

pub(super) fn physical_memory_bytes() -> Result<u64, DarwinSystemObservationError> {
    let mut value = 0_u64;
    let mut length = size_of::<u64>();
    // SAFETY: the static name is NUL-terminated, `value` and `length` are
    // writable for their exact declared sizes, and no input buffer is passed.
    let status = unsafe {
        sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&mut value as *mut u64).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 || length != size_of::<u64>() || value == 0 {
        return Err(DarwinSystemObservationError::PhysicalMemoryUnavailable);
    }
    Ok(value)
}

pub(super) fn maximum_file_descriptor_count() -> Result<u64, DarwinSystemObservationError> {
    let mut value = 0_u32;
    let mut length = size_of::<u32>();
    // SAFETY: the static name is NUL-terminated, `value` and `length` are
    // writable for their exact declared sizes, and no input buffer is passed.
    let status = unsafe {
        sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut value as *mut u32).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 || length != size_of::<u32>() || value == 0 {
        return Err(DarwinSystemObservationError::FileDescriptorCeilingUnavailable);
    }
    Ok(u64::from(value))
}

pub(super) fn process_available_memory_bytes() -> Result<Option<u64>, DarwinSystemObservationError>
{
    // SAFETY: this Apple function takes no pointers and returns the current
    // process's available-memory estimate by value.
    let available = unsafe { os_proc_available_memory() };
    let available = u64::try_from(available)
        .map_err(|_| DarwinSystemObservationError::PhysicalMemoryUnavailable)?;
    // Apple specifies zero for callers that are not apps. Positron is a
    // standalone process, so zero means there is no app-specific tighter
    // ceiling to combine with the host's physical-memory ceiling.
    Ok((available != 0).then_some(available))
}

pub(super) fn host_available_memory_bytes() -> Result<u64, DarwinSystemObservationError> {
    host_available_memory_bytes_with(&NativeMachHostApi)
}

fn host_available_memory_bytes_with<Api: MachHostApi>(
    api: &Api,
) -> Result<u64, DarwinSystemObservationError> {
    let host = HostSendRight::acquire(api);
    let mut page_size = 0_usize;
    if api.page_size(host.name(), &mut page_size) != KERNEL_SUCCESS {
        return Err(DarwinSystemObservationError::HostAvailableMemoryUnavailable);
    }

    let mut statistics = VmStatistics64RevisionZero::default();
    let integer_count = size_of::<VmStatistics64RevisionZero>()
        .checked_div(size_of::<c_int>())
        .and_then(|count| u32::try_from(count).ok())
        .ok_or(DarwinSystemObservationError::HostAvailableMemoryArithmetic)?;
    let mut returned_count = integer_count;
    let status = api.statistics(host.name(), &mut statistics, &mut returned_count);
    if status != KERNEL_SUCCESS || returned_count < integer_count {
        return Err(DarwinSystemObservationError::HostAvailableMemoryUnavailable);
    }

    let page_size = u64::try_from(page_size)
        .map_err(|_| DarwinSystemObservationError::HostAvailableMemoryArithmetic)?;
    let available = checked_host_available_memory_bytes(
        u64::from(statistics.free_count),
        u64::from(statistics.inactive_count),
        page_size,
    )?;
    host.close()?;
    Ok(available)
}

pub(super) fn open_file_descriptor_count() -> Result<u64, DarwinSystemObservationError> {
    let mut entries = [ProcFdInfo {
        descriptor: -1,
        descriptor_type: 0,
    }; MAX_OBSERVED_FILE_DESCRIPTORS];
    let byte_capacity = entries
        .len()
        .checked_mul(size_of::<ProcFdInfo>())
        .and_then(|bytes| c_int::try_from(bytes).ok())
        .ok_or(DarwinSystemObservationError::FileDescriptorCountUnavailable)?;
    // SAFETY: `entries` is a writable initialized array of the documented
    // `proc_fdinfo` layout, and `byte_capacity` exactly describes it.
    let returned = unsafe {
        proc_pidinfo(
            getpid(),
            PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast(),
            byte_capacity,
        )
    };
    if returned <= 0 {
        return Err(DarwinSystemObservationError::FileDescriptorCountUnavailable);
    }
    if returned == byte_capacity {
        return Err(DarwinSystemObservationError::FileDescriptorCountExceedsBound);
    }
    let returned = usize::try_from(returned)
        .map_err(|_| DarwinSystemObservationError::FileDescriptorCountUnavailable)?;
    if returned % size_of::<ProcFdInfo>() != 0 {
        return Err(DarwinSystemObservationError::FileDescriptorCountUnavailable);
    }
    u64::try_from(returned / size_of::<ProcFdInfo>())
        .map_err(|_| DarwinSystemObservationError::FileDescriptorCountUnavailable)
}

#[cfg(test)]
mod tests;
