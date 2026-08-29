use std::cell::Cell;
use std::mem::size_of;

use super::{
    KERNEL_SUCCESS, MachHostApi, ProcFdInfo, VmStatistics64RevisionZero,
    allocate_file_descriptor_entries, file_descriptor_count_from_response,
    host_available_memory_bytes_with,
};
use crate::DarwinSystemObservationError;

struct FakeMachHostApi {
    page_status: i32,
    statistics_status: i32,
    deallocation_status: i32,
    page_size: usize,
    free_pages: u32,
    inactive_pages: u32,
    deallocations: Cell<u32>,
}

impl FakeMachHostApi {
    fn succeeding() -> Self {
        Self {
            page_status: KERNEL_SUCCESS,
            statistics_status: KERNEL_SUCCESS,
            deallocation_status: KERNEL_SUCCESS,
            page_size: 4,
            free_pages: 2,
            inactive_pages: 3,
            deallocations: Cell::new(0),
        }
    }
}

impl MachHostApi for FakeMachHostApi {
    fn host_self(&self) -> u32 {
        7
    }

    fn task_self(&self) -> u32 {
        11
    }

    fn page_size(&self, _host: u32, page_size: &mut usize) -> i32 {
        *page_size = self.page_size;
        self.page_status
    }

    fn statistics(
        &self,
        _host: u32,
        statistics: &mut VmStatistics64RevisionZero,
        _count: &mut u32,
    ) -> i32 {
        statistics.free_count = self.free_pages;
        statistics.inactive_count = self.inactive_pages;
        self.statistics_status
    }

    fn deallocate(&self, _task: u32, _host: u32) -> i32 {
        self.deallocations.set(self.deallocations.get() + 1);
        self.deallocation_status
    }
}

#[test]
fn descriptor_buffer_allocation_overflow_fails_closed() {
    assert!(matches!(
        allocate_file_descriptor_entries(usize::MAX),
        Err(DarwinSystemObservationError::FileDescriptorCountUnavailable)
    ));
}

#[test]
fn descriptor_response_is_bounded_and_structurally_valid() -> Result<(), Box<dyn std::error::Error>>
{
    let entry_bytes = i32::try_from(size_of::<ProcFdInfo>())?;
    let byte_capacity = entry_bytes.checked_mul(4).ok_or("fixture overflow")?;

    assert_eq!(
        file_descriptor_count_from_response(
            entry_bytes.checked_mul(3).ok_or("fixture overflow")?,
            byte_capacity
        ),
        Ok(3)
    );
    assert_eq!(
        file_descriptor_count_from_response(0, byte_capacity),
        Err(DarwinSystemObservationError::FileDescriptorCountUnavailable)
    );
    assert_eq!(
        file_descriptor_count_from_response(-1, byte_capacity),
        Err(DarwinSystemObservationError::FileDescriptorCountUnavailable)
    );
    assert_eq!(
        file_descriptor_count_from_response(entry_bytes - 1, byte_capacity),
        Err(DarwinSystemObservationError::FileDescriptorCountUnavailable)
    );
    assert_eq!(
        file_descriptor_count_from_response(byte_capacity, byte_capacity),
        Err(DarwinSystemObservationError::FileDescriptorCountExceedsBound)
    );
    assert_eq!(
        file_descriptor_count_from_response(
            byte_capacity
                .checked_add(entry_bytes)
                .ok_or("fixture overflow")?,
            byte_capacity,
        ),
        Err(DarwinSystemObservationError::FileDescriptorCountExceedsBound)
    );
    Ok(())
}

#[test]
fn deallocates_the_host_right_once_on_every_observation_exit() {
    let cases = [
        (
            FakeMachHostApi {
                page_status: 1,
                ..FakeMachHostApi::succeeding()
            },
            DarwinSystemObservationError::HostAvailableMemoryUnavailable,
        ),
        (
            FakeMachHostApi {
                statistics_status: 1,
                ..FakeMachHostApi::succeeding()
            },
            DarwinSystemObservationError::HostAvailableMemoryUnavailable,
        ),
        (
            FakeMachHostApi {
                page_size: usize::MAX,
                ..FakeMachHostApi::succeeding()
            },
            DarwinSystemObservationError::HostAvailableMemoryArithmetic,
        ),
    ];
    for (api, expected) in cases {
        assert_eq!(host_available_memory_bytes_with(&api), Err(expected));
        assert_eq!(api.deallocations.get(), 1);
    }

    let api = FakeMachHostApi::succeeding();
    assert_eq!(host_available_memory_bytes_with(&api), Ok(20));
    assert_eq!(api.deallocations.get(), 1);
}

#[test]
fn reports_host_right_deallocation_failure_once() {
    let api = FakeMachHostApi {
        deallocation_status: 1,
        ..FakeMachHostApi::succeeding()
    };
    assert_eq!(
        host_available_memory_bytes_with(&api),
        Err(DarwinSystemObservationError::HostPortDeallocationUnavailable)
    );
    assert_eq!(api.deallocations.get(), 1);
}
