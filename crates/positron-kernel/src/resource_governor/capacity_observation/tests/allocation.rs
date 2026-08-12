use std::io::Cursor;

use super::{AllocationControl, AllocationStage, BoundedBytes, BoundedPathBytes};
use crate::{CapacityObservationFailure, CapacityObservationSource};

#[test]
fn bounded_read_accepts_exact_maximum_and_rejects_one_more_byte() {
    let source = CapacityObservationSource::CgroupMounts;
    assert_eq!(
        BoundedBytes::read(Cursor::new([1_u8; 8]), 8, source, AllocationControl::NONE)
            .map(|bytes| bytes.as_slice().len()),
        Ok(8)
    );
    assert_eq!(
        BoundedBytes::read(Cursor::new([1_u8; 9]), 8, source, AllocationControl::NONE).map(|_| ()),
        Err(CapacityObservationFailure::ObservationUnavailable { source })
    );
}

#[test]
fn every_pre_governor_allocation_stage_is_deterministically_fallible() {
    let source = CapacityObservationSource::CgroupMounts;
    assert_eq!(
        BoundedBytes::read(
            Cursor::new([1_u8; 1]),
            8,
            source,
            AllocationControl::failing(AllocationStage::FileBuffer),
        )
        .map(|_| ()),
        Err(CapacityObservationFailure::AllocationUnavailable { source })
    );
    assert!(matches!(
        BoundedPathBytes::new(
            8,
            8,
            source,
            AllocationControl::failing(AllocationStage::ResolvedPath),
        ),
        Err(CapacityObservationFailure::AllocationUnavailable { .. })
    ));
}
