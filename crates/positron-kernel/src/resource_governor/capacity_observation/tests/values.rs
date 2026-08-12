use super::{v1_cpu, v1_memory, v2_cpu, v2_memory};
use crate::{CapacityObservationFailure, CapacityObservationSource, ResourceDimension};

#[test]
fn parses_finite_and_unlimited_cpu_and_memory_values() {
    assert_eq!(v2_cpu(b"50000 100000\n"), Ok(Some(500)));
    assert_eq!(v2_cpu(b"125000 100000\n"), Ok(Some(1_250)));
    assert_eq!(v2_cpu(b"1 3\n"), Ok(Some(333)));
    assert_eq!(v2_cpu(b"max 100000\n"), Ok(None));
    assert_eq!(v1_cpu(b"-1\n", b"100000\n"), Ok(None));
    assert_eq!(v1_cpu(b"25000\n", b"100000\n"), Ok(Some(250)));
    assert_eq!(v2_memory(b"1000\n", b"400\n"), Ok(Some(600)));
    assert_eq!(v2_memory(b"max\n", b"400\n"), Ok(None));
    assert_eq!(v1_memory(b"1000\n", b"400\n"), Ok(Some(600)));
}

#[test]
fn rejects_zero_negative_overflow_and_usage_above_limit() {
    assert_eq!(
        v2_cpu(b"0 100000\n"),
        Err(CapacityObservationFailure::MalformedLimit {
            source: CapacityObservationSource::CgroupCpu
        })
    );
    assert_eq!(
        v2_cpu(b"1 1000000\n"),
        Err(CapacityObservationFailure::ZeroCapacity {
            dimension: ResourceDimension::CpuWorkUnits
        })
    );
    assert_eq!(
        v1_cpu(b"-2\n", b"100000\n"),
        Err(CapacityObservationFailure::MalformedLimit {
            source: CapacityObservationSource::CgroupCpu
        })
    );
    assert_eq!(
        v2_cpu(format!("{} 1\n", u64::MAX).as_bytes()),
        Err(CapacityObservationFailure::Arithmetic {
            source: CapacityObservationSource::CgroupCpu
        })
    );
    assert_eq!(
        v2_memory(b"100\n", b"101\n"),
        Err(CapacityObservationFailure::Arithmetic {
            source: CapacityObservationSource::CgroupMemory
        })
    );
    assert_eq!(
        v1_memory(b"-1\n", b"0\n"),
        Err(CapacityObservationFailure::MalformedLimit {
            source: CapacityObservationSource::CgroupMemory
        })
    );
}
