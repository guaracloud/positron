use rustix::process::{Resource, getrlimit};

use super::{
    CapacityObservationFailure, RegisteredResourceBounds, detected_descriptor_capacity,
    observe_file_descriptors, open_file_descriptor_count,
};
use crate::{InventoryCardinalityLimits, ResourceDimension};

#[test]
fn observed_descriptor_capacity_never_exceeds_current_soft_headroom_after_bootstrap() {
    let soft_limit = getrlimit(Resource::Nofile)
        .current
        .expect("the supported test host must expose a finite soft descriptor limit");
    let detected = observe_file_descriptors().expect("descriptor observation must succeed");
    let overhead = InventoryCardinalityLimits::new(1, 1)
        .and_then(|limits| limits.governor_bootstrap_overhead(1))
        .expect("one-tenant bootstrap inventory must be valid")
        .get(ResourceDimension::FileDescriptors);
    let work_ceiling = detected
        .checked_sub(overhead)
        .expect("observation reserves the fixed bootstrap descriptor overhead");
    let currently_open = open_file_descriptor_count().expect("open descriptor count succeeds");
    let current_headroom = soft_limit
        .checked_sub(currently_open)
        .expect("open descriptors remain beneath the soft limit");

    assert!(work_ceiling <= current_headroom);
}

#[test]
fn descriptor_equation_accounts_for_open_and_retained_volume_descriptors() {
    assert_eq!(detected_descriptor_capacity(100, 10), Ok(92));
    assert!(detected_descriptor_capacity(10, 11).is_err());
}

#[test]
fn registered_zero_reports_the_exact_abstract_dimension() {
    for (index, expected) in super::REGISTERED_DIMENSIONS.into_iter().enumerate() {
        let mut values = [1; 7];
        if let Some(value) = values.get_mut(index) {
            *value = 0;
        }
        assert_eq!(
            RegisteredResourceBounds::new(values),
            Err(CapacityObservationFailure::ZeroCapacity {
                dimension: expected
            })
        );
    }
}
