use std::mem::size_of;
use std::sync::atomic::{AtomicU8, AtomicU64};

use positron_domain::identity::TenantId;

use super::*;
use crate::resource_governor::accounting::KernelOwnership;
use crate::resource_governor::ledger::GrantRecord;
use crate::resource_governor::{
    DetectedCapacity, DiskObservation, DiskPressureThresholds, GovernorPolicy,
    InventoryCardinalityLimits, OperatorLimits, OrdinaryPoolPolicy, RecoveryPoolCapacities,
    RecoveryReserve, ResourceGovernorConfiguration, ResourceInventory,
};

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn tenant() -> TenantId {
    TenantId::from_bytes([97; 16]).expect("test tenant is valid")
}

fn pools() -> OrdinaryPoolPolicy {
    OrdinaryPoolPolicy::new(uniform(20), uniform(15), uniform(10), uniform(5))
        .expect("pool policy is valid")
}

fn recovery_pools() -> RecoveryPoolCapacities {
    RecoveryPoolCapacities::new(
        uniform(2),
        uniform(1),
        uniform(2),
        uniform(1),
        uniform(2),
        uniform(1),
        uniform(1),
    )
    .expect("recovery pools are valid")
}

fn inventory() -> ResourceInventory {
    let cardinality = InventoryCardinalityLimits::new(1, 8).expect("cardinality is valid");
    let overhead = cardinality
        .governor_bootstrap_overhead(1)
        .expect("bootstrap layout is valid");
    let mut raw = uniform(1_000);
    for dimension in ResourceDimension::ALL {
        raw = raw.with_amount(
            dimension,
            raw.get(dimension)
                .checked_add(overhead.get(dimension))
                .expect("test capacity fits"),
        );
    }
    ResourceInventory::new(
        DetectedCapacity::new(raw).expect("capacity is valid"),
        OperatorLimits::new(raw).expect("capacity is valid"),
        RecoveryReserve::new(uniform(10)).expect("reserve is valid"),
        cardinality,
        DiskPressureThresholds::new(20, 30, 40, 50).expect("thresholds are valid"),
        DiskObservation::new(1_000),
    )
    .expect("inventory is valid")
}

fn policy() -> GovernorPolicy {
    GovernorPolicy::new(
        [TenantQuota::new(tenant(), 1, uniform(990)).expect("quota is valid")],
        pools(),
    )
    .expect("policy is valid")
}

#[test]
fn every_named_bootstrap_allocation_stage_fails_with_typed_inventory() {
    let policy_required = policy_payload_requirement(1).expect("policy payload is bounded");
    assert_eq!(
        GovernorPolicy::new_failing_allocation(
            [TenantQuota::new(tenant(), 1, uniform(990)).expect("quota is valid")],
            pools(),
        )
        .expect_err("injected policy allocation must fail"),
        GovernorFailure::GovernorBootstrapInventoryUnavailable {
            required: policy_required,
        }
    );
    assert_eq!(policy_required.get(ResourceDimension::FileDescriptors), 0);

    let required = InventoryCardinalityLimits::new(1, 8)
        .expect("cardinality is valid")
        .governor_bootstrap_overhead(1)
        .expect("bootstrap layout is valid");
    for stage in CONFIGURATION_ALLOCATION_STAGES {
        assert!(matches!(
            ResourceGovernorConfiguration::new_failing_allocation(
                inventory(),
                policy(),
                recovery_pools(),
                stage,
            ),
            Err(GovernorFailure::GovernorBootstrapInventoryUnavailable { required: observed })
                if observed == required
        ));
    }
}

#[test]
fn tenant_payload_growth_enumerates_all_nine_retained_tables() {
    let one = BootstrapInventoryLayout::new(1, 8).expect("layout is valid");
    let maximum = BootstrapInventoryLayout::new(1_024, 8).expect("layout is valid");
    let per_tenant = [
        size_of::<TenantQuota>(),
        size_of::<PoolCapacities>(),
        size_of::<ResourceAmounts>(),
        size_of::<RecoveryPoolCapacities>(),
        size_of::<ResourceAmounts>(),
        size_of::<ResourceAmounts>(),
        size_of::<RecoveryPoolUsage>(),
        size_of::<PoolCapacities>(),
        size_of::<u32>(),
    ]
    .into_iter()
    .sum::<usize>();
    let expected_delta = 1_023_u64
        .checked_mul(u64::try_from(per_tenant).expect("element sum fits"))
        .expect("bounded delta fits");
    assert_eq!(maximum.memory_bytes() - one.memory_bytes(), expected_delta);
    assert_eq!(one.overhead().get(ResourceDimension::FileDescriptors), 2);
    assert_eq!(
        maximum.overhead().get(ResourceDimension::FileDescriptors),
        2
    );
    assert!(fixed_root_bytes_for_test() > fixed_accounting_state_bytes_for_test());
}

#[test]
fn ledger_payload_growth_enumerates_all_four_retained_tables() {
    let one = BootstrapInventoryLayout::new(1, 1).expect("layout is valid");
    let sixty_five = BootstrapInventoryLayout::new(1, 65).expect("layout is valid");
    let slot_bytes = size_of::<AtomicU8>() + size_of::<Option<GrantRecord>>() + size_of::<u16>();
    let expected_delta = 64_usize
        .checked_mul(slot_bytes)
        .and_then(|bytes| bytes.checked_add(size_of::<AtomicU64>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .expect("bounded delta fits");
    assert_eq!(
        sixty_five.memory_bytes() - one.memory_bytes(),
        expected_delta
    );
}

#[test]
fn layout_arithmetic_overflow_is_rejected_without_allocation() {
    assert_eq!(
        BootstrapInventoryLayout::new(usize::MAX, u32::MAX),
        Err(GovernorFailure::InvalidConfiguration)
    );
}

#[test]
fn zero_bootstrap_cardinalities_are_rejected_before_allocation() {
    assert_eq!(
        BootstrapInventoryLayout::new(0, 1),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        BootstrapInventoryLayout::new(1, 0),
        Err(GovernorFailure::InvalidConfiguration)
    );
}

#[test]
fn establishment_moves_every_retained_payload_without_reallocation() {
    let configuration = ResourceGovernorConfiguration::new(inventory(), policy(), recovery_pools())
        .expect("configuration is valid");
    let before = configuration.inner.payload_addresses_for_test();
    let active_segment_scopes_before = configuration.active_segment_scopes.as_ptr();
    let authority = StorageKernelResourceAuthority::from_configuration(
        KernelOwnership::TestOnly,
        configuration,
    );
    let after = authority.inner.payload_addresses_for_test();
    assert_eq!(after, before);
    assert_eq!(
        authority
            .active_segment_scopes
            .lock()
            .expect("scope inventory lock is available")
            .as_ptr(),
        active_segment_scopes_before
    );
}
