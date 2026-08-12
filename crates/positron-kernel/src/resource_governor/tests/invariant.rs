use positron_domain::identity::TenantId;

use super::*;
use crate::resource_governor::accounting::ChargeAttribution;
use crate::resource_governor::policy::{PoolCapacities, PoolCharge};
use crate::resource_governor::recovery_policy::{RecoveryPoolCharge, RecoveryPoolUsage};

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; RESOURCE_DIMENSION_COUNT])
}

fn recovery_pools() -> RecoveryPoolCapacities {
    let minimum = uniform(1);
    let dual = uniform(2);
    RecoveryPoolCapacities::new(dual, minimum, dual, minimum, dual, minimum, minimum)
        .expect("recovery pools are valid")
}

fn established() -> (StorageKernelResourceAuthority, TenantId) {
    let tenant = TenantId::from_bytes([93; 16]).expect("test tenant is valid");
    let cardinality = InventoryCardinalityLimits::new(1, 8).expect("cardinality is valid");
    let overhead = cardinality
        .governor_bootstrap_overhead(1)
        .expect("bootstrap layout is valid");
    let mut raw = uniform(100);
    for dimension in ResourceDimension::ALL {
        raw = raw.with_amount(
            dimension,
            100_u64
                .checked_add(overhead.get(dimension))
                .expect("raw capacity fits"),
        );
    }
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(raw).expect("capacity is valid"),
        OperatorLimits::new(raw).expect("capacity is valid"),
        RecoveryReserve::new(uniform(10)).expect("reserve is valid"),
        cardinality,
        DiskPressureThresholds::new(20, 30, 40, 50).expect("thresholds are valid"),
        DiskObservation::new(100),
    )
    .expect("inventory is valid");
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(90)).expect("quota is valid")],
        OrdinaryPoolPolicy::new(uniform(20), uniform(15), uniform(10), uniform(5))
            .expect("pool policy is valid"),
    )
    .expect("policy is valid");
    let authority =
        StorageKernelResourceAuthority::establish_for_test(inventory, policy, recovery_pools())
            .expect("establishment succeeds");
    (authority, tenant)
}

fn with_ordinary<R>(
    test: impl FnOnce(&StorageKernelResourceAuthority, ResourceReservation<'_>) -> R,
) -> R {
    let (authority, tenant) = established();
    let grant = authority
        .reserve(
            WorkClaim::tenant(
                tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 2).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect("admission succeeds");
    test(&authority, grant)
}

fn assert_internal_resize(mut grant: ResourceReservation<'_>) {
    let failure = grant
        .try_resize(
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
        )
        .expect_err("corrupted accounting must fail closed");
    assert_eq!(failure.code(), ResizeFailureCode::InternalFenced);
    assert_eq!(
        failure.existing_capacity(),
        ExistingCapacityDisposition::CapacityRetained
    );
}

fn assert_internal_admission(governor: &StorageKernelResourceAuthority, tenant: TenantId) {
    let failure = governor
        .reserve(
            WorkClaim::tenant(
                tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect_err("corrupted accounting must reject admission");
    assert_eq!(failure.code(), AdmissionFailureCode::InternalFenced);
    assert_eq!(
        governor
            .inspect()
            .expect("fenced state remains inspectable")
            .lifecycle(),
        GovernorLifecycle::Fenced
    );
}

#[test]
fn mismatched_resize_ownership_and_missing_pool_charge_fail_closed() {
    with_ordinary(|_, mut mismatched| {
        mismatched.owner.attribution = ChargeAttribution::Recovery { tenant_index: None };
        assert_internal_resize(mismatched);
    });

    with_ordinary(|_, mut missing_pool| {
        missing_pool.owner.pools = None;
        assert_internal_resize(missing_pool);
    });

    let (governor, _) = established();
    let recovery = governor.recovery();
    let mut recovery_grant = recovery
        .reserve(
            RecoveryWorkClaim::system(
                RecoveryWorkKind::Repair,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 2).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect("admission succeeds");
    recovery_grant.owner.attribution = ChargeAttribution::Ordinary { tenant_index: 0 };
    assert_internal_resize(recovery_grant);

    let (missing_pool_governor, _) = established();
    let recovery = missing_pool_governor.recovery();
    let mut missing_recovery_pool = recovery
        .reserve(
            RecoveryWorkClaim::system(
                RecoveryWorkKind::Repair,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect("admission succeeds");
    missing_recovery_pool.owner.recovery_pools = None;
    assert_internal_resize(missing_recovery_pool);
    drop(governor);
}

#[test]
fn corrupted_ordinary_resize_conservation_fails_closed_at_each_boundary() {
    for corruption in 0..5 {
        with_ordinary(|governor, mut grant| {
            {
                let mut state = governor.inner.state.lock().expect("test lock is healthy");
                match corruption {
                    0 => state.total_usage = ResourceAmounts::zero(),
                    1 => state.ordinary_tenant_usage[0] = ResourceAmounts::zero(),
                    2 => state.pool_usage = PoolCapacities::zero(),
                    3 => state.ordinary_tenant_pool_usage[0] = PoolCapacities::zero(),
                    _ => {
                        grant.owner.pools = Some(PoolCharge::new(
                            OrdinaryPool::Ingest,
                            ResourceAmounts::zero(),
                            ResourceAmounts::zero(),
                        ));
                    },
                }
            }
            assert_internal_resize(grant);
        });
    }
}

#[test]
fn corrupted_recovery_resize_conservation_fails_closed_at_each_boundary() {
    for corruption in 0..5 {
        let (governor, tenant) = established();
        let recovery = governor.recovery();
        let grant = recovery
            .reserve(
                RecoveryWorkClaim::tenant(
                    tenant,
                    RecoveryWorkKind::Repair,
                    ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)
                        .expect("amount is valid"),
                )
                .expect("claim is valid"),
            )
            .expect("admission succeeds");
        {
            let mut state = governor.inner.state.lock().expect("test lock is healthy");
            match corruption {
                0 => state.total_usage = ResourceAmounts::zero(),
                1 => state.recovery_usage = ResourceAmounts::zero(),
                2 => state.recovery_tenant_usage[0] = ResourceAmounts::zero(),
                3 => state.recovery_pool_usage = RecoveryPoolUsage::zero(),
                _ => state.recovery_tenant_pool_usage[0] = RecoveryPoolUsage::zero(),
            }
        }
        assert_internal_resize(grant);
    }

    let (governor, tenant) = established();
    let recovery = governor.recovery();
    let mut overflow = recovery
        .reserve(
            RecoveryWorkClaim::tenant(
                tenant,
                RecoveryWorkKind::Repair,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect("admission succeeds");
    governor
        .inner
        .state
        .lock()
        .expect("test lock is healthy")
        .recovery_tenant_usage[0] =
        ResourceAmounts::only(ResourceDimension::MemoryBytes, u64::MAX).expect("amount is valid");
    let failure = overflow
        .try_resize(
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 3).expect("amount is valid"),
        )
        .expect_err("tenant accounting overflow must fail closed");
    assert_eq!(failure.code(), ResizeFailureCode::InternalFenced);
}

#[test]
fn corrupted_release_conservation_fails_closed_at_each_boundary() {
    for corruption in 0..5 {
        with_ordinary(|governor, mut grant| {
            {
                let mut state = governor.inner.state.lock().expect("test lock is healthy");
                match corruption {
                    0 => state.total_usage = ResourceAmounts::zero(),
                    1 => state.class_counts[2] = 0,
                    2 => state.outstanding_ordinary = 0,
                    3 => state.pool_usage = PoolCapacities::zero(),
                    _ => grant.owner.pools = None,
                }
            }
            assert_eq!(grant.cancel(), Err(GovernorFailure::InternalFenced));
        });
    }

    for corruption in 0..4 {
        let (governor, _) = established();
        let recovery = governor.recovery();
        let mut grant = recovery
            .reserve(
                RecoveryWorkClaim::system(
                    RecoveryWorkKind::Repair,
                    ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                        .expect("amount is valid"),
                )
                .expect("claim is valid"),
            )
            .expect("admission succeeds");
        {
            let mut state = governor.inner.state.lock().expect("test lock is healthy");
            match corruption {
                0 => state.recovery_usage = ResourceAmounts::zero(),
                1 => state.recovery_pool_usage = RecoveryPoolUsage::zero(),
                2 => state.recovery_system_pool_usage = RecoveryPoolUsage::zero(),
                _ => grant.owner.recovery_pools = None,
            }
        }
        assert_eq!(grant.cancel(), Err(GovernorFailure::InternalFenced));
    }

    for corruption in 0..2 {
        let (governor, tenant) = established();
        let recovery = governor.recovery();
        let mut grant = recovery
            .reserve(
                RecoveryWorkClaim::tenant(
                    tenant,
                    RecoveryWorkKind::Repair,
                    ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                        .expect("amount is valid"),
                )
                .expect("claim is valid"),
            )
            .expect("admission succeeds");
        {
            let mut state = governor.inner.state.lock().expect("test lock is healthy");
            if corruption == 0 {
                state.recovery_tenant_usage[0] = ResourceAmounts::zero();
            } else {
                state.recovery_tenant_pool_usage[0] = RecoveryPoolUsage::zero();
            }
        }
        assert_eq!(grant.cancel(), Err(GovernorFailure::InternalFenced));
    }
}

#[test]
fn corrupted_release_tables_fail_closed_without_partial_success() {
    for corruption in 0..3 {
        with_ordinary(|governor, mut grant| {
            {
                let mut state = governor.inner.state.lock().expect("test lock is healthy");
                match corruption {
                    0 => state.tenant_outstanding = Box::new([]),
                    1 => state.ordinary_tenant_usage = Box::new([]),
                    _ => state.ordinary_tenant_pool_usage = Box::new([]),
                }
            }
            assert_eq!(grant.cancel(), Err(GovernorFailure::InternalFenced));
        });
    }

    let (governor, tenant) = established();
    let recovery = governor.recovery();
    let mut grant = recovery
        .reserve(
            RecoveryWorkClaim::tenant(
                tenant,
                RecoveryWorkKind::Repair,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect("admission succeeds");
    governor
        .inner
        .state
        .lock()
        .expect("test lock is healthy")
        .recovery_tenant_pool_usage = Box::new([]);
    assert_eq!(grant.cancel(), Err(GovernorFailure::InternalFenced));
}

#[test]
fn corrupted_resize_tables_fail_closed_before_replacement() {
    for corruption in 0..2 {
        with_ordinary(|governor, mut grant| {
            {
                let mut state = governor.inner.state.lock().expect("test lock is healthy");
                if corruption == 0 {
                    state.ordinary_tenant_usage = Box::new([]);
                } else {
                    state.ordinary_tenant_pool_usage = Box::new([]);
                }
            }
            assert_eq!(
                grant
                    .try_resize(
                        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                            .expect("amount is valid")
                    )
                    .expect_err("missing ordinary resize table must fence")
                    .code(),
                ResizeFailureCode::InternalFenced
            );
        });
    }

    for corruption in 0..3 {
        let (governor, tenant) = established();
        let recovery = governor.recovery();
        let mut grant = recovery
            .reserve(
                RecoveryWorkClaim::tenant(
                    tenant,
                    RecoveryWorkKind::Repair,
                    ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                        .expect("amount is valid"),
                )
                .expect("claim is valid"),
            )
            .expect("admission succeeds");
        {
            let mut state = governor.inner.state.lock().expect("test lock is healthy");
            match corruption {
                0 => state.recovery_tenant_usage = Box::new([]),
                1 => state.recovery_tenant_pool_usage = Box::new([]),
                _ => state.ordinary_tenant_usage = Box::new([]),
            }
        }
        assert_eq!(
            grant
                .try_resize(
                    ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)
                        .expect("amount is valid")
                )
                .expect_err("missing recovery resize table must fence")
                .code(),
            ResizeFailureCode::InternalFenced
        );
    }
}

#[test]
fn overflowing_recovery_failure_evidence_is_internal_and_fenced() {
    let zero = ResourceAmounts::zero();
    let one = uniform(1);
    let maximum = uniform(u64::MAX);
    let empty_usage = RecoveryPoolUsage::zero();
    let allowed_overflow = super::recovery_admission::recovery_pool_failure(
        super::recovery_policy::RecoveryPoolLimit::Global(ResourceDimension::MemoryBytes),
        false,
        RecoveryWorkKind::Repair,
        one,
        maximum,
        one,
        empty_usage,
        zero,
        (zero, zero, empty_usage, zero),
        DiskPressureState::Healthy,
    );
    assert_eq!(
        allowed_overflow.code(),
        AdmissionFailureCode::InternalFenced
    );

    let occupied = empty_usage
        .checked_add(RecoveryPoolCharge {
            kind: RecoveryWorkKind::Repair,
            shared: maximum,
            protected: zero,
        })
        .expect("maximum usage is representable");
    let usage_overflow = super::recovery_admission::recovery_pool_failure(
        super::recovery_policy::RecoveryPoolLimit::Global(ResourceDimension::MemoryBytes),
        false,
        RecoveryWorkKind::Repair,
        one,
        one,
        one,
        occupied,
        one,
        (zero, zero, empty_usage, zero),
        DiskPressureState::Healthy,
    );
    assert_eq!(usage_overflow.code(), AdmissionFailureCode::InternalFenced);
}

#[test]
fn replacement_helper_rejects_an_invalid_index_without_mutation() {
    let mut values = [1_u8, 2_u8];
    assert!(!super::resize::replace_at(&mut values, 2, 3));
    assert_eq!(values, [1, 2]);
}

#[test]
fn closed_internal_helpers_cover_invalid_inputs_without_fabricating_authority() {
    assert_eq!(
        AdmissionFailureCode::from_index(AdmissionFailureCode::COUNT),
        None
    );
    assert_eq!(OrdinaryPool::for_class(WorkClass::DurabilityRecovery), None);
    assert_eq!(PoolCapacities::zero().fair_share(0, 1), None);
    assert_eq!(PoolCapacities::zero().fair_share(1, 0), None);
    assert!(
        super::resize_types::ResizeFailure::inactive(
            WorkClass::Ingest,
            DiskPressureState::Healthy,
        )
        .admission_failure()
        .is_none()
    );
    assert_eq!(
        GovernorFailure::GovernorBootstrapInventoryUnavailable {
            required: ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                .expect("amount is valid"),
        }
        .to_string(),
        "resource governor bootstrap inventory is unavailable"
    );
    assert_eq!(
        GovernorFailure::SystemRecoveryProgressUnavailable {
            kind: RecoveryWorkKind::Fencing,
            dimension: ResourceDimension::MemoryBytes,
        }
        .to_string(),
        "resource governor system recovery progress is unavailable"
    );

    let over_occupied = super::decision::refuse_ordinary_capacity(
        WorkClass::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
        super::decision::OrdinaryCapacity {
            ordinary_usage: ResourceAmounts::zero(),
            recovery_shared_usage: ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)
                .expect("amount is valid"),
            ordinary_ceiling: ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                .expect("amount is valid"),
            total_ceiling: uniform(10),
            pressure: DiskPressureState::Healthy,
        },
    )
    .expect_err("recovery occupancy above ordinary capacity is corrupt");
    assert_eq!(over_occupied.code(), AdmissionFailureCode::InternalFenced);

    let pool_failure = super::pool_admission::plan_pool_charge(
        WorkClass::DurabilityRecovery,
        uniform(1),
        super::pool_admission::PoolAdmission {
            global_capacity: PoolCapacities::zero(),
            global_usage: PoolCapacities::zero(),
            tenant_capacity: PoolCapacities::zero(),
            tenant_usage: PoolCapacities::zero(),
        },
        DiskPressureState::Healthy,
        true,
    )
    .expect_err("recovery class cannot use ordinary pools");
    assert_eq!(pool_failure.code(), AdmissionFailureCode::InternalFenced);

    let pressure_failure = super::pool_admission::pressure_eligibility(
        DiskPressureState::HardPressure,
        WorkClass::DurabilityRecovery,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
    )
    .expect_err("ordinary pressure table rejects recovery class");
    assert_eq!(
        pressure_failure.code(),
        AdmissionFailureCode::DiskPressureAdmissionRefused
    );
}

#[test]
fn corrupted_ordinary_admission_fences_at_every_mutable_boundary() {
    for corruption in 0..10 {
        let (mut governor, tenant) = established();
        if corruption == 9 {
            governor.inner.recovery_tenant_shared_fair = Box::new([]);
        } else {
            let mut state = governor.inner.state.lock().expect("test lock is healthy");
            match corruption {
                0 => {
                    state.recovery_usage = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                        .expect("amount is valid")
                },
                1 => state.ordinary_tenant_usage = Box::new([]),
                2 => state.ordinary_tenant_pool_usage = Box::new([]),
                3 => {
                    state.pool_usage = PoolCapacities::zero().with(
                        OrdinaryPool::Shared,
                        ResourceAmounts::only(ResourceDimension::MemoryBytes, 41)
                            .expect("amount is valid"),
                    )
                },
                4 => state.outstanding_ordinary = u32::MAX,
                5 => state.class_counts[2] = u32::MAX,
                6 => state.tenant_outstanding[0] = u32::MAX,
                7 => state.recovery_tenant_pool_usage = Box::new([]),
                _ => {
                    state.ordinary_tenant_usage[0] =
                        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                            .expect("amount is valid");
                    state.recovery_tenant_pool_usage[0] = RecoveryPoolUsage::zero()
                        .checked_add(RecoveryPoolCharge {
                            kind: RecoveryWorkKind::Retention,
                            shared: ResourceAmounts::only(ResourceDimension::MemoryBytes, u64::MAX)
                                .expect("amount is valid"),
                            protected: ResourceAmounts::zero(),
                        })
                        .expect("synthetic corruption is representable");
                },
            }
        }
        assert_internal_admission(&governor, tenant);
    }
}

#[test]
fn exhausted_slot_inventory_fences_despite_healthy_outstanding_counters() {
    let (governor, tenant) = established();
    governor
        .inner
        .state
        .lock()
        .expect("test lock is healthy")
        .free_slots
        .clear();
    assert_internal_admission(&governor, tenant);
}

#[test]
fn invalid_explicit_release_slot_fences_after_exact_accounting_release() {
    with_ordinary(|governor, mut grant| {
        grant.slot = u16::MAX;
        assert_eq!(grant.cancel(), Err(GovernorFailure::InternalFenced));
        let snapshot = governor
            .inspect()
            .expect("fenced state remains inspectable");
        assert_eq!(snapshot.lifecycle(), GovernorLifecycle::Fenced);
        assert_eq!(snapshot.outstanding_total(), 0);
        std::mem::forget(grant);
    });
}

#[test]
fn recovery_slot_inventory_exhaustion_and_invalid_resize_slot_fail_closed() {
    let (governor, tenant) = established();
    let recovery = governor.recovery();
    governor
        .inner
        .state
        .lock()
        .expect("test lock is healthy")
        .free_slots
        .clear();
    let failure = recovery
        .reserve(
            RecoveryWorkClaim::tenant(
                tenant,
                RecoveryWorkKind::Repair,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect_err("missing slot inventory must fail closed");
    assert_eq!(failure.code(), AdmissionFailureCode::InternalFenced);

    with_ordinary(|ordinary_governor, mut ordinary| {
        ordinary.slot = u16::MAX;
        assert_eq!(
            ordinary
                .try_resize(
                    ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                        .expect("amount is valid")
                )
                .expect_err("invalid slot must fence")
                .code(),
            ResizeFailureCode::InternalFenced
        );
        assert_eq!(
            ordinary_governor
                .inspect()
                .expect("fenced state remains inspectable")
                .lifecycle(),
            GovernorLifecycle::Fenced
        );
        std::mem::forget(ordinary);
    });

    let (recovery_governor, _) = established();
    let recovery = recovery_governor.recovery();
    let mut recovery_grant = recovery
        .reserve(
            RecoveryWorkClaim::system(
                RecoveryWorkKind::Repair,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect("admission succeeds");
    recovery_grant.slot = u16::MAX;
    assert_eq!(
        recovery_grant
            .try_resize(
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 2).expect("amount is valid")
            )
            .expect_err("invalid recovery slot must fence")
            .code(),
        ResizeFailureCode::InternalFenced
    );
    assert_eq!(
        recovery_governor
            .inspect()
            .expect("fenced state remains inspectable")
            .lifecycle(),
        GovernorLifecycle::Fenced
    );
    std::mem::forget(recovery_grant);
}

#[test]
fn corrupted_recovery_admission_fences_at_every_mutable_boundary() {
    for corruption in 0..9 {
        let (governor, tenant) = established();
        let recovery = governor.recovery();
        {
            let mut state = governor.inner.state.lock().expect("test lock is healthy");
            match corruption {
                0 => {
                    state.recovery_usage =
                        ResourceAmounts::only(ResourceDimension::MemoryBytes, u64::MAX)
                            .expect("amount is valid")
                },
                1 => state.recovery_tenant_usage = Box::new([]),
                2 => state.outstanding_recovery = u32::MAX,
                3 => state.outstanding_uninterruptible = u32::MAX,
                4 => state.class_counts[0] = u32::MAX,
                5 => {
                    state.recovery_usage = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                        .expect("amount is valid")
                },
                6 => state.ordinary_tenant_usage = Box::new([]),
                7 => state.tenant_outstanding[0] = u32::MAX,
                _ => {
                    state.recovery_pool_usage = RecoveryPoolUsage::zero();
                    state.recovery_pool_usage = state
                        .recovery_pool_usage
                        .checked_add(RecoveryPoolCharge {
                            kind: RecoveryWorkKind::Repair,
                            shared: uniform(100),
                            protected: ResourceAmounts::zero(),
                        })
                        .expect("synthetic corruption is representable");
                },
            }
        }
        let kind = if corruption == 3 {
            RecoveryWorkKind::DurabilityCompletion
        } else {
            RecoveryWorkKind::Repair
        };
        let failure = recovery
            .reserve(
                RecoveryWorkClaim::tenant(
                    tenant,
                    kind,
                    ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                        .expect("amount is valid"),
                )
                .expect("claim is valid"),
            )
            .expect_err("corrupted accounting must reject recovery admission");
        assert_eq!(failure.code(), AdmissionFailureCode::InternalFenced);
        assert_eq!(
            governor
                .inspect()
                .expect("fenced state remains inspectable")
                .lifecycle(),
            GovernorLifecycle::Fenced
        );
    }
}

#[test]
fn cancellation_reconciliation_underflow_fences_and_retains_the_handle() {
    for corruption in 0..3 {
        with_ordinary(|governor, mut grant| {
            {
                let mut state = governor.inner.state.lock().expect("test lock is healthy");
                match corruption {
                    0 => state.outstanding = 0,
                    1 => state.outstanding_ordinary = 0,
                    _ => state.class_counts[2] = 0,
                }
            }
            let failure = grant
                .try_resize(
                    ResourceAmounts::only(ResourceDimension::MemoryBytes, 100)
                        .expect("amount is valid"),
                )
                .expect_err("failed cancellation reconciliation must fence");
            assert_eq!(failure.code(), ResizeFailureCode::InternalFenced);
            assert!(grant.is_active());
        });
    }
}

#[test]
fn cancellation_reconciliation_missing_tenant_count_fences_and_retains_handle() {
    with_ordinary(|governor, mut grant| {
        governor
            .inner
            .state
            .lock()
            .expect("test lock is healthy")
            .tenant_outstanding = Box::new([]);
        let failure = grant
            .try_resize(
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 100)
                    .expect("amount is valid"),
            )
            .expect_err("missing cancellation table must fence");
        assert_eq!(failure.code(), ResizeFailureCode::InternalFenced);
        assert!(grant.is_active());
    });
}

#[test]
fn recovery_cancellation_reconciliation_underflow_fences_and_retains_the_handle() {
    for corruption in 0..3 {
        let (governor, _) = established();
        let recovery = governor.recovery();
        let mut grant = recovery
            .reserve(
                RecoveryWorkClaim::system(
                    RecoveryWorkKind::Repair,
                    ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                        .expect("amount is valid"),
                )
                .expect("claim is valid"),
            )
            .expect("admission succeeds");
        {
            let mut state = governor.inner.state.lock().expect("test lock is healthy");
            match corruption {
                0 => state.outstanding = 0,
                1 => state.outstanding_recovery = 0,
                _ => state.class_counts[0] = 0,
            }
        }
        let failure = grant
            .try_resize(
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 101)
                    .expect("amount is valid"),
            )
            .expect_err("failed cancellation reconciliation must fence");
        assert_eq!(failure.code(), ResizeFailureCode::InternalFenced);
        assert!(grant.is_active());
    }
}

#[test]
fn pre_fenced_and_poisoned_resize_retain_existing_capacity() {
    with_ordinary(|ordinary_governor, ordinary| {
        ordinary_governor
            .inner
            .state
            .lock()
            .expect("test lock is healthy")
            .lifecycle = GovernorLifecycle::Fenced;
        assert_internal_resize(ordinary);
    });

    let (governor, _) = established();
    let recovery = governor.recovery();
    let recovery_grant = recovery
        .reserve(
            RecoveryWorkClaim::system(
                RecoveryWorkKind::Repair,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect("admission succeeds");
    governor
        .inner
        .state
        .lock()
        .expect("test lock is healthy")
        .lifecycle = GovernorLifecycle::Fenced;
    assert_internal_resize(recovery_grant);

    let (poisoned_governor, _) = established();
    let poisoned_recovery = poisoned_governor.recovery();
    let poisoned_grant = poisoned_recovery
        .reserve(
            RecoveryWorkClaim::system(
                RecoveryWorkKind::Repair,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect("admission succeeds");
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poisoned_governor.inner.poison_for_test();
    }));
    assert!(poisoned.is_err());
    assert_internal_resize(poisoned_grant);
}
