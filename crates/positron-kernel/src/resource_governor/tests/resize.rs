use positron_domain::identity::TenantId;
use positron_kernel::{
    AdmissionFailureCode, AdmissionRetry, DetectedCapacity, DiskObservation, DiskPressureState,
    DiskPressureThresholds, ExistingCapacityDisposition, GovernorPolicy,
    InventoryCardinalityLimits, LimitingScope, OperatorLimits, OrdinaryPool, OrdinaryPoolPolicy,
    RecoveryReserve, RecoveryWorkClaim, RecoveryWorkKind, ResizeFailureCode, ResourceAmounts,
    ResourceDimension, ResourceInventory, TenantQuota, WorkClaim, WorkClass, WorkKind,
};

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn tenant(byte: u8) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_bytes([byte; 16])?)
}

fn establish(
    tenant: TenantId,
    initial_disk: u64,
) -> Result<TestKernel, Box<dyn std::error::Error>> {
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            16,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            16,
        )?)?,
        RecoveryReserve::new(uniform(10))?,
        InventoryCardinalityLimits::new(1, 16)?,
        DiskPressureThresholds::new(20, 30, 40, 50)?,
        DiskObservation::new(initial_disk),
    )?;
    TestKernel::establish(
        inventory,
        GovernorPolicy::new(
            [TenantQuota::new(tenant, 1, uniform(90))?],
            OrdinaryPoolPolicy::new(uniform(20), uniform(15), uniform(10), uniform(5))?,
        )?,
    )
}

#[test]
fn ordinary_growth_and_mixed_resize_replan_exact_pool_charges()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(61)?;
    let governor = establish(tenant, 100)?;
    let mut grant = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 30)?,
    )?)?;
    let grown = grant.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 45)?)?;
    assert_eq!(grown.added().get(ResourceDimension::MemoryBytes), 15);
    assert_eq!(grown.released().get(ResourceDimension::MemoryBytes), 0);
    assert_eq!(grant.granted().get(ResourceDimension::MemoryBytes), 45);

    let mixed = grant.try_resize(ResourceAmounts::new([25, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0]))?;
    assert_eq!(mixed.released().get(ResourceDimension::MemoryBytes), 20);
    assert_eq!(mixed.added().get(ResourceDimension::QueueSlots), 25);
    let snapshot = governor.inspect()?;
    assert_eq!(
        snapshot.pool_usage(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        25
    );
    assert_eq!(
        snapshot.pool_usage(OrdinaryPool::Shared, ResourceDimension::QueueSlots),
        25
    );
    assert_eq!(
        snapshot.pool_usage(
            OrdinaryPool::InteractiveQueryTail,
            ResourceDimension::MemoryBytes,
        ),
        0
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    Ok(())
}

#[test]
fn pure_shrink_succeeds_under_hard_pressure_and_releases_immediately()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(62)?;
    let governor = establish(tenant, 100)?;
    let mut grant = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 50)?,
    )?)?;
    assert_eq!(
        governor.observe_disk(DiskObservation::new(20))?,
        DiskPressureState::HardPressure
    );
    let outcome = grant.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 10)?)?;
    assert_eq!(outcome.released().get(ResourceDimension::MemoryBytes), 40);
    assert_eq!(outcome.added().get(ResourceDimension::MemoryBytes), 0);
    assert!(grant.is_active());
    assert_eq!(grant.granted().get(ResourceDimension::MemoryBytes), 10);
    Ok(())
}

#[test]
fn interruptible_growth_failure_cancels_old_grant_and_frees_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(63)?;
    let governor = establish(tenant, 100)?;
    let mut grant = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 50)?,
    )?)?;
    let failure = grant
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 51)?)
        .expect_err("query growth beyond Shared plus protected pool cancels its grant");
    assert_eq!(failure.code(), ResizeFailureCode::AdmissionRefused);
    assert_eq!(
        failure.admission_code(),
        Some(AdmissionFailureCode::ClassCapacityUnavailable)
    );
    assert_eq!(
        failure.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    assert!(!grant.is_active());
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    let replacement = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 50)?,
    )?)?;
    drop(replacement);
    Ok(())
}

#[test]
fn durability_growth_failure_retains_exact_existing_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(64)?;
    let kernel = establish(tenant, 100)?;
    let recovery = kernel.recovery();
    let mut grant = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 91)?,
    )?)?;
    let failure = grant
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 101)?)
        .expect_err("uninterruptible durability growth cannot exceed total capacity");
    assert_eq!(failure.code(), ResizeFailureCode::AdmissionRefused);
    assert_eq!(
        failure.existing_capacity(),
        ExistingCapacityDisposition::CapacityRetained
    );
    assert!(grant.is_active());
    assert_eq!(grant.granted().get(ResourceDimension::MemoryBytes), 91);
    let blocked = recovery
        .reserve(RecoveryWorkClaim::system(
            RecoveryWorkKind::Repair,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 10)?,
        )?)
        .expect_err("the retained durability grant still occupies capacity");
    assert_eq!(
        blocked.code(),
        AdmissionFailureCode::RecoveryReserveExhausted
    );
    Ok(())
}

#[test]
fn system_recovery_resize_updates_reserve_consumption() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(65)?;
    let kernel = establish(tenant, 100)?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let mut grant = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 80)?,
    )?)?;
    assert_eq!(
        governor
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        0
    );
    grant.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 91)?)?;
    assert_eq!(
        governor
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        1
    );
    grant.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 40)?)?;
    assert_eq!(
        governor
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        0
    );
    Ok(())
}

#[test]
fn system_recovery_shrink_and_pressure_refused_ordinary_growth_are_exact()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(67)?;
    let kernel = establish(tenant, 100)?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let mut system = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 20)?,
    )?)?;
    let shrink = system.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 10)?)?;
    assert_eq!(shrink.released().get(ResourceDimension::MemoryBytes), 10);
    assert_eq!(shrink.added().get(ResourceDimension::MemoryBytes), 0);

    let mut ingest = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    assert_eq!(
        governor.observe_disk(DiskObservation::new(20))?,
        DiskPressureState::HardPressure
    );
    let pressure = ingest
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?)
        .expect_err("hard pressure cancels interruptible ingest growth");
    assert_eq!(
        pressure.admission_code(),
        Some(AdmissionFailureCode::DiskPressureAdmissionRefused)
    );
    assert_eq!(pressure.retry(), AdmissionRetry::AfterPressureTransition);
    assert_eq!(pressure.limiting_scope(), LimitingScope::Policy);
    assert_eq!(pressure.pressure_state(), DiskPressureState::HardPressure);
    assert_eq!(pressure.work_class(), WorkClass::Ingest);
    assert_eq!(
        pressure.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    drop(system);
    assert_eq!(governor.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn tenant_recovery_capacity_failure_cancels_and_releases_attribution()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(68)?;
    let kernel = establish(tenant, 100)?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let mut repair = recovery.reserve(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
    )?)?;
    let failure = repair
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 101)?)
        .expect_err("interruptible tenant recovery cancels on total exhaustion");
    assert_eq!(
        failure.admission_code(),
        Some(AdmissionFailureCode::TenantQuotaExceeded)
    );
    assert_eq!(
        failure.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    assert!(!repair.is_active());
    assert_eq!(governor.inspect()?.outstanding_total(), 0);

    let replacement = recovery.reserve(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 90)?,
    )?)?;
    drop(replacement);
    assert_eq!(governor.inspect()?.usage(ResourceDimension::MemoryBytes), 0);
    Ok(())
}

#[test]
fn invalid_or_inactive_resize_is_typed_and_max_arithmetic_is_panic_free()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(66)?;
    let governor = establish(tenant, 100)?;
    let mut grant = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let invalid = grant
        .try_resize(ResourceAmounts::new([0; 11]))
        .expect_err("empty replacement is invalid");
    assert_eq!(invalid.code(), ResizeFailureCode::InvalidRequest);
    assert_eq!(invalid.admission_code(), None);
    assert_eq!(invalid.retry(), AdmissionRetry::Never);
    assert_eq!(invalid.limiting_scope(), LimitingScope::Policy);
    assert_eq!(invalid.pressure_state(), DiskPressureState::Healthy);
    assert_eq!(invalid.work_class(), WorkClass::Ingest);
    assert_eq!(invalid.limiting_dimension(), None);
    assert_eq!(invalid.allowed(), 0);
    assert_eq!(invalid.in_use(), 0);
    assert_eq!(invalid.requested(), 0);
    assert_eq!(
        invalid.to_string(),
        "resource reservation resize incomplete"
    );
    assert_eq!(
        invalid.existing_capacity(),
        ExistingCapacityDisposition::CapacityRetained
    );
    assert!(grant.is_active());
    let overflow = grant
        .try_resize(ResourceAmounts::only(
            ResourceDimension::MemoryBytes,
            u64::MAX,
        )?)
        .expect_err("maximum request refuses without arithmetic panic");
    assert_eq!(overflow.code(), ResizeFailureCode::AdmissionRefused);
    assert_eq!(
        overflow.admission_code(),
        Some(AdmissionFailureCode::CapacityExhausted)
    );
    assert_eq!(overflow.retry(), AdmissionRetry::AfterCapacityRelease);
    assert_eq!(overflow.limiting_scope(), LimitingScope::Global);
    assert_eq!(overflow.pressure_state(), DiskPressureState::Healthy);
    assert_eq!(overflow.work_class(), WorkClass::Ingest);
    assert_eq!(
        overflow.limiting_dimension(),
        Some(ResourceDimension::MemoryBytes)
    );
    assert_eq!(overflow.allowed(), 100);
    assert_eq!(overflow.in_use(), 0);
    assert_eq!(overflow.requested(), u64::MAX);
    assert_eq!(
        overflow.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    let inactive = grant
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?)
        .expect_err("cancelled handle cannot resize again");
    assert_eq!(inactive.code(), ResizeFailureCode::InactiveReservation);
    assert_eq!(inactive.admission_code(), None);
    assert_eq!(inactive.retry(), AdmissionRetry::Never);
    assert_eq!(inactive.limiting_scope(), LimitingScope::Internal);
    assert_eq!(
        inactive.existing_capacity(),
        ExistingCapacityDisposition::NoActiveCapacity
    );
    Ok(())
}

#[test]
fn every_resize_refusal_reports_pressure_at_its_decision_point()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(69)?;
    let governor = establish(tenant, 100)?;
    let mut grant = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    governor.observe_disk(DiskObservation::new(20))?;

    let invalid = grant
        .try_resize(ResourceAmounts::new([0; 11]))
        .expect_err("invalid resize still reports the current pressure state");
    assert_eq!(invalid.pressure_state(), DiskPressureState::HardPressure);

    let refused = grant
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?)
        .expect_err("hard pressure refuses ingest growth");
    assert_eq!(refused.pressure_state(), DiskPressureState::HardPressure);
    let inactive = grant
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?)
        .expect_err("inactive resize reports the same current state");
    assert_eq!(inactive.pressure_state(), DiskPressureState::HardPressure);
    Ok(())
}

#[test]
fn ordinary_disk_growth_uses_the_latest_live_headroom() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(70)?;
    let governor = establish(tenant, 100)?;
    let mut grant = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::DiskHeadroomBytes, 10)?,
    )?)?;
    grant.try_resize(ResourceAmounts::only(
        ResourceDimension::DiskHeadroomBytes,
        20,
    )?)?;
    governor.observe_disk(DiskObservation::new(20))?;
    let failure = grant
        .try_resize(ResourceAmounts::only(
            ResourceDimension::DiskHeadroomBytes,
            21,
        )?)
        .expect_err("ordinary disk growth cannot exceed live usable bytes");
    assert_eq!(
        failure.admission_code(),
        Some(AdmissionFailureCode::CapacityExhausted)
    );
    assert_eq!(failure.pressure_state(), DiskPressureState::HardPressure);
    assert_eq!(failure.allowed(), 20);
    assert_eq!(failure.in_use(), 0);
    assert_eq!(failure.requested(), 21);
    Ok(())
}
use super::resource_governor_test_support as resource_governor_support;
use resource_governor_support::TestKernel;
