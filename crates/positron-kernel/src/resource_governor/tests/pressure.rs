use positron_domain::identity::TenantId;
use positron_kernel::{
    AdmissionFailureCode, AdmissionRetry, DetectedCapacity, DiskObservation, DiskPressureState,
    DiskPressureThresholds, GovernorFailure, GovernorPolicy, InventoryCardinalityLimits,
    LimitingScope, OperatorLimits, OrdinaryPoolPolicy, RecoveryReserve, RecoveryWorkClaim,
    RecoveryWorkKind, ResourceAmounts, ResourceDimension, ResourceInventory, TenantQuota,
    WorkClaim, WorkClass, WorkKind,
};

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn tenant(byte: u8) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_bytes([byte; 16])?)
}

fn thresholds(
    hard_enter: u64,
    hard_exit: u64,
    soft_enter: u64,
    soft_exit: u64,
) -> Result<DiskPressureThresholds, GovernorFailure> {
    DiskPressureThresholds::new(hard_enter, hard_exit, soft_enter, soft_exit)
}

fn pool_policy() -> Result<OrdinaryPoolPolicy, GovernorFailure> {
    OrdinaryPoolPolicy::new(uniform(20), uniform(15), uniform(10), uniform(5))
}

fn establish(
    tenant: TenantId,
    initial_usable: u64,
) -> Result<TestKernel, Box<dyn std::error::Error>> {
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            32,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            32,
        )?)?,
        RecoveryReserve::new(uniform(10))?,
        InventoryCardinalityLimits::new(1, 32)?,
        thresholds(20, 30, 40, 50)?,
        DiskObservation::new(initial_usable),
    )?;
    TestKernel::establish(
        inventory,
        GovernorPolicy::new([TenantQuota::new(tenant, 1, uniform(90))?], pool_policy()?)?,
    )
}

#[test]
fn thresholds_and_initial_observation_are_checked_at_exact_edges()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        thresholds(20, 20, 40, 50),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        thresholds(20, 30, 29, 50),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        thresholds(20, 30, 40, 40),
        Err(GovernorFailure::InvalidConfiguration)
    );

    let tenant = tenant(51)?;
    let hard = establish(tenant, 20)?;
    assert_eq!(
        hard.inspect()?.disk_pressure(),
        DiskPressureState::HardPressure
    );
    let soft = establish(tenant, 40)?;
    assert_eq!(
        soft.inspect()?.disk_pressure(),
        DiskPressureState::SoftPressure
    );
    let healthy = establish(tenant, 41)?;
    assert_eq!(
        healthy.inspect()?.disk_pressure(),
        DiskPressureState::Healthy
    );
    Ok(())
}

#[test]
fn threshold_safety_headroom_and_detected_capacity_bound_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(52)?;
    let invalid_reserve_order = ResourceInventory::new(
        DetectedCapacity::new(uniform(100))?,
        OperatorLimits::new(uniform(100))?,
        RecoveryReserve::new(ResourceAmounts::new([
            10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 21,
        ]))?,
        InventoryCardinalityLimits::new(1, 2)?,
        thresholds(20, 30, 40, 50)?,
        DiskObservation::new(100),
    );
    assert_eq!(
        invalid_reserve_order,
        Err(GovernorFailure::InvalidConfiguration)
    );

    let invalid_detected_bound = ResourceInventory::new(
        DetectedCapacity::new(uniform(49))?,
        OperatorLimits::new(uniform(49))?,
        RecoveryReserve::new(uniform(10))?,
        InventoryCardinalityLimits::new(1, 2)?,
        thresholds(20, 30, 40, 50)?,
        DiskObservation::new(49),
    );
    assert_eq!(
        invalid_detected_bound,
        Err(GovernorFailure::InvalidConfiguration)
    );
    let governor = establish(tenant, 100)?;
    assert_eq!(governor.inspect()?.pressure_transition_count(), 0);
    assert_eq!(governor.inspect()?.usable_disk_bytes(), 100);
    assert_eq!(
        governor.observe_disk(DiskObservation::new(99))?,
        DiskPressureState::Healthy
    );
    assert_eq!(governor.inspect()?.usable_disk_bytes(), 99);
    assert_eq!(governor.inspect()?.pressure_transition_count(), 0);
    Ok(())
}

#[test]
fn pressure_transition_table_honors_hysteresis_and_exact_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    let governor = establish(tenant(53)?, 100)?;
    assert_eq!(
        governor.observe_disk(DiskObservation::new(40))?,
        DiskPressureState::SoftPressure
    );
    assert_eq!(
        governor.observe_disk(DiskObservation::new(41))?,
        DiskPressureState::SoftPressure
    );
    assert_eq!(
        governor.observe_disk(DiskObservation::new(50))?,
        DiskPressureState::Healthy
    );
    assert_eq!(
        governor.observe_disk(DiskObservation::new(20))?,
        DiskPressureState::HardPressure
    );
    assert_eq!(
        governor.observe_disk(DiskObservation::new(29))?,
        DiskPressureState::HardPressure
    );
    assert_eq!(
        governor.observe_disk(DiskObservation::new(30))?,
        DiskPressureState::SoftPressure
    );
    assert_eq!(
        governor.observe_disk(DiskObservation::new(20))?,
        DiskPressureState::HardPressure
    );
    assert_eq!(
        governor.observe_disk(DiskObservation::new(50))?,
        DiskPressureState::Healthy
    );
    assert_eq!(governor.inspect()?.pressure_transition_count(), 6);
    Ok(())
}

#[test]
fn soft_pressure_throttles_query_and_maintenance_but_preserves_ingest_and_security()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(54)?;
    let governor = establish(tenant, 40)?;
    let query = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 10)?,
    )?)?;
    let throttled = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("soft-pressure query may not borrow Shared");
    assert_pressure_failure(
        throttled,
        DiskPressureState::SoftPressure,
        WorkClass::InteractiveQueryTail,
        0,
    );
    let growing_maintenance = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::OrdinaryMaintenanceBackup,
            ResourceAmounts::only(ResourceDimension::DiskHeadroomBytes, 1)?,
        )?)
        .expect_err("disk-growing ordinary maintenance is stopped under soft pressure");
    assert_pressure_failure(
        growing_maintenance,
        DiskPressureState::SoftPressure,
        WorkClass::OrdinaryMaintenanceBackup,
        1,
    );
    let security = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::QueueSlots, 50)?,
    )?)?;
    let ingest = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::TaskSlots, 50)?,
    )?)?;
    drop((query, security, ingest));
    Ok(())
}

#[test]
fn hard_pressure_enforces_the_closed_admission_table_and_preserves_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(55)?;
    let kernel = establish(tenant, 20)?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let ingest = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("all new ingest stops under hard pressure");
    assert_pressure_failure(
        ingest,
        DiskPressureState::HardPressure,
        WorkClass::Ingest,
        0,
    );
    for kind in [
        WorkKind::SecurityLifecycle,
        WorkKind::InteractiveQueryTail,
        WorkKind::OrdinaryMaintenanceBackup,
    ] {
        let failure = governor
            .reserve(WorkClaim::tenant(
                tenant,
                kind,
                ResourceAmounts::only(ResourceDimension::DiskHeadroomBytes, 1)?,
            )?)
            .expect_err("ordinary disk growth stops under hard pressure");
        assert_pressure_failure(failure, DiskPressureState::HardPressure, kind.class(), 1);
    }
    let query = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 10)?,
    )?)?;
    let security = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::QueueSlots, 60)?,
    )?)?;
    let maintenance = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::OrdinaryMaintenanceBackup,
        ResourceAmounts::only(ResourceDimension::TaskSlots, 5)?,
    )?)?;
    let protected = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::EmergencyCompaction,
        ResourceAmounts::only(ResourceDimension::DiskHeadroomBytes, 1)?,
    )?)?;
    drop((query, security, maintenance, protected));
    Ok(())
}

#[test]
fn pressure_transition_never_revokes_an_existing_reservation()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(56)?;
    let governor = establish(tenant, 100)?;
    let grant = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 50)?,
    )?)?;
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    governor.observe_disk(DiskObservation::new(20))?;
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    drop(grant);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

fn assert_pressure_failure(
    failure: positron_kernel::AdmissionFailure,
    pressure: DiskPressureState,
    class: WorkClass,
    disk_growth: u64,
) {
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::DiskPressureAdmissionRefused
    );
    assert_eq!(failure.retry(), AdmissionRetry::AfterPressureTransition);
    assert_eq!(failure.limiting_scope(), LimitingScope::Policy);
    assert_eq!(failure.pressure_state(), pressure);
    assert_eq!(failure.work_class(), class);
    assert_eq!(
        failure.limiting_dimension(),
        Some(ResourceDimension::DiskHeadroomBytes)
    );
    assert_eq!(failure.requested(), disk_growth);
}
use super::resource_governor_test_support as resource_governor_support;
use resource_governor_support::TestKernel;
