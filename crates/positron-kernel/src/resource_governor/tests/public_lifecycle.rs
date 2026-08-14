use positron_domain::identity::TenantId;
use positron_kernel::{
    AdmissionFailureCode, AdmissionRetry, DetectedCapacity, DiskObservation,
    DiskPressureThresholds, ExistingCapacityDisposition, GovernorLifecycle, GovernorPolicy,
    InventoryCardinalityLimits, OperatorLimits, OrdinaryPool, OrdinaryPoolPolicy, RecoveryReserve,
    RecoveryWorkClaim, RecoveryWorkKind, ReleaseOutcome, ResizeFailureCode, ResourceAmounts,
    ResourceDimension, ResourceInventory, TenantQuota, WorkClaim, WorkClass, WorkKind,
};

mod transfers;

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn tenant(byte: u8) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_bytes([byte; 16])?)
}

fn establish(tenant: TenantId) -> Result<TestKernel, Box<dyn std::error::Error>> {
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
        DiskObservation::new(100),
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
fn shutdown_closes_ordinary_and_checkpointable_recovery_but_allows_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(71)?;
    let kernel = establish(tenant)?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let first = governor.begin_shutdown()?;
    assert_eq!(first.lifecycle(), GovernorLifecycle::ShuttingDown);
    assert!(first.complete());

    let ordinary = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("new ordinary work closes at shutdown");
    assert_eq!(ordinary.code(), AdmissionFailureCode::ShuttingDown);
    assert_eq!(ordinary.retry(), AdmissionRetry::Never);

    for claim in [
        RecoveryWorkClaim::tenant(
            tenant,
            RecoveryWorkKind::Retention,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?,
        RecoveryWorkClaim::system(
            RecoveryWorkKind::EmergencyCompaction,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?,
        RecoveryWorkClaim::tenant(
            tenant,
            RecoveryWorkKind::Purge,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?,
        RecoveryWorkClaim::system(
            RecoveryWorkKind::Repair,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?,
        RecoveryWorkClaim::system(
            RecoveryWorkKind::Fencing,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?,
    ] {
        let failure = recovery
            .reserve(claim)
            .expect_err("checkpointable recovery closes at shutdown");
        assert_eq!(failure.code(), AdmissionFailureCode::ShuttingDown);
    }
    let durability = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let safe_shutdown = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    drop((durability, safe_shutdown));
    Ok(())
}

#[test]
fn existing_grants_shrink_and_drop_while_shutdown_growth_obeys_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(72)?;
    let kernel = establish(tenant)?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let mut ordinary = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 20)?,
    )?)?;
    let mut checkpointable = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 10)?,
    )?)?;
    let mut durability = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 10)?,
    )?)?;
    governor.begin_shutdown()?;

    ordinary.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 10)?)?;
    let ordinary_growth = ordinary
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 11)?)
        .expect_err("ordinary growth during shutdown cancels the grant");
    assert_eq!(ordinary_growth.code(), ResizeFailureCode::AdmissionRefused);
    assert_eq!(
        ordinary_growth.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    assert_eq!(ordinary.cancel()?, ReleaseOutcome::AlreadyInactive);

    let checkpointable_growth = checkpointable
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 11)?)
        .expect_err("checkpointable recovery growth during shutdown cancels");
    assert_eq!(
        checkpointable_growth.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    assert_eq!(checkpointable.cancel()?, ReleaseOutcome::AlreadyInactive);
    durability.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 11)?)?;
    assert!(durability.is_active());
    drop(durability);
    assert!(governor.inspect()?.complete());
    Ok(())
}

#[test]
fn reconciliation_is_idempotent_fixed_and_complete_only_when_drained()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(73)?;
    let kernel = establish(tenant)?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let ordinary = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let durability = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let first = governor.begin_shutdown()?;
    let second = governor.begin_shutdown()?;
    assert_eq!(first, second);
    assert_eq!(first.outstanding_total(), 2);
    assert_eq!(first.outstanding_ordinary(), 1);
    assert_eq!(first.outstanding_recovery(), 1);
    assert_eq!(first.outstanding_uninterruptible(), 1);
    assert_eq!(first.outstanding_for(WorkClass::InteractiveQueryTail), 1);
    assert_eq!(first.outstanding_for(WorkClass::DurabilityRecovery), 1);
    assert!(!first.complete());
    assert_eq!(first.maximum_outstanding(), 16);
    assert_eq!(first.usage(ResourceDimension::MemoryBytes), 2);
    assert_eq!(first.reserve_consumption(ResourceDimension::MemoryBytes), 0);
    assert_eq!(
        first.pool_capacity(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        40
    );
    assert_eq!(
        first.pool_usage(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        1
    );
    assert_eq!(
        first.disk_pressure(),
        positron_kernel::DiskPressureState::Healthy
    );
    assert_eq!(first.pressure_transition_count(), 0);
    drop((ordinary, durability));
    let drained = governor.begin_shutdown()?;
    assert!(drained.complete());
    assert_eq!(drained.outstanding_total(), 0);
    assert_eq!(drained.rejection_count(), 0);
    Ok(())
}

#[test]
fn explicit_cancel_reports_exact_release_and_never_double_releases()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(74)?;
    let governor = establish(tenant)?;
    let mut grant = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
    )?)?;
    assert_eq!(grant.cancel()?, ReleaseOutcome::Released);
    assert_eq!(governor.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn bounded_observations_report_capacity_pressure_and_stable_refusal_reasons()
-> Result<(), Box<dyn std::error::Error>> {
    let registered = tenant(75)?;
    let foreign = tenant(76)?;
    let governor = establish(registered)?;

    governor
        .reserve(WorkClaim::tenant(
            foreign,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("foreign tenant records one non-throttling rejection");
    governor.observe_disk(DiskObservation::new(20))?;
    governor
        .reserve(WorkClaim::tenant(
            registered,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("hard-pressure ingest records one pressure throttle");
    governor.observe_disk(DiskObservation::new(100))?;
    let mut query = governor.reserve(WorkClaim::tenant(
        registered,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 50)?,
    )?)?;
    query
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 51)?)
        .expect_err("failed resize records its exact class-capacity reason");

    let snapshot = governor.inspect()?;
    let expected_bootstrap =
        InventoryCardinalityLimits::new(1, 16)?.governor_bootstrap_overhead(1)?;
    assert_eq!(snapshot.rejection_count(), 3);
    assert_eq!(
        snapshot.rejection_count_for(AdmissionFailureCode::UnregisteredTenant),
        1
    );
    assert_eq!(
        snapshot.throttle_count_for(AdmissionFailureCode::UnregisteredTenant),
        0
    );
    assert_eq!(
        snapshot.rejection_count_for(AdmissionFailureCode::DiskPressureAdmissionRefused),
        1
    );
    assert_eq!(
        snapshot.throttle_count_for(AdmissionFailureCode::DiskPressureAdmissionRefused),
        1
    );
    assert_eq!(
        snapshot.rejection_count_for(AdmissionFailureCode::ClassCapacityUnavailable),
        1
    );
    assert_eq!(
        snapshot.throttle_count_for(AdmissionFailureCode::ClassCapacityUnavailable),
        1
    );
    assert_eq!(
        snapshot.effective_capacity(ResourceDimension::MemoryBytes),
        100 + expected_bootstrap.get(ResourceDimension::MemoryBytes)
    );
    assert_eq!(
        snapshot.governor_bootstrap_overhead(ResourceDimension::MemoryBytes),
        expected_bootstrap.get(ResourceDimension::MemoryBytes)
    );
    assert_eq!(
        snapshot.ordinary_capacity(ResourceDimension::MemoryBytes),
        90
    );
    assert_eq!(
        snapshot.recovery_reserve_capacity(ResourceDimension::MemoryBytes),
        10
    );
    assert_eq!(
        snapshot.effective_capacity(ResourceDimension::MemoryBytes),
        snapshot.governor_bootstrap_overhead(ResourceDimension::MemoryBytes)
            + snapshot.ordinary_capacity(ResourceDimension::MemoryBytes)
            + snapshot.recovery_reserve_capacity(ResourceDimension::MemoryBytes)
    );
    assert_eq!(
        snapshot.governor_bootstrap_overhead(ResourceDimension::FileDescriptors),
        2
    );
    assert_eq!(
        snapshot.effective_capacity(ResourceDimension::FileDescriptors),
        snapshot.governor_bootstrap_overhead(ResourceDimension::FileDescriptors)
            + snapshot.ordinary_capacity(ResourceDimension::FileDescriptors)
            + snapshot.recovery_reserve_capacity(ResourceDimension::FileDescriptors)
    );
    assert_eq!(snapshot.usable_disk_bytes(), 100);
    for reason in [
        AdmissionFailureCode::CapacityExhausted,
        AdmissionFailureCode::TenantQuotaExceeded,
        AdmissionFailureCode::UnregisteredTenant,
        AdmissionFailureCode::OutstandingReservationLimit,
        AdmissionFailureCode::ProtectedCapacityUnavailable,
        AdmissionFailureCode::ClassCapacityUnavailable,
        AdmissionFailureCode::TenantFairShareExceeded,
        AdmissionFailureCode::CapacityOccupiedByRecovery,
        AdmissionFailureCode::DiskPressureAdmissionRefused,
        AdmissionFailureCode::RecoveryReserveExhausted,
        AdmissionFailureCode::ShuttingDown,
        AdmissionFailureCode::InternalFenced,
    ] {
        assert!(snapshot.throttle_count_for(reason) <= snapshot.rejection_count_for(reason));
    }

    let reconciliation = governor.begin_shutdown()?;
    assert_eq!(
        reconciliation.rejection_count_for(AdmissionFailureCode::ClassCapacityUnavailable),
        1
    );
    assert_eq!(
        reconciliation.throttle_count_for(AdmissionFailureCode::ClassCapacityUnavailable),
        1
    );
    assert_eq!(
        reconciliation.effective_capacity(ResourceDimension::MemoryBytes),
        100 + expected_bootstrap.get(ResourceDimension::MemoryBytes)
    );
    assert_eq!(
        reconciliation.ordinary_capacity(ResourceDimension::MemoryBytes),
        90
    );
    assert_eq!(
        reconciliation.recovery_reserve_capacity(ResourceDimension::MemoryBytes),
        10
    );
    assert_eq!(reconciliation.usable_disk_bytes(), 100);
    Ok(())
}
use super::resource_governor_test_support as resource_governor_support;
use resource_governor_support::TestKernel;
