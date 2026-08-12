use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Barrier;

use positron_domain::identity::TenantId;

use super::lifecycle::*;
use super::{
    AdmissionFailureCode, AdmissionRetry, DetectedCapacity, DiskObservation, DiskPressureState,
    DiskPressureThresholds, ExistingCapacityDisposition, GovernorFailure, GovernorPolicy,
    InventoryCardinalityLimits, OperatorLimits, OrdinaryPoolPolicy, RecoveryPoolCapacities,
    RecoveryReserve, ResizeFailureCode, ResourceAmounts, ResourceDimension, ResourceInventory,
    StorageKernelResourceAuthority, TenantQuota, WorkClaim, WorkKind,
};

pub(super) fn governor() -> (StorageKernelResourceAuthority, TenantId) {
    let tenant = TenantId::from_bytes([91; 16]).expect("test tenant is valid");
    let uniform = |amount| ResourceAmounts::new([amount; 11]);
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
        DetectedCapacity::new(raw).expect("detected capacity is valid"),
        OperatorLimits::new(raw).expect("operator capacity is valid"),
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
    let governor =
        StorageKernelResourceAuthority::establish_for_test(inventory, policy, recovery_pools())
            .expect("governor establishment succeeds");
    (governor, tenant)
}

pub(super) fn claim(tenant: TenantId, kind: WorkKind, amount: u64) -> WorkClaim {
    WorkClaim::tenant(
        tenant,
        kind,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, amount).expect("amount is valid"),
    )
    .expect("claim is valid")
}

fn recovery_pools() -> RecoveryPoolCapacities {
    let minimum = ResourceAmounts::new([1; 11]);
    let dual = ResourceAmounts::new([2; 11]);
    RecoveryPoolCapacities::new(dual, minimum, dual, minimum, dual, minimum, minimum)
        .expect("recovery pools are valid")
}

#[test]
fn mutex_poison_fences_all_mutation_but_drop_releases_exactly() {
    let (governor, tenant) = governor();
    let mut grant = governor
        .reserve(claim(tenant, WorkKind::Ingest, 1))
        .expect("admitted");
    assert!(catch_unwind(AssertUnwindSafe(|| governor.inner.poison_for_test())).is_err());
    assert_eq!(
        governor.inspect().expect("inspectable").lifecycle(),
        GovernorLifecycle::Fenced
    );
    assert_eq!(
        governor.begin_shutdown(),
        Err(GovernorFailure::InternalFenced)
    );
    assert_eq!(
        governor.observe_disk_for_test(DiskObservation::new(1)),
        Err(GovernorFailure::InternalFenced)
    );
    assert_eq!(
        governor
            .reserve(claim(tenant, WorkKind::Ingest, 1))
            .expect_err("fenced")
            .code(),
        AdmissionFailureCode::InternalFenced
    );
    let invalid_resize = grant
        .try_resize(ResourceAmounts::new([0; 11]))
        .expect_err("empty resize is invalid even after fencing");
    assert_eq!(invalid_resize.code(), ResizeFailureCode::InvalidRequest);
    assert_eq!(invalid_resize.pressure_state(), DiskPressureState::Healthy);
    let resize = grant
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 2).expect("amount"))
        .expect_err("fenced");
    assert_eq!(resize.code(), ResizeFailureCode::InternalFenced);
    assert_eq!(
        resize.existing_capacity(),
        ExistingCapacityDisposition::CapacityRetained
    );
    drop(grant);
    let snapshot = governor.inspect().expect("inspectable");
    assert_eq!(snapshot.outstanding_total(), 0);
    assert_eq!(snapshot.usage(ResourceDimension::MemoryBytes), 0);
}

#[test]
fn reconciliation_underflow_fences_without_saturating_forgiveness() {
    let (governor, tenant) = governor();
    let grant = governor
        .reserve(claim(tenant, WorkKind::Ingest, 1))
        .expect("admitted");
    governor.inner.corrupt_outstanding_for_test();
    drop(grant);
    let snapshot = governor.inspect().expect("inspectable");
    assert_eq!(snapshot.lifecycle(), GovernorLifecycle::Fenced);
    assert_eq!(snapshot.usage(ResourceDimension::MemoryBytes), 1);
}

#[test]
fn bounded_observation_and_rejection_counters_fence_on_overflow() {
    let (pressure, _) = governor();
    pressure
        .inner
        .state
        .lock()
        .expect("healthy")
        .pressure_transition_count = u64::MAX;
    assert_eq!(
        pressure.observe_disk_for_test(DiskObservation::new(20)),
        Err(GovernorFailure::InternalFenced)
    );
    assert_eq!(
        pressure.observe_disk_for_test(DiskObservation::new(100)),
        Err(GovernorFailure::InternalFenced)
    );
    assert_eq!(
        pressure.begin_shutdown(),
        Err(GovernorFailure::InternalFenced)
    );

    let foreign = TenantId::from_bytes([92; 16]).expect("valid");
    let (total, _) = governor();
    total
        .inner
        .set_telemetry_for_test(AdmissionFailureCode::UnregisteredTenant, u64::MAX, 0, 0);
    let _ = total.reserve(claim(foreign, WorkKind::Ingest, 1));
    assert_eq!(
        total.inspect().expect("inspectable").lifecycle(),
        GovernorLifecycle::Fenced
    );
    assert_eq!(
        total
            .reserve(claim(tenant(91), WorkKind::Ingest, 1))
            .expect_err("a pre-fenced governor refuses admission")
            .code(),
        AdmissionFailureCode::InternalFenced
    );

    let (reason, _) = governor();
    reason
        .inner
        .set_telemetry_for_test(AdmissionFailureCode::UnregisteredTenant, 0, u64::MAX, 0);
    let _ = reason.reserve(claim(foreign, WorkKind::Ingest, 1));
    assert_eq!(
        reason.inspect().expect("inspectable").lifecycle(),
        GovernorLifecycle::Fenced
    );

    let (throttle, tenant) = governor();
    throttle.inner.set_telemetry_for_test(
        AdmissionFailureCode::ClassCapacityUnavailable,
        0,
        0,
        u64::MAX,
    );
    let grant = throttle
        .reserve(claim(tenant, WorkKind::InteractiveQueryTail, 50))
        .expect("admitted");
    let _ = throttle.reserve(claim(tenant, WorkKind::InteractiveQueryTail, 1));
    assert_eq!(
        throttle.inspect().expect("inspectable").lifecycle(),
        GovernorLifecycle::Fenced
    );
    drop(grant);
}

fn tenant(byte: u8) -> TenantId {
    TenantId::from_bytes([byte; 16]).expect("test tenant is valid")
}

#[test]
fn contention_is_immediate_counted_and_overflow_fences_on_next_mutation() {
    const CONTENDERS: usize = 8;
    let (governor, tenant) = governor();
    let guard = governor.inner.state.lock().expect("test lock is healthy");
    let failure = governor
        .reserve(claim(tenant, WorkKind::Ingest, 1))
        .expect_err("contended admission never waits");
    assert_eq!(failure.code(), AdmissionFailureCode::GovernorContended);
    assert_eq!(failure.retry(), AdmissionRetry::AfterCapacityRelease);
    assert_eq!(failure.pressure_state(), DiskPressureState::Healthy);
    drop(guard);
    let snapshot = governor.inspect().expect("inspectable");
    assert_eq!(snapshot.outstanding_total(), 0);
    assert_eq!(
        snapshot.rejection_count_for(AdmissionFailureCode::GovernorContended),
        1
    );

    let guard = governor.inner.state.lock().expect("test lock is healthy");
    let ready = Barrier::new(CONTENDERS + 1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..CONTENDERS)
            .map(|_| {
                scope.spawn(|| {
                    ready.wait();
                    governor
                        .reserve(claim(tenant, WorkKind::Ingest, 1))
                        .expect_err("held accounting lock makes every admission contended")
                })
            })
            .collect();
        ready.wait();
        for handle in handles {
            let failure = handle.join().expect("contender does not panic");
            assert_eq!(failure.code(), AdmissionFailureCode::GovernorContended);
        }
    });
    drop(guard);
    let snapshot = governor.inspect().expect("inspectable");
    assert_eq!(
        snapshot.rejection_count_for(AdmissionFailureCode::GovernorContended),
        1 + CONTENDERS as u64
    );
    let observed_sum = (0..AdmissionFailureCode::COUNT)
        .filter_map(AdmissionFailureCode::from_index)
        .map(|reason| {
            assert!(snapshot.throttle_count_for(reason) <= snapshot.rejection_count_for(reason));
            snapshot.rejection_count_for(reason)
        })
        .sum::<u64>();
    assert_eq!(snapshot.rejection_count(), observed_sum);

    governor.inner.set_telemetry_for_test(
        AdmissionFailureCode::GovernorContended,
        u64::MAX,
        u64::MAX,
        u64::MAX,
    );
    let guard = governor.inner.state.lock().expect("test lock is healthy");
    let _ = governor.reserve(claim(tenant, WorkKind::Ingest, 1));
    drop(guard);
    assert_eq!(
        governor
            .reserve(claim(tenant, WorkKind::Ingest, 1))
            .expect_err("overflow fences at the next acquired mutation")
            .code(),
        AdmissionFailureCode::InternalFenced
    );
}

#[test]
fn every_control_and_explicit_reservation_mutation_is_immediate_under_contention() {
    let (governor, tenant) = governor();
    let mut grant = governor
        .reserve(claim(tenant, WorkKind::Ingest, 1))
        .expect("admitted");
    let guard = governor.inner.state.lock().expect("test lock is healthy");

    assert_eq!(
        governor.observe_disk_for_test(DiskObservation::new(50)),
        Err(GovernorFailure::GovernorContended {
            pressure: DiskPressureState::Healthy,
        })
    );
    assert_eq!(
        governor.begin_shutdown(),
        Err(GovernorFailure::GovernorContended {
            pressure: DiskPressureState::Healthy,
        })
    );
    assert_eq!(
        governor.inspect(),
        Err(GovernorFailure::GovernorContended {
            pressure: DiskPressureState::Healthy,
        })
    );
    assert_eq!(
        grant.cancel(),
        Err(GovernorFailure::GovernorContended {
            pressure: DiskPressureState::Healthy,
        })
    );
    let resize = grant
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 2).expect("amount"))
        .expect_err("resize never waits");
    assert_eq!(
        resize.admission_code(),
        Some(AdmissionFailureCode::GovernorContended)
    );
    assert_eq!(
        resize.existing_capacity(),
        ExistingCapacityDisposition::CapacityRetained
    );
    assert!(grant.is_active());

    drop(guard);
    assert_eq!(
        grant.cancel().expect("release after contention"),
        ReleaseOutcome::Released
    );
    assert_eq!(
        governor.inspect().expect("inspectable").outstanding_total(),
        0
    );
}

#[test]
fn telemetry_overflow_fences_the_next_control_mutation() {
    let foreign = tenant(92);
    let (governor, _) = governor();
    governor
        .inner
        .set_telemetry_for_test(AdmissionFailureCode::UnregisteredTenant, u64::MAX, 0, 0);
    let _ = governor.reserve(claim(foreign, WorkKind::Ingest, 1));
    assert_eq!(
        governor.observe_disk_for_test(DiskObservation::new(50)),
        Err(GovernorFailure::InternalFenced)
    );
    assert_eq!(
        governor
            .inspect()
            .expect("fenced state is inspectable")
            .lifecycle(),
        GovernorLifecycle::Fenced
    );
}

#[test]
fn telemetry_snapshot_sum_overflow_is_typed_and_fences_next_observation() {
    let (governor, _) = governor();
    governor
        .inner
        .set_telemetry_for_test(AdmissionFailureCode::GovernorContended, 1, 1, 1);
    governor
        .inner
        .set_telemetry_for_test(AdmissionFailureCode::UnregisteredTenant, u64::MAX, 0, 0);
    assert_eq!(governor.inspect(), Err(GovernorFailure::InternalFenced));
    assert_eq!(governor.inspect(), Err(GovernorFailure::InternalFenced));
}

#[test]
fn pending_internal_fence_is_consumed_by_the_next_control_mutation() {
    let (governor, _) = governor();
    governor
        .inner
        .pending_fence
        .store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(
        governor.observe_disk_for_test(DiskObservation::new(100)),
        Err(GovernorFailure::InternalFenced)
    );
    assert_eq!(
        governor
            .inspect()
            .expect("fenced state is inspectable")
            .lifecycle(),
        GovernorLifecycle::Fenced
    );
}

#[test]
fn contention_refusal_is_not_recorded_in_the_locked_reason_table() {
    let (governor, _) = governor();
    let failure =
        super::decision::contention_failure(super::WorkClass::Ingest, DiskPressureState::Healthy);
    let mut state = governor.inner.state.lock().expect("test lock is healthy");
    let before = state.rejection_counts;
    governor.inner.record_refusal_locked(&mut state, &failure);
    assert_eq!(state.rejection_counts, before);
}

#[test]
fn published_soft_pressure_is_preserved_for_lock_free_failure_evidence() {
    let (governor, _) = governor();
    assert_eq!(
        governor
            .observe_disk_for_test(DiskObservation::new(40))
            .expect("observation is accepted"),
        DiskPressureState::SoftPressure
    );
    assert_eq!(
        governor.inner.pressure_for_failure(),
        DiskPressureState::SoftPressure
    );
}

#[test]
fn drop_is_nonblocking_and_the_next_inspection_drains_exactly() {
    let (governor, tenant) = governor();
    let grant = governor
        .reserve(claim(tenant, WorkKind::Ingest, 1))
        .expect("admitted");
    let guard = governor.inner.state.lock().expect("test lock is healthy");
    drop(grant);
    drop(guard);
    assert_eq!(
        governor.inspect().expect("inspectable").outstanding_total(),
        0
    );
}

#[test]
fn pending_bit_before_hint_and_after_empty_word_scan_never_lose_release() {
    let (governor, tenant) = governor();
    let mut before_hint = governor
        .reserve(claim(tenant, WorkKind::Ingest, 1))
        .expect("admitted");
    assert!(
        governor
            .inner
            .mark_status_pending_for_test(before_hint.slot)
    );
    assert!(
        governor
            .inner
            .publish_pending_bit_for_test(before_hint.slot)
    );
    {
        let mut state = governor.inner.state.lock().expect("healthy");
        governor.inner.drain_pending(&mut state);
        assert_eq!(state.outstanding, 1);
    }
    governor.inner.publish_pending_hint_for_test();
    before_hint.active = false;
    assert_eq!(governor.inspect().expect("drained").outstanding_total(), 0);

    let mut after_scan = governor
        .reserve(claim(tenant, WorkKind::Ingest, 1))
        .expect("slot is reusable");
    assert!(governor.inner.mark_status_pending_for_test(after_scan.slot));
    governor.inner.publish_pending_hint_for_test();
    {
        let mut state = governor.inner.state.lock().expect("healthy");
        governor.inner.drain_pending(&mut state);
        assert_eq!(state.outstanding, 1);
    }
    assert!(governor.inner.publish_pending_bit_for_test(after_scan.slot));
    governor.inner.publish_pending_hint_for_test();
    after_scan.active = false;
    assert_eq!(governor.inspect().expect("drained").outstanding_total(), 0);

    let replacement = governor
        .reserve(claim(tenant, WorkKind::Ingest, 1))
        .expect("slot remains reusable");
    drop(replacement);
    assert_eq!(governor.inspect().expect("drained").outstanding_total(), 0);
}
