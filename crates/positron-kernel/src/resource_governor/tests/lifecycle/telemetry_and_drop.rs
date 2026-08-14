use super::*;

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
        .drop_ledger
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
    let failure = super::super::decision::contention_failure(
        super::super::WorkClass::Ingest,
        DiskPressureState::Healthy,
    );
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
