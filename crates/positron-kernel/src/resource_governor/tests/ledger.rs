use super::*;
use crate::resource_governor::{
    GovernorFailure, GovernorLifecycle, ResourceDimension, WorkClaim, WorkKind,
};

#[test]
fn record_is_compact_and_maximum_ledger_is_bounded() {
    assert_eq!(record_size_for_test(), 184);
}

#[test]
fn invalid_drop_signals_fence_without_touching_accounting() {
    let (governor, _) = super::super::lifecycle_tests::governor();
    governor.inner.mark_drop_pending(u16::MAX);
    let snapshot = governor
        .inspect()
        .expect("invalid drop signal is inspectable");
    assert_eq!(snapshot.lifecycle(), GovernorLifecycle::Fenced);
    assert_eq!(snapshot.outstanding_total(), 0);
}

#[test]
fn duplicate_drop_signal_fences_after_releasing_the_grant_once() {
    let (governor, tenant) = super::super::lifecycle_tests::governor();
    let grant = governor
        .reserve(super::super::lifecycle_tests::claim(
            tenant,
            WorkKind::Ingest,
            1,
        ))
        .expect("grant is admitted");
    governor.inner.mark_drop_pending(grant.slot);
    governor.inner.mark_drop_pending(grant.slot);
    let snapshot = governor.inspect().expect("duplicate signal is inspectable");
    assert_eq!(snapshot.lifecycle(), GovernorLifecycle::Fenced);
    assert_eq!(snapshot.outstanding_total(), 0);
    std::mem::forget(grant);
}

#[test]
fn corrupt_pending_bit_and_missing_record_fail_closed() {
    let (empty, _) = super::super::lifecycle_tests::governor();
    assert!(empty.inner.publish_pending_bit_for_test(0));
    empty.inner.publish_pending_hint_for_test();
    assert_eq!(
        empty
            .inspect()
            .expect("corrupt bit is inspectable")
            .lifecycle(),
        GovernorLifecycle::Fenced
    );

    let (governor, tenant) = super::super::lifecycle_tests::governor();
    let grant = governor
        .reserve(
            WorkClaim::tenant(
                tenant,
                WorkKind::Ingest,
                crate::resource_governor::ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)
                    .expect("amount is valid"),
            )
            .expect("claim is valid"),
        )
        .expect("grant is admitted");
    {
        let mut state = governor.inner.state.lock().expect("test lock is healthy");
        state.grant_records[usize::from(grant.slot)] = None;
    }
    assert!(governor.inner.mark_status_pending_for_test(grant.slot));
    assert!(governor.inner.publish_pending_bit_for_test(grant.slot));
    governor.inner.publish_pending_hint_for_test();
    assert_eq!(
        governor
            .inspect()
            .expect("missing record is inspectable")
            .lifecycle(),
        GovernorLifecycle::Fenced
    );
    std::mem::forget(grant);
}

#[test]
fn padding_bit_past_the_last_slot_fences_without_indexing_storage() {
    let (governor, _) = super::super::lifecycle_tests::governor();
    governor.inner.drop_ledger.pending_words[0].fetch_or(1_u64 << 63, Ordering::Release);
    governor.inner.publish_pending_hint_for_test();
    let snapshot = governor
        .inspect()
        .expect("padding corruption is inspectable");
    assert_eq!(snapshot.lifecycle(), GovernorLifecycle::Fenced);
    assert_eq!(snapshot.outstanding_total(), 0);
}

#[test]
fn slot_mutations_reject_inactive_corrupt_and_mismatched_records() {
    let (governor, tenant) = super::super::lifecycle_tests::governor();
    let grant = governor
        .reserve(super::super::lifecycle_tests::claim(
            tenant,
            WorkKind::Ingest,
            1,
        ))
        .expect("grant is admitted");
    let mut state = governor.inner.state.lock().expect("test lock is healthy");
    assert!(!governor.inner.finish_slot(&mut state, u16::MAX));
    let mismatched = ReservationIdentity::Ordinary {
        tenant,
        kind: WorkKind::SecurityLifecycle,
    };
    assert!(!governor.inner.replace_slot_record(
        &mut state,
        grant.slot,
        grant.owner,
        mismatched,
        grant.amounts,
    ));
    let record = state.grant_records[usize::from(grant.slot)].expect("record exists");
    assert!(governor.inner.finish_slot(&mut state, grant.slot));
    assert!(!governor.inner.replace_slot_record(
        &mut state,
        grant.slot,
        grant.owner,
        grant.identity,
        grant.amounts,
    ));
    state.grant_records[usize::from(grant.slot)] = Some(record);
    assert_eq!(governor.inner.activate_slot(&mut state, record), None);
    std::mem::forget(grant);
}

#[test]
fn unreconstructable_drop_record_fences_without_applying_a_release() {
    let (governor, _) = super::super::lifecycle_tests::governor();
    let corrupt = GrantRecord {
        amounts: crate::resource_governor::ResourceAmounts::new([1; 11]),
        shared: crate::resource_governor::ResourceAmounts::new([0; 11]),
        tenant_index: SYSTEM_TENANT_INDEX,
        kind: GrantKind::Ingest,
    };
    let mut state = governor.inner.state.lock().expect("test lock is healthy");
    let status = governor.inner.release_record_locked(&mut state, corrupt);
    assert_eq!(status.result, Err(GovernorFailure::InternalFenced));
    assert!(!status.applied);
    assert_eq!(state.lifecycle, GovernorLifecycle::Fenced);
    assert_eq!(state.outstanding, 0);
}
