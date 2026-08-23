use super::*;

#[test]
fn checked_planning_arithmetic_rejects_capacity_overflow() {
    assert!(add_capacity(u64::MAX, 1, 1).is_err());
    assert!(add_capacity(0, usize::MAX, usize::MAX).is_err());
    let path = positron_signals::SchemaPath::root(
        positron_domain::value::AttributeNamespace::Record,
        "key".to_owned(),
    )
    .expect("bounded test path");
    assert!(path_memory(u64::MAX, &path).is_err());
}

#[test]
fn reservations_reconcile_transfer_and_release_exactly() {
    let memory = PlanningMemory::new(16);
    let mut reservation = memory.reserve(4).expect("reservation");
    assert_eq!(reservation.bytes(), 4);
    reservation.reconcile(8).expect("growth");
    reservation.reconcile(3).expect("shrink");
    assert!(reservation.release_bytes(4).is_err());
    reservation.release_bytes(3).expect("release");
    memory
        .retain_reservation(memory.reserve(5).expect("retained reservation"), 5)
        .expect("retained");
    assert!(memory.reserve(11).is_ok());
    assert!(memory.release_retained(6).is_err());
    let retained = memory.take_retained();
    assert_eq!(retained.bytes(), 5);
    drop(retained);
    assert!(memory.release_retained(1).is_err());
    let mut over_limit = memory.reserve(16).expect("limit reservation");
    assert!(over_limit.reconcile(17).is_err());
}

#[test]
fn planning_vec_growth_and_plan_aggregation_keep_storage_governed() {
    let memory = PlanningMemory::new(512);
    let mut values: PlanningVec<u8> = PlanningVec::with_capacity(&memory, 0).expect("vector");
    values.push(7).expect("growth");
    values[0] = 9;
    assert_eq!(&*values, &[9]);
    assert_eq!(format!("{values:?}"), "[9]");
    let (values, reservation) = values.into_vec_with_reservation();
    assert_eq!(values, vec![9]);
    drop(reservation);

    let range = crate::plan::TemporalRange::new(0, 1).expect("valid range");
    let plan = LogicalPlan::logs(crate::plan::TemporalAxis::QueryTime, range, 1).with_aggregate(
        crate::plan::AggregateSpec::count_by(vec![ProjectionColumn::QueryTime]),
    );
    assert!(retained_plan_bytes(&plan).is_ok());
}
