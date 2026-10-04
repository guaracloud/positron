use super::*;
use positron_domain::identity::TenantId;

#[test]
fn conflicting_copy_on_write_work_waits_for_the_running_owner_across_scopes() {
    let coordinator = MaintenanceCoordinator::new();
    let input = MaintenanceObjectId::new([3; 32]).expect("object identity");
    let first = task(
        1,
        MaintenanceTaskClass::SchemaStatistics,
        MaintenanceTrigger::Event,
        MaintenancePriority::Ordinary,
        vec![input],
    );
    let mut second = task(
        2,
        MaintenanceTaskClass::RetentionPublication,
        MaintenanceTrigger::Event,
        MaintenancePriority::Required,
        vec![input],
    );
    second.scope =
        MaintenanceScope::tenant(TenantId::from_bytes([4; 16]).expect("tenant identity"));
    coordinator
        .submit_at(first.clone(), 1)
        .expect("system task accepted");
    coordinator
        .submit_at(second.clone(), 2)
        .expect("tenant task accepted");

    assert_eq!(
        coordinator.start_next(3, false).expect("first starts"),
        Some(second)
    );
    assert_eq!(
        coordinator
            .start_next(4, false)
            .expect("object conflict is evaluated"),
        None,
        "the same immutable object cannot be read or written concurrently across scopes"
    );
    coordinator
        .complete(
            MaintenanceTaskId::new([2; 16]).expect("task identity"),
            true,
        )
        .expect("complete owner");
    assert_eq!(
        coordinator.start_next(5, false).expect("unblocked"),
        Some(first)
    );
}
