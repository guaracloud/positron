use super::*;

fn amount(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn view(shared: u64, protected: u64) -> RecoveryPoolView {
    RecoveryPoolView {
        shared_capacity: amount(shared),
        protected_capacity: amount(protected),
        usage: RecoveryPoolUsage::zero(),
        shared_occupied_by_ordinary: ResourceAmounts::zero(),
    }
}

#[test]
fn crossed_authority_intervals_identify_the_exact_limiting_authority() {
    let requested = amount(5);
    assert!(matches!(
        plan_recovery_charge(RecoveryWorkKind::Repair, requested, view(1, 4), view(0, 5),),
        Err(RecoveryPoolLimit::Global(ResourceDimension::MemoryBytes))
    ));
    assert!(matches!(
        plan_recovery_charge(RecoveryWorkKind::Repair, requested, view(0, 5), view(1, 4),),
        Err(RecoveryPoolLimit::Scope(ResourceDimension::MemoryBytes))
    ));
}
