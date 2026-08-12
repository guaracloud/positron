#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::TenantId;
use positron_kernel::{
    DetectedCapacity, DiskObservation, DiskPressureThresholds, GovernorPolicy,
    InventoryCardinalityLimits, OperatorLimits, OrdinaryPool, OrdinaryPoolPolicy,
    RecoveryPoolCapacities, RecoveryReserve, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts,
    ResourceDimension, ResourceGovernor, ResourceInventory, ResourceReservation,
    StorageKernelResourceAuthority, TenantQuota, WorkClaim, WorkClass, WorkKind,
};

const SLOT_COUNT: usize = 8;
const ORDINARY_CEILING: u64 = 90;
const TOTAL_CEILING: u64 = 105;
const RECOVERY_RESERVE: u64 = TOTAL_CEILING - ORDINARY_CEILING;

#[derive(Clone, Copy)]
enum SlotIdentity {
    Ordinary(WorkClass),
    Recovery { uninterruptible: bool },
}

struct Slot<'authority> {
    reservation: ResourceReservation<'authority>,
    identity: SlotIdentity,
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn establish() -> Option<(StorageKernelResourceAuthority, [TenantId; 2])> {
    let tenants = [
        TenantId::from_bytes([1; 16]).ok()?,
        TenantId::from_bytes([2; 16]).ok()?,
    ];
    let cardinality = InventoryCardinalityLimits::new(2, SLOT_COUNT as u32).ok()?;
    let bootstrap = cardinality.governor_bootstrap_overhead(2).ok()?;
    let mut raw_values = [TOTAL_CEILING; 11];
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        raw_values[index] = TOTAL_CEILING.checked_add(bootstrap.get(dimension))?;
    }
    let raw_capacity = ResourceAmounts::new(raw_values);
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(raw_capacity).ok()?,
        OperatorLimits::new(raw_capacity).ok()?,
        RecoveryReserve::new(uniform(RECOVERY_RESERVE)).ok()?,
        cardinality,
        DiskPressureThresholds::new(20, 30, 40, 50).ok()?,
        DiskObservation::new(TOTAL_CEILING),
    )
    .ok()?;
    let policy = GovernorPolicy::new(
        [
            TenantQuota::new(tenants[0], 1, uniform(90)).ok()?,
            TenantQuota::new(tenants[1], 1, uniform(90)).ok()?,
        ],
        OrdinaryPoolPolicy::new(uniform(20), uniform(15), uniform(10), uniform(5)).ok()?,
    )
    .ok()?;
    let pools = RecoveryPoolCapacities::new(
        uniform(3),
        uniform(2),
        uniform(3),
        uniform(2),
        uniform(3),
        uniform(1),
        uniform(1),
    )
    .ok()?;
    let authority =
        StorageKernelResourceAuthority::establish_for_fuzz(inventory, policy, pools).ok()?;
    Some((authority, tenants))
}

fn dimension(selector: u8) -> ResourceDimension {
    ResourceDimension::ALL
        .get(usize::from(selector) % ResourceDimension::ALL.len())
        .copied()
        .expect("modulo index is within the fixed dimension table")
}

fn ordinary_kind(selector: u8) -> WorkKind {
    match selector % 4 {
        0 => WorkKind::SecurityLifecycle,
        1 => WorkKind::Ingest,
        2 => WorkKind::InteractiveQueryTail,
        _ => WorkKind::OrdinaryMaintenanceBackup,
    }
}

fn recovery_kind(selector: u8) -> RecoveryWorkKind {
    match selector % 7 {
        0 => RecoveryWorkKind::DurabilityCompletion,
        1 => RecoveryWorkKind::Retention,
        2 => RecoveryWorkKind::EmergencyCompaction,
        3 => RecoveryWorkKind::Purge,
        4 => RecoveryWorkKind::Repair,
        5 => RecoveryWorkKind::Fencing,
        _ => RecoveryWorkKind::SafeShutdown,
    }
}

fn class_index(class: WorkClass) -> usize {
    match class {
        WorkClass::DurabilityRecovery => 0,
        WorkClass::SecurityLifecycle => 1,
        WorkClass::Ingest => 2,
        WorkClass::InteractiveQueryTail => 3,
        WorkClass::OrdinaryMaintenanceBackup => 4,
    }
}

fn add_amount(total: &mut [u64; 11], amounts: ResourceAmounts) {
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        total[index] = total[index]
            .checked_add(amounts.get(dimension))
            .expect("bounded governor usage cannot overflow");
    }
}

fn assert_conservation(
    governor: &ResourceGovernor<'_>,
    slots: &[Option<Slot<'_>>; SLOT_COUNT],
) {
    let snapshot = governor
        .inspect()
        .expect("public operations must preserve inspectable state");
    let mut total = [0_u64; 11];
    let mut ordinary = [0_u64; 11];
    let mut recovery = [0_u64; 11];
    let mut class_counts = [0_u32; 5];
    let mut outstanding = 0_u32;
    let mut outstanding_ordinary = 0_u32;
    let mut outstanding_recovery = 0_u32;
    let mut outstanding_uninterruptible = 0_u32;

    for slot in slots.iter().flatten() {
        if !slot.reservation.is_active() {
            continue;
        }
        outstanding += 1;
        add_amount(&mut total, slot.reservation.granted());
        match slot.identity {
            SlotIdentity::Ordinary(class) => {
                outstanding_ordinary += 1;
                class_counts[class_index(class)] += 1;
                add_amount(&mut ordinary, slot.reservation.granted());
            },
            SlotIdentity::Recovery { uninterruptible } => {
                outstanding_recovery += 1;
                class_counts[0] += 1;
                add_amount(&mut recovery, slot.reservation.granted());
                if uninterruptible {
                    outstanding_uninterruptible += 1;
                }
            },
        }
    }

    assert_eq!(snapshot.outstanding_total(), outstanding);
    assert_eq!(snapshot.outstanding_ordinary(), outstanding_ordinary);
    assert_eq!(snapshot.outstanding_recovery(), outstanding_recovery);
    assert_eq!(
        snapshot.outstanding_uninterruptible(),
        outstanding_uninterruptible
    );
    for class in [
        WorkClass::DurabilityRecovery,
        WorkClass::SecurityLifecycle,
        WorkClass::Ingest,
        WorkClass::InteractiveQueryTail,
        WorkClass::OrdinaryMaintenanceBackup,
    ] {
        assert_eq!(
            snapshot.outstanding_for(class),
            class_counts[class_index(class)]
        );
    }
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        assert_eq!(snapshot.usage(dimension), total[index]);
        assert_eq!(total[index], ordinary[index] + recovery[index]);
        let pool_usage = [
            OrdinaryPool::Shared,
            OrdinaryPool::SecurityLifecycle,
            OrdinaryPool::Ingest,
            OrdinaryPool::InteractiveQueryTail,
            OrdinaryPool::OrdinaryMaintenanceBackup,
        ]
        .into_iter()
        .map(|pool| snapshot.pool_usage(pool, dimension))
        .sum::<u64>();
        assert_eq!(pool_usage, ordinary[index]);
        assert_eq!(
            snapshot.reserve_consumption(dimension),
            total[index].saturating_sub(ORDINARY_CEILING)
        );
        assert_eq!(
            snapshot.effective_capacity(dimension),
            TOTAL_CEILING
                .checked_add(snapshot.governor_bootstrap_overhead(dimension))
                .expect("static capacity and bootstrap overhead fit")
        );
        assert_eq!(snapshot.ordinary_capacity(dimension), ORDINARY_CEILING);
        assert_eq!(
            snapshot.recovery_reserve_capacity(dimension),
            RECOVERY_RESERVE
        );
    }
    let reasons = [
        positron_kernel::AdmissionFailureCode::CapacityExhausted,
        positron_kernel::AdmissionFailureCode::TenantQuotaExceeded,
        positron_kernel::AdmissionFailureCode::UnregisteredTenant,
        positron_kernel::AdmissionFailureCode::OutstandingReservationLimit,
        positron_kernel::AdmissionFailureCode::ProtectedCapacityUnavailable,
        positron_kernel::AdmissionFailureCode::ClassCapacityUnavailable,
        positron_kernel::AdmissionFailureCode::TenantFairShareExceeded,
        positron_kernel::AdmissionFailureCode::CapacityOccupiedByRecovery,
        positron_kernel::AdmissionFailureCode::DiskPressureAdmissionRefused,
        positron_kernel::AdmissionFailureCode::RecoveryReserveExhausted,
        positron_kernel::AdmissionFailureCode::ShuttingDown,
        positron_kernel::AdmissionFailureCode::InternalFenced,
        positron_kernel::AdmissionFailureCode::GovernorContended,
    ];
    assert_eq!(
        reasons
            .into_iter()
            .map(|reason| snapshot.rejection_count_for(reason))
            .sum::<u64>(),
        snapshot.rejection_count()
    );
    for reason in reasons {
        assert!(snapshot.throttle_count_for(reason) <= snapshot.rejection_count_for(reason));
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 {
        return;
    }
    let (authority, tenants) = establish().expect("static governor fuzz setup must be valid");
    let governor = authority.governor();
    let recovery = authority.recovery();
    let mut slots: [Option<Slot>; SLOT_COUNT] = std::array::from_fn(|_| None);

    for command in data.chunks_exact(5) {
        let slot_index = usize::from(command[1]) % SLOT_COUNT;
        match command[0] % 7 {
            0 => {
                drop(slots[slot_index].take());
                let kind = ordinary_kind(command[2]);
                let amount = u64::from(command[4] % 20) + 1;
                let claim =
                    ResourceAmounts::only(dimension(command[3]), amount).and_then(|amounts| {
                        WorkClaim::tenant(tenants[usize::from(command[2]) % 2], kind, amounts)
                    });
                if let Ok(claim) = claim
                    && let Ok(reservation) = governor.reserve(claim)
                {
                    slots[slot_index] = Some(Slot {
                        reservation,
                        identity: SlotIdentity::Ordinary(kind.class()),
                    });
                }
            },
            1 => {
                drop(slots[slot_index].take());
                let kind = recovery_kind(command[2]);
                let amount = u64::from(command[4] % 20) + 1;
                let claim =
                    ResourceAmounts::only(dimension(command[3]), amount).and_then(|amounts| {
                        if command[2] & 0x80 == 0 && kind.permits_system_scope() {
                            RecoveryWorkClaim::system(kind, amounts)
                        } else if kind.permits_tenant_scope() {
                            RecoveryWorkClaim::tenant(
                                tenants[usize::from(command[2]) % 2],
                                kind,
                                amounts,
                            )
                        } else {
                            RecoveryWorkClaim::system(kind, amounts)
                        }
                    });
                if let Ok(claim) = claim
                    && let Ok(reservation) = recovery.reserve(claim)
                {
                    slots[slot_index] = Some(Slot {
                        reservation,
                        identity: SlotIdentity::Recovery {
                            uninterruptible: matches!(
                                kind,
                                RecoveryWorkKind::DurabilityCompletion
                                    | RecoveryWorkKind::SafeShutdown
                            ),
                        },
                    });
                }
            },
            2 => {
                if let Some(slot) = slots[slot_index].as_mut() {
                    let amount = u64::from(command[4] % 21);
                    let mut values = [0_u64; 11];
                    if amount > 0 {
                        values[usize::from(command[3]) % values.len()] = amount;
                    }
                    let _ = slot.reservation.try_resize(ResourceAmounts::new(values));
                }
            },
            3 => drop(slots[slot_index].take()),
            4 => {
                if let Some(mut slot) = slots[slot_index].take() {
                    let _ = slot.reservation.cancel();
                }
            },
            5 => {
                let usable = u64::from(command[3])
                    .checked_mul(256)
                    .and_then(|high| high.checked_add(u64::from(command[4])))
                    .map(|value| value % 101)
                    .unwrap_or_default();
                let _ = authority.observe_disk_for_fuzz(DiskObservation::new(usable));
            },
            _ => {
                let _ = authority.begin_shutdown();
            },
        }
        assert_conservation(&governor, &slots);
    }

    let _ = authority.begin_shutdown();
    for slot in &mut slots {
        drop(slot.take());
    }
    assert_conservation(&governor, &slots);
    assert!(
        authority
            .begin_shutdown()
            .expect("drained governor must reconcile")
            .complete()
    );
});
