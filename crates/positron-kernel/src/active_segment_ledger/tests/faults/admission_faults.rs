use super::*;
use crate::{DiskObservation, DiskPressureState};

#[test]
fn hard_pressure_resolves_replay_and_conflict_before_refusing_new_work()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let committed = ledger.append(prepared(scope, b"hard-pressure-committed")?)?;
        let snapshot = ledger.snapshot()?;
        let usage = authority.governor().inspect()?.outstanding_total();
        assert_eq!(
            authority.observe_disk_for_test(DiskObservation::new(0))?,
            DiskPressureState::HardPressure
        );

        assert_eq!(
            ledger.append(prepared(scope, b"hard-pressure-committed")?)?,
            committed
        );
        assert_eq!(
            ledger
                .append(prepared(scope, b"hard-pressure-conflict")?)
                .expect_err("conflict is resolved before new-work admission")
                .code(),
            LedgerFailureCode::IdempotencyConflict
        );
        assert_eq!(
            ledger
                .append(prepared(scope, b"new-work")?)
                .expect_err("hard pressure refuses new work")
                .code(),
            LedgerFailureCode::ResourceAdmissionRefused
        );
        assert_eq!(authority.governor().inspect()?.outstanding_total(), usage);
        assert_eq!(snapshot.blocks().len(), 1);
        assert_eq!(snapshot.blocks()[0].payload(), b"hard-pressure-committed");
        Ok(())
    })
}

#[test]
fn exhausted_scope_lease_inventory_refuses_before_storage_mutation() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let mut leases = Vec::new();
        for value in 0..crate::MAX_TENANT_QUOTAS {
            let mut key = [0_u8; 22];
            key[..2].copy_from_slice(&u16::try_from(value)?.to_be_bytes());
            let lease = authority
                .acquire_active_segment_ledger(key)
                .ok()
                .expect("unique bounded scope lease");
            leases.push(lease);
        }
        let failure = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )
        .expect_err("bounded scope inventory cannot grow");
        assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
        assert!(
            authority
                .primary_data_volume()
                .expect("fixture volume")
                ._root
                .metadata()
                .is_ok()
        );
        drop(leases);
        Ok(())
    })
}
