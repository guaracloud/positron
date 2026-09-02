use super::*;

#[test]
fn unreclaimed_transferred_grant_releases_intrinsically_on_drop()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(76)?;
    let governor = establish(tenant)?;
    let transferred = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
        )?)?
        .transfer();
    assert_eq!(governor.inspect()?.outstanding_total(), 1);

    drop(transferred);

    assert_eq!(governor.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn repeated_transfer_and_reclaim_preserve_one_grant_until_final_drop()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(77)?;
    let governor = establish(tenant)?;
    let reservation = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
    )?)?;

    let reservation = reservation.transfer().reclaim(governor.governor())?;
    let reservation = reservation.transfer().reclaim(governor.governor())?;
    assert_eq!(governor.inspect()?.outstanding_total(), 1);

    drop(reservation);
    assert_eq!(governor.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn foreign_reclaim_fences_foreign_governor_and_releases_original_grant()
-> Result<(), Box<dyn std::error::Error>> {
    let original_tenant = tenant(78)?;
    let foreign_tenant = tenant(79)?;
    let original = establish(original_tenant)?;
    let foreign = establish(foreign_tenant)?;
    let transferred = original
        .reserve(WorkClaim::tenant(
            original_tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
        )?)?
        .transfer();

    assert_eq!(
        transferred
            .reclaim(foreign.governor())
            .expect_err("a transferred grant cannot cross governors"),
        positron_kernel::GovernorFailure::InternalFenced
    );
    assert_eq!(original.inspect()?.outstanding_total(), 0);
    assert_eq!(foreign.inspect()?.lifecycle(), GovernorLifecycle::Fenced);
    Ok(())
}

#[test]
fn foreign_release_fences_foreign_governor_and_releases_original_grant()
-> Result<(), Box<dyn std::error::Error>> {
    let original_tenant = tenant(80)?;
    let foreign_tenant = tenant(81)?;
    let original = establish(original_tenant)?;
    let foreign = establish(foreign_tenant)?;
    let transferred = original
        .reserve(WorkClaim::tenant(
            original_tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
        )?)?
        .transfer();

    transferred.release(foreign.governor());

    assert_eq!(original.inspect()?.outstanding_total(), 0);
    assert_eq!(foreign.inspect()?.lifecycle(), GovernorLifecycle::Fenced);
    Ok(())
}
