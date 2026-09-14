use std::error::Error;
use std::num::NonZeroU64;
use std::sync::Arc;

use positron_domain::time::UnixNanoseconds;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{
    CatalogPublicationFault, RetentionTimeAuthority, with_catalog_publication_fault_after,
};

use super::schema_maintenance::Fixture;
use crate::BootstrapFailureCode;
#[test]
fn retention_fault_is_atomic_then_exact_retry_and_reopen_replay_remain_stable()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let (retention_time, _elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance reference")?
        .install_retention_time_for_test(retention_time)?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized.default_tenant_id();
    let expected = ResourceGeneration::new(1)?;
    let proposed = NonZeroU64::new(86_400).ok_or("nonzero retention")?;
    let preview = initialized.inspect_tenant_retention_impact(actor, tenant, proposed)?;
    let key = AdministrativeIdempotencyKey::new([0xc8; 16])?;
    let audit_count = initialized.governance_audit_for_test()?.len();
    let failed =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.update_tenant_retention(
                actor,
                tenant,
                proposed,
                expected,
                Some(&preview),
                key,
            )
        })
        .expect_err("a pre-marker fault must publish neither retention nor audit evidence");
    assert_eq!(failed.code(), BootstrapFailureCode::CatalogUnavailable);
    let first = initialized
        .update_tenant_retention(actor, tenant, proposed, expected, Some(&preview), key)
        .map_err(|failure| format!("prepared retry: {failure:?}"))?;
    let audit = initialized
        .governance_audit_for_test()
        .map_err(|failure| format!("audit after prepared retry: {failure:?}"))?;
    assert_eq!(audit.len(), audit_count + 1);
    let retention_audit = audit
        .iter()
        .find(|entry| entry.position() == first.audit_position())
        .and_then(positron_governance::GovernanceAuditEntry::as_tenant_retention_update)
        .ok_or("retention audit meaning")?;
    assert_eq!(retention_audit.tenant_id(), tenant);
    assert_eq!(retention_audit.expected_generation(), expected);
    assert_eq!(retention_audit.generation(), first.retention_generation());
    assert_eq!(retention_audit.idempotency_key(), key);
    assert!(
        retention_audit
            .request_digest()
            .iter()
            .any(|byte| *byte != 0),
        "audit retains a digest instead of retention seconds"
    );
    let successor = initialized
        .update_tenant_retention(
            actor,
            tenant,
            NonZeroU64::new(2_700_000).ok_or("nonzero retention")?,
            ResourceGeneration::new(2)?,
            None,
            AdministrativeIdempotencyKey::new([0xc9; 16])?,
        )
        .map_err(|failure| format!("post-retry successor: {failure:?}"))?;
    assert_eq!(successor.retention_generation().get(), 3);
    drop(initialized);

    let reopened = fixture
        .reopen()
        .map_err(|failure| format!("reopen after prepared retry: {failure:?}"))?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        reopened
            .update_tenant_retention(actor, tenant, proposed, expected, Some(&preview), key)
            .map_err(|failure| format!("historical reopen replay: {failure:?}"))?,
        first,
        "an exact historical receipt replays after a later successor and reopen"
    );
    assert!(
        reopened.catalog_generation() >= 3,
        "reopen retains the successor that the old receipt must not restore"
    );
    Ok(())
}
