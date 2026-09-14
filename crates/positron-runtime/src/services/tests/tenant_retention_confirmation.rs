use std::error::Error;
use std::num::NonZeroU64;
use std::sync::Arc;

use positron_domain::{identity::Scope, time::UnixNanoseconds};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::RetentionTimeAuthority;
use prost::Message;

use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, request};
#[test]
fn confirmed_retention_reduction_replays_after_its_successor() -> Result<(), Box<dyn Error>> {
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
    let proposed = NonZeroU64::new(86_400).ok_or("nonzero retention")?;
    let preview = initialized.inspect_tenant_retention_impact(actor, tenant, proposed)?;
    let idempotency = AdministrativeIdempotencyKey::new([0xc1; 16])?;
    let updated = initialized.update_tenant_retention(
        actor,
        tenant,
        proposed,
        ResourceGeneration::new(1)?,
        Some(&preview),
        idempotency,
    )?;
    assert_eq!(updated.retention_generation().get(), 2);
    assert_eq!(
        initialized.update_tenant_retention(
            actor,
            tenant,
            proposed,
            ResourceGeneration::new(1)?,
            Some(&preview),
            idempotency,
        )?,
        updated,
        "an exact retention retry replays after its successor"
    );
    Ok(())
}

#[test]
fn retention_confirmation_uses_the_preview_instant_but_rechecks_current_impact()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance reference")?
        .install_retention_time_for_test(retention_time)?;
    let tenant = initialized.default_tenant_id();
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let administrator_secret = initialized
        .create_api_key_for_tenant(
            system,
            tenant,
            Scope::TenantAdministration,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xd2; 16])?,
        )?
        .secret()
        .ok_or("tenant-administration credential")?
        .to_owned();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let preview = services
        .preview_tenant_retention(
            &administrator_secret,
            &positron_api::tenant_retention::TenantRetentionPreviewRequest::new(
                tenant.to_canonical_text(),
                86_400,
            )
            .encode()?,
        )
        .map_err(|failure| {
            std::io::Error::other(format!("retention preview service failure: {failure:?}"))
        })?;
    assert_eq!(preview.confirmation_evaluated_at_unix_nanos, 10_000_000_000);

    elapsed.advance(2_000_000_000)?;
    let confirmed = positron_api::tenant_retention::TenantRetentionUpdateRequest::new(
        tenant.to_canonical_text(),
        86_400,
        preview.retention_generation,
        Some(preview.confirmation_digest.clone()),
        "c4c4c4c4-c4c4-c4c4-c4c4-c4c4c4c4c4c4".to_owned(),
    )
    .with_confirmation_evaluated_at_unix_nanos(preview.confirmation_evaluated_at_unix_nanos);
    assert_eq!(
        services
            .update_tenant_retention_service(&administrator_secret, &confirmed.encode()?)
            .map_err(|failure| {
                std::io::Error::other(format!("retention update service failure: {failure:?}"))
            })?
            .retention_generation,
        2,
        "ordinary trusted-clock advancement must not invalidate unchanged evidence"
    );
    elapsed.advance(2_000_000_000)?;
    assert_eq!(
        services
            .update_tenant_retention_service(&administrator_secret, &confirmed.encode()?)
            .map_err(|failure| {
                std::io::Error::other(format!("retention replay service failure: {failure:?}"))
            })?
            .retention_generation,
        2,
        "an exact receipt replay resolves before current-impact validation"
    );

    let fixture = Fixture::new()?;
    let (mut initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let (retention_time, _elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance reference")?
        .install_retention_time_for_test(retention_time)?;
    let tenant = initialized.default_tenant_id();
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let administrator_secret = initialized
        .create_api_key_for_tenant(
            system,
            tenant,
            Scope::TenantAdministration,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xd3; 16])?,
        )?
        .secret()
        .ok_or("tenant-administration credential")?
        .to_owned();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let preview = services
        .preview_tenant_retention(
            &administrator_secret,
            &positron_api::tenant_retention::TenantRetentionPreviewRequest::new(
                tenant.to_canonical_text(),
                86_400,
            )
            .encode()?,
        )
        .map_err(|_| "retention preview service failure")?;
    let forged_future = positron_api::tenant_retention::TenantRetentionUpdateRequest::new(
        tenant.to_canonical_text(),
        86_400,
        preview.retention_generation,
        Some(preview.confirmation_digest),
        "c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3".to_owned(),
    )
    .with_confirmation_evaluated_at_unix_nanos(
        preview
            .confirmation_evaluated_at_unix_nanos
            .checked_add(1)
            .ok_or("future timestamp")?,
    );
    assert!(matches!(
        services.update_tenant_retention_service(&administrator_secret, &forged_future.encode()?),
        Err(
            super::super::tenant_retention::TenantRetentionHttpFailure::Code(
                409,
                "invalid_confirmation"
            )
        )
    ));
    Ok(())
}

#[test]
fn retention_confirmation_rejects_newly_eligible_data_after_its_preview()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, ingest_secret, _, administrator_secret) =
        fixture.initialized_with_admin()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance reference")?
        .install_retention_time_for_test(retention_time)?;
    let tenant = initialized.default_tenant_id();
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let administrator_secret = initialized
        .create_api_key_for_tenant(
            system,
            tenant,
            Scope::TenantAdministration,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xd4; 16])?,
        )?
        .secret()
        .ok_or("tenant-administration credential")?
        .to_owned();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(
                &ingest_secret,
                request("retention-before-preview").encode_to_vec()
            )?
            .accepted_records(),
        1
    );
    elapsed.advance(2_000_000_000)?;
    let preview = services
        .preview_tenant_retention(
            &administrator_secret,
            &positron_api::tenant_retention::TenantRetentionPreviewRequest::new(
                tenant.to_canonical_text(),
                1,
            )
            .encode()?,
        )
        .map_err(|failure| {
            std::io::Error::other(format!("retention preview service failure: {failure:?}"))
        })?;
    assert!(preview.scopes.iter().any(|scope| scope.affected_bytes > 0));

    elapsed.advance(2_000_000_000)?;
    assert_eq!(
        services
            .ingest_otlp_logs(
                &ingest_secret,
                request("retention-before-preview").encode_to_vec()
            )?
            .accepted_records(),
        1
    );
    let confirmation = positron_api::tenant_retention::TenantRetentionUpdateRequest::new(
        tenant.to_canonical_text(),
        1,
        preview.retention_generation,
        Some(preview.confirmation_digest),
        "c5c5c5c5-c5c5-c5c5-c5c5-c5c5c5c5c5c5".to_owned(),
    )
    .with_confirmation_evaluated_at_unix_nanos(preview.confirmation_evaluated_at_unix_nanos);
    assert!(matches!(
        services.update_tenant_retention_service(&administrator_secret, &confirmation.encode()?),
        Err(
            super::super::tenant_retention::TenantRetentionHttpFailure::Code(
                409,
                "invalid_confirmation"
            )
        )
    ));
    Ok(())
}
