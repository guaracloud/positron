use std::error::Error;
use std::fs;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::identity::Scope;
use positron_domain::identity::{ExternalTenantAlias, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration, TenantAdministration,
};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule};
use positron_kernel::{
    ActiveSegmentLedger, CatalogObject, CatalogProposal, CatalogPublicationFault, FormatEpoch,
    MountQualification, RetentionReclamationEstimate, RetentionTimeAuthority, TransactionId,
    with_catalog_publication_fault_after,
};
use positron_query::QueryBudget;
use prost::Message;

use super::super::{ServiceFailure, ServiceHandle};
use super::schema_maintenance::{Fixture, open_catalog, request};
use crate::{BootstrapFailureCode, BootstrapPaths, InstanceBootstrap};

#[test]
fn ordinary_ingest_fails_closed_when_its_tenant_envelope_is_corrupt() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    corrupt_default_tenant_envelope(&initialized)?;
    assert!(
        matches!(
            ServiceHandle::new(Arc::clone(&initialized)),
            Err(ServiceFailure::KeyUnavailable)
        ),
        "ordinary services must not recover or admit data with a corrupt authenticated tenant envelope"
    );
    assert!(
        initialized
            .attribute(
                PresentedCredential::parse(&ingest)?,
                RequestedIntent::Ingest,
                CompatibilityHints::none(),
            )
            .is_ok(),
        "envelope corruption is a key-custody failure, not a credential mutation"
    );
    Ok(())
}

#[test]
fn system_administrator_binds_an_immutable_alias_with_an_exact_replay() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, ingest_secret, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let alias = ExternalTenantAlias::parse("loki.compatibility_42")?;
    let bound = initialized.bind_tenant_alias(
        actor,
        initialized.default_tenant_id(),
        alias.clone(),
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb1; 16])?,
    )?;
    assert_eq!(bound.alias_generation(), ResourceGeneration::new(2)?);
    assert_eq!(
        initialized.bind_tenant_alias(
            actor,
            initialized.default_tenant_id(),
            alias,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xb1; 16])?,
        )?,
        bound
    );
    assert_eq!(
        initialized
            .bind_tenant_alias(
                actor,
                initialized.default_tenant_id(),
                ExternalTenantAlias::parse("loki.rebind_forbidden")?,
                ResourceGeneration::new(2)?,
                AdministrativeIdempotencyKey::new([0xb2; 16])?,
            )
            .expect_err("an immutable alias must not be rebound")
            .code(),
        BootstrapFailureCode::TenantAliasAlreadyBound
    );
    assert!(
        initialized
            .attribute(
                PresentedCredential::parse(&ingest_secret)?,
                RequestedIntent::Ingest,
                CompatibilityHints::external_tenant_alias("loki.compatibility_42")?,
            )
            .is_ok(),
        "the post-authentication compatibility assertion accepts the bound alias"
    );
    assert!(
        initialized
            .attribute(
                PresentedCredential::parse(&ingest_secret)?,
                RequestedIntent::Ingest,
                CompatibilityHints::external_tenant_alias("trace-external")?,
            )
            .is_err(),
        "the bootstrap alias cannot remain an alternate routing selector after a bind"
    );
    Ok(())
}

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

#[test]
fn system_administrator_previews_real_log_and_trace_retention_impact_without_mutation()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance reference")?
        .install_retention_time_for_test(retention_time)?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let ordinary_ingest = initialized.attribute(
        PresentedCredential::parse(&ingest)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized.default_tenant_id();
    let proposed = NonZeroU64::new(1).ok_or("one-second retention")?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("retention-preview-log").encode_to_vec())?
            .accepted_records(),
        1
    );
    let trace = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x71; 16],
                    span_id: vec![0x72; 8],
                    name: "retention-preview-trace".to_owned(),
                    start_time_unix_nano: 42,
                    end_time_unix_nano: 43,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    assert_eq!(
        services
            .ingest_otlp_traces(&ingest, trace.encode_to_vec())?
            .accepted_records(),
        1
    );
    elapsed.advance(2_000_000_000)?;

    let catalog = open_catalog(&initialized)
        .map_err(|failure| format!("open log lease catalog: {failure:?}"))?;
    let log_scope = catalog
        .pin()
        .map_err(|failure| format!("pin log lease catalog: {failure:?}"))?
        .reachable_ledger_scopes(tenant, SignalKind::Logs)
        .map_err(|failure| format!("find runtime log scope: {failure:?}"))?
        .into_iter()
        .next()
        .ok_or("runtime log scope")?;
    let log_ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        log_scope,
        initialized.tenant_segment_key_for_test(log_scope)?,
    )
    .map_err(|failure| format!("open log retention ledger: {failure:?}"))?;
    log_ledger
        .seal()
        .map_err(|failure| format!("seal log retention ledger: {failure:?}"))?;
    let lease_ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        log_scope,
        initialized.tenant_segment_key_for_test(log_scope)?,
    )
    .map_err(|failure| format!("reopen log lease ledger: {failure:?}"))?;
    let lease = lease_ledger
        .create_snapshot_lease_for(0, NonZeroU64::new(10).ok_or("ten-second lease")?)
        .map_err(|failure| format!("create log snapshot lease: {failure:?}"))?;
    assert_eq!(lease.expiry(), 22);
    drop(lease);
    drop(lease_ledger);
    drop(catalog);

    let catalog_before = open_catalog(&initialized)?.pin()?.identity();
    let audit_before = initialized.governance_audit_for_test()?.len();
    let preview = initialized.inspect_tenant_retention_impact(system, tenant, proposed)?;
    assert_eq!(preview.tenant(), tenant);
    assert_eq!(preview.retention_generation(), ResourceGeneration::new(1)?);
    assert_eq!(preview.proposed_retention_seconds(), proposed);
    assert_eq!(preview.catalog_identity(), catalog_before);
    assert!(preview.catalog_generation() > 0);
    let [logs, traces] = preview.scopes() else {
        return Err("one log and one trace retention scope".into());
    };
    assert_eq!(logs.approximate_affected_bytes(), 172);
    assert_eq!(traces.approximate_affected_bytes(), 205);
    for (scope, signal) in [(logs, SignalKind::Logs), (traces, SignalKind::Traces)] {
        assert_eq!(scope.scope().tenant_id(), tenant);
        assert_eq!(scope.scope().signal_kind(), signal);
        assert_eq!(scope.catalog_identity(), preview.catalog_identity());
        assert_eq!(scope.catalog_generation(), preview.catalog_generation());
        assert_eq!(scope.evaluated_at(), UnixNanoseconds::new(12_000_000_000));
        let range = scope
            .affected_time_range()
            .ok_or("expired ingest-time range")?;
        assert_eq!(range.earliest(), UnixNanoseconds::new(10_000_000_000));
        assert_eq!(range.latest(), UnixNanoseconds::new(10_000_000_000));
        assert!(scope.approximate_affected_bytes() > 0);
        match signal {
            SignalKind::Logs => {
                assert_eq!(scope.deferred_active_segment_bytes(), 0);
                assert_eq!(scope.approximate_immediately_reclaimable_bytes(), 172);
                assert_eq!(
                    scope.earliest_reclamation(),
                    RetentionReclamationEstimate::BlockedByDurableLease(UnixNanoseconds::new(
                        22_000_000_000
                    ))
                );
            },
            SignalKind::Traces => {
                assert_eq!(
                    scope.deferred_active_segment_bytes(),
                    scope.approximate_affected_bytes(),
                    "active data is affected but cannot be physically reclaimed"
                );
                assert_eq!(scope.approximate_immediately_reclaimable_bytes(), 0);
                assert_eq!(
                    scope.earliest_reclamation(),
                    RetentionReclamationEstimate::None
                );
            },
        }
        assert_eq!(scope.deferred_mixed_sealed_segment_bytes(), 0);
    }
    assert_eq!(
        open_catalog(&initialized)?.pin()?.identity(),
        catalog_before
    );
    assert_eq!(initialized.governance_audit_for_test()?.len(), audit_before);
    elapsed.advance(2_000_000_000)?;
    let resumed = initialized.inspect_tenant_retention_impact_at(
        system,
        tenant,
        proposed,
        Some(preview.evaluated_at()),
    )?;
    assert_eq!(
        resumed.confirmation_digest(),
        preview.confirmation_digest(),
        "a continuation resumes the original trusted evaluation instant after the clock advances"
    );
    let unauthorized =
        match initialized.inspect_tenant_retention_impact(ordinary_ingest, tenant, proposed) {
            Ok(_) => return Err("ingest credentials cannot inspect tenant-retention impact".into()),
            Err(failure) => failure,
        };
    assert_eq!(
        unauthorized.code(),
        BootstrapFailureCode::ApiKeyUnauthorized
    );

    let digest = preview.confirmation_digest();
    let changed_candidate = initialized.inspect_tenant_retention_impact(
        system,
        tenant,
        NonZeroU64::new(2).ok_or("two-second retention")?,
    )?;
    assert_ne!(changed_candidate.confirmation_digest(), digest);
    initialized.update_tenant_display_name(
        system,
        tenant,
        ResourceGeneration::new(1)?,
        "Retention preview catalog binding",
        AdministrativeIdempotencyKey::new([0x71; 16])?,
    )?;
    let changed_catalog = initialized.inspect_tenant_retention_impact(system, tenant, proposed)?;
    assert_ne!(changed_catalog.confirmation_digest(), digest);
    let expanded = initialized.update_tenant_retention(
        system,
        tenant,
        NonZeroU64::new(2_700_000).ok_or("expanded retention")?,
        ResourceGeneration::new(1)?,
        None,
        AdministrativeIdempotencyKey::new([0x72; 16])?,
    )?;
    assert_eq!(expanded.retention_generation(), ResourceGeneration::new(2)?);
    let changed_generation =
        initialized.inspect_tenant_retention_impact(system, tenant, proposed)?;
    assert_eq!(
        changed_generation.retention_generation(),
        ResourceGeneration::new(2)?
    );
    assert_ne!(
        changed_generation.confirmation_digest(),
        changed_catalog.confirmation_digest()
    );
    Ok(())
}

#[test]
fn retention_reduction_confirmation_is_required_and_bound_to_its_tenant_and_candidate()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized.default_tenant_id();
    let expected = ResourceGeneration::new(1)?;
    let proposed = NonZeroU64::new(86_400).ok_or("nonzero retention")?;
    let missing = initialized
        .update_tenant_retention(
            actor,
            tenant,
            proposed,
            expected,
            None,
            AdministrativeIdempotencyKey::new([0xc2; 16])?,
        )
        .expect_err("a retention reduction needs a current impact confirmation");
    assert_eq!(
        missing.code(),
        BootstrapFailureCode::TenantRetentionInvalidConfirmation
    );

    let wrong_candidate = initialized.inspect_tenant_retention_impact(
        actor,
        tenant,
        NonZeroU64::new(86_401).ok_or("nonzero retention")?,
    )?;
    let changed_candidate = initialized
        .update_tenant_retention(
            actor,
            tenant,
            proposed,
            expected,
            Some(&wrong_candidate),
            AdministrativeIdempotencyKey::new([0xc3; 16])?,
        )
        .expect_err("a confirmation cannot be reused for a different candidate");
    assert_eq!(
        changed_candidate.code(),
        BootstrapFailureCode::TenantRetentionInvalidConfirmation
    );

    let other_tenant = TenantId::from_bytes([0xc4; 16])?;
    initialized.create_tenant(
        actor,
        other_tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("retention-other")?,
            "Retention other",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xc4; 16])?,
    )?;
    let other_preview =
        initialized.inspect_tenant_retention_impact(actor, other_tenant, proposed)?;
    let cross_tenant = initialized
        .update_tenant_retention(
            actor,
            tenant,
            proposed,
            expected,
            Some(&other_preview),
            AdministrativeIdempotencyKey::new([0xc5; 16])?,
        )
        .expect_err("a confirmation from another tenant cannot authorize this reduction");
    assert_eq!(
        cross_tenant.code(),
        BootstrapFailureCode::TenantRetentionInvalidConfirmation
    );
    assert_eq!(
        initialized
            .inspect_tenant(actor, tenant)?
            .retention_generation()
            .get(),
        1
    );
    Ok(())
}

#[test]
fn retention_expansion_and_stale_reduction_report_a_redacted_generation_conflict()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized.default_tenant_id();
    let expanded = initialized.update_tenant_retention(
        actor,
        tenant,
        NonZeroU64::new(2_700_000).ok_or("nonzero retention")?,
        ResourceGeneration::new(1)?,
        None,
        AdministrativeIdempotencyKey::new([0xc6; 16])?,
    )?;
    assert_eq!(expanded.retention_generation().get(), 2);
    let stale = initialized
        .update_tenant_retention(
            actor,
            tenant,
            NonZeroU64::new(86_400).ok_or("nonzero retention")?,
            ResourceGeneration::new(1)?,
            None,
            AdministrativeIdempotencyKey::new([0xc7; 16])?,
        )
        .expect_err("a new mutation must compare against the current retention generation");
    assert_eq!(
        stale.code(),
        BootstrapFailureCode::TenantRetentionStaleGeneration
    );
    assert_eq!(
        stale
            .retention_generation_conflict()
            .map(|conflict| conflict.current_generation().get()),
        Some(2)
    );
    assert_eq!(
        stale
            .retention_generation_conflict()
            .map(positron_governance::TenantRetentionGenerationConflict::semantic_diff),
        Some("retention_seconds")
    );
    Ok(())
}

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

#[test]
fn tenant_aliases_are_unique_and_secondary_retries_are_exact_after_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0xD1; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("alias-secondary")?,
            "Alias secondary",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xD1; 16])?,
    )?;
    let key = AdministrativeIdempotencyKey::new([0xD2; 16])?;
    let bound = initialized.bind_tenant_alias(
        system,
        tenant,
        ExternalTenantAlias::parse("loki.secondary")?,
        ResourceGeneration::new(1)?,
        key,
    )?;
    drop(initialized);
    let reopened = fixture.reopen()?;
    let system = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        reopened.bind_tenant_alias(
            system,
            tenant,
            ExternalTenantAlias::parse("loki.secondary")?,
            ResourceGeneration::new(1)?,
            key,
        )?,
        bound,
        "a reopen must retain the original exact idempotency receipt"
    );
    assert_eq!(
        reopened
            .bind_tenant_alias(
                system,
                tenant,
                ExternalTenantAlias::parse("loki.changed-body")?,
                ResourceGeneration::new(1)?,
                key,
            )
            .expect_err("same idempotency key with changed alias must conflict")
            .code(),
        BootstrapFailureCode::TenantAliasIdempotencyConflict
    );
    assert_eq!(
        reopened
            .bind_tenant_alias(
                system,
                reopened.default_tenant_id(),
                ExternalTenantAlias::parse("loki.secondary")?,
                ResourceGeneration::new(1)?,
                AdministrativeIdempotencyKey::new([0xD3; 16])?,
            )
            .expect_err("an alias cannot move across tenants")
            .code(),
        BootstrapFailureCode::TenantAliasConflict
    );
    Ok(())
}

#[test]
fn alias_publication_fault_leaves_no_audit_or_generation_successor() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let key = AdministrativeIdempotencyKey::new([0xD4; 16])?;
    let audit_count = initialized.governance_audit_for_test()?.len();
    let failed =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.bind_tenant_alias(
                system,
                initialized.default_tenant_id(),
                ExternalTenantAlias::parse("loki.atomic").expect("known alias"),
                ResourceGeneration::new(1).expect("known generation"),
                key,
            )
        })
        .expect_err("a pre-marker fault cannot publish alias state or audit evidence");
    assert_eq!(failed.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(initialized.governance_audit_for_test()?.len(), audit_count);
    let bound = initialized.bind_tenant_alias(
        system,
        initialized.default_tenant_id(),
        ExternalTenantAlias::parse("loki.atomic")?,
        ResourceGeneration::new(1)?,
        key,
    )?;
    assert_eq!(bound.alias_generation().get(), 2);
    assert_eq!(
        initialized.governance_audit_for_test()?.len(),
        audit_count + 1
    );
    Ok(())
}

#[test]
fn secondary_alias_is_only_a_post_authentication_compatibility_assertion()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0xD5; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("alias-credential")?,
            "Alias credential",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xD5; 16])?,
    )?;
    initialized.bind_tenant_alias(
        system,
        tenant,
        ExternalTenantAlias::parse("loki.secondary-credential")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xD6; 16])?,
    )?;
    let credential = initialized
        .create_api_key_for_tenant(
            system,
            tenant,
            Scope::Ingest,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xD7; 16])?,
        )?
        .secret()
        .ok_or("secondary ingest credential")?
        .to_owned();
    let attributed = initialized.attribute(
        PresentedCredential::parse(&credential)?,
        RequestedIntent::Ingest,
        CompatibilityHints::external_tenant_alias("loki.secondary-credential")?,
    )?;
    assert_eq!(
        attributed
            .tenant_attribution()
            .map(|value| value.tenant_id()),
        Some(tenant)
    );
    for alias in ["loki.wrong-secondary", "trace-external"] {
        assert!(
            initialized
                .attribute(
                    PresentedCredential::parse(&credential)?,
                    RequestedIntent::Ingest,
                    CompatibilityHints::external_tenant_alias(alias)?,
                )
                .is_err(),
            "a compatibility hint cannot select or redirect the credential tenant"
        );
    }
    Ok(())
}

#[test]
fn new_default_tenant_envelope_serves_data_after_reopen() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    assert!(
        initialized
            .durable_identity()?
            .tenant_key_envelope(initialized.tenant)?
            .starts_with(b"POSTKE01"),
        "new initial tenants must persist a provisioned tenant KEK envelope"
    );
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("postke-reopen").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["postke-reopen"]
    );
    Ok(())
}

#[test]
fn system_administrator_inspects_default_and_provisioned_tenants_without_secret_material()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0xA1; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("inspection-tenant")?,
            "Inspection tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xA1; 16])?,
    )?;

    let listed = initialized.list_tenants(system)?;
    assert_eq!(listed.len(), 2);
    let inspection = initialized.inspect_tenant(system, tenant)?;
    assert_eq!(inspection.slug(), "inspection-tenant");
    assert_eq!(inspection.display_name(), "Inspection tenant");
    assert_eq!(inspection.display_generation().get(), 1);
    assert_eq!(inspection.retention_generation().get(), 1);
    Ok(())
}

#[test]
fn system_administrator_updates_a_provisioned_tenant_display_name_idempotently()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0xB1; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("display-name-tenant")?,
            "Original display name",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xB1; 16])?,
    )?;

    let key = AdministrativeIdempotencyKey::new([0xB2; 16])?;
    let updated = initialized.update_tenant_display_name(
        system,
        tenant,
        ResourceGeneration::new(1)?,
        "Renamed tenant",
        key,
    )?;
    let replay = initialized.update_tenant_display_name(
        system,
        tenant,
        ResourceGeneration::new(1)?,
        "Renamed tenant",
        key,
    )?;
    assert_eq!(updated, replay);
    assert_eq!(updated.resource_generation().get(), 2);

    let changed_retry = initialized
        .update_tenant_display_name(
            system,
            tenant,
            ResourceGeneration::new(1)?,
            "Changed retry",
            key,
        )
        .expect_err("a changed retry must not reuse the original display successor");
    assert_eq!(
        changed_retry.code(),
        BootstrapFailureCode::TenantDisplayNameIdempotencyConflict
    );

    let second = initialized.update_tenant_display_name(
        system,
        tenant,
        ResourceGeneration::new(2)?,
        "Second display name",
        AdministrativeIdempotencyKey::new([0xB3; 16])?,
    )?;
    assert_eq!(second.resource_generation().get(), 3);
    let audit = initialized
        .governance_audit_for_test()?
        .into_iter()
        .find(|entry| entry.position() == updated.audit_position())
        .ok_or("display-name audit")?;
    let display_audit = audit
        .as_tenant_display_name_update()
        .ok_or("display-name audit meaning")?;
    assert_eq!(audit.action(), "tenant.display-name.update");
    assert_eq!(display_audit.tenant_id(), tenant);
    assert_eq!(display_audit.expected_generation().get(), 1);
    assert_eq!(display_audit.generation().get(), 2);
    assert_eq!(display_audit.idempotency_key(), key);
    assert!(
        display_audit.request_digest().iter().any(|byte| *byte != 0),
        "audit retains a digest instead of the display name"
    );
    assert_eq!(
        initialized.update_tenant_display_name(
            system,
            tenant,
            ResourceGeneration::new(1)?,
            "Renamed tenant",
            key,
        )?,
        updated,
        "an old exact retry returns its original result without restoring old state"
    );
    let stale = initialized
        .update_tenant_display_name(
            system,
            tenant,
            ResourceGeneration::new(2)?,
            "Stale name",
            AdministrativeIdempotencyKey::new([0xB4; 16])?,
        )
        .expect_err("new display mutations require the current display generation");
    assert_eq!(
        stale.code(),
        BootstrapFailureCode::TenantDisplayNameStaleGeneration
    );
    assert_eq!(
        stale
            .display_generation_conflict()
            .map(|conflict| conflict.current_generation().get()),
        Some(3)
    );
    assert_eq!(
        stale
            .display_generation_conflict()
            .map(positron_governance::TenantDisplayGenerationConflict::semantic_diff),
        Some("display_name")
    );
    let publication =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.update_tenant_display_name(
                system,
                tenant,
                ResourceGeneration::new(3).expect("known display generation"),
                "Faulted display name",
                AdministrativeIdempotencyKey::new([0xB5; 16]).expect("known idempotency key"),
            )
        })
        .expect_err("failed publication must leave the display name unchanged");
    assert_eq!(publication.code(), BootstrapFailureCode::CatalogUnavailable);

    let inspection = initialized.inspect_tenant(system, tenant)?;
    assert_eq!(inspection.display_name(), "Second display name");
    assert_eq!(inspection.display_generation().get(), 3);
    assert_eq!(inspection.retention_seconds(), 2_592_000);
    assert_eq!(inspection.retention_generation().get(), 1);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let system = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let inspection = reopened.inspect_tenant(system, tenant)?;
    assert_eq!(inspection.display_name(), "Second display name");
    assert_eq!(inspection.display_generation().get(), 3);
    assert_eq!(inspection.retention_generation().get(), 1);
    Ok(())
}

#[test]
fn system_administrator_updates_default_tenant_display_without_changing_retention()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized.default_tenant_id();
    let updated = initialized.update_tenant_display_name(
        system,
        tenant,
        ResourceGeneration::new(1)?,
        "Renamed default tenant",
        AdministrativeIdempotencyKey::new([0xB6; 16])?,
    )?;
    assert_eq!(updated.resource_generation().get(), 2);
    let inspection = initialized.inspect_tenant(system, tenant)?;
    assert_eq!(inspection.display_name(), "Renamed default tenant");
    assert_eq!(inspection.display_generation().get(), 2);
    assert_eq!(inspection.retention_generation().get(), 1);
    Ok(())
}

#[test]
fn fresh_instance_publishes_epoch_two_default_tenant_registry_before_serving()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator_secret) = fixture.initialized_with_admin()?;
    assert_eq!(
        initialized.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2),
        "fresh initialization must never publish provisioned tenant state as Epoch 1"
    );
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::registered_tenant_ids(&snapshot)?,
        [initialized.default_tenant_id()],
        "the directory must contain the one default tenant state held by POSGOV"
    );
    drop((snapshot, catalog));

    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant_key = initialized.create_api_key(
        system,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x71; 16])?,
    )?;
    let tenant_administrator = initialized.attribute(
        PresentedCredential::parse(tenant_key.secret().ok_or("tenant key")?)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_tenant_quota(
        tenant_administrator,
        initialized.default_tenant_id(),
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x72; 16])?,
        1,
        [
            32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
        ],
    )?;
    initialized.transition_tenant_lifecycle(
        system,
        initialized.default_tenant_id(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x73; 16])?,
    )?;
    initialized.transition_tenant_lifecycle(
        system,
        initialized.default_tenant_id(),
        TenantLifecycleState::Active,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x74; 16])?,
    )?;

    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("fresh-epoch-two").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    let catalog = open_catalog(&reopened)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::registered_tenant_ids(&snapshot)?,
        [reopened.default_tenant_id()]
    );
    drop((snapshot, catalog));
    let reconstructed_tenant_administrator = reopened.attribute(
        PresentedCredential::parse(tenant_key.secret().ok_or("tenant key")?)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    assert!(
        reconstructed_tenant_administrator
            .tenant_attribution()
            .is_some_and(|attribution| attribution.tenant_id() == reopened.default_tenant_id())
    );
    assert!(
        reopened
            .durable_identity()?
            .tenant_key_envelope(reopened.default_tenant_id())?
            .starts_with(b"POSTKE01")
    );
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["fresh-epoch-two"]
    );
    Ok(())
}

#[test]
fn created_tenant_reopens_with_its_authenticated_envelope() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x75; 16])?;
    initialized
        .create_tenant(
            system,
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("envelope-tenant")?,
                "Envelope tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x76; 16])?,
        )
        .map_err(|failure| format!("tenant creation: {failure:?}"))?;
    drop(initialized);

    let reopened = fixture.reopen()?;
    assert!(
        reopened
            .durable_identity()?
            .tenant_key_envelope(tenant)?
            .starts_with(b"POSTKE01"),
        "a registered tenant must reconstruct its own authenticated data-protection envelope"
    );
    Ok(())
}

#[test]
fn tenant_creation_does_not_require_a_registry_generation_precondition()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;

    let created = initialized.create_tenant(
        system,
        TenantId::from_bytes([0x74; 16])?,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("no-create-precondition")?,
            "No creation precondition",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0x73; 16])?,
    );

    assert!(
        created.is_ok(),
        "tenant creation must not require a stale registry precondition"
    );
    Ok(())
}

#[test]
fn explicit_default_tenant_key_provisioning_uses_the_single_governance_authority()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let created = initialized.create_api_key_for_tenant(
        system,
        initialized.default_tenant_id(),
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x91; 16])?,
    )?;
    let secret = created
        .secret()
        .ok_or("default query credential")?
        .to_owned();
    drop(initialized);

    let reopened = fixture.reopen()?;
    reopened.attribute(
        PresentedCredential::parse(&secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    Ok(())
}

#[test]
fn secondary_tenant_key_lifecycle_is_replay_safe_and_reopens_bound_to_its_tenant()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x97; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("key-lifecycle-tenant")?,
            "Key lifecycle tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0x98; 16])?,
    )?;
    let created = initialized.create_api_key_for_tenant(
        system,
        tenant,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x99; 16])?,
    )?;
    let predecessor = created.principal_id();
    let predecessor_secret = created.secret().ok_or("secondary query secret")?.to_owned();
    let listed = initialized.list_api_keys_for_tenant(system, tenant)?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].principal_id(), predecessor);
    assert_eq!(listed[0].scope(), Scope::Query);
    assert!(listed[0].is_active());
    assert_eq!(listed[0].generation().get(), 2);
    let rotation_key = AdministrativeIdempotencyKey::new([0x9a; 16])?;
    let rotated = initialized.rotate_api_key_for_tenant(
        system,
        tenant,
        predecessor,
        ResourceGeneration::new(2)?,
        rotation_key,
    )?;
    let successor = rotated.principal_id();
    let successor_secret = rotated
        .secret()
        .ok_or("secondary successor secret")?
        .to_owned();
    let replay = initialized.rotate_api_key_for_tenant(
        system,
        tenant,
        predecessor,
        ResourceGeneration::new(2)?,
        rotation_key,
    )?;
    assert_eq!(replay.principal_id(), successor);
    assert!(
        replay.secret().is_none(),
        "replay must not redisplay a secret"
    );
    initialized.revoke_api_key_for_tenant(
        system,
        tenant,
        predecessor,
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([0x9b; 16])?,
    )?;
    let replay_after_later_mutation = initialized.rotate_api_key_for_tenant(
        system,
        tenant,
        predecessor,
        ResourceGeneration::new(2)?,
        rotation_key,
    )?;
    assert_eq!(replay_after_later_mutation.principal_id(), successor);
    assert!(
        replay_after_later_mutation.secret().is_none(),
        "a terminal retry after a later mutation must not redisplay its secret"
    );
    drop(initialized);

    let reopened = fixture.reopen()?;
    let system = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let descriptors = reopened.list_api_keys_for_tenant(system, tenant)?;
    assert_eq!(descriptors.len(), 2);
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == predecessor
            && !descriptor.is_active()
            && descriptor.generation().get() == 4
    }));
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == successor
            && descriptor.is_active()
            && descriptor.generation().get() == 4
    }));
    assert!(
        reopened
            .attribute(
                PresentedCredential::parse(&predecessor_secret)?,
                RequestedIntent::Query,
                CompatibilityHints::none(),
            )
            .is_err()
    );
    let context = reopened.attribute(
        PresentedCredential::parse(&successor_secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        context.tenant_attribution().map(|value| value.tenant_id()),
        Some(tenant)
    );
    Ok(())
}

#[test]
fn secondary_tenant_uses_its_own_activated_policy_after_reopen() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, default_ingest, _, administrator_secret) =
        fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x92; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("policy-tenant")?,
            "Policy tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0x93; 16])?,
    )?;
    let ingest = initialized.create_api_key_for_tenant(
        system,
        tenant,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x94; 16])?,
    )?;
    let administration = initialized.create_api_key_for_tenant(
        system,
        tenant,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x95; 16])?,
    )?;
    let ingest = ingest
        .secret()
        .ok_or("tenant ingest credential")?
        .to_owned();
    let administration = administration
        .secret()
        .ok_or("tenant administration credential")?
        .to_owned();
    let actor = initialized.attribute(
        PresentedCredential::parse(&administration)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.activate_ingest_policy(
        actor,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x96; 16])?,
        IngestPolicy::compile(
            2,
            vec![PolicyRule::new(
                "reject-tenant",
                Vec::new(),
                PolicyAction::Reject,
            )?],
        )?,
    )?;
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("secondary-policy").encode_to_vec())?
            .permanently_rejected_records(),
        1,
        "the secondary tenant must use its own persisted reject policy"
    );
    assert_eq!(
        services
            .ingest_otlp_logs(&default_ingest, request("default-policy").encode_to_vec())?
            .accepted_records(),
        1,
        "the secondary policy must not affect the default tenant"
    );
    Ok(())
}

#[test]
fn secondary_tenant_administrator_updates_quotas_with_replay_reopen_and_fault_safety()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x88; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("quota-tenant")?,
            "Quota tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0x89; 16])?,
    )?;
    let tenant_administration = initialized.create_api_key_for_tenant(
        system,
        tenant,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x8a; 16])?,
    )?;
    let tenant_administration_secret = tenant_administration
        .secret()
        .ok_or("tenant administration credential")?
        .to_owned();
    let actor = initialized.attribute(
        PresentedCredential::parse(&tenant_administration_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let first_key = AdministrativeIdempotencyKey::new([0x8b; 16])?;
    let first = initialized.update_tenant_quota(
        actor,
        tenant,
        ResourceGeneration::new(1)?,
        first_key,
        1,
        [1; 11],
    )?;
    assert_eq!(first.resource_generation().get(), 2);
    assert_eq!(
        initialized.update_tenant_quota(
            actor,
            tenant,
            ResourceGeneration::new(1)?,
            first_key,
            1,
            [1; 11],
        )?,
        first,
        "an exact secondary quota retry returns the original successor"
    );
    let conflict = initialized
        .update_tenant_quota(
            actor,
            tenant,
            ResourceGeneration::new(1)?,
            first_key,
            1,
            [2; 11],
        )
        .expect_err("a changed retry must not reuse a secondary quota receipt");
    assert_eq!(
        conflict.code(),
        BootstrapFailureCode::TenantQuotaIdempotencyConflict
    );
    let second = initialized.update_tenant_quota(
        actor,
        tenant,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x8c; 16])?,
        1,
        [3; 11],
    )?;
    assert_eq!(second.resource_generation().get(), 3);
    assert_eq!(
        initialized.update_tenant_quota(
            actor,
            tenant,
            ResourceGeneration::new(1)?,
            first_key,
            1,
            [1; 11],
        )?,
        first,
        "an old receipt must not restore an obsolete live or durable quota"
    );
    let stale = initialized
        .update_tenant_quota(
            actor,
            tenant,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0x8d; 16])?,
            1,
            [4; 11],
        )
        .expect_err("new secondary mutations require the current resource generation");
    assert_eq!(
        stale.code(),
        BootstrapFailureCode::TenantQuotaStaleGeneration
    );
    assert_eq!(
        stale
            .quota_generation_conflict()
            .map(ResourceGeneration::get),
        Some(3)
    );

    let publication =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.update_tenant_quota(
                actor,
                tenant,
                ResourceGeneration::new(3).expect("known valid generation"),
                AdministrativeIdempotencyKey::new([0x8e; 16]).expect("known valid key"),
                1,
                [1; 11],
            )
        })
        .expect_err("failed publication must leave the secondary quota unchanged");
    assert_eq!(publication.code(), BootstrapFailureCode::CatalogUnavailable);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let reopened_actor = reopened.attribute(
        PresentedCredential::parse(&tenant_administration_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let successor = reopened.update_tenant_quota(
        reopened_actor,
        tenant,
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([0x8f; 16])?,
        1,
        [2; 11],
    )?;
    assert_eq!(successor.resource_generation().get(), 4);
    Ok(())
}

#[test]
fn tenant_bound_keys_serve_only_the_created_tenant_after_reopen() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, default_query, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x77; 16])?;
    initialized
        .create_tenant(
            system,
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("serving-tenant")?,
                "Serving tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x78; 16])?,
        )
        .map_err(|failure| format!("tenant creation: {failure:?}"))?;
    let ingest = initialized
        .create_api_key_for_tenant(
            system,
            tenant,
            Scope::Ingest,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x79; 16])?,
        )
        .map_err(|failure| format!("ingest key creation: {failure:?}"))?;
    let query = initialized
        .create_api_key_for_tenant(
            system,
            tenant,
            Scope::Query,
            None,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0x7a; 16])?,
        )
        .map_err(|failure| format!("query key creation: {failure:?}"))?;
    let ingest = ingest
        .secret()
        .ok_or("created ingest credential")?
        .to_owned();
    let query = query.secret().ok_or("created query credential")?.to_owned();
    drop(initialized);

    let reopened = fixture
        .reopen()
        .map_err(|failure| format!("reopen: {failure:?}"))?;
    let services = ServiceHandle::new(Arc::clone(&reopened))
        .map_err(|failure| format!("service construction: {failure:?}"))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("created-tenant-only").encode_to_vec())
            .map_err(|failure| format!("tenant ingest: {failure:?}"))?
            .accepted_records(),
        1
    );
    let budget =
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(15)?;
    assert_eq!(
        services.query_log_bodies(&query, "logs | range query_time 0 100 | limit 16", budget)?,
        ["created-tenant-only"]
    );
    let budget =
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(15)?;
    assert!(
        services
            .query_log_bodies(
                &default_query,
                "logs | range query_time 0 100 | limit 16",
                budget
            )?
            .is_empty(),
        "the default tenant must not read newly created tenant data"
    );
    Ok(())
}

#[test]
fn released_legacy_envelope_data_serves_after_epoch_two_migration() -> Result<(), Box<dyn Error>> {
    let fixture = LegacyFixtureRoots::from_f9_fixture()?;
    let data = fixture.root().join("data");
    let secrets = fixture.root().join("secrets");
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let administrator_secret = claim.secret().to_owned();
    let query = claim
        .query_secret()
        .ok_or("legacy query credential")?
        .to_owned();
    let initialized = Arc::new(InstanceBootstrap::reopen(&paths)?);
    assert_eq!(
        initialized.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V1)
    );
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized
        .migrate_catalog_to_epoch_two(system, AdministrativeIdempotencyKey::new([0xd3; 16])?)?;
    assert_eq!(
        initialized.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::registered_tenant_ids(&snapshot)?,
        [initialized.default_tenant_id()],
        "migration must publish the V2 directory for the legacy default tenant"
    );
    drop(snapshot);
    let policy = positron_governance::IngestPolicyAdministration::open(
        &catalog,
        initialized.default_tenant_id(),
    )?;
    assert_eq!(policy.serving().pin()?.generation(), 1);
    drop(catalog);
    drop(initialized);
    let reopened = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["legacy-f9-before-v2"]
    );
    Ok(())
}

struct LegacyFixtureRoots {
    root: PathBuf,
}

impl LegacyFixtureRoots {
    fn from_f9_fixture() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-f9-v1-compatibility-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        let fixture = Self { root };
        let source = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy-f9-v1"
        ));
        for name in ["data", "secrets"] {
            copy_tree(&source.join(name), &fixture.root().join(name))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                fixture.root().join("secrets"),
                fs::Permissions::from_mode(0o700),
            )?;
            for name in ["bootstrap-claim.v1", "local-root-key.v1"] {
                fs::set_permissions(
                    fixture.root().join("secrets").join(name),
                    fs::Permissions::from_mode(0o600),
                )?;
            }
            assert_eq!(
                fs::metadata(fixture.root().join("secrets"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o700,
                "copied legacy secrets root stays owner-only"
            );
            for name in ["bootstrap-claim.v1", "local-root-key.v1"] {
                assert_eq!(
                    fs::metadata(fixture.root().join("secrets").join(name))?
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600,
                    "copied legacy {name} stays owner-only"
                );
            }
        }
        Ok(fixture)
    }

    fn root(&self) -> &std::path::Path {
        &self.root
    }
}

fn copy_tree(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), std::io::Error> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), destination_path)?;
        } else {
            return Err(std::io::Error::other(
                "legacy V1 fixture contains an unsupported entry",
            ));
        }
    }
    Ok(())
}

impl Drop for LegacyFixtureRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn corrupt_default_tenant_envelope(
    initialized: &crate::InitializedInstance,
) -> Result<(), Box<dyn Error>> {
    let envelope = initialized
        .durable_identity()?
        .tenant_key_envelope(initialized.tenant)?
        .to_vec();
    let catalog = open_catalog(initialized)?;
    let snapshot = catalog.pin()?;
    let mut changed = false;
    let objects = snapshot
        .object_identities()
        .map(|identity| {
            let mut bytes = snapshot
                .object(identity)?
                .ok_or("missing catalog object")?
                .to_vec();
            if !changed
                && let Some(offset) = bytes
                    .windows(envelope.len())
                    .position(|candidate| candidate == envelope)
            {
                bytes[offset] ^= 0x01;
                changed = true;
            }
            CatalogObject::new(bytes).map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    assert!(
        changed,
        "the authenticated tenant envelope must be catalog-carried"
    );
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0xd2; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
