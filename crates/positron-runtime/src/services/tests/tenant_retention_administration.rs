use std::error::Error;
use std::num::NonZeroU64;
use std::sync::Arc;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::identity::{TenantId, TenantSlug};
use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{ActiveSegmentLedger, RetentionReclamationEstimate, RetentionTimeAuthority};
use prost::Message;

use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, open_catalog, request};
use crate::BootstrapFailureCode;
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
