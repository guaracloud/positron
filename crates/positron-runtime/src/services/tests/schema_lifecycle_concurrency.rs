use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use positron_api::tenant_lifecycle::{
    TenantLifecycleState as ApiTenantLifecycleState, TenantLifecycleTransitionRequest,
};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_query::QueryCancellation;
use prost::Message;

use super::super::tenant_lifecycle::TenantLifecycleHttpFailure;
use super::schema_lifecycle_support::{BlockingFinalizationBackend, trace_request};
use super::schema_maintenance::{Fixture, request};
use crate::services::{ServiceFailure, ServiceHandle};

#[test]
fn read_only_closure_waits_for_entered_trace_finalization() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (lifecycle_tx, lifecycle_rx) = mpsc::channel();
    services.install_receiver_test_backend(Arc::new(BlockingFinalizationBackend {
        entered: entered_tx,
        release: Mutex::new(release_rx),
        lifecycle_before_finish: Some((Arc::clone(&initialized), ingest.clone(), lifecycle_tx)),
    }))?;
    let first_services = services.clone();
    let first_ingest = ingest.clone();
    let first = std::thread::spawn(move || {
        first_services.ingest_otlp_traces(&first_ingest, trace_request().encode_to_vec())
    });
    entered_rx.recv()?;
    let (closed_tx, closed_rx) = mpsc::channel();
    initialized.install_lifecycle_transition_observer(closed_tx)?;
    let transitioning = Arc::clone(&initialized);
    let transition = std::thread::spawn(move || {
        let actor = transitioning
            .attribute(
                PresentedCredential::parse(&administrator_secret).map_err(|_| {
                    crate::BootstrapFailure::new(
                        crate::BootstrapFailureCode::TenantLifecycleUnauthorized,
                    )
                })?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| {
                crate::BootstrapFailure::new(
                    crate::BootstrapFailureCode::TenantLifecycleUnauthorized,
                )
            })?;
        transitioning.transition_tenant_lifecycle(
            actor,
            transitioning.default_tenant_id(),
            TenantLifecycleState::ReadOnly,
            ResourceGeneration::new(1).map_err(|_| {
                crate::BootstrapFailure::new(crate::BootstrapFailureCode::ResourceUnavailable)
            })?,
            AdministrativeIdempotencyKey::new([0x77; 16]).map_err(|_| {
                crate::BootstrapFailure::new(crate::BootstrapFailureCode::ResourceUnavailable)
            })?,
        )
    });
    closed_rx.recv()?;
    assert_eq!(
        services.ingest_otlp_traces(&ingest, trace_request().encode_to_vec()),
        Err(ServiceFailure::Unauthorized),
    );
    release_tx.send(())?;
    assert!(first.join().map_err(|_| "trace thread panicked")?.is_ok());
    assert!(
        lifecycle_rx.recv()?,
        "the admitted trace must finish before ReadOnly publishes"
    );
    assert_eq!(
        transition
            .join()
            .map_err(|_| "transition thread panicked")??
            .to(),
        TenantLifecycleState::ReadOnly
    );
    Ok(())
}

#[test]
fn rejected_lifecycle_transition_reopens_native_ingest_admission() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let rejected = initialized
        .transition_tenant_lifecycle(
            actor,
            initialized.default_tenant_id(),
            TenantLifecycleState::Active,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x7d; 16])?,
        )
        .expect_err("the closed lifecycle graph rejects a no-op transition");
    assert_eq!(
        rejected.code(),
        crate::BootstrapFailureCode::TenantLifecycleInvalidTransition
    );
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("admission-reopened").encode_to_vec())?
            .accepted_records(),
        1
    );
    Ok(())
}

#[test]
fn stale_and_invalid_lifecycle_requests_do_not_interrupt_live_work_or_publish()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let _ingest = initialized.enter_ingest_finalization_for(initialized.default_tenant_id())?;
    let cancellation = QueryCancellation::new();
    let _query = initialized
        .enter_query_execution_for(initialized.default_tenant_id(), cancellation.clone())?;
    let audit_before = initialized.governance_audit_for_test()?;
    let tenant = initialized.default_tenant_id().to_canonical_text();

    let stale = TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        ApiTenantLifecycleState::Suspended,
        2,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaab".to_owned(),
    );
    assert!(matches!(
        services.administer_tenant_lifecycle(&administrator_secret, &stale.encode()?),
        Err(TenantLifecycleHttpFailure::StaleGeneration { .. })
    ));
    assert!(
        !cancellation.is_cancelled(),
        "a stale 409 must not cancel an already admitted query"
    );

    let invalid = TenantLifecycleTransitionRequest::new(
        tenant,
        ApiTenantLifecycleState::Active,
        1,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaac".to_owned(),
    );
    assert!(matches!(
        services.administer_tenant_lifecycle(&administrator_secret, &invalid.encode()?),
        Err(TenantLifecycleHttpFailure::Code(409, "invalid_transition"))
    ));
    assert!(
        !cancellation.is_cancelled(),
        "an invalid 409 must not cancel an already admitted query"
    );
    assert_eq!(initialized.governance_audit_for_test()?, audit_before);
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("still-open-after-409").encode_to_vec())?
            .accepted_records(),
        1,
        "preflight failures leave ingestion open"
    );
    Ok(())
}

#[test]
fn lifecycle_successor_between_preflight_and_drain_does_not_cancel_live_query()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let cancellation = QueryCancellation::new();
    let _query = initialized
        .enter_query_execution_for(initialized.default_tenant_id(), cancellation.clone())?;
    let audit_before = initialized.governance_audit_for_test()?;
    let (preflight_tx, preflight_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let hook_calls = Arc::clone(&calls);
    let hook_release = Arc::new(Mutex::new(release_rx));
    initialized.install_lifecycle_preflight_hook(Arc::new(move || {
        if hook_calls.fetch_add(1, Ordering::AcqRel) == 0 {
            let _ = preflight_tx.send(());
            if let Ok(receiver) = hook_release.lock() {
                let _ = receiver.recv();
            }
        }
    }))?;

    let racing = Arc::clone(&initialized);
    let racing_secret = administrator_secret.clone();
    let stale = std::thread::spawn(move || {
        let actor = racing
            .attribute(
                PresentedCredential::parse(&racing_secret).map_err(|_| {
                    crate::BootstrapFailure::new(
                        crate::BootstrapFailureCode::TenantLifecycleUnauthorized,
                    )
                })?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| {
                crate::BootstrapFailure::new(
                    crate::BootstrapFailureCode::TenantLifecycleUnauthorized,
                )
            })?;
        racing.transition_tenant_lifecycle(
            actor,
            racing.default_tenant_id(),
            TenantLifecycleState::Suspended,
            ResourceGeneration::new(1).map_err(|_| {
                crate::BootstrapFailure::new(crate::BootstrapFailureCode::ResourceUnavailable)
            })?,
            AdministrativeIdempotencyKey::new([0xac; 16]).map_err(|_| {
                crate::BootstrapFailure::new(crate::BootstrapFailureCode::ResourceUnavailable)
            })?,
        )
    });
    preflight_rx.recv()?;

    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let successor = initialized.transition_tenant_lifecycle(
        actor,
        initialized.default_tenant_id(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xad; 16])?,
    )?;
    assert_eq!(successor.to(), TenantLifecycleState::ReadOnly);
    release_tx.send(())?;
    let stale = stale
        .join()
        .map_err(|_| "racing lifecycle transition panicked")?;
    assert!(
        !cancellation.is_cancelled(),
        "a stale transition must not cancel work after another successor wins"
    );
    let stale = stale.expect_err("the successor advances the lifecycle generation");
    assert_eq!(
        stale.code(),
        crate::BootstrapFailureCode::TenantLifecycleStaleGeneration
    );
    assert_eq!(
        initialized.governance_audit_for_test()?.len(),
        audit_before.len() + 1
    );
    Ok(())
}

#[test]
fn committed_active_retry_does_not_close_fresh_active_ingest_admission()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let actor = || {
        initialized.attribute(
            PresentedCredential::parse(&administrator_secret).expect("fixture credential"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };
    initialized.transition_tenant_lifecycle(
        actor()?,
        initialized.default_tenant_id(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x81; 16])?,
    )?;
    let request_key = AdministrativeIdempotencyKey::new([0x82; 16])?;
    let committed = initialized.transition_tenant_lifecycle(
        actor()?,
        initialized.default_tenant_id(),
        TenantLifecycleState::Active,
        ResourceGeneration::new(2)?,
        request_key,
    )?;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    services.install_receiver_test_backend(Arc::new(BlockingFinalizationBackend {
        entered: entered_tx,
        release: Mutex::new(release_rx),
        lifecycle_before_finish: None,
    }))?;
    let active_services = services.clone();
    let active_ingest = ingest.clone();
    let active_request = std::thread::spawn(move || {
        active_services.ingest_otlp_logs(&active_ingest, request("active-retry").encode_to_vec())
    });
    entered_rx.recv()?;
    let (closed_tx, closed_rx) = mpsc::channel();
    initialized.install_lifecycle_transition_observer(closed_tx)?;

    let replay = initialized.transition_tenant_lifecycle(
        actor()?,
        initialized.default_tenant_id(),
        TenantLifecycleState::Active,
        ResourceGeneration::new(2)?,
        request_key,
    )?;

    assert_eq!(replay, committed);
    assert!(
        closed_rx.try_recv().is_err(),
        "an exact committed retry must not close fresh admission"
    );
    release_tx.send(())?;
    assert!(
        active_request
            .join()
            .map_err(|_| "ingest thread panicked")?
            .is_ok()
    );
    Ok(())
}

#[test]
fn timed_out_lifecycle_drain_reopens_admission_without_publishing() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let held = initialized.enter_ingest_finalization_for(initialized.default_tenant_id())?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let failure = initialized
        .transition_tenant_lifecycle(
            actor,
            initialized.default_tenant_id(),
            TenantLifecycleState::ReadOnly,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x7e; 16])?,
        )
        .expect_err("a non-completing finalization must time out");
    assert_eq!(
        failure.code(),
        crate::BootstrapFailureCode::ResourceUnavailable
    );
    drop(held);
    assert_eq!(
        services
            .ingest_otlp_logs(
                &ingest,
                request("admission-reopened-after-timeout").encode_to_vec()
            )?
            .accepted_records(),
        1
    );
    Ok(())
}
