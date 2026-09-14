use std::error::Error;
use std::sync::{Arc, Mutex, mpsc};

use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_query::{QueryBudget, QueryEvent, QueryFailureCode, QueryTerminal};
use prost::Message;

use super::super::query::QueryTestOutcome;
use super::schema_lifecycle_support::BlockingFinalizationBackend;
use super::schema_maintenance::{Fixture, request};
use crate::services::{ServiceFailure, ServiceHandle};

#[test]
fn checked_query_resume_revalidates_every_durable_tenant_lifecycle_state()
-> Result<(), Box<dyn Error>> {
    for (state, lifecycle, ingest_allowed, query_allowed) in [
        ("active", TenantLifecycleState::Active, true, true),
        ("read-only", TenantLifecycleState::ReadOnly, false, true),
        ("suspended", TenantLifecycleState::Suspended, false, false),
        ("purging", TenantLifecycleState::Purging, false, false),
        ("purged", TenantLifecycleState::Purged, false, false),
    ] {
        let fixture = Fixture::new()?;
        let (initialized, ingest, query_secret) = fixture.initialized()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        for body in ["first", "second"] {
            let request = request(body);
            assert_eq!(
                services
                    .ingest_otlp_logs(&ingest, request.encode_to_vec())?
                    .accepted_records(),
                1
            );
        }
        let context = initialized.attribute(
            PresentedCredential::parse(&query_secret)?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        )?;
        let events = match services.query_events_for_test(
            context,
            "logs | range query_time 0 100 | limit 2",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)?
                .with_cpu_work_units(16)?,
            Some(1),
        )? {
            QueryTestOutcome::Events(events) => events,
            QueryTestOutcome::Failure(code) => {
                return Err(format!("{state} initial page failed: {code:?}").into());
            },
        };
        let cursor = match events.last() {
            Some(QueryEvent::Terminal(QueryTerminal::Continued(cursor))) => cursor.clone(),
            _ => return Err(format!("{state} query did not produce a cursor").into()),
        };
        initialized.set_governance_lifecycle_for_test(lifecycle)?;
        let contended_authorization = services.authorize_logs(&ingest);
        let direct_attribution = initialized.attribute(
            PresentedCredential::parse(&ingest)?,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        );
        assert_eq!(
            direct_attribution.is_ok(),
            ingest_allowed,
            "{state} stale attribution"
        );
        if ingest_allowed {
            assert!(
                contended_authorization.is_ok(),
                "{state} read-only authorization must not require the writer"
            );
        } else {
            assert_eq!(
                contended_authorization,
                Err(ServiceFailure::Unauthorized),
                "{state} lifecycle rejection must remain authorization-shaped"
            );
        }
        let durable_ingest = initialized.attribute(
            PresentedCredential::parse(&ingest)?,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        );
        let durable_query = initialized.attribute(
            PresentedCredential::parse(&query_secret)?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        );
        assert_eq!(
            durable_ingest.is_ok(),
            ingest_allowed,
            "{state} ingest identity state"
        );
        assert_eq!(
            durable_query.is_ok(),
            query_allowed,
            "{state} query identity state"
        );
        // Every resume request authenticates its bearer against the durable
        // lifecycle state before presenting its cursor.
        let resume_context = durable_query.unwrap_or(context);

        let before = initialized
            .resource_governor()
            .inspect()?
            .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
        let resumed = services.resume_query_events_for_test(resume_context, &cursor, 1)?;
        if query_allowed {
            match resumed {
                QueryTestOutcome::Events(_) => {},
                QueryTestOutcome::Failure(code) => {
                    return Err(format!("{state} resume failed: {code:?}").into());
                },
            }
        } else {
            assert_eq!(
                resumed,
                QueryTestOutcome::Failure(QueryFailureCode::Unauthorized),
                "{state}"
            );
        }
        let after = initialized
            .resource_governor()
            .inspect()?
            .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
        if query_allowed {
            assert_eq!(after, 0, "{state} completion did not release query work");
        } else {
            assert_eq!(
                after, before,
                "{state} lifecycle rejection leaked query work"
            );
        }
    }
    Ok(())
}

#[test]
fn durable_lifecycle_transition_drains_admitted_ingest_and_revalidates_query_cursor()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query_secret, administrator_secret) =
        fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    for body in ["first", "second"] {
        assert_eq!(
            services
                .ingest_otlp_logs(&ingest, request(body).encode_to_vec())?
                .accepted_records(),
            1
        );
    }
    let query_context = initialized.attribute(
        PresentedCredential::parse(&query_secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let events = match services.query_events_for_test(
        query_context,
        "logs | range query_time 0 100 | limit 2",
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)?.with_cpu_work_units(16)?,
        Some(1),
    )? {
        QueryTestOutcome::Events(events) => events,
        QueryTestOutcome::Failure(code) => {
            return Err(format!("initial query failed: {code:?}").into());
        },
    };
    let cursor = match events.last() {
        Some(QueryEvent::Terminal(QueryTerminal::Continued(cursor))) => cursor.clone(),
        _ => return Err("initial query did not produce a cursor".into()),
    };
    let ingest_context = services.authorize_logs(&ingest)?;
    let reservation = services.admit_logs(ingest_context)?.take()?;
    let administrator = || {
        initialized.attribute(
            PresentedCredential::parse(&administrator_secret)
                .expect("fixture administrator syntax"),
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
    };

    let read_only = initialized.transition_tenant_lifecycle(
        administrator()?,
        initialized.default_tenant_id(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x73; 16])?,
    )?;
    assert_eq!(read_only.to(), TenantLifecycleState::ReadOnly);
    assert_eq!(
        services.ingest_decoded_otlp_logs(ingest_context, request("must-not-append"), reservation),
        Err(ServiceFailure::Unauthorized),
        "the final Catalog-writer check drains pre-admitted ingest before ReadOnly publishes"
    );
    let read_only_query_context = initialized.attribute(
        PresentedCredential::parse(&query_secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let resumed = services.resume_query_events_for_test(read_only_query_context, &cursor, 1)?;
    assert!(
        matches!(resumed, QueryTestOutcome::Events(_)),
        "ReadOnly preserves bounded cursor resume: {resumed:?}"
    );

    let suspended = initialized.transition_tenant_lifecycle(
        administrator()?,
        initialized.default_tenant_id(),
        TenantLifecycleState::Suspended,
        read_only.resource_generation(),
        AdministrativeIdempotencyKey::new([0x74; 16])?,
    )?;
    assert_eq!(suspended.to(), TenantLifecycleState::Suspended);
    let before = initialized
        .resource_governor()
        .inspect()?
        .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
    assert_eq!(
        services.resume_query_events_for_test(query_context, &cursor, 1)?,
        QueryTestOutcome::Failure(QueryFailureCode::Unauthorized)
    );
    let after = initialized
        .resource_governor()
        .inspect()?
        .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
    assert_eq!(
        after, before,
        "a suspended cursor cannot admit or leak query work"
    );
    Ok(())
}

#[test]
fn read_only_closure_waits_for_entered_ingest_and_rejects_later_admission()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    services.install_receiver_test_backend(Arc::new(BlockingFinalizationBackend {
        entered: entered_tx,
        release: Mutex::new(release_rx),
        lifecycle_before_finish: None,
    }))?;
    let first_services = services.clone();
    let first_ingest = ingest.clone();
    let first = std::thread::spawn(move || {
        first_services.ingest_otlp_logs(&first_ingest, request("draining").encode_to_vec())
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
        let expected_generation = ResourceGeneration::new(1).map_err(|_| {
            crate::BootstrapFailure::new(crate::BootstrapFailureCode::ResourceUnavailable)
        })?;
        let idempotency_key = AdministrativeIdempotencyKey::new([0x76; 16]).map_err(|_| {
            crate::BootstrapFailure::new(crate::BootstrapFailureCode::ResourceUnavailable)
        })?;
        transitioning.transition_tenant_lifecycle(
            actor,
            transitioning.default_tenant_id(),
            TenantLifecycleState::ReadOnly,
            expected_generation,
            idempotency_key,
        )
    });
    closed_rx.recv()?;
    assert_eq!(
        services.ingest_otlp_logs(&ingest, request("must-not-admit").encode_to_vec()),
        Err(ServiceFailure::Unauthorized),
        "closure rejects later native admission while the entered finalization drains"
    );
    release_tx.send(())?;
    assert!(first.join().map_err(|_| "ingest thread panicked")?.is_ok());
    let transition = transition
        .join()
        .map_err(|_| "transition thread panicked")??;
    assert_eq!(transition.to(), TenantLifecycleState::ReadOnly);
    assert_eq!(
        services.ingest_otlp_logs(&ingest, request("closed").encode_to_vec()),
        Err(ServiceFailure::Unauthorized)
    );
    Ok(())
}
