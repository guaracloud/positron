use std::error::Error;
use std::sync::{Arc, Mutex, mpsc};

use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_query::QueryBudget;
use prost::Message;

use super::schema_lifecycle_support::BlockingQueryExecution;
use super::schema_maintenance::{Fixture, request};
use crate::services::{ServiceFailure, ServiceHandle};

#[test]
fn suspended_transition_cancels_and_drains_actual_query_route_before_publication()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query_secret, administrator_secret) =
        fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("query-drain").encode_to_vec())?
            .accepted_records(),
        1
    );
    let before = initialized
        .resource_governor()
        .inspect()?
        .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
    let (progress_tx, progress_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    services.install_query_execution_test_hook(Arc::new(BlockingQueryExecution {
        progress: progress_tx.clone(),
        release: Mutex::new(release_rx),
    }))?;
    let querying_services = services.clone();
    let query = std::thread::spawn(move || {
        let result = querying_services.query_log_bodies(
            &query_secret,
            "logs | range query_time 0 100 | limit 2",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)
                .expect("fixed query budget")
                .with_cpu_work_units(16)
                .expect("fixed query work"),
        );
        let _ = progress_tx.send("returned");
        result
    });
    if progress_rx.recv()? != "admitted" {
        return Err(format!(
            "query route returned before lifecycle admission: {:?}",
            query.join().map_err(|_| "query thread panicked")?
        )
        .into());
    }
    let (closing_tx, closing_rx) = mpsc::channel();
    initialized.install_lifecycle_query_transition_observer(closing_tx)?;
    let transitioning = Arc::clone(&initialized);
    let (completed_tx, completed_rx) = mpsc::channel();
    let transition = std::thread::spawn(move || {
        let result = (|| {
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
                TenantLifecycleState::Suspended,
                ResourceGeneration::new(1).map_err(|_| {
                    crate::BootstrapFailure::new(crate::BootstrapFailureCode::ResourceUnavailable)
                })?,
                AdministrativeIdempotencyKey::new([0x7f; 16]).map_err(|_| {
                    crate::BootstrapFailure::new(crate::BootstrapFailureCode::ResourceUnavailable)
                })?,
            )
        })();
        let _ = completed_tx.send(result);
    });
    closing_rx.recv()?;
    assert!(
        completed_rx.try_recv().is_err(),
        "restrictive transition must wait for the admitted route to unwind"
    );
    release_tx.send(())?;
    assert_eq!(
        query.join().map_err(|_| "query thread panicked")?,
        Err(ServiceFailure::Cancelled),
        "the ordinary query route observes lifecycle cancellation"
    );
    assert_eq!(completed_rx.recv()??.to(), TenantLifecycleState::Suspended);
    transition
        .join()
        .map_err(|_| "transition thread panicked")?;
    let after = initialized
        .resource_governor()
        .inspect()?
        .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
    assert_eq!(
        after, before,
        "cancelled query route released its query work"
    );
    Ok(())
}

#[test]
fn read_only_query_uses_the_current_durable_identity_after_transition() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, ingest, query_secret) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    for body in ["first", "second"] {
        assert_eq!(
            services
                .ingest_otlp_logs(&ingest, request(body).encode_to_vec())?
                .accepted_records(),
            1
        );
    }
    initialized.set_governance_lifecycle_for_test(TenantLifecycleState::ReadOnly)?;

    assert_eq!(
        services.query_log_bodies(
            &query_secret,
            "logs | range query_time 0 100 | limit 2",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)?
                .with_cpu_work_units(16)?,
        )?,
        ["first", "second"]
    );
    Ok(())
}

#[test]
fn admitted_active_ingest_is_revalidated_before_append_after_lifecycle_transition()
-> Result<(), Box<dyn Error>> {
    for (state, lifecycle) in [
        ("read-only", TenantLifecycleState::ReadOnly),
        ("suspended", TenantLifecycleState::Suspended),
        ("purging", TenantLifecycleState::Purging),
        ("purged", TenantLifecycleState::Purged),
    ] {
        let fixture = Fixture::new()?;
        let (initialized, ingest, query_secret) = fixture.initialized()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        let context = services.authorize_logs(&ingest)?;
        let governor_before = initialized.resource_governor().inspect()?;
        let admission = services.admit_logs(context)?;
        let reservation = admission.take()?;

        initialized.set_governance_lifecycle_for_test(lifecycle)?;

        assert_eq!(
            services.ingest_decoded_otlp_logs(context, request("must-not-append"), reservation),
            Err(ServiceFailure::Unauthorized),
            "state {state}"
        );
        let governor_after = initialized.resource_governor().inspect()?;
        assert_eq!(
            governor_after.outstanding_total(),
            governor_before.outstanding_total(),
            "state {state} leaked a reservation",
        );
        assert_eq!(
            governor_after.outstanding_ordinary(),
            governor_before.outstanding_ordinary(),
            "state {state} leaked ordinary capacity",
        );
        assert_eq!(
            governor_after.outstanding_recovery(),
            governor_before.outstanding_recovery(),
            "state {state} leaked recovery capacity",
        );
        for dimension in positron_kernel::ResourceDimension::ALL {
            assert_eq!(
                governor_after.usage(dimension),
                governor_before.usage(dimension),
                "state {state} leaked {dimension:?}",
            );
        }

        initialized.set_governance_lifecycle_for_test(TenantLifecycleState::Active)?;
        assert!(
            services
                .query_log_bodies(
                    &query_secret,
                    "logs | range query_time 0 100 | limit 10",
                    QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)?
                        .with_cpu_work_units(16)?,
                )?
                .is_empty()
        );
    }
    Ok(())
}
