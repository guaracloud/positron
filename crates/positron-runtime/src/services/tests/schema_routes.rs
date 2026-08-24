use std::error::Error;
use std::sync::Arc;

use positron_domain::routing::SignalKind;
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::LokiPushRequestEncoding;
use positron_ingest::{
    AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome,
    NativeLogAdmissionGroups,
};
use positron_kernel::{ActiveSegmentLedger, SegmentScope};
use positron_kernel::{CatalogObject, CatalogProposal, FormatEpoch, TransactionId};
use positron_query::{
    QueryBudget, QueryBudgetDimension, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
};
use prost::Message;

use super::schema_maintenance::{Fixture, open_catalog, request};
use crate::services::{ReceiverTestBackend, ServiceFailure, ServiceHandle};

#[test]
fn real_otlp_and_loki_routes_share_one_live_schema_session() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("otlp-shared").encode_to_vec())?
            .accepted_records(),
        1
    );
    let context = services.authorize_logs(&ingest)?;
    let admission = services.admit_logs(context)?;
    let loki = br#"{"streams":[{"stream":{"app":"shared"},"values":[["42","loki-shared"]]}]}"#;
    let loki_outcome = services.ingest_encoded_loki_push(
        context,
        LokiPushRequestEncoding::Json,
        loki.to_vec(),
        admission.take()?,
    )?;
    assert_eq!(
        loki_outcome.accepted_records(),
        1,
        "Loki groups: {:?}",
        loki_outcome.groups()
    );
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["otlp-shared", "loki-shared"]
    );
    assert_eq!(
        services
            .schema_sessions
            .session(initialized.tenant, initialized.resource_governor(),)?
            .checkpoint()?
            .entry_count(),
        1
    );
    Ok(())
}

#[test]
fn production_query_pool_admits_the_full_effective_cpu_budget() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query_secret) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let ingest_context = services.authorize_logs(&ingest)?;
    for (instant, body) in [("42", "one"), ("43", "two")] {
        let admission = services.admit_logs(ingest_context)?;
        let loki = format!(
            r#"{{"streams":[{{"stream":{{"app":"budget"}},"values":[["{instant}","{body}"]]}}]}}"#
        );
        assert_eq!(
            services
                .ingest_encoded_loki_push(
                    ingest_context,
                    LokiPushRequestEncoding::Json,
                    loki.into_bytes(),
                    admission.take()?,
                )?
                .accepted_records(),
            1
        );
    }

    let catalog = open_catalog(&initialized)?;
    let scope = SegmentScope::new(initialized.tenant, SignalKind::Logs, initialized.logs_shard);
    let protection = initialized.key.segment_key(initialized.instance, scope)?;
    let ledger = ActiveSegmentLedger::open(&initialized._authority, &catalog, scope, protection)?;
    let query_service = QueryService::new(
        initialized.resource_governor(),
        &ledger,
        100,
        initialized.identity.clone(),
    );
    let context = initialized.attribute(
        PresentedCredential::parse(&query_secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let source = "logs | range query_time 0 100 | limit 16";

    let exact = query_service.plan_pipeline(
        context,
        source,
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(16)?,
    )?;
    let schema = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?;
    let exact_events = schema
        .with_catalog_view(initialized.tenant, |view| {
            query_service.execute_with_schema(exact, view)
        })??
        .collect::<Vec<_>>();
    assert!(
        matches!(
            exact_events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Complete(stats)))
                if stats.cpu_work_units() == 16 && stats.records() == 2
        ),
        "exact events: {exact_events:?}"
    );

    let exhausted = query_service.plan_pipeline(
        context,
        source,
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(15)?,
    )?;
    let exhausted_events = schema
        .with_catalog_view(initialized.tenant, |view| {
            query_service.execute_with_schema(exhausted, view)
        })??
        .collect::<Vec<_>>();
    assert!(matches!(
        exhausted_events.first(),
        Some(QueryEvent::Header(_))
    ));
    assert!(matches!(
        exhausted_events.last(),
        Some(QueryEvent::Terminal(QueryTerminal::Incomplete(failure)))
            if failure.code() == QueryFailureCode::BudgetExhausted
                && failure.stats().cpu_work_units() == 16
                && failure.stats().limiting_budget()
                    == Some(QueryBudgetDimension::CpuWorkUnits)
    ));

    let refused = match query_service.plan_pipeline(
        context,
        source,
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(17)?,
    ) {
        Ok(_) => return Err("17 CPU work units exceeded the production query pool".into()),
        Err(failure) => failure,
    };
    assert_eq!(refused.code(), QueryFailureCode::ResourceAdmissionRefused);
    Ok(())
}

#[test]
fn checked_query_resume_revalidates_every_durable_tenant_lifecycle_state()
-> Result<(), Box<dyn Error>> {
    for (state, code) in [
        ("active", 1_u8),
        ("read-only", 2),
        ("suspended", 3),
        ("purging", 4),
        ("purged", 5),
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
        let catalog = open_catalog(&initialized)?;
        let scope = SegmentScope::new(initialized.tenant, SignalKind::Logs, initialized.logs_shard);
        let protection = initialized.key.segment_key(initialized.instance, scope)?;
        let ledger =
            ActiveSegmentLedger::open(&initialized._authority, &catalog, scope, protection)?;
        let context = initialized.attribute(
            PresentedCredential::parse(&query_secret)?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        )?;
        let service = QueryService::new(
            initialized.resource_governor(),
            &ledger,
            1,
            initialized.identity.clone(),
        );
        let query = service
            .plan_pipeline(
                context,
                "logs | range query_time 0 100 | limit 2",
                QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                    .with_cpu_work_units(16)?,
            )
            .map_err(|failure| format!("{state} plan failed: {failure:?}"))?;
        let events = service
            .execute_page(query)
            .map_err(|failure| format!("{state} initial page failed: {failure:?}"))?
            .collect::<Vec<_>>();
        let cursor = match events.last() {
            Some(QueryEvent::Terminal(QueryTerminal::Continued(cursor))) => cursor.clone(),
            _ => return Err(format!("{state} query did not produce a cursor").into()),
        };
        publish_lifecycle(&catalog, code, code)?;
        if code != 1 {
            assert!(
                services.authorize_logs(&ingest).is_err(),
                "{state} ingest authorization must fail closed"
            );
        }
        assert!(
            matches!(
                services.authorize_logs(&ingest),
                Err(ServiceFailure::StorageUnavailable)
            ),
            "{state} catalog contention must not be reported as Unauthorized"
        );
        drop(service);
        drop(ledger);
        drop(catalog);
        let fresh_query = services.query_log_bodies(
            &query_secret,
            "logs | range query_time 0 100 | limit 2",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(16)?,
        );
        if code <= 2 {
            let fresh_query = fresh_query
                .map_err(|failure| format!("{state} fresh query failed: {failure:?}"))?;
            assert_eq!(fresh_query, ["first", "second"], "{state} fresh query");
        } else {
            assert!(fresh_query.is_err(), "{state} fresh query must fail closed");
        }
        let durable_identity = initialized.durable_identity()?;
        let durable_ingest = durable_identity.attribute(
            &initialized.key,
            PresentedCredential::parse(&ingest)?,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        );
        let durable_query = durable_identity.attribute(
            &initialized.key,
            PresentedCredential::parse(&query_secret)?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        );
        assert_eq!(
            durable_ingest.is_ok(),
            code == 1,
            "{state} ingest identity state"
        );
        assert_eq!(
            durable_query.is_ok(),
            code <= 2,
            "{state} query identity state"
        );

        let reopened_catalog = open_catalog(&initialized)?;
        let reopened_identity = positron_governance::Identity::open(&reopened_catalog.pin()?)?;
        let reopened_protection = initialized.key.segment_key(initialized.instance, scope)?;
        let reopened_ledger = ActiveSegmentLedger::open(
            &initialized._authority,
            &reopened_catalog,
            scope,
            reopened_protection,
        )?;
        let resumed_service = QueryService::new(
            initialized.resource_governor(),
            &reopened_ledger,
            1,
            reopened_identity,
        );
        let before = initialized
            .resource_governor()
            .inspect()?
            .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
        let resumed = resumed_service.resume(context, &cursor);
        if code == 1 {
            let _ = resumed?.collect::<Vec<_>>();
        } else {
            let failure = resumed.expect_err("lifecycle transition must reject the stale context");
            assert_eq!(failure.code(), QueryFailureCode::Unauthorized, "{state}");
        }
        let after = initialized
            .resource_governor()
            .inspect()?
            .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
        if code == 1 {
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

fn publish_lifecycle(
    catalog: &positron_kernel::Catalog<'_>,
    state: u8,
    transaction_byte: u8,
) -> Result<(), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .map(|identity| {
            let bytes = basis.object(identity)?.ok_or("missing Catalog object")?;
            let mut bytes = bytes.to_vec();
            if bytes.starts_with(b"POSGOV01")
                || bytes.starts_with(b"POSGOV02")
                || bytes.starts_with(b"POSGOV03")
            {
                let offset = bytes.len().checked_sub(5).ok_or("identity too short")?;
                bytes[offset] = state;
            }
            CatalogObject::new(bytes).map_err(|failure| -> Box<dyn Error> { Box::new(failure) })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction_byte; 16])?,
            FormatEpoch::CATALOG_V1,
            std::mem::take(&mut objects),
        )?,
        None,
    )?;
    Ok(())
}

#[test]
fn transferred_grpc_admission_reaches_the_scripted_backend_on_a_worker_thread()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(initialized)?;
    services.install_receiver_test_backend(Arc::new(RetryBackend))?;
    let context = services.authorize_logs(&ingest)?;
    let admission = services.admit_logs(context)?;
    let decoded = request("threaded");
    let worker = std::thread::spawn(move || {
        let reservation = admission.take().map_err(|_| "take")?;
        services
            .ingest_decoded_otlp_logs(context, decoded, reservation)
            .map_err(|_| "ingest")
    });
    let outcome = worker.join().map_err(|_| "worker panicked")??;
    assert_eq!(
        outcome.terminal_failure(),
        Some(IngestOutcome::Retryable(
            IngestFailureCode::StorageUnavailable
        ))
    );
    Ok(())
}

struct RetryBackend;

impl ReceiverTestBackend for RetryBackend {
    fn ingest(&self, groups: NativeLogAdmissionGroups<'_>) -> IngestRequestOutcome {
        IngestRequestOutcome::new(
            groups
                .map(|group| {
                    AdmissionGroupOutcome::new(
                        group.shard(),
                        group.records(),
                        IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
                    )
                })
                .collect(),
        )
    }
}
