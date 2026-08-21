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
use positron_query::{
    QueryBudget, QueryBudgetDimension, QueryEvent, QueryFailureCode, QueryService, QueryTerminal,
};
use prost::Message;

use super::schema_maintenance::{Fixture, open_catalog, request};
use crate::services::{ReceiverTestBackend, ServiceHandle};

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
    let query_service = QueryService::new(initialized.resource_governor(), &ledger, 100);
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
