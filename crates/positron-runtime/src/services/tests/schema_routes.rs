use std::error::Error;
use std::sync::Arc;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use positron_domain::routing::SignalKind;
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome,
    NativeLogAdmissionGroups,
};
use positron_ingest::{LokiPushRequestEncoding, OtlpLogsRequestEncoding};
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
    assert_eq!(
        super::super::failure::collect_query_bodies(exact_events.clone())?,
        vec!["one".to_owned(), "two".to_owned()]
    );
    let complete = exact_events
        .last()
        .cloned()
        .ok_or("exact query omitted its terminal")?;
    let batch = exact_events
        .iter()
        .find(|event| matches!(event, QueryEvent::Batch(_)))
        .cloned()
        .ok_or("exact query omitted its batch")?;
    let mut duplicate_complete = exact_events.clone();
    duplicate_complete.push(complete.clone());
    assert_eq!(
        super::super::failure::collect_query_bodies(duplicate_complete),
        Err(ServiceFailure::Internal)
    );
    let mut batch_after_terminal = exact_events.clone();
    batch_after_terminal.push(batch.clone());
    assert_eq!(
        super::super::failure::collect_query_bodies(batch_after_terminal),
        Err(ServiceFailure::Internal)
    );
    let header = exact_events
        .first()
        .cloned()
        .ok_or("exact query omitted its header")?;
    let mut header_after_terminal = exact_events.clone();
    header_after_terminal.push(header.clone());
    assert_eq!(
        super::super::failure::collect_query_bodies(header_after_terminal),
        Err(ServiceFailure::Internal)
    );
    let paged_service = QueryService::new(initialized.resource_governor(), &ledger, 1);
    let paged = paged_service.plan_pipeline(
        context,
        source,
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(16)?,
    )?;
    let paged_events = schema
        .with_catalog_view(initialized.tenant, |_view| {
            paged_service.execute_page(paged)
        })??
        .collect::<Vec<_>>();
    assert!(
        matches!(
            paged_events.last(),
            Some(QueryEvent::Terminal(QueryTerminal::Continued(_)))
        ),
        "paged events: {paged_events:?}"
    );
    let continued = paged_events
        .last()
        .cloned()
        .ok_or("paged query omitted its terminal")?;
    assert_eq!(
        super::super::failure::collect_query_bodies(paged_events),
        Err(ServiceFailure::Internal)
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

    let incomplete = exhausted_events
        .last()
        .cloned()
        .ok_or("exhausted query omitted its terminal")?;
    assert_eq!(
        super::super::failure::collect_query_bodies(vec![header.clone(), incomplete.clone()]),
        Err(ServiceFailure::CapacityUnavailable)
    );
    assert_eq!(
        super::super::failure::collect_query_bodies(vec![incomplete.clone(), header.clone()]),
        Err(ServiceFailure::Internal)
    );
    assert_eq!(
        super::super::failure::collect_query_bodies(vec![continued, header.clone()]),
        Err(ServiceFailure::Internal)
    );
    assert_eq!(
        super::super::failure::collect_query_bodies(vec![header.clone()]),
        Err(ServiceFailure::Internal)
    );
    assert_eq!(
        super::super::failure::collect_query_bodies(vec![batch.clone(), complete.clone()]),
        Err(ServiceFailure::Internal)
    );
    assert_eq!(
        super::super::failure::collect_query_bodies(vec![complete.clone(), header.clone()]),
        Err(ServiceFailure::Internal)
    );
    assert_eq!(
        super::super::failure::collect_query_bodies(vec![
            header.clone(),
            batch.clone(),
            complete.clone(),
            incomplete
        ]),
        Err(ServiceFailure::Internal)
    );
    assert_eq!(
        super::super::failure::collect_query_bodies(vec![
            header.clone(),
            header.clone(),
            complete.clone()
        ]),
        Err(ServiceFailure::Internal)
    );
    assert_eq!(
        super::super::failure::collect_query_bodies(vec![header.clone(), batch, complete]),
        Ok(vec!["one".to_owned(), "two".to_owned()])
    );

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
fn public_query_route_preserves_failure_class_and_never_returns_incomplete_rows()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    for body in ["first", "second"] {
        assert_eq!(
            services
                .ingest_otlp_logs(&ingest, request(body).encode_to_vec())?
                .accepted_records(),
            1
        );
    }
    let budget = || {
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)
            .and_then(|budget| budget.with_cpu_work_units(1))
    };
    assert_eq!(
        services.query_log_bodies(&query, "not a Positron query", budget()?),
        Err(ServiceFailure::InvalidRequest)
    );
    assert_eq!(
        services.query_log_bodies(
            "not-the-query-credential",
            "logs | range query_time 0 100 | limit 16",
            budget()?,
        ),
        Err(ServiceFailure::Unauthorized)
    );
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            budget()?,
        ),
        Err(ServiceFailure::CapacityUnavailable),
        "incomplete query terminals must not be reported as partial success"
    );
    let complete_budget = || {
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)
            .and_then(|budget| budget.with_cpu_work_units(16))
    };
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            complete_budget()?,
        )?,
        vec!["first".to_owned(), "second".to_owned()]
    );
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
        let service = QueryService::new(initialized.resource_governor(), &ledger, 1);
        let query = service
            .plan_pipeline(
                context,
                "logs | range query_time 0 100 | limit 2",
                QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)?
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
        let contended_authorization = services.authorize_logs(&ingest);
        let direct_attribution = initialized.attribute(
            PresentedCredential::parse(&ingest)?,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        );
        assert_eq!(
            direct_attribution.is_ok(),
            code == 1,
            "{state} stale attribution"
        );
        if code == 1 {
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
        drop(service);
        drop(ledger);
        drop(catalog);
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
        let reopened_protection = initialized.key.segment_key(initialized.instance, scope)?;
        let reopened_ledger = ActiveSegmentLedger::open(
            &initialized._authority,
            &reopened_catalog,
            scope,
            reopened_protection,
        )?;
        let resumed_service =
            QueryService::new(initialized.resource_governor(), &reopened_ledger, 1);
        let before = initialized
            .resource_governor()
            .inspect()?
            .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
        let resumed = resumed_service.resume(context, &cursor);
        if code == 1 {
            let _ = resumed
                .map_err(|failure| format!("{state} resume failed: {failure:?}"))?
                .collect::<Vec<_>>();
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
        drop(resumed_service);
        drop(reopened_ledger);
        drop(reopened_catalog);
    }
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
    let catalog = open_catalog(&initialized)?;
    publish_lifecycle(&catalog, 2, 0xe5)?;
    drop(catalog);

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
    for (state, transaction, restore_transaction) in [
        (2_u8, 0xf1_u8, 0x01_u8),
        (3, 0xf2, 0x02),
        (4, 0xf3, 0x03),
        (5, 0xf4, 0x04),
    ] {
        let fixture = Fixture::new()?;
        let (initialized, ingest, query_secret) = fixture.initialized()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        let context = services.authorize_logs(&ingest)?;
        let governor_before = initialized._authority.governor().inspect()?;
        let admission = services.admit_logs(context)?;
        let reservation = admission.take()?;

        let catalog = open_catalog(&initialized)?;
        publish_lifecycle(&catalog, state, transaction)?;
        drop(catalog);

        assert_eq!(
            services.ingest_decoded_otlp_logs(context, request("must-not-append"), reservation),
            Err(ServiceFailure::Unauthorized),
            "state {state}"
        );
        let governor_after = initialized._authority.governor().inspect()?;
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

        let catalog = open_catalog(&initialized)?;
        publish_lifecycle(&catalog, 1, restore_transaction)?;
        drop(catalog);
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

#[test]
fn stale_active_ingest_context_is_rejected_before_receiver_admission() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let context = services.authorize_logs(&ingest)?;
    let catalog = open_catalog(&initialized)?;
    publish_lifecycle(&catalog, 2, 0xd1)?;
    drop(catalog);

    let before = initialized.resource_governor().inspect()?;
    assert!(
        matches!(
            services.admit_logs(context),
            Err(ServiceFailure::Unauthorized)
        ),
        "a context attributed while Active must not reserve after ReadOnly"
    );
    let after = initialized.resource_governor().inspect()?;
    assert_eq!(after.outstanding_total(), before.outstanding_total());
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(
            after.usage(dimension),
            before.usage(dimension),
            "{dimension:?}"
        );
    }
    Ok(())
}

#[test]
fn stale_active_ingest_context_rejects_empty_request_before_native_planning()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let context = services.authorize_logs(&ingest)?;
    let baseline = initialized.resource_governor().inspect()?;
    let admission = services.admit_logs(context)?;
    let reservation = admission.take()?;
    let catalog = open_catalog(&initialized)?;
    publish_lifecycle(&catalog, 2, 0xd2)?;
    drop(catalog);

    let result = services.ingest_decoded_otlp_logs(
        context,
        ExportLogsServiceRequest::default(),
        reservation,
    );
    assert!(
        matches!(result, Err(ServiceFailure::Unauthorized)),
        "an empty stale request must not bypass lifecycle validation"
    );
    let after = initialized.resource_governor().inspect()?;
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(
            after.usage(dimension),
            baseline.usage(dimension),
            "{dimension:?}"
        );
    }
    Ok(())
}

#[test]
fn stale_active_ingest_context_is_rejected_before_protocol_decode() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let context = services.authorize_logs(&ingest)?;
    let admission = services.admit_logs(context)?;
    let reservation = admission.take()?;
    let catalog = open_catalog(&initialized)?;
    publish_lifecycle(&catalog, 2, 0xd3)?;
    drop(catalog);

    let result = services.ingest_encoded_otlp_http_logs(
        context,
        OtlpLogsRequestEncoding::Protobuf,
        vec![0xff],
        reservation,
    );
    assert!(
        matches!(result, Err(ServiceFailure::Unauthorized)),
        "lifecycle rejection must precede malformed-payload decoding"
    );
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
