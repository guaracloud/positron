use std::error::Error;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeNamespace, AttributeValueKind, MarkerAction};
use positron_ingest::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyPredicate, PolicyRule, PolicyTarget,
};
use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};
use positron_signals::{ScanLimit, TraceScan, TraceStore};

use super::trace_support::{ReceiverHarness, trace_request};

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_policy_marker_survives_grpc_ack_and_runtime_restart()
-> Result<(), Box<dyn Error>> {
    let path = PolicyAttributePath::new(AttributeNamespace::Record, "secret")?;
    let policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "redact-secret",
            vec![PolicyPredicate::attribute_exists(path.clone())],
            PolicyAction::Redact(PolicyTarget::attribute(path)),
        )?],
    )?;
    let mut harness = ReceiverHarness::start_durable_with_policy(policy.clone())?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let mut request = trace_request(0xa1);
    request
        .get_mut()
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .and_then(|scope| scope.spans.first_mut())
        .ok_or("trace fixture span missing")?
        .attributes
        .push(KeyValue {
            key: "secret".to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue("source-secret".to_owned())),
            }),
            ..KeyValue::default()
        });
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(request)?),
    )
    .await??;
    assert!(response.into_inner().partial_success.is_none());
    drop(client);

    assert_trace_marker(harness.initialized()?, &policy)?;
    harness.restart_durable()?;
    assert_trace_marker(harness.initialized()?, &policy)?;
    harness.finish()?;
    Ok(())
}

fn assert_trace_marker(
    initialized: &crate::InitializedInstance,
    policy: &IngestPolicy,
) -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let basis = catalog.pin()?;
    let scope = basis
        .reachable_ledger_scopes(initialized.tenant, SignalKind::Traces)?
        .into_iter()
        .next()
        .ok_or("trace scope missing after authenticated export")?;
    let protection = initialized.key.segment_key(initialized.instance, scope)?;
    let ledger = ActiveSegmentLedger::open(
        &initialized._authority,
        &catalog,
        SegmentScope::new(initialized.tenant, SignalKind::Traces, scope.shard_id()),
        protection,
    )?;
    let result = TraceStore::new().scan(
        initialized.resource_governor(),
        initialized.tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    let observation = result
        .observations()
        .first()
        .ok_or("authenticated export did not persist a span")?
        .observation();
    let value = observation
        .attributes()
        .iter()
        .find(|attribute| attribute.key() == "secret")
        .and_then(|attribute| attribute.occurrence(0))
        .ok_or("trace marker attribute missing")?;
    assert_eq!(value.marker_action(), Some(MarkerAction::Redacted));
    assert_eq!(
        value.marker_original_kind(),
        Some(AttributeValueKind::String)
    );
    assert_eq!(value.as_str(), None);
    assert_eq!(
        observation.policy_provenance().generation(),
        policy.generation()
    );
    assert_eq!(observation.policy_provenance().digest(), policy.digest());
    assert_eq!(
        observation.policy_provenance().applied_rules(),
        &["redact-secret"]
    );
    Ok(())
}
