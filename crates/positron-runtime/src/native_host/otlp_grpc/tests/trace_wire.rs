use std::sync::Arc;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use positron_domain::value::AttributeNamespace;
use positron_ingest::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyPredicate, PolicyRule, PolicyTarget,
};
use tonic::Code;

use super::trace_support::{
    Completion, ReceiverHarness, ScriptedBackend, profile_with_dynamic_value_limits,
    profile_with_individual_value_bytes, trace_request,
};

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_statuses_preserve_retry_classes_and_release_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([
        Completion::Capacity,
        Completion::Retryable,
        Completion::Permanent,
        Completion::Ambiguous,
        Completion::Committed,
        Completion::Committed,
    ]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let capacity = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x11))?),
    )
    .await?
    .expect_err("capacity must be retryable");
    assert_eq!(capacity.code(), Code::ResourceExhausted);
    assert_eq!(
        capacity.message(),
        "OTLP Traces ingest capacity is unavailable"
    );
    assert_eq!(harness.snapshot()?, baseline);

    let retryable = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x21))?),
    )
    .await?
    .expect_err("storage failure must be retryable");
    assert_eq!(retryable.code(), Code::Unavailable);
    assert_eq!(
        retryable.message(),
        "OTLP Traces ingest is temporarily unavailable"
    );
    assert_eq!(harness.snapshot()?, baseline);

    let permanent = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x31))?),
    )
    .await?
    .expect_err("permanent rejection must not be retried");
    assert_eq!(permanent.code(), Code::InvalidArgument);
    assert_eq!(permanent.message(), "OTLP Traces request was rejected");
    assert_eq!(harness.snapshot()?, baseline);

    let ambiguous = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x41))?),
    )
    .await?
    .expect_err("post-commit failure must be explicit ambiguity");
    assert_eq!(ambiguous.code(), Code::Unavailable);
    assert_eq!(
        ambiguous.message(),
        "OTLP Traces commit outcome is ambiguous; retry may duplicate spans"
    );
    assert_eq!(backend.committed_records(), 1);
    assert_eq!(harness.snapshot()?, baseline);

    // The caller may lose the ambiguous response. A retry remains at-least-once
    // and is visible as a second committed observation in the native seam.
    let retry = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x41))?),
    )
    .await??;
    assert!(retry.into_inner().partial_success.is_none());
    assert_eq!(backend.committed_records(), 2);
    assert_eq!(harness.snapshot()?, baseline);

    let mut gzip_client = client
        .clone()
        .send_compressed(tonic::codec::CompressionEncoding::Gzip);
    let gzip = tokio::time::timeout(
        Duration::from_secs(2),
        gzip_client.export(harness.authorize_trace(trace_request(0x51))?),
    )
    .await??;
    assert!(gzip.into_inner().partial_success.is_none());
    assert_eq!(backend.committed_records(), 3);
    assert_eq!(harness.snapshot()?, baseline);

    drop(gzip_client);
    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_authentication_and_tenant_attribution_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let missing = tokio::time::timeout(Duration::from_secs(2), client.export(trace_request(0x61)))
        .await?
        .expect_err("missing credentials must be rejected");
    assert_eq!(missing.code(), Code::Unauthenticated);
    assert_eq!(
        missing.message(),
        "OTLP Traces request authentication was rejected"
    );

    let conflict = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace_with_tenant(trace_request(0x71), "other-tenant")?),
    )
    .await?
    .expect_err("tenant mismatch must be rejected");
    assert_eq!(conflict.code(), Code::Unauthenticated);
    assert_eq!(
        conflict.message(),
        "OTLP Traces request authentication was rejected"
    );
    assert_eq!(backend.calls(), 0);
    assert_eq!(harness.snapshot()?, baseline);

    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_rejects_conflicting_tenant_hints_before_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let mut request = harness.authorize_trace(trace_request(0x72))?;
    request
        .metadata_mut()
        .append("x-scope-orgid", "trace-external".parse()?);
    request
        .metadata_mut()
        .append("x-scope-orgid", "other-tenant".parse()?);
    let rejected = tokio::time::timeout(Duration::from_secs(2), client.export(request))
        .await?
        .expect_err("conflicting tenant hints must fail before admission");
    assert_eq!(rejected.code(), Code::Unauthenticated);
    assert_eq!(
        rejected.message(),
        "OTLP Traces request authentication was rejected"
    );
    assert_eq!(backend.calls(), 0);
    assert_eq!(harness.snapshot()?, baseline);

    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn logs_grpc_rejects_conflicting_tenant_hints_before_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let mut request = tonic::Request::new(ExportLogsServiceRequest::default());
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", harness.bearer).parse()?,
    );
    request
        .metadata_mut()
        .append("x-scope-orgid", "trace-external".parse()?);
    request
        .metadata_mut()
        .append("x-scope-orgid", "other-tenant".parse()?);
    let rejected = tokio::time::timeout(Duration::from_secs(2), client.export(request))
        .await?
        .expect_err("conflicting tenant hints must fail before admission");
    assert_eq!(rejected.code(), Code::Unauthenticated);
    assert_eq!(
        rejected.message(),
        "OTLP Logs request authentication was rejected"
    );
    assert_eq!(backend.calls(), 0);
    assert_eq!(harness.snapshot()?, baseline);

    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_rejects_duplicate_bearer_credentials_before_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let mut request = harness.authorize_trace(trace_request(0x73))?;
    request.metadata_mut().append(
        "authorization",
        "Bearer pos_0000000000000000000000000000000000000000000000000000000000000000".parse()?,
    );
    let rejected = tokio::time::timeout(Duration::from_secs(2), client.export(request))
        .await?
        .expect_err("multiple bearer credentials must fail before admission");
    assert_eq!(rejected.code(), Code::Unauthenticated);
    assert_eq!(
        rejected.message(),
        "OTLP Traces request authentication was rejected"
    );
    assert_eq!(backend.calls(), 0);
    assert_eq!(harness.snapshot()?, baseline);

    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_invalid_tenant_alias_is_rejected_before_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let rejected = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace_with_tenant(trace_request(0x79), "tenant#alias")?),
    )
    .await?
    .expect_err("invalid tenant aliases must fail authentication");
    assert_eq!(rejected.code(), Code::Unauthenticated);
    assert_eq!(
        rejected.message(),
        "OTLP Traces request authentication was rejected"
    );
    assert_eq!(backend.calls(), 0);
    assert_eq!(harness.snapshot()?, baseline);

    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_accepts_the_authenticated_external_tenant_alias()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([Completion::Committed]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace_with_tenant(trace_request(0x7a), "trace-external")?),
    )
    .await??;
    assert!(response.into_inner().partial_success.is_none());
    assert_eq!(backend.calls(), 1);
    assert_eq!(backend.committed_records(), 1);

    let slug = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace_with_tenant(trace_request(0x7b), "default")?),
    )
    .await?
    .expect_err("the tenant slug is not an external alias");
    assert_eq!(slug.code(), Code::Unauthenticated);
    assert_eq!(backend.calls(), 1);

    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_policy_truncation_runs_before_tenant_value_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let path = PolicyAttributePath::new(AttributeNamespace::Record, "secret")?;
    let policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "truncate-secret",
            vec![PolicyPredicate::attribute_exists(path.clone())],
            PolicyAction::TruncateBytes(PolicyTarget::attribute(path), 4),
        )?],
    )?;
    let backend = Arc::new(ScriptedBackend::new([Completion::Committed]));
    let harness = ReceiverHarness::start_durable_with_profile_and_policy(
        profile_with_individual_value_bytes(4),
        backend.clone(),
        policy,
    )?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;
    let mut request = trace_request(0x81);
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
                value: Some(any_value::Value::BytesValue(vec![1, 2, 3, 4, 5])),
            }),
            ..KeyValue::default()
        });

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(request)?),
    )
    .await??;
    assert!(response.into_inner().partial_success.is_none());
    assert_eq!(backend.calls(), 1);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_all_rejected_value_limit_reports_safe_partial_detail()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start_with_profile(
        backend.clone(),
        profile_with_individual_value_bytes(4),
    )?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;
    let mut request = trace_request(0x91);
    request
        .get_mut()
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .and_then(|scope| scope.spans.first_mut())
        .ok_or("trace fixture span missing")?
        .attributes
        .push(KeyValue {
            key: "short-key".to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue("12345".to_owned())),
            }),
            ..KeyValue::default()
        });

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(request)?),
    )
    .await??;
    let partial = response
        .into_inner()
        .partial_success
        .ok_or("missing partial success")?;
    assert_eq!(partial.rejected_spans, 1);
    assert_eq!(
        partial.error_message,
        "some spans were permanently rejected (individual value bytes: actual 5, allowed 4)"
    );
    assert!(!partial.error_message.contains("12345"));
    assert_eq!(backend.calls(), 0);
    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_mixed_value_limit_keeps_one_span_and_maximum_detail()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([Completion::Committed]));
    let harness = ReceiverHarness::start_with_profile(
        backend.clone(),
        profile_with_individual_value_bytes(4),
    )?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;
    let mut request = trace_request(0x9a);
    let spans = request
        .get_mut()
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .ok_or("trace fixture scope missing")?;
    let accepted = spans
        .spans
        .first()
        .cloned()
        .ok_or("trace fixture span missing")?;
    let mut rejected_seven = accepted.clone();
    rejected_seven.attributes.push(KeyValue {
        key: "short-key".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue("1234567".to_owned())),
        }),
        ..KeyValue::default()
    });
    let mut rejected_five = accepted.clone();
    rejected_five.attributes.push(KeyValue {
        key: "short-key".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue("12345".to_owned())),
        }),
        ..KeyValue::default()
    });
    spans.spans = vec![accepted, rejected_seven, rejected_five];

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(request)?),
    )
    .await??;
    let partial = response
        .into_inner()
        .partial_success
        .ok_or("missing partial success")?;
    assert_eq!(partial.rejected_spans, 2);
    assert_eq!(
        partial.error_message,
        "some spans were permanently rejected (individual value bytes: actual 7, allowed 4)"
    );
    assert!(!partial.error_message.contains("1234567"));
    assert!(!partial.error_message.contains("12345"));
    assert_eq!(backend.calls(), 1);
    assert_eq!(backend.committed_records(), 1);
    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_partial_detail_is_bounded_and_class_ordered()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([Completion::Committed]));
    let harness = ReceiverHarness::start_with_profile(
        backend.clone(),
        profile_with_dynamic_value_limits(4, 64, 1, 1, 128),
    )?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;
    let mut request = trace_request(0xa1);
    let spans = request
        .get_mut()
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .ok_or("trace fixture scope missing")?;
    let template = spans
        .spans
        .first()
        .cloned()
        .ok_or("trace fixture span missing")?;
    let mut value = template.clone();
    value.attributes.push(KeyValue {
        key: "value".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue("12345".to_owned())),
        }),
        ..KeyValue::default()
    });
    let mut array = template.clone();
    array.attributes.push(KeyValue {
        key: "array".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::ArrayValue(
                opentelemetry_proto::tonic::common::v1::ArrayValue {
                    values: vec![
                        AnyValue {
                            value: Some(any_value::Value::BoolValue(true)),
                        },
                        AnyValue {
                            value: Some(any_value::Value::BoolValue(false)),
                        },
                    ],
                },
            )),
        }),
        ..KeyValue::default()
    });
    let mut list = template.clone();
    list.attributes.push(KeyValue {
        key: "list".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::KvlistValue(
                opentelemetry_proto::tonic::common::v1::KeyValueList {
                    values: vec![
                        KeyValue {
                            key: "a".to_owned(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::BoolValue(true)),
                            }),
                            ..KeyValue::default()
                        },
                        KeyValue {
                            key: "b".to_owned(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::BoolValue(false)),
                            }),
                            ..KeyValue::default()
                        },
                    ],
                },
            )),
        }),
        ..KeyValue::default()
    });
    spans.spans = vec![template, value, array, list];

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(request)?),
    )
    .await??;
    let partial = response
        .into_inner()
        .partial_success
        .ok_or("missing partial success")?;
    assert_eq!(partial.rejected_spans, 3);
    assert_eq!(
        partial.error_message,
        "some spans were permanently rejected (array entries: actual 2, allowed 1; key/value-list entries: actual 2, allowed 1; individual value bytes: actual 5, allowed 4)"
    );
    assert!(partial.error_message.len() < 256);
    assert!(!partial.error_message.contains("12345"));
    assert_eq!(backend.calls(), 1);
    assert_eq!(backend.committed_records(), 1);
    drop(client);
    harness.finish()?;
    Ok(())
}
