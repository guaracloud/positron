use std::sync::Arc;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, KeyValue, KeyValueList, any_value,
};
use tonic::Request;

use super::trace_support::{
    ReceiverHarness, ScriptedBackend, profile_with_dynamic_value_limits, trace_request,
};

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_all_rejected_distinct_limits_keep_fixed_detail_order()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start_with_profile(
        backend.clone(),
        profile_with_dynamic_value_limits(4, 64, 1, 1, 128),
    )?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;
    let mut request = trace_request(0x61).into_inner();
    let spans = request
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
    value.span_id = vec![0x71; 8];
    value.attributes.push(KeyValue {
        key: "value".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue("12345".to_owned())),
        }),
        ..KeyValue::default()
    });
    let mut array = template;
    array.span_id = vec![0x72; 8];
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
    spans.spans = vec![value, array];
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(Request::new(request))?),
    )
    .await??;
    let partial = response
        .into_inner()
        .partial_success
        .ok_or("missing partial success")?;
    assert_eq!(partial.rejected_spans, 2);
    assert_eq!(
        partial.error_message,
        "some spans were permanently rejected (array entries: actual 2, allowed 1; individual value bytes: actual 5, allowed 4)"
    );
    assert!(!partial.error_message.contains("12345"));
    assert_eq!(backend.calls(), 0);
    assert_eq!(harness.snapshot()?, baseline);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_post_policy_profile_matrix_reaches_each_nested_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([
        super::trace_support::Completion::Committed,
    ]));
    // The system profile remains permissive; these are tenant-effective
    // limits, so every rejected span must reach post-policy inspection.
    let harness = ReceiverHarness::start_with_profile(
        backend.clone(),
        profile_with_dynamic_value_limits(4, 4, 1, 1, 2),
    )?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;
    let mut request = trace_request(0x66).into_inner();
    let scope = request
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .ok_or("trace fixture scope missing")?;
    let template = scope
        .spans
        .first()
        .cloned()
        .ok_or("trace fixture span missing")?;

    let mut accepted = template.clone();
    accepted.span_id = vec![0x71; 8];
    accepted.name = "ok".to_owned();

    let mut key_path = template.clone();
    key_path.span_id = vec![0x72; 8];
    key_path.name = "ok".to_owned();
    key_path.attributes.push(KeyValue {
        key: "producer".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::BoolValue(true)),
        }),
        ..KeyValue::default()
    });

    let mut bytes = template.clone();
    bytes.span_id = vec![0x73; 8];
    bytes.name = "ok".to_owned();
    bytes.attributes.push(KeyValue {
        key: "bin".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::BytesValue(vec![0xa1; 5])),
        }),
        ..KeyValue::default()
    });

    let mut depth = template.clone();
    depth.span_id = vec![0x74; 8];
    depth.name = "ok".to_owned();
    depth.attributes.push(KeyValue {
        key: "deep".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::ArrayValue(ArrayValue {
                values: vec![AnyValue {
                    value: Some(any_value::Value::KvlistValue(KeyValueList {
                        values: vec![KeyValue {
                            key: "x".to_owned(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::ArrayValue(ArrayValue {
                                    values: vec![AnyValue {
                                        value: Some(any_value::Value::BoolValue(true)),
                                    }],
                                })),
                            }),
                            ..KeyValue::default()
                        }],
                    })),
                }],
            })),
        }),
        ..KeyValue::default()
    });

    let mut array = template;
    array.span_id = vec![0x75; 8];
    array.name = "ok".to_owned();
    array.attributes.push(KeyValue {
        key: "arr".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::ArrayValue(ArrayValue {
                values: vec![
                    AnyValue {
                        value: Some(any_value::Value::BoolValue(true)),
                    },
                    AnyValue {
                        value: Some(any_value::Value::BoolValue(false)),
                    },
                ],
            })),
        }),
        ..KeyValue::default()
    });
    scope.spans = vec![accepted, key_path, bytes, depth, array];

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(Request::new(request))?),
    )
    .await??;
    let partial = response
        .into_inner()
        .partial_success
        .ok_or("missing partial success")?;
    assert_eq!(partial.rejected_spans, 4);
    assert_eq!(
        partial.error_message,
        "some spans were permanently rejected (nesting depth: actual 1, allowed 0; array entries: actual 2, allowed 1; individual value bytes: actual 5, allowed 4; key/path bytes: actual 8, allowed 4)"
    );
    assert!(partial.error_message.len() < 256);
    assert!(!partial.error_message.contains("producer"));
    assert_eq!(backend.calls(), 1);
    assert_eq!(backend.committed_records(), 1);
    assert_eq!(harness.snapshot()?, baseline);
    harness.finish()?;
    Ok(())
}
