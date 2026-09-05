use std::sync::Arc;

use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use prost::Message;

use super::super::super::ResponseEncoding;
use super::support::{
    Completion, HttpHarness, ScriptedBackend, decode_success, profile_with_dynamic_value_limits,
    profile_with_individual_value_bytes, trace_request,
};

#[test]
fn live_http_trace_all_rejected_value_limit_reports_safe_partial_detail()
-> Result<(), Box<dyn std::error::Error>> {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let backend = Arc::new(ScriptedBackend::new([]));
        let harness = HttpHarness::start_with_profile(
            backend.clone(),
            profile_with_individual_value_bytes(4),
        )?;
        let baseline = harness.governor_snapshot()?.outstanding_total();
        let mut request = trace_request();
        let span = request
            .resource_spans
            .first_mut()
            .and_then(|resource| resource.scope_spans.first_mut())
            .and_then(|scope| scope.spans.first_mut())
            .ok_or("trace fixture span missing")?;
        span.attributes.push(KeyValue {
            key: "short-key".to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue("12345".to_owned())),
            }),
            ..KeyValue::default()
        });
        let body = match encoding {
            ResponseEncoding::Protobuf => request.encode_to_vec(),
            ResponseEncoding::Json => serde_json::to_vec(&request)?,
        };
        let response = harness.request(encoding, body, None, Some(&harness.bearer), None, None)?;
        assert_eq!(response.status(), 200);
        let partial = decode_success(&response, encoding)?
            .partial_success
            .ok_or("missing partial success")?;
        assert_eq!(partial.rejected_spans, 1);
        assert_eq!(
            partial.error_message,
            "some spans were permanently rejected (individual value bytes: actual 5, allowed 4)"
        );
        assert!(!partial.error_message.contains("12345"));
        assert_eq!(harness.backend_calls(), 0);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);
    }
    Ok(())
}

#[test]
fn live_http_trace_mixed_value_limit_keeps_accepted_span_and_detail()
-> Result<(), Box<dyn std::error::Error>> {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let backend = Arc::new(ScriptedBackend::new([Completion::Committed]));
        let harness = HttpHarness::start_with_profile(
            backend.clone(),
            profile_with_individual_value_bytes(4),
        )?;
        let mut request = trace_request();
        let spans = request
            .resource_spans
            .first_mut()
            .and_then(|resource| resource.scope_spans.first_mut())
            .ok_or("trace fixture scope missing")?;
        let accepted = spans
            .spans
            .first()
            .cloned()
            .ok_or("trace fixture span missing")?;
        spans.spans.push(accepted);
        spans
            .spans
            .first_mut()
            .ok_or("rejected span missing")?
            .attributes
            .push(KeyValue {
                key: "short-key".to_owned(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue("12345".to_owned())),
                }),
                ..KeyValue::default()
            });
        let body = match encoding {
            ResponseEncoding::Protobuf => request.encode_to_vec(),
            ResponseEncoding::Json => serde_json::to_vec(&request)?,
        };
        let response = harness.request(encoding, body, None, Some(&harness.bearer), None, None)?;
        assert_eq!(response.status(), 200);
        let partial = decode_success(&response, encoding)?
            .partial_success
            .ok_or("missing partial success")?;
        assert_eq!(partial.rejected_spans, 1);
        assert_eq!(
            partial.error_message,
            "some spans were permanently rejected (individual value bytes: actual 5, allowed 4)"
        );
        assert!(!partial.error_message.contains("12345"));
        assert_eq!(backend.calls(), 1);
        assert_eq!(backend.committed_records(), 1);
    }
    Ok(())
}

#[test]
fn live_http_trace_partial_detail_is_bounded_and_class_ordered()
-> Result<(), Box<dyn std::error::Error>> {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let backend = Arc::new(ScriptedBackend::new([Completion::Committed]));
        let harness = HttpHarness::start_with_profile(
            backend.clone(),
            profile_with_dynamic_value_limits(4, 64, 1, 1, 128),
        )?;
        let mut request = trace_request();
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
        let body = match encoding {
            ResponseEncoding::Protobuf => request.encode_to_vec(),
            ResponseEncoding::Json => serde_json::to_vec(&request)?,
        };
        let response = harness.request(encoding, body, None, Some(&harness.bearer), None, None)?;
        assert_eq!(response.status(), 200);
        let partial = decode_success(&response, encoding)?
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
    }
    Ok(())
}

#[test]
fn live_http_trace_export_reports_per_span_rejection_as_partial_success()
-> Result<(), Box<dyn std::error::Error>> {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let backend = Arc::new(ScriptedBackend::new([]));
        let harness = HttpHarness::start(backend.clone())?;
        let baseline = harness.governor_snapshot()?.outstanding_total();
        let mut request = trace_request();
        request
            .resource_spans
            .first_mut()
            .and_then(|resource| resource.scope_spans.first_mut())
            .and_then(|scope| scope.spans.first_mut())
            .ok_or("trace fixture span missing")?
            .attributes
            .push(KeyValue {
                key: "profile-only".to_owned(),
                key_strindex: 1,
                ..KeyValue::default()
            });
        let body = match encoding {
            ResponseEncoding::Protobuf => request.encode_to_vec(),
            ResponseEncoding::Json => serde_json::to_vec(&request)?,
        };
        let response = harness.request(encoding, body, None, Some(&harness.bearer), None, None)?;
        assert_eq!(response.status(), 200);
        let partial = decode_success(&response, encoding)?
            .partial_success
            .ok_or("missing partial success")?;
        assert_eq!(partial.rejected_spans, 1);
        assert_eq!(
            partial.error_message,
            "some spans were permanently rejected"
        );
        assert_eq!(backend.calls(), 0);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);
    }
    Ok(())
}
