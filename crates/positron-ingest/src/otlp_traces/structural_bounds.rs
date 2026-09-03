use super::{
    AuthenticatedOtlpTracesRequest, OtlpTracesReceiver, TraceReceiveFailure,
    preflight_otlp_traces_gzip, preflight_otlp_traces_json, preflight_otlp_traces_protobuf,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, InstrumentationScope, KeyValue, any_value,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::value::{
    ByteLimit, CollectionLimit, DynamicValueLimits, NestingLimit, RequestLimits, ValueLimitProfile,
    ValueLimitProfileCandidate, ValueLimitSet,
};
use prost::Message;
use std::io::Write;

const MAX_CONTAINERS: usize = 1_024;
const MAX_RECORDS: usize = 1_024;
const MAX_ATTRIBUTES: usize = 4_096;
const MAX_BYTES: usize = 1_048_576;

fn attribution() -> positron_domain::identity::TenantAttribution {
    positron_domain::identity::TenantAttribution::new(
        positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
        positron_domain::identity::Scope::Ingest,
        positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("attribution")
}

fn request(resource_spans: Vec<ResourceSpans>) -> Vec<u8> {
    ExportTraceServiceRequest { resource_spans }.encode_to_vec()
}

fn span() -> Span {
    Span {
        trace_id: vec![1; 16],
        span_id: vec![2; 8],
        name: "span".to_owned(),
        ..Span::default()
    }
}

fn one_scope(spans: Vec<Span>) -> ResourceSpans {
    ResourceSpans {
        scope_spans: vec![ScopeSpans {
            spans,
            ..ScopeSpans::default()
        }],
        ..ResourceSpans::default()
    }
}

#[test]
fn protobuf_container_limits_are_exact_and_one_over() {
    let resources = request(
        (0..MAX_CONTAINERS)
            .map(|_| ResourceSpans::default())
            .collect(),
    );
    assert_eq!(preflight_otlp_traces_protobuf(&resources), Ok(()));
    let resources_over = request(
        (0..=MAX_CONTAINERS)
            .map(|_| ResourceSpans::default())
            .collect(),
    );
    assert_eq!(
        preflight_otlp_traces_protobuf(&resources_over),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let scopes = request(vec![ResourceSpans {
        scope_spans: (0..MAX_CONTAINERS).map(|_| ScopeSpans::default()).collect(),
        ..ResourceSpans::default()
    }]);
    assert_eq!(preflight_otlp_traces_protobuf(&scopes), Ok(()));
    let scopes_over = request(vec![ResourceSpans {
        scope_spans: (0..=MAX_CONTAINERS)
            .map(|_| ScopeSpans::default())
            .collect(),
        ..ResourceSpans::default()
    }]);
    assert_eq!(
        preflight_otlp_traces_protobuf(&scopes_over),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let spans = request(vec![one_scope((0..MAX_RECORDS).map(|_| span()).collect())]);
    assert_eq!(preflight_otlp_traces_protobuf(&spans), Ok(()));
    let spans_over = request(vec![one_scope((0..=MAX_RECORDS).map(|_| span()).collect())]);
    assert_eq!(
        preflight_otlp_traces_protobuf(&spans_over),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );
}

#[test]
fn protobuf_event_and_link_limits_are_exact_and_one_over() {
    let mut exact_event_span = span();
    exact_event_span.events = (0..MAX_CONTAINERS).map(|_| Event::default()).collect();
    assert_eq!(
        preflight_otlp_traces_protobuf(&request(vec![one_scope(vec![exact_event_span])])),
        Ok(())
    );
    let mut over_event_span = span();
    over_event_span.events = (0..=MAX_CONTAINERS).map(|_| Event::default()).collect();
    assert_eq!(
        preflight_otlp_traces_protobuf(&request(vec![one_scope(vec![over_event_span])])),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let link = Link {
        trace_id: vec![3; 16],
        span_id: vec![4; 8],
        ..Link::default()
    };
    let mut exact_link_span = span();
    exact_link_span.links = vec![link.clone(); MAX_CONTAINERS];
    assert_eq!(
        preflight_otlp_traces_protobuf(&request(vec![one_scope(vec![exact_link_span])])),
        Ok(())
    );
    let mut over_link_span = span();
    over_link_span.links = vec![link; MAX_CONTAINERS + 1];
    assert_eq!(
        preflight_otlp_traces_protobuf(&request(vec![one_scope(vec![over_link_span])])),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );
}

#[test]
fn protobuf_attribute_limits_cover_per_collection_and_aggregate_occurrences() {
    let exact_attributes = request(vec![one_scope(vec![Span {
        attributes: (0..MAX_CONTAINERS)
            .map(|index| attribute(&format!("key-{index}"), AnyValue::default()))
            .collect(),
        ..span()
    }])]);
    assert_eq!(preflight_otlp_traces_protobuf(&exact_attributes), Ok(()));
    let over_attributes = request(vec![one_scope(vec![Span {
        attributes: (0..=MAX_CONTAINERS)
            .map(|index| attribute(&format!("key-{index}"), AnyValue::default()))
            .collect(),
        ..span()
    }])]);
    assert_eq!(
        preflight_otlp_traces_protobuf(&over_attributes),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let exact_aggregate = request(vec![one_scope(
        (0..(MAX_ATTRIBUTES / MAX_CONTAINERS))
            .map(|span_index| Span {
                attributes: (0..MAX_CONTAINERS)
                    .map(|attribute_index| {
                        attribute(
                            &format!("key-{span_index}-{attribute_index}"),
                            AnyValue::default(),
                        )
                    })
                    .collect(),
                ..span()
            })
            .collect(),
    )]);
    assert_eq!(preflight_otlp_traces_protobuf(&exact_aggregate), Ok(()));

    let mut aggregate_over = ExportTraceServiceRequest::decode(exact_aggregate.as_slice())
        .expect("the exact aggregate request is valid");
    aggregate_over.resource_spans[0].scope_spans[0].spans[3]
        .attributes
        .push(attribute("one-over", AnyValue::default()));
    assert_eq!(
        preflight_otlp_traces_protobuf(&aggregate_over.encode_to_vec()),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );
}

#[test]
fn protobuf_attribute_limits_apply_to_resource_scope_event_and_link_collections() {
    let exact = attributes(MAX_CONTAINERS, "exact");
    let over = attributes(MAX_CONTAINERS + 1, "over");

    let resource_exact = request(vec![ResourceSpans {
        resource: Some(Resource {
            attributes: exact.clone(),
            ..Resource::default()
        }),
        ..ResourceSpans::default()
    }]);
    assert_eq!(preflight_otlp_traces_protobuf(&resource_exact), Ok(()));
    let resource_over = request(vec![ResourceSpans {
        resource: Some(Resource {
            attributes: over.clone(),
            ..Resource::default()
        }),
        ..ResourceSpans::default()
    }]);
    assert_eq!(
        preflight_otlp_traces_protobuf(&resource_over),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let scope_exact = request(vec![ResourceSpans {
        scope_spans: vec![ScopeSpans {
            scope: Some(InstrumentationScope {
                attributes: exact.clone(),
                ..InstrumentationScope::default()
            }),
            ..ScopeSpans::default()
        }],
        ..ResourceSpans::default()
    }]);
    assert_eq!(preflight_otlp_traces_protobuf(&scope_exact), Ok(()));
    let scope_over = request(vec![ResourceSpans {
        scope_spans: vec![ScopeSpans {
            scope: Some(InstrumentationScope {
                attributes: over.clone(),
                ..InstrumentationScope::default()
            }),
            ..ScopeSpans::default()
        }],
        ..ResourceSpans::default()
    }]);
    assert_eq!(
        preflight_otlp_traces_protobuf(&scope_over),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let mut event_exact_span = span();
    event_exact_span.events = vec![Event {
        attributes: exact.clone(),
        ..Event::default()
    }];
    assert_eq!(
        preflight_otlp_traces_protobuf(&request(vec![one_scope(vec![event_exact_span])])),
        Ok(())
    );
    let mut event_over_span = span();
    event_over_span.events = vec![Event {
        attributes: over.clone(),
        ..Event::default()
    }];
    assert_eq!(
        preflight_otlp_traces_protobuf(&request(vec![one_scope(vec![event_over_span])])),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let mut link_exact_span = span();
    link_exact_span.links = vec![Link {
        trace_id: vec![3; 16],
        span_id: vec![4; 8],
        attributes: exact,
        ..Link::default()
    }];
    assert_eq!(
        preflight_otlp_traces_protobuf(&request(vec![one_scope(vec![link_exact_span])])),
        Ok(())
    );
    let mut link_over_span = span();
    link_over_span.links = vec![Link {
        trace_id: vec![3; 16],
        span_id: vec![4; 8],
        attributes: over,
        ..Link::default()
    }];
    assert_eq!(
        preflight_otlp_traces_protobuf(&request(vec![one_scope(vec![link_over_span])])),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );
}

#[test]
fn protobuf_aggregate_string_bytes_have_exact_and_one_over_outcomes() {
    let span_name_length = MAX_BYTES / MAX_RECORDS;
    let exact = request(vec![one_scope(
        (0..MAX_RECORDS)
            .map(|_| Span {
                name: "n".repeat(span_name_length),
                ..span()
            })
            .collect(),
    )]);
    assert_eq!(preflight_otlp_traces_protobuf(&exact), Ok(()));

    let over = request(vec![one_scope(
        (0..MAX_RECORDS)
            .map(|index| Span {
                name: "n".repeat(span_name_length + usize::from(index == 0)),
                ..span()
            })
            .collect(),
    )]);
    assert_eq!(
        preflight_otlp_traces_protobuf(&over),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );
}

#[test]
fn nested_values_have_exact_and_one_over_depth_entries_and_bytes() {
    let profile = profile_with(3, 64, MAX_CONTAINERS, MAX_CONTAINERS, 65_536);
    let exact_depth = nested_array(3);
    let batch = decode_with_profile(exact_depth, profile)
        .expect("the configured nested-value depth is accepted");
    assert_eq!(batch.records().len(), 1);

    let over_depth = nested_array(4);
    let over_depth_result = decode_with_profile(over_depth, profile);
    assert!(
        matches!(
            &over_depth_result,
            Err(TraceReceiveFailure::ValueLimitExceeded)
        ),
        "unexpected nested-depth outcome: {over_depth_result:?}"
    );

    let exact_array = value_attribute(AnyValue {
        value: Some(any_value::Value::ArrayValue(ArrayValue {
            values: vec![AnyValue::default(); MAX_CONTAINERS],
        })),
    });
    assert_eq!(
        OtlpTracesReceiver::with_value_limit_profile(profile)
            .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                exact_array,
            ))
            .map(|batch| batch.records().len()),
        Ok(1)
    );
    let over_array = value_attribute(AnyValue {
        value: Some(any_value::Value::ArrayValue(ArrayValue {
            values: vec![AnyValue::default(); MAX_CONTAINERS + 1],
        })),
    });
    assert_eq!(
        OtlpTracesReceiver::with_value_limit_profile(profile)
            .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                over_array,
            ))
            .expect_err("one array entry over the configured bound"),
        TraceReceiveFailure::ValueLimitExceeded
    );

    let exact_bytes = value_attribute(AnyValue {
        value: Some(any_value::Value::BytesValue(vec![0x5a; 65_536])),
    });
    assert_eq!(
        OtlpTracesReceiver::new()
            .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                exact_bytes,
            ))
            .map(|batch| batch.records().len()),
        Ok(1)
    );
    let over_bytes = value_attribute(AnyValue {
        value: Some(any_value::Value::BytesValue(vec![0x5a; 65_537])),
    });
    assert_eq!(
        OtlpTracesReceiver::new()
            .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                over_bytes,
            ))
            .expect_err("one byte over the value bound"),
        TraceReceiveFailure::ValueLimitExceeded
    );
}

#[test]
fn protobuf_known_fields_reject_wrong_wire_types_and_truncated_values() {
    for payload in [
        vec![0x08, 0],             // resource_spans is length-delimited
        vec![0x0a, 0x02, 0x10, 0], // resource_spans nested field is length-delimited
        vec![0x0a, 0x02, 0x08, 0], // a known nested field has the wrong wire type
        vec![0x0a, 0x01, 0x0a],    // missing the nested length-delimited payload
    ] {
        assert_eq!(
            preflight_otlp_traces_protobuf(&payload),
            Err(TraceReceiveFailure::MalformedPayload),
            "malformed known OTLP field: {payload:?}"
        );
    }
}

#[test]
fn json_bounds_reject_overlong_strings_and_structural_depth_without_intermediate_trees() {
    let exact = format!(r#"{{"unknown":"{}"}}"#, "x".repeat(65_536));
    assert_eq!(preflight_otlp_traces_json(exact.as_bytes()), Ok(()));
    let over = format!(r#"{{"unknown":"{}"}}"#, "x".repeat(65_537));
    assert_eq!(
        preflight_otlp_traces_json(over.as_bytes()),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let exact_containers = format!(r#"{{"unknown":[{}]}}"#, vec!["[]"; 1_022].join(","));
    assert_eq!(
        preflight_otlp_traces_json(exact_containers.as_bytes()),
        Ok(())
    );
    let too_many_arrays = format!(r#"{{"unknown":[{}]}}"#, vec!["[]"; 1_023].join(","));
    assert_eq!(
        preflight_otlp_traces_json(too_many_arrays.as_bytes()),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );
    assert_eq!(
        preflight_otlp_traces_json(br#"{"unknown":[] } trailing"#),
        Err(TraceReceiveFailure::MalformedPayload)
    );

    let exact_depth = nested_json(100);
    assert_eq!(preflight_otlp_traces_json(&exact_depth), Ok(()));
    let over_depth = nested_json(127);
    assert_eq!(
        preflight_otlp_traces_json(&over_depth),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let mut exact_body = br#"{"resourceSpans":[]}"#.to_vec();
    exact_body.resize(MAX_BYTES, b' ');
    assert_eq!(preflight_otlp_traces_json(&exact_body), Ok(()));
    exact_body.push(b' ');
    assert_eq!(
        preflight_otlp_traces_json(&exact_body),
        Err(TraceReceiveFailure::TransportLimitExceeded)
    );
}

#[test]
fn gzip_expansion_is_bounded_at_exact_and_one_over_decompressed_bytes() {
    let mut exact = Vec::with_capacity(MAX_BYTES);
    for _ in 0..(MAX_BYTES / 2) {
        exact.extend_from_slice(&[0x10, 0]);
    }
    assert_eq!(exact.len(), MAX_BYTES);
    let compressed = gzip(&exact);
    assert_eq!(preflight_otlp_traces_gzip(&compressed, false), Ok(()));
    exact.push(0);
    assert_eq!(
        preflight_otlp_traces_gzip(&gzip(&exact), false),
        Err(TraceReceiveFailure::TransportLimitExceeded)
    );

    let mut json = br#"{"resourceSpans":[]}"#.to_vec();
    json.resize(MAX_BYTES, b' ');
    assert_eq!(preflight_otlp_traces_gzip(&gzip(&json), true), Ok(()));
    json.push(b' ');
    assert_eq!(
        preflight_otlp_traces_gzip(&gzip(&json), true),
        Err(TraceReceiveFailure::TransportLimitExceeded)
    );
    assert_eq!(
        preflight_otlp_traces_gzip(&[0x1f, 0x8b, 0x08], true),
        Err(TraceReceiveFailure::MalformedCompression)
    );
}

fn attribute(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(value),
        ..KeyValue::default()
    }
}

fn attributes(count: usize, prefix: &str) -> Vec<KeyValue> {
    (0..count)
        .map(|index| attribute(&format!("{prefix}-{index}"), AnyValue::default()))
        .collect()
}

fn nested_array(depth: usize) -> Vec<u8> {
    let mut value = AnyValue::default();
    for _ in 0..depth {
        value = AnyValue {
            value: Some(any_value::Value::ArrayValue(ArrayValue {
                values: vec![value],
            })),
        };
    }
    value_attribute(value)
}

fn value_attribute(value: AnyValue) -> Vec<u8> {
    request(vec![one_scope(vec![Span {
        attributes: vec![attribute("value", value)],
        ..span()
    }])])
}

fn decode_with_profile(
    protobuf: Vec<u8>,
    profile: ValueLimitProfile,
) -> Result<super::NativeSpanBatch<'static>, TraceReceiveFailure> {
    OtlpTracesReceiver::with_value_limit_profile(profile).decode(
        AuthenticatedOtlpTracesRequest::test_only_protobuf(attribution(), protobuf),
    )
}

fn profile_with(
    nesting_depth: u16,
    attributes_per_namespace: u32,
    array_entries: usize,
    key_value_entries: usize,
    individual_value_bytes: u32,
) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let dynamic = DynamicValueLimits::new(
        ByteLimit::new(individual_value_bytes).expect("valid value bound"),
        CollectionLimit::new(attributes_per_namespace).expect("valid attribute bound"),
        maximum.dynamic_value().key_path_bytes(),
        NestingLimit::new(nesting_depth).expect("valid nesting bound"),
        CollectionLimit::new(u32::try_from(array_entries).expect("array bound"))
            .expect("valid array bound"),
        CollectionLimit::new(u32::try_from(key_value_entries).expect("key/value bound"))
            .expect("valid key/value bound"),
    );
    ValueLimitProfileCandidate::new(
        ValueLimitSet::new(
            RequestLimits::new(
                maximum.request().compressed_bytes(),
                maximum.request().decompressed_bytes(),
                maximum.request().records(),
                maximum.request().aggregate_attributes(),
            ),
            maximum.record(),
            dynamic,
        ),
        None,
    )
    .validate()
    .expect("profile is below system maximum")
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn nested_json(arrays: usize) -> Vec<u8> {
    let mut json = String::from(r#"{"unknown":["#);
    json.push_str(&"[".repeat(arrays));
    json.push('0');
    json.push_str(&"]".repeat(arrays));
    json.push_str("]}");
    json.into_bytes()
}
