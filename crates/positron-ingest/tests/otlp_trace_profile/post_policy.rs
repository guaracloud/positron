use super::*;

use opentelemetry_proto::tonic::common::v1::{ArrayValue, KeyValueList};
use positron_domain::routing::VirtualShardId;
use positron_domain::value::RequestLimits;
use positron_ingest::{FixedAdmissionGroupPlanner, TraceLimitClass, TraceLimitViolation};

fn dynamic_limits(
    value_bytes: u32,
    attributes_per_namespace: u32,
    key_path_bytes: u32,
    nesting_depth: u16,
    array_entries: u32,
    key_value_list_entries: u32,
) -> DynamicValueLimits {
    DynamicValueLimits::new(
        ByteLimit::new(value_bytes).expect("value limit"),
        CollectionLimit::new(attributes_per_namespace).expect("attribute limit"),
        ByteLimit::new(key_path_bytes).expect("key/path limit"),
        NestingLimit::new(nesting_depth).expect("depth limit"),
        CollectionLimit::new(array_entries).expect("array limit"),
        CollectionLimit::new(key_value_list_entries).expect("list limit"),
    )
}

fn request_limits(records: u32, aggregate_attributes: u32) -> RequestLimits {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    RequestLimits::new(
        maximum.effective_limits().request().compressed_bytes(),
        maximum.effective_limits().request().decompressed_bytes(),
        CollectionLimit::new(records).expect("record limit"),
        CollectionLimit::new(aggregate_attributes).expect("aggregate limit"),
    )
}

fn profile_with_limits(dynamic: DynamicValueLimits, request: RequestLimits) -> ValueLimitProfile {
    let maximum = ValueLimitProfile::release_1_system_maximum();
    ValueLimitProfileCandidate::new(
        maximum.system_limits(),
        Some(ValueLimitSet::new(
            request,
            maximum.effective_limits().record(),
            dynamic,
        )),
    )
    .validate()
    .expect("lowered profile")
}

fn any_value(value: any_value::Value) -> AnyValue {
    AnyValue { value: Some(value) }
}

fn attribute(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(value),
        ..KeyValue::default()
    }
}

fn span(attributes: Vec<KeyValue>, events: Vec<Event>) -> Span {
    Span {
        trace_id: vec![1; 16],
        span_id: vec![2; 8],
        name: "sp".to_owned(),
        attributes,
        events,
        ..Span::default()
    }
}

fn span_named(name: &str, attributes: Vec<KeyValue>, events: Vec<Event>) -> Span {
    Span {
        trace_id: vec![1; 16],
        span_id: vec![2; 8],
        name: name.to_owned(),
        attributes,
        events,
        ..Span::default()
    }
}

fn request_with_span(span: Span) -> ExportTraceServiceRequest {
    request_with_spans(vec![span])
}

fn request_with_spans(spans: Vec<Span>) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans,
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}

fn expected(class: TraceLimitClass, actual: u64, allowed: u64) -> TraceLimitViolation {
    TraceLimitViolation::new(class, actual, allowed)
}

#[test]
fn nested_post_policy_paths_keep_valid_records_and_reject_one_over_depth()
-> Result<(), Box<dyn Error>> {
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    let baseline = governor.inspect()?.outstanding_total();
    let valid_nested = any_value(any_value::Value::ArrayValue(ArrayValue {
        values: vec![any_value(any_value::Value::KvlistValue(KeyValueList {
            values: vec![attribute(
                "child",
                any_value(any_value::Value::StringValue("ok".to_owned())),
            )],
        }))],
    }));
    let mut over_depth = any_value(any_value::Value::BoolValue(true));
    for _ in 0..4 {
        over_depth = any_value(any_value::Value::ArrayValue(ArrayValue {
            values: vec![over_depth],
        }));
    }
    let mut accepted = span(vec![attribute("nested", valid_nested)], Vec::new());
    accepted.span_id = vec![3; 8];
    let request = request_with_spans(vec![accepted]);
    let authenticated = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request.encode_to_vec(),
    )?;
    let batch = OtlpTracesReceiver::with_value_limit_profile(profile_with_limits(
        dynamic_limits(64, 16, 16, 4, 2, 2),
        request_limits(8, 64),
    ))
    .decode(authenticated)?;
    assert_eq!(batch.records().len(), 1);
    let planner = FixedAdmissionGroupPlanner::new(VirtualShardId::new(1)?);
    let groups = batch.into_admission_groups(&planner)?;
    assert_eq!(groups.len(), 1);
    assert!(groups.limit_rejections().is_empty());
    drop(groups);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);

    let mut rejected = span(vec![attribute("nested", over_depth)], Vec::new());
    rejected.span_id = vec![4; 8];
    let authenticated = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request_with_spans(vec![rejected]).encode_to_vec(),
    )?;
    let batch = OtlpTracesReceiver::with_value_limit_profile(profile_with_limits(
        dynamic_limits(64, 16, 16, 1, 2, 2),
        request_limits(8, 64),
    ))
    .decode(authenticated)?;
    assert!(batch.records().is_empty());
    let groups = batch.into_admission_groups(&planner)?;
    assert!(groups.is_empty());
    assert_eq!(
        groups.limit_rejections().iter().collect::<Vec<_>>(),
        vec![expected(TraceLimitClass::NestingDepth, 1, 0),]
    );
    drop(groups);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    Ok(())
}

#[test]
fn authenticated_effective_profile_reports_post_policy_limit_classes() -> Result<(), Box<dyn Error>>
{
    let roots = support::temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    let baseline = governor.inspect()?.outstanding_total();
    let nested_array = any_value(any_value::Value::ArrayValue(ArrayValue {
        values: vec![any_value(any_value::Value::ArrayValue(ArrayValue {
            values: vec![any_value(any_value::Value::BoolValue(true))],
        }))],
    }));
    let nested_list = any_value(any_value::Value::KvlistValue(KeyValueList {
        values: vec![attribute(
            "long",
            any_value(any_value::Value::BoolValue(true)),
        )],
    }));
    let nested_size = any_value(any_value::Value::ArrayValue(ArrayValue {
        values: vec![
            any_value(any_value::Value::StringValue("abc".to_owned())),
            any_value(any_value::Value::StringValue("abc".to_owned())),
        ],
    }));
    let planner = FixedAdmissionGroupPlanner::new(VirtualShardId::new(1)?);
    let cases = vec![
        (
            profile_with_limits(
                dynamic_limits(65_536, 1_024, 3, 128, 1_024, 1_024),
                request_limits(1_024, 4_096),
            ),
            request_with_span(span_named("long", Vec::new(), Vec::new())),
            expected(TraceLimitClass::KeyPathBytes, 4, 3),
        ),
        (
            profile_with_limits(
                dynamic_limits(65_536, 1, 65_536, 128, 1_024, 1_024),
                request_limits(1_024, 4_096),
            ),
            request_with_span(span(
                vec![
                    attribute("x", any_value(any_value::Value::BoolValue(true))),
                    attribute("x", any_value(any_value::Value::BoolValue(false))),
                ],
                Vec::new(),
            )),
            expected(TraceLimitClass::AttributesPerNamespace, 2, 1),
        ),
        (
            profile_with_limits(
                dynamic_limits(4, 1_024, 65_536, 128, 1_024, 1_024),
                request_limits(1_024, 4_096),
            ),
            request_with_span(span(
                vec![attribute(
                    "v",
                    any_value(any_value::Value::StringValue("12345".to_owned())),
                )],
                Vec::new(),
            )),
            expected(TraceLimitClass::IndividualValueBytes, 5, 4),
        ),
        (
            profile_with_limits(
                dynamic_limits(65_536, 1_024, 65_536, 128, 1, 1_024),
                request_limits(1_024, 4_096),
            ),
            request_with_span(span(
                vec![attribute(
                    "a",
                    any_value(any_value::Value::ArrayValue(ArrayValue {
                        values: vec![
                            any_value(any_value::Value::BoolValue(true)),
                            any_value(any_value::Value::BoolValue(false)),
                        ],
                    })),
                )],
                Vec::new(),
            )),
            expected(TraceLimitClass::ArrayEntries, 2, 1),
        ),
        (
            profile_with_limits(
                dynamic_limits(65_536, 1_024, 65_536, 128, 1_024, 1),
                request_limits(1_024, 4_096),
            ),
            request_with_span(span(
                vec![attribute(
                    "l",
                    any_value(any_value::Value::KvlistValue(KeyValueList {
                        values: vec![
                            attribute("a", any_value(any_value::Value::BoolValue(true))),
                            attribute("b", any_value(any_value::Value::BoolValue(false))),
                        ],
                    })),
                )],
                Vec::new(),
            )),
            expected(TraceLimitClass::KeyValueListEntries, 2, 1),
        ),
        (
            profile_with_limits(
                dynamic_limits(65_536, 1_024, 65_536, 1, 1_024, 1_024),
                request_limits(1_024, 4_096),
            ),
            request_with_span(span(vec![attribute("n", nested_array)], Vec::new())),
            expected(TraceLimitClass::NestingDepth, 1, 0),
        ),
        (
            profile_with_limits(
                dynamic_limits(65_536, 1_024, 3, 128, 1_024, 1_024),
                request_limits(1_024, 4_096),
            ),
            request_with_span(span(vec![attribute("l", nested_list)], Vec::new())),
            expected(TraceLimitClass::KeyPathBytes, 4, 3),
        ),
        (
            profile_with_limits(
                dynamic_limits(4, 1_024, 65_536, 128, 1_024, 1_024),
                request_limits(1_024, 4_096),
            ),
            request_with_span(span(vec![attribute("v", nested_size)], Vec::new())),
            expected(TraceLimitClass::IndividualValueBytes, 6, 4),
        ),
    ];

    for (profile, request, expected_violation) in cases {
        let authenticated = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            request.encode_to_vec(),
        )?;
        let batch = OtlpTracesReceiver::with_value_limit_profile(profile).decode(authenticated)?;
        assert!(batch.records().is_empty());
        let groups = batch.into_admission_groups(&planner)?;
        assert_eq!(
            groups.limit_rejections().iter().collect::<Vec<_>>(),
            vec![expected_violation]
        );
        assert!(groups.is_empty());
        drop(groups);
        assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    }

    let detail_request =
        request_with_span(span(Vec::new(), vec![Event::default(), Event::default()]));
    let authenticated = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        detail_request.encode_to_vec(),
    )?;
    let result = OtlpTracesReceiver::with_value_limit_profile(profile_with_limits(
        dynamic_limits(65_536, 1_024, 65_536, 128, 1_024, 1_024),
        request_limits(1, 4_096),
    ))
    .decode(authenticated);
    let result = result?;
    assert!(result.records().is_empty());
    let groups = result.into_admission_groups(&planner)?;
    assert_eq!(
        groups.limit_rejections().iter().collect::<Vec<_>>(),
        vec![expected(TraceLimitClass::RecordCount, 2, 1)]
    );
    assert!(groups.is_empty());
    drop(groups);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);

    let aggregate_request = request_with_span(span(
        vec![
            attribute("a", any_value(any_value::Value::BoolValue(true))),
            attribute("b", any_value(any_value::Value::BoolValue(false))),
        ],
        Vec::new(),
    ));
    let authenticated = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        aggregate_request.encode_to_vec(),
    )?;
    let result = OtlpTracesReceiver::with_value_limit_profile(profile_with_limits(
        dynamic_limits(65_536, 1_024, 65_536, 128, 1_024, 1_024),
        request_limits(1_024, 1),
    ))
    .decode(authenticated)?;
    assert!(result.records().is_empty());
    drop(result);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    Ok(())
}
