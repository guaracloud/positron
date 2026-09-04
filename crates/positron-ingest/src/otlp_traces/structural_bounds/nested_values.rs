use super::super::{
    AuthenticatedOtlpTracesRequest, NativeSpanBatch, OtlpTracesReceiver, TraceReceiveFailure,
};
use super::support::{MAX_CONTAINERS, one_scope, request, span};
use opentelemetry_proto::tonic::common::v1::{AnyValue, ArrayValue, any_value};
use positron_domain::value::{
    ByteLimit, CollectionLimit, DynamicValueLimits, NestingLimit, RequestLimits, ValueLimitProfile,
    ValueLimitProfileCandidate, ValueLimitSet,
};

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
                super::support::attribution(),
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
                super::support::attribution(),
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
                super::support::attribution(),
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
                super::support::attribution(),
                over_bytes,
            ))
            .expect_err("one byte over the value bound"),
        TraceReceiveFailure::ValueLimitExceeded
    );
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

pub(crate) fn value_attribute(value: AnyValue) -> Vec<u8> {
    request(vec![one_scope(vec![
        opentelemetry_proto::tonic::trace::v1::Span {
            attributes: vec![super::support::attribute("value", value)],
            ..span()
        },
    ])])
}

fn decode_with_profile(
    protobuf: Vec<u8>,
    profile: ValueLimitProfile,
) -> Result<NativeSpanBatch<'static>, TraceReceiveFailure> {
    OtlpTracesReceiver::with_value_limit_profile(profile).decode(
        AuthenticatedOtlpTracesRequest::test_only_protobuf(super::support::attribution(), protobuf),
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
