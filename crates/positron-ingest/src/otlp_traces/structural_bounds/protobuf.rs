use super::super::{TraceReceiveFailure, preflight_otlp_traces_protobuf};
use super::support::{
    MAX_ATTRIBUTES, MAX_CONTAINERS, MAX_RECORDS, attribute, attributes, one_scope, request, span,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;

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
