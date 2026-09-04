use std::error::Error;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::EntityRef;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{AuthenticatedOtlpTracesRequest, OtlpTracesReceiver, TraceReceiveFailure};
use positron_kernel::{MountQualification, ResourceDimension};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use prost::Message;

#[path = "otlp_trace_admission/support.rs"]
mod support;

#[test]
fn maximum_event_and_link_collections_are_charged_and_released_before_one_over()
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
    let baseline_memory = governor.inspect()?.usage(ResourceDimension::MemoryBytes);
    let exact = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request(1_024, 1_024).encode_to_vec(),
    )?;
    let exact = OtlpTracesReceiver::new().decode(exact)?;
    assert_eq!(exact.records().len(), 1);
    assert!(
        governor.inspect()?.usage(ResourceDimension::MemoryBytes) > baseline_memory,
        "detail vectors and their strings remain charged while the batch is live"
    );
    drop(exact);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);

    for (events, links) in [(1_025, 0), (0, 1_025)] {
        let request = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            request(events, links).encode_to_vec(),
        )?;
        assert_eq!(
            OtlpTracesReceiver::new().decode(request).err(),
            Some(TraceReceiveFailure::ValueLimitExceeded),
            "one-over detail collection must fail before native materialization"
        );
        assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    }
    Ok(())
}

#[test]
fn resource_entity_reference_collection_is_bounded_before_materialization()
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
    let exact = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request_with_entity_refs(1_024).encode_to_vec(),
    )?;
    let exact = OtlpTracesReceiver::new().decode(exact)?;
    assert!(exact.records().is_empty());
    drop(exact);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);

    let over = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request_with_entity_refs(1_025).encode_to_vec(),
    )?;
    assert_eq!(
        OtlpTracesReceiver::new().decode(over).err(),
        Some(TraceReceiveFailure::ValueLimitExceeded)
    );
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    Ok(())
}

#[test]
fn event_attribute_sets_are_reserved_before_detail_materialization() -> Result<(), Box<dyn Error>> {
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
    let exact = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request_with_event_attributes(1_024).encode_to_vec(),
    )?;
    let batch = OtlpTracesReceiver::new().decode(exact)?;
    assert_eq!(batch.records().len(), 1);
    assert_eq!(
        batch.records()[0].details().events()[0].attributes().len(),
        1_024
    );
    assert_eq!(
        batch.records()[0].details().links()[0].attributes().len(),
        1_024
    );
    drop(batch);
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);

    let over = AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
        context,
        governor,
        request_with_event_attributes(1_025).encode_to_vec(),
    )?;
    assert_eq!(
        OtlpTracesReceiver::new().decode(over).err(),
        Some(TraceReceiveFailure::ValueLimitExceeded)
    );
    assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    Ok(())
}

fn request(events: usize, links: usize) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![1; 16],
                    span_id: vec![2; 8],
                    name: "detail-boundary".to_owned(),
                    events: (0..events)
                        .map(|index| Event {
                            time_unix_nano: u64::try_from(index).unwrap_or(0),
                            name: format!("event-{index}"),
                            ..Event::default()
                        })
                        .collect(),
                    links: (0..links)
                        .map(|index| Link {
                            trace_id: vec![3; 16],
                            span_id: vec![u8::try_from(index % 255).unwrap_or(1).max(1); 8],
                            trace_state: format!("link-{index}"),
                            ..Link::default()
                        })
                        .collect(),
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}

fn request_with_entity_refs(count: usize) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                entity_refs: (0..count)
                    .map(|index| EntityRef {
                        schema_url: "https://entity.example/v1".to_owned(),
                        r#type: "service".to_owned(),
                        id_keys: vec![format!("service-{index}")],
                        ..EntityRef::default()
                    })
                    .collect(),
                ..Resource::default()
            }),
            ..ResourceSpans::default()
        }],
    }
}

fn request_with_event_attributes(count: usize) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![1; 16],
                    span_id: vec![2; 8],
                    name: "event-attributes".to_owned(),
                    events: vec![Event {
                        time_unix_nano: 1,
                        name: "event".to_owned(),
                        attributes: (0..count)
                            .map(|index| KeyValue {
                                key: format!("event-{index}"),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::BoolValue(true)),
                                }),
                                ..KeyValue::default()
                            })
                            .collect(),
                        ..Event::default()
                    }],
                    links: vec![Link {
                        trace_id: vec![3; 16],
                        span_id: vec![4; 8],
                        attributes: (0..count)
                            .map(|index| KeyValue {
                                key: format!("link-{index}"),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::BoolValue(true)),
                                }),
                                ..KeyValue::default()
                            })
                            .collect(),
                        ..Link::default()
                    }],
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}
