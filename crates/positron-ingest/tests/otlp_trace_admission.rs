use std::error::Error;
use std::io::Write;

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::SourceTimeQuality;
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AdmissionGroupPlanFailure, AdmissionGroupPlanner, AuthenticatedOtlpTracesRequest,
    OtlpGrpcTransportEvidence, OtlpTracesReceiver, OtlpTracesRequestEncoding, PolicyAction,
    PolicyAttributePath, PolicyPredicate, PolicyReceiver, PolicyRule, TraceLimitClass,
    TraceLimitViolation, TraceReceiveFailure, otlp_traces_timestamp_presence_json,
    reserve_trace_receiver_transport,
};
use positron_kernel::{MountQualification, ResourceDimension};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use prost::Message;

#[path = "otlp_trace_admission/support.rs"]
mod support;

struct AlternatingTraceShards([VirtualShardId; 2]);

impl AdmissionGroupPlanner for AlternatingTraceShards {
    fn assigned_shard(
        &self,
        _tenant: TenantId,
        _signal: SignalKind,
        _record_ordinal: u32,
        _record: &positron_policy::NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        Err(AdmissionGroupPlanFailure::UnsupportedSignal)
    }

    fn assigned_trace_shard(
        &self,
        _tenant: TenantId,
        signal: SignalKind,
        record_ordinal: u32,
        _record: &positron_signals::SpanObservation,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        if signal != SignalKind::Traces {
            return Err(AdmissionGroupPlanFailure::UnsupportedSignal);
        }
        let ordinal = usize::try_from(record_ordinal)
            .map_err(|_| AdmissionGroupPlanFailure::RecordCountExceeded)?;
        self.0
            .get(ordinal % 2)
            .copied()
            .ok_or(AdmissionGroupPlanFailure::AssignmentUnavailable)
    }
}

#[test]
fn authenticated_trace_constructors_cover_wire_variants_and_decoded_handoff()
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
    let protobuf = ExportTraceServiceRequest::default().encode_to_vec();
    let json = serde_json::to_vec(&ExportTraceServiceRequest::default())?;

    let grpc =
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(context, governor, protobuf.clone())?;
    assert_eq!(
        OtlpTracesReceiver::new().decode(grpc)?.receiver(),
        PolicyReceiver::OtlpGrpc
    );
    let grpc_gzip = AuthenticatedOtlpTracesRequest::otlp_grpc_gzip_protobuf(
        context,
        governor,
        gzip(&protobuf)?,
    )?;
    assert_eq!(
        OtlpTracesReceiver::new().decode(grpc_gzip)?.receiver(),
        PolicyReceiver::OtlpGrpc
    );

    for (encoding, body, expected) in [
        (
            OtlpTracesRequestEncoding::Protobuf,
            protobuf.clone(),
            PolicyReceiver::OtlpHttpProtobuf,
        ),
        (
            OtlpTracesRequestEncoding::GzipProtobuf,
            gzip(&protobuf)?,
            PolicyReceiver::OtlpHttpProtobuf,
        ),
        (
            OtlpTracesRequestEncoding::Json,
            json.clone(),
            PolicyReceiver::OtlpHttpJson,
        ),
        (
            OtlpTracesRequestEncoding::GzipJson,
            gzip(&json)?,
            PolicyReceiver::OtlpHttpJson,
        ),
    ] {
        let request = AuthenticatedOtlpTracesRequest::otlp_http(context, governor, encoding, body)?;
        assert_eq!(
            OtlpTracesReceiver::new().decode(request)?.receiver(),
            expected
        );
    }

    let capacity = positron_ingest::reserve_trace_receiver_transport(context, governor)?;
    let decoded = AuthenticatedOtlpTracesRequest::decoded_otlp_grpc_after_transport_admission(
        context,
        ExportTraceServiceRequest::default(),
        OtlpGrpcTransportEvidence::prevalidated(5, 0),
        capacity,
    )?;
    assert_eq!(
        OtlpTracesReceiver::new().decode(decoded)?.receiver(),
        PolicyReceiver::OtlpGrpc
    );
    Ok(())
}

#[test]
fn public_protobuf_timestamp_presence_respects_record_profile_limit() -> Result<(), Box<dyn Error>>
{
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: (0..1_025)
                    .map(|ordinal| Span {
                        trace_id: vec![1; 16],
                        span_id: vec![(ordinal % 256) as u8; 8],
                        ..Span::default()
                    })
                    .collect(),
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };

    assert_eq!(
        positron_ingest::otlp_traces_timestamp_presence_protobuf(&request.encode_to_vec())
            .expect_err("presence scan accepted more than the canonical record limit"),
        TraceReceiveFailure::ValueLimitExceededWithDetail(TraceLimitViolation::new(
            TraceLimitClass::RecordCount,
            1_025,
            1_024,
        ))
    );
    Ok(())
}

#[test]
fn legacy_decoded_trace_rejects_zero_timestamp_without_wire_presence() -> Result<(), Box<dyn Error>>
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
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![1; 16],
                    span_id: vec![2; 8],
                    name: "legacy-zero".to_owned(),
                    start_time_unix_nano: 0,
                    end_time_unix_nano: 0,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let encoded = request.encoded_len();
    let decoded = AuthenticatedOtlpTracesRequest::decoded_otlp_grpc_after_transport_admission(
        context,
        request,
        OtlpGrpcTransportEvidence::prevalidated(encoded + 5, encoded),
        reserve_trace_receiver_transport(context, governor)?,
    )?;
    assert_eq!(
        OtlpTracesReceiver::new().decode(decoded).err(),
        Some(TraceReceiveFailure::MalformedPayload),
        "an already-decoded zero timestamp without wire presence is ambiguous"
    );
    Ok(())
}

#[test]
fn authenticated_trace_admission_enforces_exact_transport_limit_before_reservation()
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
    let limit = usize::try_from(
        positron_domain::value::ValueLimitProfile::release_1_system_maximum()
            .system_limits()
            .request()
            .compressed_bytes()
            .value(),
    )?;
    let baseline = governor.inspect()?.outstanding_reservations();

    let accepted =
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(context, governor, vec![0; limit])?;
    drop(accepted);
    assert_eq!(governor.inspect()?.outstanding_reservations(), baseline);

    assert_eq!(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            vec![0; limit.saturating_add(1)],
        )
        .err(),
        Some(TraceReceiveFailure::TransportLimitExceeded),
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), baseline);
    Ok(())
}

#[test]
fn non_ingest_authority_is_rejected_before_trace_reservation() -> Result<(), Box<dyn Error>> {
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
    let query_context = instance.attribute(
        PresentedCredential::parse(claim.query_secret().ok_or("query credential")?)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    assert_eq!(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(query_context, governor, Vec::new())
            .err(),
        Some(TraceReceiveFailure::AuthenticationRejected),
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[test]
fn malformed_trace_decode_releases_transport_reservation_without_drift()
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
    let baseline = governor.inspect()?.outstanding_reservations();
    let request =
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(context, governor, vec![0x08, 0x00])?;
    assert!(governor.inspect()?.outstanding_reservations() > baseline);
    assert_eq!(
        OtlpTracesReceiver::new()
            .decode(request)
            .expect_err("known-field wire mismatch must fail"),
        TraceReceiveFailure::MalformedPayload
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), baseline);
    Ok(())
}

#[test]
fn encoded_trace_transport_limits_are_format_specific_and_release_admission()
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
    let limit = usize::try_from(
        positron_domain::value::ValueLimitProfile::release_1_system_maximum()
            .system_limits()
            .request()
            .compressed_bytes()
            .value(),
    )?;
    let baseline = governor.inspect()?.outstanding_total();

    for encoding in [
        OtlpTracesRequestEncoding::GzipProtobuf,
        OtlpTracesRequestEncoding::Json,
        OtlpTracesRequestEncoding::GzipJson,
    ] {
        let capacity = reserve_trace_receiver_transport(context, governor)?;
        let request = AuthenticatedOtlpTracesRequest::encoded_otlp_http_after_transport_admission(
            context,
            encoding,
            vec![0; limit.saturating_add(1)],
            capacity,
        )?;
        assert_eq!(
            OtlpTracesReceiver::new().decode(request).err(),
            Some(TraceReceiveFailure::TransportLimitExceeded),
            "oversized {encoding:?} body must be rejected before decompression or decoding",
        );
        assert_eq!(governor.inspect()?.outstanding_total(), baseline);
    }
    Ok(())
}

#[test]
fn trace_policy_rejections_still_reserve_materialized_record_slots() -> Result<(), Box<dyn Error>> {
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
    let count = 8_usize;
    let spans = (0..count)
        .map(|ordinal| Span {
            trace_id: vec![ordinal as u8 + 1; 16],
            span_id: vec![ordinal as u8 + 1; 8],
            name: "rejected".to_owned(),
            start_time_unix_nano: 10,
            end_time_unix_nano: 20,
            ..Span::default()
        })
        .collect();
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans,
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let policy = positron_policy::IngestPolicy::compile(
        7,
        vec![positron_policy::PolicyRule::new(
            "reject-all",
            Vec::new(),
            positron_policy::PolicyAction::Reject,
        )?],
    )?;
    let batch = OtlpTracesReceiver::new().decode_with_policy(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            request.encode_to_vec(),
        )?,
        &policy,
    )?;
    assert!(batch.records().is_empty());
    let reserved_memory = governor.inspect()?.usage(ResourceDimension::MemoryBytes);
    let minimum_record_slots = u64::try_from(count)?
        .checked_mul(u64::try_from(std::mem::size_of::<
            positron_signals::SpanObservation,
        >())?)
        .ok_or("record slot expectation overflow")?;
    assert!(
        reserved_memory >= minimum_record_slots,
        "rejected materialization capacity was not reserved: {reserved_memory} < {minimum_record_slots}"
    );
    drop(batch);
    assert_eq!(
        governor
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        0
    );
    Ok(())
}

#[test]
fn trace_grouping_reserves_rejected_source_slots_and_multishard_vectors()
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
    let spans = (0..8)
        .map(|ordinal| {
            let mut span = Span {
                trace_id: vec![ordinal + 1; 16],
                span_id: vec![ordinal + 1; 8],
                name: format!("span-{ordinal}"),
                start_time_unix_nano: 10,
                end_time_unix_nano: 20,
                ..Span::default()
            };
            if ordinal >= 2 {
                span.attributes.push(KeyValue {
                    key: "reject".to_owned(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::BoolValue(true)),
                    }),
                    ..KeyValue::default()
                });
            }
            span
        })
        .collect();
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans,
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let policy = positron_ingest::IngestPolicy::compile(
        8,
        vec![PolicyRule::new(
            "reject-marked",
            vec![PolicyPredicate::attribute_exists(PolicyAttributePath::new(
                positron_domain::value::AttributeNamespace::Record,
                "reject",
            )?)],
            PolicyAction::Reject,
        )?],
    )?;
    let batch = OtlpTracesReceiver::new().decode_with_policy(
        AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            request.encode_to_vec(),
        )?,
        &policy,
    )?;
    assert_eq!(batch.records().len(), 2);
    let source_slot_bytes = u64::try_from(8_usize)?
        .checked_mul(u64::try_from(std::mem::size_of::<
            positron_signals::SpanObservation,
        >())?)
        .ok_or("source slot expectation overflow")?;
    let group_slot_bytes = u64::try_from(2_usize)?
        .checked_mul(u64::try_from(std::mem::size_of::<
            positron_signals::SpanObservation,
        >())?)
        .ok_or("group slot expectation overflow")?;
    let groups = batch.into_admission_groups(&AlternatingTraceShards([
        VirtualShardId::new(201)?,
        VirtualShardId::new(202)?,
    ]))?;
    assert_eq!(groups.len(), 2);
    let reserved_memory = governor.inspect()?.usage(ResourceDimension::MemoryBytes);
    let minimum_grouping_charge = source_slot_bytes
        .checked_add(group_slot_bytes)
        .ok_or("grouping charge expectation overflow")?;
    assert!(
        reserved_memory >= minimum_grouping_charge,
        "grouping charge omitted overlapping capacities: {reserved_memory} < {}",
        minimum_grouping_charge
    );
    drop(groups);
    assert_eq!(
        governor
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        0
    );
    Ok(())
}

#[test]
fn raw_trace_timestamps_preserve_wire_presence_and_unsigned_range() -> Result<(), Box<dyn Error>> {
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

    let omitted =
        OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            raw_trace_request(None, None, None),
        )?)?;
    assert_eq!(omitted.records().len(), 1);
    assert_eq!(
        omitted.records()[0].start_time().quality(),
        SourceTimeQuality::Missing
    );
    assert_eq!(omitted.records()[0].start_time().instant(), None);
    assert_eq!(
        omitted.records()[0].end_time().quality(),
        SourceTimeQuality::Missing
    );
    assert_eq!(
        omitted.records()[0].details().events()[0]
            .timestamp()
            .quality(),
        SourceTimeQuality::Missing
    );

    let explicit_zero =
        OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            raw_trace_request(Some(0), Some(0), Some(0)),
        )?)?;
    assert_eq!(explicit_zero.records().len(), 1);
    assert_eq!(
        explicit_zero.records()[0].start_time().quality(),
        SourceTimeQuality::Zero
    );
    assert_eq!(
        explicit_zero.records()[0].start_time().source_value(),
        Some(0)
    );
    assert_eq!(
        explicit_zero.records()[0].end_time().quality(),
        SourceTimeQuality::Zero
    );
    assert_eq!(
        explicit_zero.records()[0].details().events()[0]
            .timestamp()
            .quality(),
        SourceTimeQuality::Zero
    );

    let out_of_range = u64::MAX;
    let preserved =
        OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::otlp_grpc_protobuf(
            context,
            governor,
            raw_trace_request(Some(out_of_range), Some(out_of_range), Some(out_of_range)),
        )?)?;
    assert_eq!(preserved.records().len(), 1);
    assert_eq!(
        preserved.records()[0].start_time().source_value(),
        Some(out_of_range)
    );
    assert_eq!(preserved.records()[0].start_time().instant(), None);
    assert_eq!(
        preserved.records()[0].start_time().quality(),
        SourceTimeQuality::Outlier
    );
    assert_eq!(
        preserved.records()[0].end_time().source_value(),
        Some(out_of_range)
    );
    assert_eq!(
        preserved.records()[0].details().events()[0]
            .timestamp()
            .source_value(),
        Some(out_of_range)
    );
    Ok(())
}

#[test]
fn protojson_trace_timestamps_preserve_wire_presence_and_unsigned_range()
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

    // Exercise the public bounded presence adapter's forward-compatible
    // unknown/null container handling and every JSON scalar representation.
    let adapter_boundary = serde_json::json!({
        "unknownRoot": [null, {"ignored": true}],
        "resource_spans": [
            null,
            {
                "unknownResource": {"ignored": [1, 2]},
                "scope_spans": [
                    null,
                    {
                        "unknownScope": false,
                        "spans": [
                            null,
                            {
                                "unknownSpan": {"ignored": "value"},
                                "start_time_unix_nano": null,
                                "endTimeUnixNano": true,
                                "events": [
                                    null,
                                    {
                                        "unknownEvent": [],
                                        "time_unix_nano": null,
                                    },
                                    {"timeUnixNano": -1},
                                    {"timeUnixNano": 1},
                                    {"timeUnixNano": 1.5},
                                    {"timeUnixNano": "0"},
                                ],
                            },
                        ],
                    },
                ],
            },
        ],
    });
    assert!(otlp_traces_timestamp_presence_json(&serde_json::to_vec(&adapter_boundary,)?).is_ok());

    let null_containers = [
        serde_json::json!({"resourceSpans": null}),
        serde_json::json!({"resourceSpans": [{"scopeSpans": null}]}),
        serde_json::json!({"resourceSpans": [{"scopeSpans": [{"spans": null}]}]}),
        serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{"events": null}]}]}]
        }),
    ];
    for fixture in null_containers {
        assert!(otlp_traces_timestamp_presence_json(&serde_json::to_vec(&fixture)?).is_ok());
    }

    let malformed_shapes = [
        serde_json::json!([]),
        serde_json::json!({"resourceSpans": 1}),
        serde_json::json!({"resourceSpans": [1]}),
        serde_json::json!({"resourceSpans": [{"scopeSpans": 1}]}),
        serde_json::json!({"resourceSpans": [{"scopeSpans": [1]}]}),
        serde_json::json!({"resourceSpans": [{"scopeSpans": [{"spans": 1}]}]}),
        serde_json::json!({"resourceSpans": [{"scopeSpans": [{"spans": [1]}]}]}),
        serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{"events": 1}]}]}]
        }),
        serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{"events": [1]}]}]}]
        }),
        serde_json::json!({
            "resourceSpans": [{
                "scopeSpans": [{"spans": [{"startTimeUnixNano": {}}]}]
            }]
        }),
    ];
    for fixture in malformed_shapes {
        assert_eq!(
            otlp_traces_timestamp_presence_json(&serde_json::to_vec(&fixture)?)
                .expect_err("malformed presence shape accepted"),
            TraceReceiveFailure::MalformedPayload
        );
    }

    let omitted = OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::otlp_http(
        context,
        governor,
        OtlpTracesRequestEncoding::Json,
        json_trace_request(None, None, None),
    )?)?;
    assert_eq!(omitted.records().len(), 1);
    assert_eq!(
        omitted.records()[0].start_time().quality(),
        SourceTimeQuality::Missing
    );
    assert_eq!(
        omitted.records()[0].end_time().quality(),
        SourceTimeQuality::Missing
    );
    assert_eq!(
        omitted.records()[0].details().events()[0]
            .timestamp()
            .quality(),
        SourceTimeQuality::Missing
    );

    let explicit_zero =
        OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::otlp_http(
            context,
            governor,
            OtlpTracesRequestEncoding::Json,
            json_trace_request(Some(0), Some(0), Some(0)),
        )?)?;
    assert_eq!(explicit_zero.records().len(), 1);
    assert_eq!(
        explicit_zero.records()[0].start_time().quality(),
        SourceTimeQuality::Zero
    );
    assert_eq!(
        explicit_zero.records()[0].end_time().quality(),
        SourceTimeQuality::Zero
    );
    assert_eq!(
        explicit_zero.records()[0].details().events()[0]
            .timestamp()
            .quality(),
        SourceTimeQuality::Zero
    );

    let reversed = OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::otlp_http(
        context,
        governor,
        OtlpTracesRequestEncoding::Json,
        json_trace_request(Some(10), Some(0), Some(1)),
    )?)?;
    assert_eq!(reversed.records().len(), 1);
    assert_eq!(reversed.records()[0].end_time().source_value(), Some(0));
    assert_eq!(
        reversed.records()[0].end_time().quality(),
        SourceTimeQuality::Contradictory
    );

    let source = u64::MAX;
    let preserved = OtlpTracesReceiver::new().decode(AuthenticatedOtlpTracesRequest::otlp_http(
        context,
        governor,
        OtlpTracesRequestEncoding::Json,
        json_trace_request(Some(source), Some(source), Some(source)),
    )?)?;
    assert_eq!(preserved.records().len(), 1);
    assert_eq!(
        preserved.records()[0].start_time().source_value(),
        Some(source)
    );
    assert_eq!(
        preserved.records()[0].end_time().source_value(),
        Some(source)
    );
    assert_eq!(
        preserved.records()[0].details().events()[0]
            .timestamp()
            .source_value(),
        Some(source)
    );
    Ok(())
}

fn raw_trace_request(start: Option<u64>, end: Option<u64>, event_time: Option<u64>) -> Vec<u8> {
    let mut event = Vec::new();
    length_field(&mut event, 2, b"event");
    if let Some(value) = event_time {
        fixed64_field(&mut event, 1, value);
    }

    let mut span = Vec::new();
    length_field(&mut span, 1, &[1; 16]);
    length_field(&mut span, 2, &[2; 8]);
    length_field(&mut span, 5, b"span");
    if let Some(value) = start {
        fixed64_field(&mut span, 7, value);
    }
    if let Some(value) = end {
        fixed64_field(&mut span, 8, value);
    }
    length_field(&mut span, 11, &event);

    let mut scope = Vec::new();
    length_field(&mut scope, 2, &span);
    let mut resource = Vec::new();
    length_field(&mut resource, 2, &scope);
    let mut request = Vec::new();
    length_field(&mut request, 1, &resource);
    request
}

fn json_trace_request(start: Option<u64>, end: Option<u64>, event_time: Option<u64>) -> Vec<u8> {
    let mut span = serde_json::json!({
        "traceId": "01010101010101010101010101010101",
        "spanId": "0202020202020202",
        "name": "span",
        "events": [{"name": "event"}],
    });
    if let Some(value) = start {
        span["startTimeUnixNano"] = serde_json::Value::String(value.to_string());
    }
    if let Some(value) = end {
        span["endTimeUnixNano"] = serde_json::Value::String(value.to_string());
    }
    if let Some(value) = event_time {
        span["events"][0]["timeUnixNano"] = serde_json::Value::String(value.to_string());
    }
    serde_json::to_vec(&serde_json::json!({
        "resourceSpans": [{"scopeSpans": [{"spans": [span]}]}],
    }))
    .expect("valid ProtoJSON fixture")
}

fn length_field(output: &mut Vec<u8>, field: u8, value: &[u8]) {
    output.push(field << 3 | 2);
    append_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn fixed64_field(output: &mut Vec<u8>, field: u8, value: u64) {
    output.push(field << 3 | 1);
    output.extend_from_slice(&value.to_le_bytes());
}

fn append_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push(value as u8 & 0x7f | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes)?;
    encoder.finish()
}
