use opentelemetry_proto::tonic::trace::v1::Status;
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use positron_policy::NativePolicyAttribute;

#[path = "../otlp_traces/drafts.rs"]
mod drafts;
#[path = "../otlp_traces/materialize.rs"]
mod materialize;

pub(crate) use drafts::native_records;

/// A bounded raw span draft. It contains only structurally decoded protocol
/// fields and policy-visible generic attributes; native identifiers, times,
/// kinds, statuses, events, and links are materialized after policy accepts
/// the candidate.
#[derive(Debug)]
pub(super) struct NativeSpanDraft {
    trace_id: Vec<u8>,
    span_id: Vec<u8>,
    parent_span_id: Vec<u8>,
    name: String,
    start_time_unix_nano: u64,
    end_time_unix_nano: u64,
    attributes: Vec<NativePolicyAttribute>,
    kind: i32,
    flags: u32,
    details: NativeSpanDetailDraft,
    has_entity_refs: bool,
    estimated_bytes: u64,
}

#[derive(Debug)]
struct NativeSpanDetailDraft {
    trace_state: String,
    flags: u32,
    status: Option<Status>,
    events: Vec<Event>,
    links: Vec<Link>,
    dropped_attributes_count: u32,
    dropped_events_count: u32,
    dropped_links_count: u32,
    metadata: SpanDetailMetadata,
}

#[derive(Clone, Debug)]
struct SpanDetailMetadata {
    resource_dropped_attributes_count: u32,
    resource_schema_url: String,
    scope_name: String,
    scope_version: String,
    scope_dropped_attributes_count: u32,
    scope_schema_url: String,
    has_entity_refs: bool,
}
