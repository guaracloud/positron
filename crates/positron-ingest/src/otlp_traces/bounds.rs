use super::{TraceLimitClass, TraceLimitViolation, TraceReceiveFailure};
use positron_domain::value::ValueLimitProfile;

#[path = "bounds_json.rs"]
mod json;
#[path = "protobuf_wire.rs"]
mod protobuf_wire;
use protobuf_wire::visit_fields;
pub(super) use protobuf_wire::visit_fields_with_wire;

const REQUEST_FIELDS: &[(u64, u8)] = &[(1, 2)];
const RESOURCE_SPANS_FIELDS: &[(u64, u8)] = &[(1, 2), (2, 2), (3, 2)];
const RESOURCE_FIELDS: &[(u64, u8)] = &[(1, 2), (2, 0), (3, 2)];
const ENTITY_REF_FIELDS: &[(u64, u8)] = &[(1, 2), (2, 2), (3, 2), (4, 2)];
const SCOPE_SPANS_FIELDS: &[(u64, u8)] = &[(1, 2), (2, 2), (3, 2)];
const SCOPE_FIELDS: &[(u64, u8)] = &[(1, 2), (2, 2), (3, 2), (4, 0)];
const KEY_VALUE_FIELDS: &[(u64, u8)] = &[(1, 2), (2, 2), (3, 0)];
const ANY_VALUE_FIELDS: &[(u64, u8)] = &[
    (1, 2),
    (2, 0),
    (3, 0),
    (4, 1),
    (5, 2),
    (6, 2),
    (7, 2),
    (8, 0),
];
const ARRAY_FIELDS: &[(u64, u8)] = &[(1, 2)];
const KEY_VALUE_LIST_FIELDS: &[(u64, u8)] = &[(1, 2)];
const SPAN_FIELDS: &[(u64, u8)] = &[
    (1, 2),
    (2, 2),
    (3, 2),
    (4, 2),
    (5, 2),
    (6, 0),
    (7, 1),
    (8, 1),
    (9, 2),
    (10, 0),
    (11, 2),
    (12, 0),
    (13, 2),
    (14, 0),
    (15, 2),
    (16, 5),
];
const STATUS_FIELDS: &[(u64, u8)] = &[(1, 0), (2, 2)];
const EVENT_FIELDS: &[(u64, u8)] = &[(1, 1), (2, 2), (3, 2), (4, 0)];
const LINK_FIELDS: &[(u64, u8)] = &[(1, 2), (2, 2), (3, 2), (4, 2), (5, 0), (6, 5)];

pub(super) fn validate_protobuf(
    protobuf: &[u8],
    profile: ValueLimitProfile,
) -> Result<(), TraceReceiveFailure> {
    Counters {
        limits: Limits::from_profile(profile)?,
        ..Counters::default()
    }
    .visit_request(protobuf)
}

pub(super) fn validate_json(
    json: &[u8],
    profile: ValueLimitProfile,
) -> Result<(), TraceReceiveFailure> {
    json::validate(json, profile)
}

pub(super) fn retained_native_batch_bytes(
    records: &[positron_signals::SpanObservation],
    record_capacity: usize,
) -> Result<u64, TraceReceiveFailure> {
    let native = u64::try_from(record_capacity)
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
        .checked_mul(
            u64::try_from(std::mem::size_of::<positron_signals::SpanObservation>())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
        )
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    records.iter().try_fold(native, |total, record| {
        let heap = u64::try_from(
            record
                .retained_heap_bytes()
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
        )
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        total
            .checked_add(heap)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })
}

pub(super) fn grouped_retained_native_batch_bytes(
    records: &[positron_signals::SpanObservation],
    record_capacity: usize,
) -> Result<u64, TraceReceiveFailure> {
    let source = retained_native_batch_bytes(records, record_capacity)?;
    let record_count = records.len();
    let shard_items = std::mem::size_of::<positron_domain::routing::VirtualShardId>()
        .checked_mul(2)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let per_record = std::mem::size_of::<positron_signals::SpanObservation>()
        .checked_add(std::mem::size_of::<super::NativeSpanAdmissionGroup<'static>>())
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<(
                positron_domain::routing::VirtualShardId,
                Vec<positron_signals::SpanObservation>,
            )>())
        })
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<positron_domain::routing::VirtualShardId>())
        })
        .and_then(|bytes| bytes.checked_add(shard_items))
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<Vec<positron_signals::SpanObservation>>())
        })
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let vector_metadata = std::mem::size_of::<Vec<positron_domain::routing::VirtualShardId>>()
        .checked_add(std::mem::size_of::<
            Vec<positron_domain::routing::VirtualShardId>,
        >())
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<
                Vec<(
                    positron_domain::routing::VirtualShardId,
                    Vec<positron_signals::SpanObservation>,
                )>,
            >())
        })
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<
                Vec<super::NativeSpanAdmissionGroup<'static>>,
            >())
        })
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let planning = record_count
        .checked_mul(per_record)
        .and_then(|bytes| bytes.checked_add(vector_metadata))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    source
        .checked_add(u64::try_from(planning).map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)
}

struct Limits {
    containers: usize,
    records: usize,
    attributes: usize,
    attribute_entries: usize,
    array_entries: usize,
    key_value_entries: usize,
    nesting_depth: usize,
    value_bytes: usize,
    json_bytes_text: usize,
    key_bytes: usize,
    decoded_batch_bytes: usize,
}

impl Limits {
    fn from_profile(profile: ValueLimitProfile) -> Result<Self, TraceReceiveFailure> {
        let system = profile.effective_limits();
        let dynamic = system.dynamic_value();
        let containers = 1_024;
        let records = usize::try_from(system.request().records().value())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let attributes = usize::try_from(system.request().aggregate_attributes().value())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let attribute_entries = usize::try_from(dynamic.attributes_per_namespace().value())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let value_bytes = usize::try_from(dynamic.individual_value_bytes().value())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let json_bytes_text = value_bytes
            .checked_add(2)
            .map(|value| value / 3)
            .and_then(|value| value.checked_mul(4))
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        Ok(Self {
            containers,
            records,
            attributes,
            attribute_entries,
            array_entries: usize::try_from(dynamic.array_entries().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            key_value_entries: usize::try_from(dynamic.key_value_list_entries().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            nesting_depth: usize::from(dynamic.nesting_depth().value()),
            value_bytes,
            json_bytes_text,
            key_bytes: usize::try_from(dynamic.key_path_bytes().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            decoded_batch_bytes: usize::try_from(system.request().decompressed_bytes().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
        })
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            resources: 0,
            scopes: 0,
            records: 0,
            events: 0,
            links: 0,
            attributes: 0,
            entity_refs: 0,
            entity_ref_keys: 0,
            decoded_bytes: 0,
            limits: Limits {
                containers: 1,
                records: 1,
                attributes: 1,
                attribute_entries: 1,
                array_entries: 1,
                key_value_entries: 1,
                nesting_depth: 1,
                value_bytes: 1,
                json_bytes_text: 1,
                key_bytes: 1,
                decoded_batch_bytes: 1,
            },
        }
    }
}

struct Counters {
    resources: usize,
    scopes: usize,
    records: usize,
    events: usize,
    links: usize,
    attributes: usize,
    entity_refs: usize,
    entity_ref_keys: usize,
    decoded_bytes: usize,
    limits: Limits,
}

impl Counters {
    fn visit_request(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        visit_fields(message, REQUEST_FIELDS, |field, value| {
            if field == 1 {
                increment_with_class(
                    &mut self.resources,
                    self.limits.containers,
                    TraceLimitClass::ContainerCount,
                )?;
                self.visit_resource_spans(value)?;
            }
            Ok(())
        })
    }

    fn visit_resource_spans(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        visit_fields(message, RESOURCE_SPANS_FIELDS, |field, value| match field {
            1 => self.visit_resource(value),
            2 => {
                increment_with_class(
                    &mut self.scopes,
                    self.limits.containers,
                    TraceLimitClass::ContainerCount,
                )?;
                self.visit_scope_spans(value)
            },
            3 => self.visit_string(value),
            _ => Ok(()),
        })
    }

    fn visit_resource(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        let mut entries = 0;
        visit_fields(message, RESOURCE_FIELDS, |field, value| {
            if field == 1 {
                increment_with_class(
                    &mut entries,
                    self.limits.attribute_entries,
                    TraceLimitClass::AttributesPerNamespace,
                )?;
                self.visit_attribute(value, 0)?;
            } else if field == 3 {
                increment_with_class(
                    &mut self.entity_refs,
                    self.limits.containers,
                    TraceLimitClass::ContainerCount,
                )?;
                self.visit_entity_ref(value)?;
            }
            Ok(())
        })
    }

    fn visit_entity_ref(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        visit_fields(message, ENTITY_REF_FIELDS, |field, value| {
            if field == 1 || field == 2 {
                self.visit_string(value)?;
            } else if field == 3 || field == 4 {
                increment_with_class(
                    &mut self.entity_ref_keys,
                    self.limits.containers,
                    TraceLimitClass::ContainerCount,
                )?;
                self.visit_string(value)?;
            }
            Ok(())
        })
    }

    fn visit_scope_spans(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        visit_fields(message, SCOPE_SPANS_FIELDS, |field, value| match field {
            1 => self.visit_scope(value),
            2 => {
                increment_with_class(
                    &mut self.records,
                    self.limits.records,
                    TraceLimitClass::RecordCount,
                )?;
                self.visit_span(value)
            },
            3 => self.visit_string(value),
            _ => Ok(()),
        })
    }

    fn visit_scope(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        let mut entries = 0;
        visit_fields(message, SCOPE_FIELDS, |field, value| {
            if field == 1 || field == 2 {
                self.visit_string(value)?;
            } else if field == 3 {
                increment_with_class(
                    &mut entries,
                    self.limits.attribute_entries,
                    TraceLimitClass::AttributesPerNamespace,
                )?;
                self.visit_attribute(value, 0)?;
            }
            Ok(())
        })
    }

    fn visit_span(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        let mut entries = 0;
        visit_fields(message, SPAN_FIELDS, |field, value| match field {
            3 => self.visit_string(value),
            5 => self.visit_string(value),
            9 => {
                increment_with_class(
                    &mut entries,
                    self.limits.attribute_entries,
                    TraceLimitClass::AttributesPerNamespace,
                )?;
                self.visit_attribute(value, 0)
            },
            11 => {
                increment_with_class(
                    &mut self.events,
                    self.limits.containers,
                    TraceLimitClass::ContainerCount,
                )?;
                self.visit_event(value)
            },
            13 => {
                increment_with_class(
                    &mut self.links,
                    self.limits.containers,
                    TraceLimitClass::ContainerCount,
                )?;
                self.visit_link(value)
            },
            15 => self.visit_status(value),
            _ => Ok(()),
        })
    }

    fn visit_status(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        visit_fields(message, STATUS_FIELDS, |field, value| {
            if field == 2 {
                self.visit_string(value)?;
            }
            Ok(())
        })
    }

    fn visit_event(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        let mut entries = 0;
        visit_fields(message, EVENT_FIELDS, |field, value| {
            if field == 2 {
                self.visit_string(value)?;
            } else if field == 3 {
                increment_with_class(
                    &mut entries,
                    self.limits.attribute_entries,
                    TraceLimitClass::AttributesPerNamespace,
                )?;
                self.visit_attribute(value, 0)?;
            }
            Ok(())
        })
    }

    fn visit_link(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        let mut entries = 0;
        visit_fields(message, LINK_FIELDS, |field, value| {
            if field == 3 {
                self.visit_string(value)?;
            } else if field == 4 {
                increment_with_class(
                    &mut entries,
                    self.limits.attribute_entries,
                    TraceLimitClass::AttributesPerNamespace,
                )?;
                self.visit_attribute(value, 0)?;
            }
            Ok(())
        })
    }

    fn visit_attribute(&mut self, message: &[u8], depth: usize) -> Result<(), TraceReceiveFailure> {
        increment_with_class(
            &mut self.attributes,
            self.limits.attributes,
            TraceLimitClass::AggregateAttributeCount,
        )?;
        visit_fields(message, KEY_VALUE_FIELDS, |field, value| {
            if field == 1 {
                self.visit_string(value)?;
            } else if field == 2 {
                self.visit_any_value(value, depth)?;
            }
            Ok(())
        })
    }

    fn visit_any_value(&mut self, message: &[u8], depth: usize) -> Result<(), TraceReceiveFailure> {
        visit_fields(message, ANY_VALUE_FIELDS, |field, value| match field {
            1 => self.visit_value_string(value),
            7 => self.visit_bytes(value),
            5 => self.visit_array(value, depth),
            6 => self.visit_key_value_list(value, depth),
            _ => Ok(()),
        })
    }

    fn visit_array(&mut self, message: &[u8], depth: usize) -> Result<(), TraceReceiveFailure> {
        let next = depth
            .checked_add(1)
            .filter(|next| *next <= self.limits.nesting_depth)
            .ok_or_else(|| {
                limit_failure(
                    TraceLimitClass::NestingDepth,
                    depth.saturating_add(1),
                    self.limits.nesting_depth,
                )
            })?;
        let mut entries = 0;
        visit_fields(message, ARRAY_FIELDS, |field, value| {
            if field == 1 {
                increment_with_class(
                    &mut entries,
                    self.limits.array_entries,
                    TraceLimitClass::ArrayEntries,
                )?;
                self.visit_any_value(value, next)?;
            }
            Ok(())
        })
    }

    fn visit_key_value_list(
        &mut self,
        message: &[u8],
        depth: usize,
    ) -> Result<(), TraceReceiveFailure> {
        let next = depth
            .checked_add(1)
            .filter(|next| *next <= self.limits.nesting_depth)
            .ok_or_else(|| {
                limit_failure(
                    TraceLimitClass::NestingDepth,
                    depth.saturating_add(1),
                    self.limits.nesting_depth,
                )
            })?;
        let mut entries = 0;
        visit_fields(message, KEY_VALUE_LIST_FIELDS, |field, value| {
            if field == 1 {
                increment_with_class(
                    &mut entries,
                    self.limits.key_value_entries,
                    TraceLimitClass::KeyValueListEntries,
                )?;
                self.visit_attribute(value, next)?;
            }
            Ok(())
        })
    }

    fn visit_string(&mut self, value: &[u8]) -> Result<(), TraceReceiveFailure> {
        let length = value.len();
        if length > self.limits.key_bytes {
            return Err(limit_failure(
                TraceLimitClass::KeyPathBytes,
                length,
                self.limits.key_bytes,
            ));
        }
        self.add_decoded(length)
    }

    fn visit_value_string(&mut self, value: &[u8]) -> Result<(), TraceReceiveFailure> {
        if value.len() > self.limits.value_bytes {
            return Err(limit_failure(
                TraceLimitClass::IndividualValueBytes,
                value.len(),
                self.limits.value_bytes,
            ));
        }
        self.add_decoded(value.len())
    }

    fn visit_bytes(&mut self, value: &[u8]) -> Result<(), TraceReceiveFailure> {
        if value.len() > self.limits.value_bytes {
            return Err(limit_failure(
                TraceLimitClass::IndividualValueBytes,
                value.len(),
                self.limits.value_bytes,
            ));
        }
        self.add_decoded(value.len())
    }

    fn add_decoded(&mut self, bytes: usize) -> Result<(), TraceReceiveFailure> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(bytes)
            .filter(|value| *value <= self.limits.decoded_batch_bytes)
            .ok_or_else(|| {
                let actual = self.decoded_bytes.saturating_add(bytes);
                limit_failure(
                    TraceLimitClass::DecodedBatchBytes,
                    actual,
                    self.limits.decoded_batch_bytes,
                )
            })?;
        Ok(())
    }
}

fn increment_with_class(
    value: &mut usize,
    limit: usize,
    class: TraceLimitClass,
) -> Result<(), TraceReceiveFailure> {
    let next = value
        .checked_add(1)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    if next > limit {
        return Err(limit_failure(class, next, limit));
    }
    *value = next;
    Ok(())
}

fn limit_failure(class: TraceLimitClass, actual: usize, allowed: usize) -> TraceReceiveFailure {
    match (u64::try_from(actual), u64::try_from(allowed)) {
        (Ok(actual), Ok(allowed)) => TraceReceiveFailure::ValueLimitExceededWithDetail(
            TraceLimitViolation::new(class, actual, allowed),
        ),
        _ => TraceReceiveFailure::ValueLimitExceeded,
    }
}
