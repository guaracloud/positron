use super::TraceReceiveFailure;
use positron_domain::value::ValueLimitProfile;

#[path = "bounds_json.rs"]
mod json;

const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;
const MAX_GROUP_DEPTH: usize = 64;

const REQUEST_FIELDS: &[(u64, u8)] = &[(1, 2)];
const RESOURCE_SPANS_FIELDS: &[(u64, u8)] = &[(1, 2), (2, 2), (3, 2)];
const RESOURCE_FIELDS: &[(u64, u8)] = &[(1, 2), (2, 0), (3, 2)];
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
) -> Result<u64, TraceReceiveFailure> {
    records.iter().try_fold(0_u64, |total, record| {
        let native = u64::try_from(std::mem::size_of::<positron_signals::SpanObservation>())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let heap = u64::try_from(
            record
                .retained_heap_bytes()
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
        )
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        total
            .checked_add(native)
            .and_then(|size| size.checked_add(heap))
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })
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
    decoded_bytes: usize,
    limits: Limits,
}

impl Counters {
    fn visit_request(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        visit_fields(message, REQUEST_FIELDS, |field, value| {
            if field == 1 {
                increment(&mut self.resources, self.limits.containers)?;
                self.visit_resource_spans(value)?;
            }
            Ok(())
        })
    }

    fn visit_resource_spans(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        visit_fields(message, RESOURCE_SPANS_FIELDS, |field, value| match field {
            1 => self.visit_resource(value),
            2 => {
                increment(&mut self.scopes, self.limits.containers)?;
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
                increment(&mut entries, self.limits.attribute_entries)?;
                self.visit_attribute(value, 0)?;
            }
            Ok(())
        })
    }

    fn visit_scope_spans(&mut self, message: &[u8]) -> Result<(), TraceReceiveFailure> {
        visit_fields(message, SCOPE_SPANS_FIELDS, |field, value| match field {
            1 => self.visit_scope(value),
            2 => {
                increment(&mut self.records, self.limits.records)?;
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
                increment(&mut entries, self.limits.attribute_entries)?;
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
                increment(&mut entries, self.limits.attribute_entries)?;
                self.visit_attribute(value, 0)
            },
            11 => {
                increment(&mut self.events, self.limits.containers)?;
                self.visit_event(value)
            },
            13 => {
                increment(&mut self.links, self.limits.containers)?;
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
                increment(&mut entries, self.limits.attribute_entries)?;
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
                increment(&mut entries, self.limits.attribute_entries)?;
                self.visit_attribute(value, 0)?;
            }
            Ok(())
        })
    }

    fn visit_attribute(&mut self, message: &[u8], depth: usize) -> Result<(), TraceReceiveFailure> {
        increment(&mut self.attributes, self.limits.attributes)?;
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
            1 => self.visit_string(value),
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
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        let mut entries = 0;
        visit_fields(message, ARRAY_FIELDS, |field, value| {
            if field == 1 {
                increment(&mut entries, self.limits.array_entries)?;
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
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        let mut entries = 0;
        visit_fields(message, KEY_VALUE_LIST_FIELDS, |field, value| {
            if field == 1 {
                increment(&mut entries, self.limits.key_value_entries)?;
                self.visit_attribute(value, next)?;
            }
            Ok(())
        })
    }

    fn visit_string(&mut self, value: &[u8]) -> Result<(), TraceReceiveFailure> {
        let length = value.len();
        if length > self.limits.key_bytes {
            return Err(TraceReceiveFailure::ValueLimitExceeded);
        }
        self.add_decoded(length)
    }

    fn visit_bytes(&mut self, value: &[u8]) -> Result<(), TraceReceiveFailure> {
        if value.len() > self.limits.value_bytes {
            return Err(TraceReceiveFailure::ValueLimitExceeded);
        }
        self.add_decoded(value.len())
    }

    fn add_decoded(&mut self, bytes: usize) -> Result<(), TraceReceiveFailure> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(bytes)
            .filter(|value| *value <= self.limits.decoded_batch_bytes)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        Ok(())
    }
}

fn increment(value: &mut usize, limit: usize) -> Result<(), TraceReceiveFailure> {
    *value = value
        .checked_add(1)
        .filter(|value| *value <= limit)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    Ok(())
}

fn visit_fields(
    message: &[u8],
    known_fields: &[(u64, u8)],
    mut visit: impl FnMut(u64, &[u8]) -> Result<(), TraceReceiveFailure>,
) -> Result<(), TraceReceiveFailure> {
    let mut cursor = Cursor::new(message);
    while !cursor.is_empty() {
        let (field, wire) = cursor.take_key()?;
        if known_fields
            .iter()
            .find(|(known_field, _)| *known_field == field)
            .is_some_and(|(_, expected_wire)| *expected_wire != wire)
        {
            return Err(TraceReceiveFailure::MalformedPayload);
        }
        if wire == 2 {
            visit(field, cursor.take_length_delimited()?)?;
        } else {
            cursor.skip_value(field, wire)?;
        }
    }
    Ok(())
}

struct Cursor<'message> {
    remaining: &'message [u8],
}

impl<'message> Cursor<'message> {
    const fn new(message: &'message [u8]) -> Self {
        Self { remaining: message }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take_key(&mut self) -> Result<(u64, u8), TraceReceiveFailure> {
        let key = self.take_varint()?;
        let field = key >> 3;
        let wire = (key & 7) as u8;
        if field == 0 || field > MAX_FIELD_NUMBER || wire > 5 {
            return Err(TraceReceiveFailure::MalformedPayload);
        }
        Ok((field, wire))
    }

    fn take_varint(&mut self) -> Result<u64, TraceReceiveFailure> {
        let mut value = 0_u64;
        for index in 0..10 {
            let (byte, remaining) = self
                .remaining
                .split_first()
                .ok_or(TraceReceiveFailure::MalformedPayload)?;
            self.remaining = remaining;
            if index == 9 && *byte > 1 {
                return Err(TraceReceiveFailure::MalformedPayload);
            }
            value |= u64::from(*byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(TraceReceiveFailure::MalformedPayload)
    }

    fn take_length_delimited(&mut self) -> Result<&'message [u8], TraceReceiveFailure> {
        let length = usize::try_from(self.take_varint()?)
            .map_err(|_| TraceReceiveFailure::MalformedPayload)?;
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(TraceReceiveFailure::MalformedPayload)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn skip_value(&mut self, field: u64, wire: u8) -> Result<(), TraceReceiveFailure> {
        match wire {
            0 => self.take_varint().map(|_| ()),
            1 => self.skip_bytes(8),
            2 => self.take_length_delimited().map(|_| ()),
            3 => self.skip_group(field),
            4 => Err(TraceReceiveFailure::MalformedPayload),
            5 => self.skip_bytes(4),
            _ => Err(TraceReceiveFailure::MalformedPayload),
        }
    }

    fn skip_group(&mut self, first_field: u64) -> Result<(), TraceReceiveFailure> {
        let mut groups = [first_field; MAX_GROUP_DEPTH];
        let mut depth = 1;
        while depth > 0 {
            let (field, wire) = self.take_key()?;
            match wire {
                3 => {
                    if depth == MAX_GROUP_DEPTH {
                        return Err(TraceReceiveFailure::MalformedPayload);
                    }
                    if let Some(slot) = groups.get_mut(depth) {
                        *slot = field;
                        depth += 1;
                    }
                },
                4 => {
                    if groups.get(depth - 1).copied() != Some(field) {
                        return Err(TraceReceiveFailure::MalformedPayload);
                    }
                    depth -= 1;
                },
                _ => self.skip_value(field, wire)?,
            }
        }
        Ok(())
    }

    fn skip_bytes(&mut self, count: usize) -> Result<(), TraceReceiveFailure> {
        self.remaining = self
            .remaining
            .split_at_checked(count)
            .ok_or(TraceReceiveFailure::MalformedPayload)?
            .1;
        Ok(())
    }
}
