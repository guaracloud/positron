use positron_domain::value::ValueLimitProfile;

use super::labels::{LabelSummary, validate_label_set};
use crate::ReceiveFailure;
use crate::otlp_logs::preflight::Cursor;
use crate::otlp_logs::preflight::limits::{StructuralLimits, increment};

pub(crate) fn validate_protobuf(
    protobuf: &[u8],
    profile: ValueLimitProfile,
) -> Result<(), ReceiveFailure> {
    let system = profile.system_limits();
    let mut scanner = Scanner {
        limits: StructuralLimits::from_profile(profile)?,
        body_bytes: usize::try_from(system.record().log_body_bytes().value())
            .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
        record_bytes: usize::try_from(system.record().decoded_bytes().value())
            .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
        streams: 0,
        records: 0,
        attributes: 0,
    };
    scanner.request(protobuf)
}

#[derive(Clone, Copy, Default)]
struct EntrySummary {
    bytes: usize,
    attributes: usize,
}

struct Scanner {
    limits: StructuralLimits,
    body_bytes: usize,
    record_bytes: usize,
    streams: usize,
    records: usize,
    attributes: usize,
}

impl Scanner {
    fn request(&mut self, message: &[u8]) -> Result<(), ReceiveFailure> {
        let mut cursor = Cursor::new(message);
        let mut format = false;
        while !cursor.is_empty() {
            let (field, wire) = cursor.take_key()?;
            match field {
                1 => {
                    require_wire(wire, 2)?;
                    increment(&mut self.streams, self.limits.containers)?;
                    self.stream(cursor.take_length_delimited()?)?;
                },
                2 => {
                    require_wire(wire, 2)?;
                    if format {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                    format = true;
                    let value = cursor.take_length_delimited()?;
                    bounded_utf8(value, self.limits.value_bytes)?;
                },
                _ => cursor.skip_value(field, wire)?,
            }
        }
        Ok(())
    }

    fn stream(&mut self, message: &[u8]) -> Result<(), ReceiveFailure> {
        let mut cursor = Cursor::new(message);
        let mut labels = None;
        let mut entries = Vec::new();
        while !cursor.is_empty() {
            let (field, wire) = cursor.take_key()?;
            match field {
                1 => {
                    require_wire(wire, 2)?;
                    if labels.is_some() {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                    let source = bounded_utf8(cursor.take_length_delimited()?, self.record_bytes)?;
                    labels = Some(validate_label_set(
                        source,
                        self.limits.attribute_entries,
                        self.limits.key_bytes,
                        self.limits.value_bytes,
                    )?);
                },
                2 => {
                    require_wire(wire, 2)?;
                    increment(&mut self.records, self.limits.records)?;
                    entries
                        .try_reserve(1)
                        .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
                    entries.push(self.entry(cursor.take_length_delimited()?)?);
                },
                3 => {
                    require_wire(wire, 0)?;
                    cursor.take_varint()?;
                },
                _ => cursor.skip_value(field, wire)?,
            }
        }
        let LabelSummary { count, bytes } = labels.ok_or(ReceiveFailure::MalformedPayload)?;
        for entry in entries {
            self.attributes = self
                .attributes
                .checked_add(count)
                .and_then(|total| total.checked_add(entry.attributes))
                .filter(|total| *total <= self.limits.attributes)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            bytes
                .checked_add(entry.bytes)
                .filter(|total| *total <= self.record_bytes)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
        }
        Ok(())
    }

    fn entry(&self, message: &[u8]) -> Result<EntrySummary, ReceiveFailure> {
        let mut cursor = Cursor::new(message);
        let mut summary = EntrySummary::default();
        let mut timestamp = false;
        let mut line = false;
        while !cursor.is_empty() {
            let (field, wire) = cursor.take_key()?;
            match field {
                1 => {
                    require_wire(wire, 2)?;
                    if timestamp {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                    timestamp = true;
                    validate_timestamp(cursor.take_length_delimited()?)?;
                },
                2 => {
                    require_wire(wire, 2)?;
                    if line {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                    line = true;
                    let value = cursor.take_length_delimited()?;
                    bounded_utf8(value, self.body_bytes)?;
                    summary.bytes = value.len();
                },
                3 | 4 => {
                    require_wire(wire, 2)?;
                    let pair = pair(cursor.take_length_delimited()?, &self.limits)?;
                    increment(&mut summary.attributes, self.limits.attribute_entries)?;
                    summary.bytes = summary
                        .bytes
                        .checked_add(pair)
                        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                },
                _ => cursor.skip_value(field, wire)?,
            }
        }
        if !timestamp {
            return Err(ReceiveFailure::MalformedPayload);
        }
        Ok(summary)
    }
}

fn pair(message: &[u8], limits: &StructuralLimits) -> Result<usize, ReceiveFailure> {
    let mut cursor = Cursor::new(message);
    let mut name = None;
    let mut value = None;
    while !cursor.is_empty() {
        let (field, wire) = cursor.take_key()?;
        match field {
            1 => set_string(&mut cursor, wire, &mut name, limits.key_bytes)?,
            2 => set_string(&mut cursor, wire, &mut value, limits.value_bytes)?,
            _ => cursor.skip_value(field, wire)?,
        }
    }
    name.unwrap_or(0)
        .checked_add(value.unwrap_or(0))
        .ok_or(ReceiveFailure::ValueLimitExceeded)
}

fn set_string(
    cursor: &mut Cursor<'_>,
    wire: u8,
    slot: &mut Option<usize>,
    limit: usize,
) -> Result<(), ReceiveFailure> {
    require_wire(wire, 2)?;
    if slot.is_some() {
        return Err(ReceiveFailure::MalformedPayload);
    }
    let value = cursor.take_length_delimited()?;
    bounded_utf8(value, limit)?;
    *slot = Some(value.len());
    Ok(())
}

fn validate_timestamp(message: &[u8]) -> Result<(), ReceiveFailure> {
    let mut cursor = Cursor::new(message);
    let mut fields = [false; 2];
    while !cursor.is_empty() {
        let (field, wire) = cursor.take_key()?;
        match field {
            1 | 2 => {
                require_wire(wire, 0)?;
                let index =
                    usize::try_from(field - 1).map_err(|_| ReceiveFailure::MalformedPayload)?;
                let seen = fields
                    .get_mut(index)
                    .ok_or(ReceiveFailure::MalformedPayload)?;
                if *seen {
                    return Err(ReceiveFailure::MalformedPayload);
                }
                *seen = true;
                cursor.take_varint()?;
            },
            _ => cursor.skip_value(field, wire)?,
        }
    }
    Ok(())
}

fn bounded_utf8(bytes: &[u8], limit: usize) -> Result<&str, ReceiveFailure> {
    if bytes.len() > limit {
        return Err(ReceiveFailure::ValueLimitExceeded);
    }
    std::str::from_utf8(bytes).map_err(|_| ReceiveFailure::MalformedPayload)
}

fn require_wire(actual: u8, expected: u8) -> Result<(), ReceiveFailure> {
    if actual == expected {
        Ok(())
    } else {
        Err(ReceiveFailure::MalformedPayload)
    }
}
