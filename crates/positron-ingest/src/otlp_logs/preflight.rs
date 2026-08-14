use super::ReceiveFailure;
use positron_domain::value::ValueLimitProfile;

pub(crate) mod json;
pub(crate) mod limits;

pub(super) use json::validate_json;
use limits::{StructuralLimits, increment};

const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;
const MAX_GROUP_DEPTH: usize = 64;

pub(super) fn validate_record_count(
    protobuf: &[u8],
    profile: ValueLimitProfile,
) -> Result<(), ReceiveFailure> {
    Counters {
        limits: StructuralLimits::from_profile(profile)?,
        ..Counters::default()
    }
    .visit_request(protobuf)
}

struct Counters {
    resource_logs: usize,
    scope_logs: usize,
    records: usize,
    attributes: usize,
    limits: StructuralLimits,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            resource_logs: 0,
            scope_logs: 0,
            records: 0,
            attributes: 0,
            limits: StructuralLimits {
                containers: 1,
                records: 1,
                attributes: 1,
                attribute_entries: 1,
                array_entries: 1,
                key_value_entries: 1,
                nesting_depth: 1,
                value_bytes: 1,
                key_bytes: 1,
            },
        }
    }
}

impl Counters {
    fn visit_request(&mut self, message: &[u8]) -> Result<(), ReceiveFailure> {
        visit_fields(message, |field, value| {
            if field == 1 {
                increment(&mut self.resource_logs, self.limits.containers)?;
                self.visit_resource_logs(value)?;
            }
            Ok(())
        })
    }

    fn visit_resource_logs(&mut self, message: &[u8]) -> Result<(), ReceiveFailure> {
        visit_fields(message, |field, value| match field {
            1 => self.visit_resource(value),
            2 => {
                increment(&mut self.scope_logs, self.limits.containers)?;
                self.visit_scope_logs(value)
            },
            _ => Ok(()),
        })
    }

    fn visit_resource(&mut self, message: &[u8]) -> Result<(), ReceiveFailure> {
        let mut entries = 0;
        visit_fields(message, |field, value| {
            if field == 1 {
                increment(&mut entries, self.limits.attribute_entries)?;
                self.visit_attribute(value, 0)?;
            }
            Ok(())
        })
    }

    fn visit_scope_logs(&mut self, message: &[u8]) -> Result<(), ReceiveFailure> {
        visit_fields(message, |field, value| match field {
            1 => self.visit_scope(value),
            2 => {
                increment(&mut self.records, self.limits.records)?;
                self.visit_log_record(value)
            },
            _ => Ok(()),
        })
    }

    fn visit_scope(&mut self, message: &[u8]) -> Result<(), ReceiveFailure> {
        let mut entries = 0;
        visit_fields(message, |field, value| {
            if field == 3 {
                increment(&mut entries, self.limits.attribute_entries)?;
                self.visit_attribute(value, 0)?;
            }
            Ok(())
        })
    }

    fn visit_log_record(&mut self, message: &[u8]) -> Result<(), ReceiveFailure> {
        let mut entries = 0;
        visit_fields(message, |field, value| match field {
            5 => self.visit_any_value(value, 0),
            6 => {
                increment(&mut entries, self.limits.attribute_entries)?;
                self.visit_attribute(value, 0)
            },
            _ => Ok(()),
        })
    }

    fn visit_attribute(&mut self, message: &[u8], depth: usize) -> Result<(), ReceiveFailure> {
        increment(&mut self.attributes, self.limits.attributes)?;
        self.visit_key_value(message, depth)
    }

    fn visit_key_value(&mut self, message: &[u8], depth: usize) -> Result<(), ReceiveFailure> {
        visit_fields(message, |field, value| {
            if field == 2 {
                self.visit_any_value(value, depth)?;
            }
            Ok(())
        })
    }

    fn visit_any_value(&mut self, message: &[u8], depth: usize) -> Result<(), ReceiveFailure> {
        visit_fields(message, |field, value| match field {
            5 => self.visit_array(value, depth),
            6 => self.visit_key_value_list(value, depth),
            _ => Ok(()),
        })
    }

    fn visit_array(&mut self, message: &[u8], depth: usize) -> Result<(), ReceiveFailure> {
        let next = self.next_depth(depth)?;
        let mut entries = 0_usize;
        visit_fields(message, |field, value| {
            if field == 1 {
                increment(&mut entries, self.limits.array_entries)?;
                self.visit_any_value(value, next)?;
            }
            Ok(())
        })
    }

    fn visit_key_value_list(&mut self, message: &[u8], depth: usize) -> Result<(), ReceiveFailure> {
        let next = self.next_depth(depth)?;
        let mut entries = 0_usize;
        visit_fields(message, |field, value| {
            if field == 1 {
                increment(&mut entries, self.limits.key_value_entries)?;
                self.visit_key_value(value, next)?;
            }
            Ok(())
        })
    }
    fn next_depth(&self, depth: usize) -> Result<usize, ReceiveFailure> {
        depth
            .checked_add(1)
            .filter(|next| *next <= self.limits.nesting_depth)
            .ok_or(ReceiveFailure::ValueLimitExceeded)
    }
}

fn visit_fields(
    message: &[u8],
    mut visit: impl FnMut(u64, &[u8]) -> Result<(), ReceiveFailure>,
) -> Result<(), ReceiveFailure> {
    let mut cursor = Cursor::new(message);
    while !cursor.is_empty() {
        let (field, wire) = cursor.take_key()?;
        if wire == 2 {
            visit(field, cursor.take_length_delimited()?)?;
        } else {
            cursor.skip_value(field, wire)?;
        }
    }
    Ok(())
}

pub(crate) struct Cursor<'message> {
    remaining: &'message [u8],
}

impl<'message> Cursor<'message> {
    pub(crate) const fn new(message: &'message [u8]) -> Self {
        Self { remaining: message }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    pub(crate) fn take_key(&mut self) -> Result<(u64, u8), ReceiveFailure> {
        let key = self.take_varint()?;
        let field = key >> 3;
        let wire = (key & 7) as u8;
        if field == 0 || field > MAX_FIELD_NUMBER || wire > 5 {
            return Err(ReceiveFailure::MalformedPayload);
        }
        Ok((field, wire))
    }

    pub(crate) fn take_varint(&mut self) -> Result<u64, ReceiveFailure> {
        let mut value = 0_u64;
        for index in 0..10 {
            let (byte, remaining) = self
                .remaining
                .split_first()
                .ok_or(ReceiveFailure::MalformedPayload)?;
            self.remaining = remaining;
            if index == 9 && *byte > 1 {
                return Err(ReceiveFailure::MalformedPayload);
            }
            value |= u64::from(*byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                if index > 0 && value < (1_u64 << (index * 7)) {
                    return Err(ReceiveFailure::MalformedPayload);
                }
                return Ok(value);
            }
        }
        Err(ReceiveFailure::MalformedPayload)
    }

    pub(crate) fn take_length_delimited(&mut self) -> Result<&'message [u8], ReceiveFailure> {
        let length =
            usize::try_from(self.take_varint()?).map_err(|_| ReceiveFailure::MalformedPayload)?;
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(ReceiveFailure::MalformedPayload)?;
        self.remaining = remaining;
        Ok(value)
    }

    pub(crate) fn skip_value(&mut self, field: u64, wire: u8) -> Result<(), ReceiveFailure> {
        match wire {
            0 => self.take_varint().map(|_| ()),
            1 => self.skip_bytes(8),
            2 => self.take_length_delimited().map(|_| ()),
            3 => self.skip_group(field),
            4 => Err(ReceiveFailure::MalformedPayload),
            5 => self.skip_bytes(4),
            _ => Err(ReceiveFailure::MalformedPayload),
        }
    }

    fn skip_group(&mut self, first_field: u64) -> Result<(), ReceiveFailure> {
        let mut groups = [0_u64; MAX_GROUP_DEPTH];
        groups[0] = first_field;
        let mut depth = 1_usize;
        while depth > 0 {
            let (field, wire) = self.take_key()?;
            match wire {
                3 => {
                    if depth == MAX_GROUP_DEPTH {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                    groups[depth] = field;
                    depth += 1;
                },
                4 => {
                    if groups.get(depth - 1).copied() != Some(field) {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                    depth -= 1;
                },
                _ => self.skip_value(field, wire)?,
            }
        }
        Ok(())
    }

    fn skip_bytes(&mut self, length: usize) -> Result<(), ReceiveFailure> {
        let (_, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(ReceiveFailure::MalformedPayload)?;
        self.remaining = remaining;
        Ok(())
    }
}

#[cfg(test)]
#[path = "preflight/tests/mod.rs"]
mod tests;
