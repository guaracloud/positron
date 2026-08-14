use positron_domain::value::ValueLimitProfile;

mod cursor;

use super::limits::{StructuralLimits, increment};
use crate::ReceiveFailure;
use cursor::Cursor;

pub(in crate::otlp_logs) fn validate_json(
    json: &[u8],
    profile: ValueLimitProfile,
) -> Result<(), ReceiveFailure> {
    let limits = StructuralLimits::from_profile(profile)?;
    let mut validator = Validator {
        cursor: Cursor::new(json),
        limits,
        resource_logs: 0,
        scope_logs: 0,
        records: 0,
        attributes: 0,
    };
    validator.request()?;
    validator.cursor.finish()
}

struct Validator<'json> {
    cursor: Cursor<'json>,
    limits: StructuralLimits,
    resource_logs: usize,
    scope_logs: usize,
    records: usize,
    attributes: usize,
}

impl Validator<'_> {
    fn request(&mut self) -> Result<(), ReceiveFailure> {
        self.cursor.object_start()?;
        while let Some(field) = self.cursor.field()? {
            if field.is("resourceLogs") {
                self.resource_logs()?;
            } else {
                self.cursor.skip_value(0, self.limits.nesting_depth)?;
            }
        }
        Ok(())
    }

    fn resource_logs(&mut self) -> Result<(), ReceiveFailure> {
        self.cursor.array_start()?;
        while self.cursor.element()? {
            increment(&mut self.resource_logs, self.limits.containers)?;
            self.cursor.object_start()?;
            while let Some(field) = self.cursor.field()? {
                if field.is("resource") {
                    self.attributes_object()?;
                } else if field.is("scopeLogs") {
                    self.scope_logs()?;
                } else {
                    self.cursor.skip_value(0, self.limits.nesting_depth)?;
                }
            }
        }
        Ok(())
    }

    fn scope_logs(&mut self) -> Result<(), ReceiveFailure> {
        self.cursor.array_start()?;
        while self.cursor.element()? {
            increment(&mut self.scope_logs, self.limits.containers)?;
            self.cursor.object_start()?;
            while let Some(field) = self.cursor.field()? {
                if field.is("scope") {
                    self.attributes_object()?;
                } else if field.is("logRecords") {
                    self.log_records()?;
                } else {
                    self.cursor.skip_value(0, self.limits.nesting_depth)?;
                }
            }
        }
        Ok(())
    }

    fn log_records(&mut self) -> Result<(), ReceiveFailure> {
        self.cursor.array_start()?;
        while self.cursor.element()? {
            increment(&mut self.records, self.limits.records)?;
            self.cursor.object_start()?;
            while let Some(field) = self.cursor.field()? {
                if field.is("attributes") {
                    self.attributes()?;
                } else if field.is("body") {
                    self.any_value(0)?;
                } else if field.is("severityText") || field.is("eventName") {
                    self.bounded_string(self.limits.value_bytes)?;
                } else {
                    self.cursor.skip_value(0, self.limits.nesting_depth)?;
                }
            }
        }
        Ok(())
    }

    fn attributes_object(&mut self) -> Result<(), ReceiveFailure> {
        if self.cursor.take_null()? {
            return Ok(());
        }
        self.cursor.object_start()?;
        while let Some(field) = self.cursor.field()? {
            if field.is("attributes") {
                self.attributes()?;
            } else {
                self.cursor.skip_value(0, self.limits.nesting_depth)?;
            }
        }
        Ok(())
    }

    fn attributes(&mut self) -> Result<(), ReceiveFailure> {
        self.cursor.array_start()?;
        let mut entries = 0;
        while self.cursor.element()? {
            increment(&mut entries, self.limits.attribute_entries)?;
            increment(&mut self.attributes, self.limits.attributes)?;
            self.key_value(0)?;
        }
        Ok(())
    }

    fn key_value(&mut self, depth: usize) -> Result<(), ReceiveFailure> {
        self.cursor.object_start()?;
        while let Some(field) = self.cursor.field()? {
            if field.is("key") {
                self.bounded_string(self.limits.key_bytes)?;
            } else if field.is("value") {
                self.any_value(depth)?;
            } else {
                self.cursor.skip_value(depth, self.limits.nesting_depth)?;
            }
        }
        Ok(())
    }

    fn any_value(&mut self, depth: usize) -> Result<(), ReceiveFailure> {
        if self.cursor.take_null()? {
            return Ok(());
        }
        self.cursor.object_start()?;
        while let Some(field) = self.cursor.field()? {
            if field.is("stringValue") {
                self.bounded_string(self.limits.value_bytes)?;
            } else if field.is("bytesValue") {
                let value = self.cursor.string()?;
                if value.base64_decoded_len()? > self.limits.value_bytes {
                    return Err(ReceiveFailure::ValueLimitExceeded);
                }
            } else if field.is("arrayValue") {
                self.dynamic_values(depth, false)?;
            } else if field.is("kvlistValue") {
                self.dynamic_values(depth, true)?;
            } else {
                self.cursor.skip_value(depth, self.limits.nesting_depth)?;
            }
        }
        Ok(())
    }

    fn dynamic_values(&mut self, depth: usize, keyed: bool) -> Result<(), ReceiveFailure> {
        let next = depth
            .checked_add(1)
            .filter(|next| *next <= self.limits.nesting_depth)
            .ok_or(ReceiveFailure::ValueLimitExceeded)?;
        self.cursor.object_start()?;
        while let Some(field) = self.cursor.field()? {
            if field.is("values") {
                self.cursor.array_start()?;
                let mut entries = 0;
                while self.cursor.element()? {
                    increment(
                        &mut entries,
                        if keyed {
                            self.limits.key_value_entries
                        } else {
                            self.limits.array_entries
                        },
                    )?;
                    if keyed {
                        self.key_value(next)?;
                    } else {
                        self.any_value(next)?;
                    }
                }
            } else {
                self.cursor.skip_value(next, self.limits.nesting_depth)?;
            }
        }
        Ok(())
    }

    fn bounded_string(&mut self, limit: usize) -> Result<(), ReceiveFailure> {
        if self.cursor.string()?.decoded_len > limit {
            return Err(ReceiveFailure::ValueLimitExceeded);
        }
        Ok(())
    }
}
