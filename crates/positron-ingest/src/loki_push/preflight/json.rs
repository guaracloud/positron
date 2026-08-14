use positron_domain::value::ValueLimitProfile;

use crate::ReceiveFailure;
use crate::otlp_logs::preflight::json::cursor::{Cursor, StringToken};
use crate::otlp_logs::preflight::limits::{StructuralLimits, increment};

pub(crate) fn validate_json(json: &[u8], profile: ValueLimitProfile) -> Result<(), ReceiveFailure> {
    let system = profile.system_limits();
    let record_bytes = usize::try_from(system.record().decoded_bytes().value())
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let body_bytes = usize::try_from(system.record().log_body_bytes().value())
        .map_err(|_| ReceiveFailure::ValueLimitExceeded)?;
    let mut validator = Validator {
        cursor: Cursor::new(json),
        limits: StructuralLimits::from_profile(profile)?,
        record_bytes,
        body_bytes,
        streams: 0,
        records: 0,
        attributes: 0,
    };
    validator.request()?;
    validator.cursor.finish()
}

struct RecordSize {
    bytes: usize,
    attributes: usize,
}

struct Validator<'a> {
    cursor: Cursor<'a>,
    limits: StructuralLimits,
    record_bytes: usize,
    body_bytes: usize,
    streams: usize,
    records: usize,
    attributes: usize,
}

impl Validator<'_> {
    fn request(&mut self) -> Result<(), ReceiveFailure> {
        self.cursor.object_start()?;
        let mut found = false;
        while let Some(field) = self.cursor.field()? {
            if field.is("streams") {
                if found {
                    return Err(ReceiveFailure::MalformedPayload);
                }
                found = true;
                self.streams()?;
            } else {
                self.cursor.skip_value(0, self.limits.nesting_depth)?;
            }
        }
        if !found {
            return Err(ReceiveFailure::MalformedPayload);
        }
        Ok(())
    }

    fn streams(&mut self) -> Result<(), ReceiveFailure> {
        self.cursor.array_start()?;
        while self.cursor.element()? {
            increment(&mut self.streams, self.limits.containers)?;
            self.stream()?;
        }
        Ok(())
    }

    fn stream(&mut self) -> Result<(), ReceiveFailure> {
        self.cursor.object_start()?;
        let mut labels = None;
        let mut records = None;
        while let Some(field) = self.cursor.field()? {
            if field.is("stream") {
                if labels.is_some() {
                    return Err(ReceiveFailure::MalformedPayload);
                }
                labels = Some(self.labels()?);
            } else if field.is("values") {
                if records.is_some() {
                    return Err(ReceiveFailure::MalformedPayload);
                }
                records = Some(self.values()?);
            } else {
                self.cursor.skip_value(0, self.limits.nesting_depth)?;
            }
        }
        let (label_count, label_bytes) = labels.ok_or(ReceiveFailure::MalformedPayload)?;
        if label_count == 0 {
            return Err(ReceiveFailure::MalformedPayload);
        }
        for record in records.ok_or(ReceiveFailure::MalformedPayload)? {
            let attributes = label_count
                .checked_add(record.attributes)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            self.attributes = self
                .attributes
                .checked_add(attributes)
                .filter(|value| *value <= self.limits.attributes)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            let bytes = label_bytes
                .checked_add(record.bytes)
                .filter(|value| *value <= self.record_bytes)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            let _ = bytes;
        }
        Ok(())
    }

    fn labels(&mut self) -> Result<(usize, usize), ReceiveFailure> {
        self.cursor.object_start()?;
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut bytes = 0usize;
        let mut count = 0usize;
        while let Some(name) = self.cursor.field()? {
            increment(&mut count, self.limits.attribute_entries)?;
            if !valid_label_name(&name) || names.iter().any(|seen| seen == name.raw()) {
                return Err(ReceiveFailure::MalformedPayload);
            }
            if name.decoded_len > self.limits.key_bytes {
                return Err(ReceiveFailure::ValueLimitExceeded);
            }
            let value = self.cursor.string()?;
            if value.decoded_len > self.limits.value_bytes {
                return Err(ReceiveFailure::ValueLimitExceeded);
            }
            bytes = bytes
                .checked_add(name.decoded_len)
                .and_then(|total| total.checked_add(value.decoded_len))
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            names.push(name.raw().to_vec());
        }
        Ok((names.len(), bytes))
    }

    fn values(&mut self) -> Result<Vec<RecordSize>, ReceiveFailure> {
        self.cursor.array_start()?;
        let mut sizes = Vec::new();
        while self.cursor.element()? {
            increment(&mut self.records, self.limits.records)?;
            sizes
                .try_reserve(1)
                .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
            sizes.push(self.value()?);
        }
        Ok(sizes)
    }

    fn value(&mut self) -> Result<RecordSize, ReceiveFailure> {
        self.cursor.array_start()?;
        if !self.cursor.element()? {
            return Err(ReceiveFailure::MalformedPayload);
        }
        let timestamp = self.cursor.string()?;
        if timestamp.decoded_len > 20 {
            return Err(ReceiveFailure::TimestampOutOfRange);
        }
        if !self.cursor.element()? {
            return Err(ReceiveFailure::MalformedPayload);
        }
        let line = self.cursor.string()?;
        if line.decoded_len > self.body_bytes {
            return Err(ReceiveFailure::ValueLimitExceeded);
        }
        let mut record = RecordSize {
            bytes: line.decoded_len,
            attributes: 0,
        };
        if self.cursor.element()? {
            record = self.metadata(record)?;
            if self.cursor.element()? {
                return Err(ReceiveFailure::MalformedPayload);
            }
        }
        Ok(record)
    }

    fn metadata(&mut self, mut record: RecordSize) -> Result<RecordSize, ReceiveFailure> {
        self.cursor.object_start()?;
        let mut names: Vec<Vec<u8>> = Vec::new();
        while let Some(name) = self.cursor.field()? {
            increment(&mut record.attributes, self.limits.attribute_entries)?;
            if names.iter().any(|seen| seen == name.raw()) {
                return Err(ReceiveFailure::MalformedPayload);
            }
            if name.decoded_len > self.limits.key_bytes {
                return Err(ReceiveFailure::ValueLimitExceeded);
            }
            let value = self.cursor.string()?;
            if value.decoded_len > self.limits.value_bytes {
                return Err(ReceiveFailure::ValueLimitExceeded);
            }
            record.bytes = record
                .bytes
                .checked_add(name.decoded_len)
                .and_then(|total| total.checked_add(value.decoded_len))
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            names.push(name.raw().to_vec());
        }
        Ok(record)
    }
}

fn valid_label_name(name: &StringToken<'_>) -> bool {
    let raw = name.raw();
    raw.first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && raw
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}
