use super::ReceiveFailure;

const MAX_RECORDS: usize = 1_024;
const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;
const MAX_GROUP_DEPTH: usize = 64;

pub(super) fn validate_record_count(protobuf: &[u8]) -> Result<(), ReceiveFailure> {
    let mut records = 0_usize;
    visit_request(protobuf, &mut records)
}

fn visit_request(message: &[u8], records: &mut usize) -> Result<(), ReceiveFailure> {
    visit_fields(message, 1, |resource_logs| {
        visit_fields(resource_logs, 2, |scope_logs| {
            visit_fields(scope_logs, 2, |_| {
                *records = records
                    .checked_add(1)
                    .filter(|count| *count <= MAX_RECORDS)
                    .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                Ok(())
            })
        })
    })
}

fn visit_fields(
    message: &[u8],
    nested_field: u64,
    mut visit: impl FnMut(&[u8]) -> Result<(), ReceiveFailure>,
) -> Result<(), ReceiveFailure> {
    let mut cursor = Cursor::new(message);
    while !cursor.is_empty() {
        let (field, wire) = cursor.take_key()?;
        if field == nested_field && wire == 2 {
            visit(cursor.take_length_delimited()?)?;
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

    fn take_key(&mut self) -> Result<(u64, u8), ReceiveFailure> {
        let key = self.take_varint()?;
        let field = key >> 3;
        let wire = (key & 7) as u8;
        if field == 0 || field > MAX_FIELD_NUMBER || wire > 5 {
            return Err(ReceiveFailure::MalformedPayload);
        }
        Ok((field, wire))
    }

    fn take_varint(&mut self) -> Result<u64, ReceiveFailure> {
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

    fn take_length_delimited(&mut self) -> Result<&'message [u8], ReceiveFailure> {
        let length =
            usize::try_from(self.take_varint()?).map_err(|_| ReceiveFailure::MalformedPayload)?;
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(ReceiveFailure::MalformedPayload)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn skip_value(&mut self, field: u64, wire: u8) -> Result<(), ReceiveFailure> {
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
mod tests {
    use super::validate_record_count;
    use crate::ReceiveFailure;

    #[test]
    fn exact_record_limit_is_accepted_and_the_next_record_is_rejected() {
        assert_eq!(
            validate_record_count(&request_with_empty_records(1_024)),
            Ok(())
        );
        assert_eq!(
            validate_record_count(&request_with_empty_records(1_025)),
            Err(ReceiveFailure::ValueLimitExceeded),
        );
    }

    #[test]
    fn a_huge_empty_record_fanout_is_rejected_without_decoding() {
        let request = request_with_empty_records(100_000);
        assert!(request.len() < 1_048_576);
        assert_eq!(
            validate_record_count(&request),
            Err(ReceiveFailure::ValueLimitExceeded),
        );
    }

    #[test]
    fn unrelated_length_delimited_fields_do_not_count_as_log_records() {
        let log_like_bytes = request_with_empty_records(1_025);
        let mut request = Vec::new();
        push_length_delimited(9, &log_like_bytes, &mut request);
        push_length_delimited(1, &[0x0a, 0x02, 0x12, 0x00], &mut request);

        assert_eq!(validate_record_count(&request), Ok(()));
    }

    #[test]
    fn malformed_nested_wire_is_rejected() {
        for request in [
            vec![0x0a, 0x02, 0x12],
            vec![0x0a, 0x03, 0x12, 0x01, 0x80],
            vec![
                0x0a, 0x0b, 0x12, 0x09, 0x12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            ],
        ] {
            assert_eq!(
                validate_record_count(&request),
                Err(ReceiveFailure::MalformedPayload),
            );
        }
    }

    #[test]
    fn unknown_wire_types_are_skipped_and_group_hazards_fail_closed() {
        let valid_unknowns = [
            0x10, 0x01, // varint
            0x19, 0, 0, 0, 0, 0, 0, 0, 0, // fixed64
            0x25, 0, 0, 0, 0, // fixed32
            0x2b, 0x30, 0x01, 0x2c, // matching group
        ];
        assert_eq!(validate_record_count(&valid_unknowns), Ok(()));

        for malformed in [
            vec![0x00],
            vec![0x0e],
            vec![0x0c],
            vec![0x0a, 0x80, 0x00],
            vec![0x11, 0, 0, 0],
            vec![0x1d, 0, 0],
            vec![0x0b, 0x14],
        ] {
            assert_eq!(
                validate_record_count(&malformed),
                Err(ReceiveFailure::MalformedPayload),
            );
        }

        let mut too_deep = Vec::new();
        too_deep.extend(std::iter::repeat_n(0x0b, 65));
        too_deep.extend(std::iter::repeat_n(0x0c, 65));
        assert_eq!(
            validate_record_count(&too_deep),
            Err(ReceiveFailure::MalformedPayload),
        );
    }

    fn request_with_empty_records(count: usize) -> Vec<u8> {
        let mut scope_logs = Vec::with_capacity(count.saturating_mul(2));
        for _ in 0..count {
            scope_logs.extend_from_slice(&[0x12, 0x00]);
        }
        let mut resource_logs = Vec::new();
        push_length_delimited(2, &scope_logs, &mut resource_logs);
        let mut request = Vec::new();
        push_length_delimited(1, &resource_logs, &mut request);
        request
    }

    fn push_length_delimited(field: u64, value: &[u8], output: &mut Vec<u8>) {
        push_varint((field << 3) | 2, output);
        push_varint(value.len() as u64, output);
        output.extend_from_slice(value);
    }

    fn push_varint(mut value: u64, output: &mut Vec<u8>) {
        while value >= 0x80 {
            output.push((value as u8) | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }
}
