use super::TraceReceiveFailure;

const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;
const MAX_GROUP_DEPTH: usize = 64;

pub(super) fn visit_fields(
    message: &[u8],
    known_fields: &[(u64, u8)],
    mut visit: impl FnMut(u64, &[u8]) -> Result<(), TraceReceiveFailure>,
) -> Result<(), TraceReceiveFailure> {
    visit_fields_with_wire(message, known_fields, |field, wire, value| {
        if wire == 2 {
            visit(field, value.ok_or(TraceReceiveFailure::MalformedPayload)?)?;
        }
        Ok(())
    })
}

pub(in crate::otlp_traces) fn visit_fields_with_wire(
    message: &[u8],
    known_fields: &[(u64, u8)],
    mut visit: impl FnMut(u64, u8, Option<&[u8]>) -> Result<(), TraceReceiveFailure>,
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
        let value = if wire == 2 {
            Some(cursor.take_length_delimited()?)
        } else {
            cursor.skip_value(field, wire)?;
            None
        };
        visit(field, wire, value)?;
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
