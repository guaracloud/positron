use crate::ReceiveFailure;

pub(crate) struct StringToken<'json> {
    raw: &'json [u8],
    pub(crate) decoded_len: usize,
}

impl StringToken<'_> {
    pub(crate) fn is(&self, expected: &str) -> bool {
        let mut expected = expected.as_bytes().iter().copied();
        let mut offset = 0;
        while offset < self.raw.len() {
            let Some(decoded) = decoded_ascii(self.raw, &mut offset) else {
                return false;
            };
            if expected.next() != Some(decoded) {
                return false;
            }
        }
        expected.next().is_none()
    }

    pub(crate) fn raw(&self) -> &[u8] {
        self.raw
    }

    pub(crate) fn base64_decoded_len(&self) -> Result<usize, ReceiveFailure> {
        let mut offset = 0;
        let mut characters = 0usize;
        let mut padding = 0usize;
        while offset < self.raw.len() {
            let byte =
                decoded_ascii(self.raw, &mut offset).ok_or(ReceiveFailure::MalformedPayload)?;
            characters = characters
                .checked_add(1)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            if byte == b'=' {
                padding = padding
                    .checked_add(1)
                    .ok_or(ReceiveFailure::MalformedPayload)?;
            } else if padding > 0 || !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
            {
                return Err(ReceiveFailure::MalformedPayload);
            }
        }
        if padding > 2 || !characters.is_multiple_of(4) {
            return Err(ReceiveFailure::MalformedPayload);
        }
        characters
            .checked_div(4)
            .and_then(|groups| groups.checked_mul(3))
            .and_then(|bytes| bytes.checked_sub(padding))
            .ok_or(ReceiveFailure::MalformedPayload)
    }
}

fn decoded_ascii(raw: &[u8], offset: &mut usize) -> Option<u8> {
    let byte = raw.get(*offset).copied()?;
    *offset += 1;
    if byte != b'\\' {
        return byte.is_ascii().then_some(byte);
    }
    let escape = raw.get(*offset).copied()?;
    *offset += 1;
    match escape {
        b'"' | b'\\' | b'/' => Some(escape),
        b'b' => Some(8),
        b'f' => Some(12),
        b'n' => Some(b'\n'),
        b'r' => Some(b'\r'),
        b't' => Some(b'\t'),
        b'u' => {
            let value = ascii_hex(raw.get(*offset..offset.checked_add(4)?)?)?;
            *offset += 4;
            u8::try_from(value).ok()
        },
        _ => None,
    }
}

pub(crate) struct Cursor<'json> {
    input: &'json [u8],
    offset: usize,
    first: [bool; 512],
    depth: usize,
}

impl<'json> Cursor<'json> {
    pub(crate) const fn new(input: &'json [u8]) -> Self {
        Self {
            input,
            offset: 0,
            first: [false; 512],
            depth: 0,
        }
    }

    pub(crate) fn finish(&mut self) -> Result<(), ReceiveFailure> {
        self.whitespace();
        if self.offset == self.input.len() && self.depth == 0 {
            Ok(())
        } else {
            Err(ReceiveFailure::MalformedPayload)
        }
    }

    pub(crate) fn object_start(&mut self) -> Result<(), ReceiveFailure> {
        self.punctuation(b'{')?;
        self.push_container()
    }

    pub(crate) fn array_start(&mut self) -> Result<(), ReceiveFailure> {
        self.punctuation(b'[')?;
        self.push_container()
    }

    pub(crate) fn field(&mut self) -> Result<Option<StringToken<'json>>, ReceiveFailure> {
        if !self.next_entry(b'}')? {
            return Ok(None);
        }
        let field = self.string()?;
        self.punctuation(b':')?;
        Ok(Some(field))
    }

    pub(crate) fn element(&mut self) -> Result<bool, ReceiveFailure> {
        self.next_entry(b']')
    }

    fn push_container(&mut self) -> Result<(), ReceiveFailure> {
        let slot = self
            .first
            .get_mut(self.depth)
            .ok_or(ReceiveFailure::ValueLimitExceeded)?;
        *slot = true;
        self.depth += 1;
        Ok(())
    }

    fn next_entry(&mut self, end: u8) -> Result<bool, ReceiveFailure> {
        self.whitespace();
        let index = self
            .depth
            .checked_sub(1)
            .ok_or(ReceiveFailure::MalformedPayload)?;
        if self.input.get(self.offset) == Some(&end) {
            self.offset += 1;
            self.depth = index;
            return Ok(false);
        }
        let first = self
            .first
            .get_mut(index)
            .ok_or(ReceiveFailure::MalformedPayload)?;
        if *first {
            *first = false;
        } else {
            self.punctuation(b',')?;
        }
        Ok(true)
    }

    pub(crate) fn string(&mut self) -> Result<StringToken<'json>, ReceiveFailure> {
        self.whitespace();
        if self.input.get(self.offset) != Some(&b'"') {
            return Err(ReceiveFailure::MalformedPayload);
        }
        self.offset += 1;
        let start = self.offset;
        let mut decoded_len = 0usize;
        loop {
            let byte = *self
                .input
                .get(self.offset)
                .ok_or(ReceiveFailure::MalformedPayload)?;
            match byte {
                b'"' => {
                    let raw = self
                        .input
                        .get(start..self.offset)
                        .ok_or(ReceiveFailure::MalformedPayload)?;
                    self.offset += 1;
                    return Ok(StringToken { raw, decoded_len });
                },
                b'\\' => {
                    self.offset += 1;
                    decoded_len = decoded_len
                        .checked_add(self.escape_len()?)
                        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                },
                0..=0x1f => return Err(ReceiveFailure::MalformedPayload),
                0x20..=0x7f => {
                    self.offset += 1;
                    decoded_len += 1;
                },
                _ => {
                    let remaining = self
                        .input
                        .get(self.offset..)
                        .ok_or(ReceiveFailure::MalformedPayload)?;
                    let (encoded, decoded) = validated_utf8_scalar(remaining)?;
                    self.offset += encoded;
                    decoded_len = decoded_len
                        .checked_add(decoded)
                        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
                },
            }
        }
    }

    fn escape_len(&mut self) -> Result<usize, ReceiveFailure> {
        let escape = *self
            .input
            .get(self.offset)
            .ok_or(ReceiveFailure::MalformedPayload)?;
        self.offset += 1;
        match escape {
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Ok(1),
            b'u' => {
                let value = self.hex4()?;
                let scalar = if (0xd800..=0xdbff).contains(&value) {
                    if self.input.get(self.offset..self.offset + 2) != Some(b"\\u") {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                    self.offset += 2;
                    let low = self.hex4()?;
                    if !(0xdc00..=0xdfff).contains(&low) {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                    0x1_0000 + ((u32::from(value) - 0xd800) << 10) + (u32::from(low) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&value) {
                    return Err(ReceiveFailure::MalformedPayload);
                } else {
                    u32::from(value)
                };
                char::from_u32(scalar)
                    .map(char::len_utf8)
                    .ok_or(ReceiveFailure::MalformedPayload)
            },
            _ => Err(ReceiveFailure::MalformedPayload),
        }
    }

    fn hex4(&mut self) -> Result<u16, ReceiveFailure> {
        let bytes = self
            .input
            .get(self.offset..self.offset + 4)
            .ok_or(ReceiveFailure::MalformedPayload)?;
        let value = ascii_hex(bytes).ok_or(ReceiveFailure::MalformedPayload)?;
        self.offset += 4;
        Ok(value)
    }

    pub(super) fn take_null(&mut self) -> Result<bool, ReceiveFailure> {
        self.whitespace();
        if self.input.get(self.offset..self.offset + 4) == Some(b"null") {
            self.offset += 4;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn skip_value(
        &mut self,
        depth: usize,
        maximum: usize,
    ) -> Result<(), ReceiveFailure> {
        self.whitespace();
        match self.input.get(self.offset).copied() {
            Some(b'"') => self.string().map(|_| ()),
            Some(b'{') => {
                let next = bounded_depth(depth, maximum)?;
                self.object_start()?;
                while self.field()?.is_some() {
                    self.skip_value(next, maximum)?;
                }
                Ok(())
            },
            Some(b'[') => {
                let next = bounded_depth(depth, maximum)?;
                self.array_start()?;
                while self.element()? {
                    self.skip_value(next, maximum)?;
                }
                Ok(())
            },
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(ReceiveFailure::MalformedPayload),
        }
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), ReceiveFailure> {
        if self.input.get(self.offset..self.offset + literal.len()) == Some(literal) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(ReceiveFailure::MalformedPayload)
        }
    }

    fn number(&mut self) -> Result<(), ReceiveFailure> {
        if self.input.get(self.offset) == Some(&b'-') {
            self.offset += 1;
        }
        match self.input.get(self.offset) {
            Some(b'0') => self.offset += 1,
            Some(b'1'..=b'9') => self.decimal_digits(),
            _ => return Err(ReceiveFailure::MalformedPayload),
        }
        if self.input.get(self.offset) == Some(&b'.') {
            self.offset += 1;
            self.required_digits()?;
        }
        if matches!(self.input.get(self.offset), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.input.get(self.offset), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            self.required_digits()?;
        }
        Ok(())
    }

    fn required_digits(&mut self) -> Result<(), ReceiveFailure> {
        if !matches!(self.input.get(self.offset), Some(b'0'..=b'9')) {
            return Err(ReceiveFailure::MalformedPayload);
        }
        self.decimal_digits();
        Ok(())
    }

    fn decimal_digits(&mut self) {
        while matches!(self.input.get(self.offset), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
    }

    fn punctuation(&mut self, punctuation: u8) -> Result<(), ReceiveFailure> {
        self.whitespace();
        if self.input.get(self.offset) == Some(&punctuation) {
            self.offset += 1;
            Ok(())
        } else {
            Err(ReceiveFailure::MalformedPayload)
        }
    }

    fn whitespace(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }
}

fn validated_utf8_scalar(input: &[u8]) -> Result<(usize, usize), ReceiveFailure> {
    let encoded = match input.first().copied() {
        Some(0xc2..=0xdf) => 2,
        Some(0xe0..=0xef) => 3,
        Some(0xf0..=0xf4) => 4,
        _ => return Err(ReceiveFailure::MalformedPayload),
    };
    let scalar = input
        .get(..encoded)
        .ok_or(ReceiveFailure::MalformedPayload)?;
    let text = std::str::from_utf8(scalar).map_err(|_| ReceiveFailure::MalformedPayload)?;
    let decoded = text
        .chars()
        .next()
        .map(char::len_utf8)
        .filter(|decoded| *decoded == encoded)
        .ok_or(ReceiveFailure::MalformedPayload)?;
    Ok((encoded, decoded))
}

fn ascii_hex(bytes: &[u8]) -> Option<u16> {
    let mut value = 0u16;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u16::from(*byte - b'0'),
            b'a'..=b'f' => u16::from(*byte - b'a' + 10),
            b'A'..=b'F' => u16::from(*byte - b'A' + 10),
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    Some(value)
}

fn bounded_depth(depth: usize, maximum: usize) -> Result<usize, ReceiveFailure> {
    depth
        .checked_add(1)
        .filter(|next| *next <= maximum)
        .ok_or(ReceiveFailure::ValueLimitExceeded)
}

#[cfg(test)]
#[path = "cursor/tests.rs"]
mod tests;
