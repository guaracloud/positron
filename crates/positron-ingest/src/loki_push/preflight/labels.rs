use crate::ReceiveFailure;

#[derive(Clone, Copy)]
pub(super) struct LabelSummary {
    pub(super) count: usize,
    pub(super) bytes: usize,
}

pub(super) fn validate_label_set(
    source: &str,
    maximum_pairs: usize,
    maximum_key_bytes: usize,
    maximum_value_bytes: usize,
) -> Result<LabelSummary, ReceiveFailure> {
    Parser::new(
        source,
        maximum_pairs,
        maximum_key_bytes,
        maximum_value_bytes,
    )
    .parse(None)
}

pub(in crate::loki_push) fn parse_label_set(
    source: &str,
    maximum_pairs: usize,
    maximum_key_bytes: usize,
    maximum_value_bytes: usize,
) -> Result<Vec<(String, String)>, ReceiveFailure> {
    let summary = validate_label_set(
        source,
        maximum_pairs,
        maximum_key_bytes,
        maximum_value_bytes,
    )?;
    let mut labels = Vec::new();
    labels
        .try_reserve_exact(summary.count)
        .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
    Parser::new(
        source,
        maximum_pairs,
        maximum_key_bytes,
        maximum_value_bytes,
    )
    .parse(Some(&mut labels))?;
    Ok(labels)
}

struct Parser<'source> {
    source: &'source str,
    offset: usize,
    maximum_pairs: usize,
    maximum_key_bytes: usize,
    maximum_value_bytes: usize,
}

impl<'source> Parser<'source> {
    const fn new(
        source: &'source str,
        maximum_pairs: usize,
        maximum_key_bytes: usize,
        maximum_value_bytes: usize,
    ) -> Self {
        Self {
            source,
            offset: 0,
            maximum_pairs,
            maximum_key_bytes,
            maximum_value_bytes,
        }
    }

    fn parse(
        mut self,
        mut output: Option<&mut Vec<(String, String)>>,
    ) -> Result<LabelSummary, ReceiveFailure> {
        self.whitespace();
        self.take(b'{')?;
        self.whitespace();
        let mut names: Vec<&str> = Vec::new();
        let mut bytes = 0usize;
        if self.peek() == Some(b'}') {
            return Err(ReceiveFailure::MalformedPayload);
        }
        loop {
            if names.len() == self.maximum_pairs {
                return Err(ReceiveFailure::ValueLimitExceeded);
            }
            let name = self.name()?;
            if names.contains(&name) {
                return Err(ReceiveFailure::MalformedPayload);
            }
            names
                .try_reserve(1)
                .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
            names.push(name);
            self.whitespace();
            self.take(b'=')?;
            self.whitespace();
            let value_start = self.offset;
            let value_bytes = self.value(None)?;
            bytes = bytes
                .checked_add(name.len())
                .and_then(|total| total.checked_add(value_bytes))
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            if let Some(labels) = output.as_deref_mut() {
                let mut value = String::new();
                value
                    .try_reserve_exact(value_bytes)
                    .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
                let end = self.offset;
                let mut materializer = Parser::new(
                    self.source
                        .get(value_start..end)
                        .ok_or(ReceiveFailure::MalformedPayload)?,
                    self.maximum_pairs,
                    self.maximum_key_bytes,
                    self.maximum_value_bytes,
                );
                materializer.value(Some(&mut value))?;
                labels.push((name.to_owned(), value));
            }
            self.whitespace();
            match self.peek() {
                Some(b',') => {
                    self.offset += 1;
                    self.whitespace();
                    if self.peek() == Some(b'}') {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                },
                Some(b'}') => {
                    self.offset += 1;
                    self.whitespace();
                    if self.offset != self.source.len() {
                        return Err(ReceiveFailure::MalformedPayload);
                    }
                    return Ok(LabelSummary {
                        count: names.len(),
                        bytes,
                    });
                },
                _ => return Err(ReceiveFailure::MalformedPayload),
            }
        }
    }

    fn name(&mut self) -> Result<&'source str, ReceiveFailure> {
        let start = self.offset;
        let first = self.peek().ok_or(ReceiveFailure::MalformedPayload)?;
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return Err(ReceiveFailure::MalformedPayload);
        }
        self.offset += 1;
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            self.offset += 1;
        }
        let name = self
            .source
            .get(start..self.offset)
            .ok_or(ReceiveFailure::MalformedPayload)?;
        if name.len() > self.maximum_key_bytes {
            return Err(ReceiveFailure::ValueLimitExceeded);
        }
        Ok(name)
    }

    fn value(&mut self, output: Option<&mut String>) -> Result<usize, ReceiveFailure> {
        match self.peek() {
            Some(b'"') => self.quoted(output),
            Some(b'`') => self.raw(output),
            _ => Err(ReceiveFailure::MalformedPayload),
        }
    }

    fn quoted(&mut self, mut output: Option<&mut String>) -> Result<usize, ReceiveFailure> {
        self.offset += 1;
        let mut bytes = 0usize;
        loop {
            match self.peek().ok_or(ReceiveFailure::MalformedPayload)? {
                b'"' => {
                    self.offset += 1;
                    return Ok(bytes);
                },
                b'\\' => {
                    self.offset += 1;
                    let scalar = self.escape()?;
                    bytes = add_scalar(bytes, scalar, self.maximum_value_bytes)?;
                    if let Some(value) = output.as_deref_mut() {
                        value.push(scalar);
                    }
                },
                0..=0x1f => return Err(ReceiveFailure::MalformedPayload),
                _ => {
                    let scalar = self.scalar()?;
                    bytes = add_scalar(bytes, scalar, self.maximum_value_bytes)?;
                    if let Some(value) = output.as_deref_mut() {
                        value.push(scalar);
                    }
                },
            }
        }
    }

    fn raw(&mut self, mut output: Option<&mut String>) -> Result<usize, ReceiveFailure> {
        self.offset += 1;
        let mut bytes = 0usize;
        loop {
            match self.peek().ok_or(ReceiveFailure::MalformedPayload)? {
                b'`' => {
                    self.offset += 1;
                    return Ok(bytes);
                },
                b'\r' => self.offset += 1,
                _ => {
                    let scalar = self.scalar()?;
                    bytes = add_scalar(bytes, scalar, self.maximum_value_bytes)?;
                    if let Some(value) = output.as_deref_mut() {
                        value.push(scalar);
                    }
                },
            }
        }
    }

    fn escape(&mut self) -> Result<char, ReceiveFailure> {
        let escape = self.peek().ok_or(ReceiveFailure::MalformedPayload)?;
        self.offset += 1;
        match escape {
            b'a' => Ok('\u{0007}'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'v' => Ok('\u{000b}'),
            b'\\' => Ok('\\'),
            b'"' => Ok('"'),
            b'x' => self.hex_scalar(2),
            b'u' => self.hex_scalar(4),
            b'U' => self.hex_scalar(8),
            b'0'..=b'7' => self.octal_scalar(escape),
            _ => Err(ReceiveFailure::MalformedPayload),
        }
    }

    fn hex_scalar(&mut self, digits: usize) -> Result<char, ReceiveFailure> {
        let mut value = 0u32;
        for _ in 0..digits {
            let digit = hex(self.take_any()?).ok_or(ReceiveFailure::MalformedPayload)?;
            value = value
                .checked_mul(16)
                .and_then(|value| value.checked_add(u32::from(digit)))
                .ok_or(ReceiveFailure::MalformedPayload)?;
        }
        valid_scalar(value)
    }

    fn octal_scalar(&mut self, first: u8) -> Result<char, ReceiveFailure> {
        let mut value = u32::from(first - b'0');
        for _ in 0..2 {
            let byte = self.take_any()?;
            if !(b'0'..=b'7').contains(&byte) {
                return Err(ReceiveFailure::MalformedPayload);
            }
            value = value * 8 + u32::from(byte - b'0');
        }
        if value > u32::from(u8::MAX) {
            return Err(ReceiveFailure::MalformedPayload);
        }
        valid_scalar(value)
    }

    fn scalar(&mut self) -> Result<char, ReceiveFailure> {
        let tail = self
            .source
            .get(self.offset..)
            .ok_or(ReceiveFailure::MalformedPayload)?;
        let scalar = tail
            .chars()
            .next()
            .ok_or(ReceiveFailure::MalformedPayload)?;
        self.offset += scalar.len_utf8();
        Ok(scalar)
    }

    fn take(&mut self, expected: u8) -> Result<(), ReceiveFailure> {
        if self.peek() != Some(expected) {
            return Err(ReceiveFailure::MalformedPayload);
        }
        self.offset += 1;
        Ok(())
    }

    fn take_any(&mut self) -> Result<u8, ReceiveFailure> {
        let byte = self.peek().ok_or(ReceiveFailure::MalformedPayload)?;
        self.offset += 1;
        Ok(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }

    fn whitespace(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.offset += 1;
        }
    }
}

fn add_scalar(bytes: usize, scalar: char, maximum: usize) -> Result<usize, ReceiveFailure> {
    bytes
        .checked_add(scalar.len_utf8())
        .filter(|bytes| *bytes <= maximum)
        .ok_or(ReceiveFailure::ValueLimitExceeded)
}

fn valid_scalar(value: u32) -> Result<char, ReceiveFailure> {
    char::from_u32(value).ok_or(ReceiveFailure::MalformedPayload)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
