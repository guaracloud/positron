use crate::ReceiveFailure;
use crate::otlp_logs::preflight::json::cursor::StringToken;

pub(super) fn decode(token: &StringToken<'_>, maximum: usize) -> Result<String, ReceiveFailure> {
    if token.decoded_len > maximum {
        return Err(ReceiveFailure::ValueLimitExceeded);
    }
    let mut decoded = String::new();
    decoded
        .try_reserve_exact(token.decoded_len)
        .map_err(|_| ReceiveFailure::CapacityUnavailable)?;
    let raw = token.raw();
    let mut offset = 0usize;
    while offset < raw.len() {
        let byte = *raw.get(offset).ok_or(ReceiveFailure::MalformedPayload)?;
        if byte == b'\\' {
            offset = offset
                .checked_add(1)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            decode_escape(raw, &mut offset, &mut decoded)?;
        } else if byte.is_ascii() {
            decoded.push(char::from(byte));
            offset += 1;
        } else {
            let tail =
                std::str::from_utf8(raw.get(offset..).ok_or(ReceiveFailure::MalformedPayload)?)
                    .map_err(|_| ReceiveFailure::MalformedPayload)?;
            let scalar = tail
                .chars()
                .next()
                .ok_or(ReceiveFailure::MalformedPayload)?;
            decoded.push(scalar);
            offset = offset
                .checked_add(scalar.len_utf8())
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
        }
    }
    Ok(decoded)
}

fn decode_escape(
    raw: &[u8],
    offset: &mut usize,
    output: &mut String,
) -> Result<(), ReceiveFailure> {
    let escape = *raw.get(*offset).ok_or(ReceiveFailure::MalformedPayload)?;
    *offset += 1;
    match escape {
        b'"' | b'\\' | b'/' => output.push(char::from(escape)),
        b'b' => output.push('\u{0008}'),
        b'f' => output.push('\u{000c}'),
        b'n' => output.push('\n'),
        b'r' => output.push('\r'),
        b't' => output.push('\t'),
        b'u' => output.push(decode_unicode(raw, offset)?),
        _ => return Err(ReceiveFailure::MalformedPayload),
    }
    Ok(())
}

fn decode_unicode(raw: &[u8], offset: &mut usize) -> Result<char, ReceiveFailure> {
    let high = hex4(raw, offset)?;
    let scalar = if (0xd800..=0xdbff).contains(&high) {
        if raw.get(*offset..offset.saturating_add(2)) != Some(b"\\u") {
            return Err(ReceiveFailure::MalformedPayload);
        }
        *offset += 2;
        let low = hex4(raw, offset)?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return Err(ReceiveFailure::MalformedPayload);
        }
        0x1_0000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00)
    } else if (0xdc00..=0xdfff).contains(&high) {
        return Err(ReceiveFailure::MalformedPayload);
    } else {
        u32::from(high)
    };
    char::from_u32(scalar).ok_or(ReceiveFailure::MalformedPayload)
}

fn hex4(raw: &[u8], offset: &mut usize) -> Result<u16, ReceiveFailure> {
    let bytes = raw
        .get(*offset..offset.saturating_add(4))
        .ok_or(ReceiveFailure::MalformedPayload)?;
    let mut value = 0u16;
    for byte in bytes {
        value = value
            .checked_mul(16)
            .and_then(|value| value.checked_add(u16::from(hex(*byte)?)))
            .ok_or(ReceiveFailure::MalformedPayload)?;
    }
    *offset += 4;
    Ok(value)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
