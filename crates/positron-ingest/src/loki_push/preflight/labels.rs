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
    let inner = source
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .ok_or(ReceiveFailure::MalformedPayload)?;
    let mut remaining = inner;
    let mut names: Vec<&str> = Vec::new();
    let mut bytes = 0usize;
    while !remaining.trim().is_empty() {
        if names.len() == maximum_pairs {
            return Err(ReceiveFailure::ValueLimitExceeded);
        }
        remaining = remaining.trim_start();
        let equals = remaining
            .find('=')
            .ok_or(ReceiveFailure::MalformedPayload)?;
        let name = remaining[..equals].trim();
        if !valid_name(name) || names.contains(&name) {
            return Err(ReceiveFailure::MalformedPayload);
        }
        if name.len() > maximum_key_bytes {
            return Err(ReceiveFailure::ValueLimitExceeded);
        }
        remaining = remaining[(equals + 1)..].trim_start();
        let quoted = quoted_value_length(remaining)?;
        let value = serde_json::from_str::<String>(&remaining[..quoted])
            .map_err(|_| ReceiveFailure::MalformedPayload)?;
        if value.len() > maximum_value_bytes {
            return Err(ReceiveFailure::ValueLimitExceeded);
        }
        bytes = bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(ReceiveFailure::ValueLimitExceeded)?;
        names.push(name);
        remaining = remaining[quoted..].trim_start();
        if remaining.is_empty() {
            break;
        }
        remaining = remaining
            .strip_prefix(',')
            .ok_or(ReceiveFailure::MalformedPayload)?;
        if remaining.trim().is_empty() {
            return Err(ReceiveFailure::MalformedPayload);
        }
    }
    if names.is_empty() {
        return Err(ReceiveFailure::MalformedPayload);
    }
    Ok(LabelSummary {
        count: names.len(),
        bytes,
    })
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn quoted_value_length(source: &str) -> Result<usize, ReceiveFailure> {
    if !source.starts_with('"') {
        return Err(ReceiveFailure::MalformedPayload);
    }
    let mut escaped = false;
    for (index, byte) in source.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Ok(index + 1);
        }
    }
    Err(ReceiveFailure::MalformedPayload)
}
