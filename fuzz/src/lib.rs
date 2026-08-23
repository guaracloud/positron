#![forbid(unsafe_code)]

/// Truncate a lossy-decoded body without splitting a UTF-8 scalar value.
pub fn truncate_utf8(value: &mut String, maximum_bytes: usize) {
    let mut end = value.len().min(maximum_bytes);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::truncate_utf8;

    #[test]
    fn invalid_utf8_replacement_crossing_limit_truncates_at_character_boundary() {
        let mut bytes = vec![b'a'; 510];
        bytes.extend_from_slice(&[0xff, b'b']);
        let mut body = String::from_utf8_lossy(&bytes).into_owned();

        truncate_utf8(&mut body, 512);

        assert_eq!(body, "a".repeat(510));
        assert!(body.is_char_boundary(body.len()));
        assert!(body.len() <= 512);
    }
}
