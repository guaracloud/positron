//! Strict bounded stdout frames for the registered concurrency runners.

use std::io::Write;

use crate::error::XtaskError;

pub(crate) const MAXIMUM_RECORD_BYTES: usize = 4_096;
pub(crate) const MAXIMUM_FRAME_BYTES: usize = 8_256;
pub(crate) const RUNNER_READY_FRAME: &str = "runner-ready-v1\n";
pub(crate) const LIFECYCLE_STALLED_FRAME: &str = "lifecycle-stalled-v1\n";
const OUTCOME_PREFIX: &str = "runner-outcome-v1:";
const ERROR_PREFIX: &str = "runner-error-v1:";

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CapturedFrame {
    Outcome(String),
    Error(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlFrame {
    RunnerReady,
    LifecycleStalled,
}

pub(crate) fn emit_result(result: &Result<String, XtaskError>) -> Result<(), XtaskError> {
    match result {
        Ok(record) => emit_encoded(OUTCOME_PREFIX, record),
        Err(error) => emit_encoded(ERROR_PREFIX, &error.to_string()),
    }
}

pub(crate) fn emit_control(frame: ControlFrame) -> Result<(), XtaskError> {
    let bytes = match frame {
        ControlFrame::RunnerReady => RUNNER_READY_FRAME.as_bytes(),
        ControlFrame::LifecycleStalled => LIFECYCLE_STALLED_FRAME.as_bytes(),
    };
    write_stdout(bytes)
}

pub(crate) fn control_frame(line: &[u8]) -> Option<ControlFrame> {
    match line {
        bytes if bytes == RUNNER_READY_FRAME.as_bytes() => Some(ControlFrame::RunnerReady),
        bytes if bytes == LIFECYCLE_STALLED_FRAME.as_bytes() => {
            Some(ControlFrame::LifecycleStalled)
        },
        _ => None,
    }
}

pub(crate) fn parse_captured(stdout: &str) -> Result<CapturedFrame, XtaskError> {
    if stdout.len() > MAXIMUM_FRAME_BYTES {
        return Err(XtaskError::invalid(
            "bounded runner stdout protocol",
            "captured frame exceeds its exact byte bound",
        ));
    }
    if !stdout.ends_with('\n') || stdout.lines().count() != 1 {
        return Err(XtaskError::invalid(
            "bounded runner stdout protocol",
            "captured output must contain exactly one complete frame",
        ));
    }
    let frame = stdout.trim_end_matches('\n');
    if frame == RUNNER_READY_FRAME.trim_end() || frame == LIFECYCLE_STALLED_FRAME.trim_end() {
        return Err(XtaskError::invalid(
            "bounded runner stdout protocol",
            "control frame reached the normal outcome parser",
        ));
    }
    if let Some(encoded) = frame.strip_prefix(OUTCOME_PREFIX) {
        return decode_payload(encoded).map(CapturedFrame::Outcome);
    }
    if let Some(encoded) = frame.strip_prefix(ERROR_PREFIX) {
        return decode_payload(encoded).map(CapturedFrame::Error);
    }
    Err(XtaskError::invalid(
        "bounded runner stdout protocol",
        "captured frame has an unknown or stale version",
    ))
}

fn emit_encoded(prefix: &str, payload: &str) -> Result<(), XtaskError> {
    if payload.len() > MAXIMUM_RECORD_BYTES {
        return Err(XtaskError::invalid(
            "bounded runner stdout protocol",
            "frame payload exceeds its exact byte bound",
        ));
    }
    let encoded = hex_encode(payload.as_bytes())?;
    let frame = format!("{prefix}{encoded}\n");
    if frame.len() > MAXIMUM_FRAME_BYTES {
        return Err(XtaskError::invalid(
            "bounded runner stdout protocol",
            "encoded frame exceeds its exact byte bound",
        ));
    }
    write_stdout(frame.as_bytes())
}

fn write_stdout(bytes: &[u8]) -> Result<(), XtaskError> {
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    locked
        .write_all(bytes)
        .and_then(|()| locked.flush())
        .map_err(|source| XtaskError::io("emit bounded runner stdout frame", source))
}

fn hex_encode(bytes: &[u8]) -> Result<String, XtaskError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes.len().checked_mul(2).ok_or_else(|| {
        XtaskError::invalid(
            "bounded runner stdout protocol",
            "encoded payload length cannot be represented",
        )
    })?;
    let mut encoded = String::with_capacity(capacity);
    for byte in bytes {
        let high = HEX.get(usize::from(byte >> 4)).copied().ok_or_else(|| {
            XtaskError::invalid("bounded runner stdout protocol", "invalid high hex index")
        })?;
        let low = HEX.get(usize::from(byte & 0x0f)).copied().ok_or_else(|| {
            XtaskError::invalid("bounded runner stdout protocol", "invalid low hex index")
        })?;
        encoded.push(char::from(high));
        encoded.push(char::from(low));
    }
    Ok(encoded)
}

fn decode_payload(encoded: &str) -> Result<String, XtaskError> {
    if encoded.len() > MAXIMUM_RECORD_BYTES.saturating_mul(2) || !encoded.len().is_multiple_of(2) {
        return Err(XtaskError::invalid(
            "bounded runner stdout protocol",
            "encoded frame payload has an invalid bounded length",
        ));
    }
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let [high, low] = pair else {
                return Err(XtaskError::invalid(
                    "bounded runner stdout protocol",
                    "encoded frame payload contains an incomplete byte",
                ));
            };
            Ok((hex_nibble(*high)? << 4) | hex_nibble(*low)?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(|_| {
        XtaskError::invalid(
            "bounded runner stdout protocol",
            "decoded frame payload is not UTF-8",
        )
    })
}

fn hex_nibble(byte: u8) -> Result<u8, XtaskError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(XtaskError::invalid(
            "bounded runner stdout protocol",
            "encoded frame payload contains a noncanonical hex digit",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{CapturedFrame, MAXIMUM_FRAME_BYTES, MAXIMUM_RECORD_BYTES, parse_captured};

    #[test]
    fn accepts_the_exact_payload_boundary() -> Result<(), crate::error::XtaskError> {
        let payload = "a".repeat(MAXIMUM_RECORD_BYTES);
        let encoded = "61".repeat(MAXIMUM_RECORD_BYTES);
        let frame = format!("runner-outcome-v1:{encoded}\n");

        assert!(frame.len() <= MAXIMUM_FRAME_BYTES);
        assert_eq!(parse_captured(&frame)?, CapturedFrame::Outcome(payload),);
        Ok(())
    }

    #[test]
    fn rejects_malformed_frames() {
        for malformed in [
            "",
            "runner-outcome-v1:0\n",
            "runner-outcome-v1:4F\n",
            "runner-outcome-v0:6f6b\n",
            "runner-outcome-v1:6f6b",
        ] {
            assert!(parse_captured(malformed).is_err(), "{malformed}");
        }
    }

    #[test]
    fn rejects_duplicate_and_extra_frames() {
        assert!(parse_captured("runner-outcome-v1:6f6b\nrunner-outcome-v1:6f6b\n").is_err());
        assert!(parse_captured("noise\nrunner-outcome-v1:6f6b\n").is_err());
    }

    #[test]
    fn rejects_frames_above_the_exact_capture_bound() {
        let oversized = format!("runner-outcome-v1:{}\n", "61".repeat(MAXIMUM_FRAME_BYTES));
        assert!(parse_captured(&oversized).is_err());
    }
}
