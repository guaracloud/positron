//! Child invocation and bounded stdout outcome protocol.

use std::ffi::OsString;
use std::time::Duration;

use crate::bounded_runner_frames;
use crate::error::XtaskError;

use super::registry::{FrozenBoundedRunnerRegistry, ScenarioGate, hex_encode};
use super::scenarios::{run_concurrency_scenario, run_resource_scenario};

const MAXIMUM_CHILD_ARGUMENT_BYTES: usize = 32_768;

impl FrozenBoundedRunnerRegistry {
    pub(crate) fn child_arguments(
        &self,
        gate: &str,
        execution_timeout: Duration,
    ) -> Result<Vec<OsString>, XtaskError> {
        let registry = hex_encode(self.bytes())?;
        let spawn_sites = hex_encode(self.spawn_site_bytes())?;
        Ok(vec![
            OsString::from("quality-bounded-runner"),
            OsString::from(gate),
            OsString::from(registry),
            OsString::from(spawn_sites),
            OsString::from(execution_timeout.as_millis().to_string()),
        ])
    }

    pub(crate) fn retained_child_invocation_matches(
        gate: &str,
        timeout_ms: u128,
        arguments: &[&str],
    ) -> bool {
        Self::validate_child_invocation(gate, timeout_ms, arguments).is_ok()
    }

    pub(crate) fn validate_child_invocation(
        gate: &str,
        timeout_ms: u128,
        arguments: &[&str],
    ) -> Result<(), XtaskError> {
        let [
            command,
            recorded_gate,
            registry,
            spawn_sites,
            recorded_timeout,
        ] = arguments
        else {
            return Err(XtaskError::invalid(
                "bounded runner child invocation",
                "child invocation does not have the exact registered argument count",
            ));
        };
        if *command != "quality-bounded-runner"
            || *recorded_gate != gate
            || timeout_ms == 0
            || *recorded_timeout != timeout_ms.to_string()
        {
            return Err(XtaskError::invalid(
                "bounded runner child invocation",
                "child arguments do not match the frozen registries and timeout",
            ));
        }
        let parsed_gate = ScenarioGate::parse(gate)?;
        FrozenBoundedRunnerRegistry::capture(hex_decode(registry)?, hex_decode(spawn_sites)?)?
            .scenario(parsed_gate)
            .map(|_| ())
    }
}

pub(crate) fn run_process(arguments: impl Iterator<Item = String>) -> Result<(), XtaskError> {
    let [gate, registry, spawn_sites, execution_timeout_ms] = process_arguments(arguments)?;
    let result = (|| {
        let execution_timeout = parse_execution_timeout(&execution_timeout_ms)?;
        let registry = FrozenBoundedRunnerRegistry::capture(
            hex_decode(&registry)?,
            hex_decode(&spawn_sites)?,
        )?;
        match ScenarioGate::parse(&gate)? {
            ScenarioGate::Concurrency => run_concurrency_scenario(&registry, execution_timeout),
            ScenarioGate::Resource => run_resource_scenario(&registry, execution_timeout),
        }
    })();
    bounded_runner_frames::emit_result(&result)?;
    result.map(|_| ())
}

fn process_arguments(
    mut arguments: impl Iterator<Item = String>,
) -> Result<[String; 4], XtaskError> {
    let exact = [
        arguments.next(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
    ];
    let [
        Some(gate),
        Some(registry),
        Some(spawn_sites),
        Some(execution_timeout),
    ] = exact
    else {
        return Err(child_argument_count_failure());
    };
    if arguments.next().is_some() {
        return Err(child_argument_count_failure());
    }
    Ok([gate, registry, spawn_sites, execution_timeout])
}

fn child_argument_count_failure() -> XtaskError {
    XtaskError::usage(
        "quality-bounded-runner requires one gate, two frozen registries, and one execution timeout",
    )
}

fn parse_execution_timeout(value: &str) -> Result<Duration, XtaskError> {
    let milliseconds = value.parse::<u64>().map_err(|_| {
        XtaskError::invalid(
            "bounded runner child arguments",
            "execution timeout is not a canonical positive unsigned millisecond value",
        )
    })?;
    if milliseconds == 0 || value != milliseconds.to_string() {
        return Err(XtaskError::invalid(
            "bounded runner child arguments",
            "execution timeout is not a canonical positive unsigned millisecond value",
        ));
    }
    Ok(Duration::from_millis(milliseconds))
}

pub(super) fn hex_decode(encoded: &str) -> Result<Vec<u8>, XtaskError> {
    if encoded.len() > MAXIMUM_CHILD_ARGUMENT_BYTES || !encoded.len().is_multiple_of(2) {
        return Err(XtaskError::invalid(
            "bounded runner child arguments",
            "hex-encoded field has an invalid bounded length",
        ));
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let [high, low] = pair else {
                return Err(XtaskError::invalid(
                    "bounded runner child arguments",
                    "hex-encoded field contains an incomplete byte",
                ));
            };
            let high = hex_nibble(*high)?;
            let low = hex_nibble(*low)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, XtaskError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(XtaskError::invalid(
            "bounded runner child arguments",
            "hex-encoded field contains a non-canonical digit",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_execution_timeout, process_arguments};

    #[test]
    fn child_protocol_requires_exact_arguments_and_a_canonical_positive_timeout() {
        let arguments = ["EG-CONCURRENCY", "00", "00", "1"]
            .into_iter()
            .map(str::to_owned);
        assert!(process_arguments(arguments).is_ok());
        assert!(matches!(
            parse_execution_timeout("1"),
            Ok(timeout) if timeout.as_millis() == 1
        ));

        let extra = ["EG-CONCURRENCY", "00", "00", "1", "unexpected"]
            .into_iter()
            .map(str::to_owned);
        assert!(process_arguments(extra).is_err());
        for invalid in ["001", "+1", "-1", " 1", "1 ", "0", "18446744073709551616"] {
            assert!(
                parse_execution_timeout(invalid).is_err(),
                "noncanonical timeout `{invalid}` was accepted"
            );
        }
    }
}
