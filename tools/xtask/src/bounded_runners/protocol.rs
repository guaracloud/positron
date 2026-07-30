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
            || recorded_timeout.parse::<u128>().ok() != Some(timeout_ms)
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
    let arguments = arguments.take(5).collect::<Vec<_>>();
    let [gate, registry, spawn_sites, execution_timeout_ms] = arguments.as_slice() else {
        return Err(XtaskError::usage(
            "quality-bounded-runner requires one gate, two frozen registries, and one execution timeout",
        ));
    };
    let result = (|| {
        let execution_timeout_ms = execution_timeout_ms.parse::<u64>().map_err(|_| {
            XtaskError::invalid(
                "bounded runner child arguments",
                "execution timeout is not a canonical unsigned millisecond value",
            )
        })?;
        let execution_timeout = Duration::from_millis(execution_timeout_ms);
        if execution_timeout.is_zero() {
            return Err(XtaskError::invalid(
                "bounded runner child arguments",
                "execution timeout must be positive",
            ));
        }
        let registry =
            FrozenBoundedRunnerRegistry::capture(hex_decode(registry)?, hex_decode(spawn_sites)?)?;
        match ScenarioGate::parse(gate)? {
            ScenarioGate::Concurrency => run_concurrency_scenario(&registry, execution_timeout),
            ScenarioGate::Resource => run_resource_scenario(&registry, execution_timeout),
        }
    })();
    bounded_runner_frames::emit_result(&result)?;
    result.map(|_| ())
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
