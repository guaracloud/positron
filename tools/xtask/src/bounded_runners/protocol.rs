//! Child protocol and owned outcome publication.

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::error::XtaskError;
use crate::qualification_fixtures::{DirectoryCapability, DirectoryIdentity};
use crate::registered_task_lifecycle::WorkerReadiness;

use super::registry::{FrozenBoundedRunnerRegistry, ScenarioGate, hex_encode};
use super::scenarios::{run_concurrency_scenario, run_resource_scenario};

const MAXIMUM_CHILD_ARGUMENT_BYTES: usize = 32_768;
const MAXIMUM_CHILD_OUTCOME_BYTES: usize = 8_192;
const OUTCOME_NAME: &str = "outcome.out";
const READINESS_NAME: &str = "worker.ready";
const CANCELLATION_NAME: &str = "worker.cancel";

#[derive(Debug)]
pub(crate) struct OwnedOutcomeTicket {
    parent: DirectoryCapability,
    name: String,
    directory: DirectoryCapability,
    identity: DirectoryIdentity,
}

impl OwnedOutcomeTicket {
    pub(crate) fn create(root: &Path, name: &str) -> Result<Self, XtaskError> {
        let parent = DirectoryCapability::open(root, "bounded runner temporary root")?;
        let directory = parent.create_child_directory(name, "bounded runner outcome ticket")?;
        let identity = directory.identity()?;
        Ok(Self {
            parent,
            name: name.to_owned(),
            directory,
            identity,
        })
    }

    pub(crate) fn outcome_path(&self) -> PathBuf {
        self.directory.diagnostic_path().join(OUTCOME_NAME)
    }

    pub(crate) fn cancellation_path(&self) -> PathBuf {
        self.directory.diagnostic_path().join(CANCELLATION_NAME)
    }

    pub(crate) fn take_outcome(&self) -> Result<String, XtaskError> {
        self.require_identity()?;
        let bytes = self.directory.read_bounded(
            OUTCOME_NAME,
            MAXIMUM_CHILD_OUTCOME_BYTES,
            "bounded runner outcome",
        )?;
        self.directory.remove_file(OUTCOME_NAME)?;
        String::from_utf8(bytes).map_err(|_| {
            XtaskError::invalid_path(
                &self.outcome_path(),
                "bounded runner outcome is not valid UTF-8",
            )
        })
    }

    pub(crate) fn remove_optional_markers(&self) -> Result<(), XtaskError> {
        self.require_identity()?;
        self.directory.remove_file_if_exists(READINESS_NAME)?;
        self.directory.remove_file_if_exists(CANCELLATION_NAME)
    }

    pub(crate) fn remove_optional_outcome(&self) -> Result<(), XtaskError> {
        self.require_identity()?;
        self.directory.remove_file_if_exists(OUTCOME_NAME)
    }

    fn require_identity(&self) -> Result<(), XtaskError> {
        self.parent.require_child_directory_identity(
            &self.name,
            self.identity,
            "bounded runner outcome ticket",
        )
    }
}

impl FrozenBoundedRunnerRegistry {
    pub(crate) fn child_arguments(
        &self,
        gate: &str,
        ticket: &OwnedOutcomeTicket,
        execution_timeout: Duration,
    ) -> Result<Vec<OsString>, XtaskError> {
        ticket.require_identity()?;
        let registry = hex_encode(self.bytes())?;
        let spawn_sites = hex_encode(self.spawn_site_bytes())?;
        Ok(vec![
            OsString::from("quality-bounded-runner"),
            OsString::from(gate),
            OsString::from(registry),
            OsString::from(spawn_sites),
            ticket.directory.diagnostic_path().as_os_str().to_owned(),
            OsString::from(OUTCOME_NAME),
            OsString::from(execution_timeout.as_millis().to_string()),
            OsString::from(READINESS_NAME),
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
            owned_directory,
            outcome_name,
            recorded_timeout,
            readiness_name,
        ] = arguments
        else {
            return Err(XtaskError::invalid(
                "bounded runner child invocation",
                "child invocation does not have the exact registered argument count",
            ));
        };
        require_normal_component(outcome_name, "outcome")?;
        require_normal_component(readiness_name, "readiness")?;
        if *command != "quality-bounded-runner"
            || *recorded_gate != gate
            || recorded_timeout.parse::<u128>().ok() != Some(timeout_ms)
            || *outcome_name != OUTCOME_NAME
            || *readiness_name != READINESS_NAME
        {
            return Err(XtaskError::invalid(
                "bounded runner child invocation",
                "child arguments do not match the retained ticket and frozen registries",
            ));
        }
        if !Path::new(owned_directory).is_absolute() {
            return Err(XtaskError::invalid_path(
                Path::new(owned_directory),
                "bounded runner outcome ticket is not absolute",
            ));
        }
        let _ticket = open_owned_outcome_directory(Path::new(owned_directory))?;
        let parsed_gate = ScenarioGate::parse(gate)?;
        FrozenBoundedRunnerRegistry::capture(hex_decode(registry)?, hex_decode(spawn_sites)?)?
            .scenario(parsed_gate)
            .map(|_| ())
    }
}

pub(crate) fn run_process(arguments: impl Iterator<Item = String>) -> Result<(), XtaskError> {
    let arguments = arguments.take(8).collect::<Vec<_>>();
    let [
        gate,
        registry,
        spawn_sites,
        owned_directory,
        outcome_name,
        execution_timeout_ms,
        readiness_name,
    ] = arguments.as_slice()
    else {
        return Err(XtaskError::usage(
            "quality-bounded-runner requires one gate, two frozen registries, one outcome path, one execution timeout, and one readiness path",
        ));
    };
    let owned_directory = open_owned_outcome_directory(Path::new(owned_directory))?;
    let result = (|| {
        require_normal_component(outcome_name, "outcome")?;
        require_normal_component(readiness_name, "readiness")?;
        if outcome_name != OUTCOME_NAME || readiness_name != READINESS_NAME {
            return Err(XtaskError::invalid(
                "bounded runner child arguments",
                "child outcome or readiness identity does not match its retained ticket",
            ));
        }
        let readiness =
            WorkerReadiness::new(owned_directory.diagnostic_path().join(readiness_name))?;
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
        let record = match ScenarioGate::parse(gate)? {
            ScenarioGate::Concurrency => {
                run_concurrency_scenario(&registry, execution_timeout, readiness)?
            },
            ScenarioGate::Resource => {
                run_resource_scenario(&registry, execution_timeout, readiness)?
            },
        };
        Ok(record)
    })();
    write_child_outcome(&owned_directory, OUTCOME_NAME, &result)?;
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

fn write_child_outcome(
    directory: &DirectoryCapability,
    name: &str,
    result: &Result<String, XtaskError>,
) -> Result<(), XtaskError> {
    let content = match result {
        Ok(record) => format!("ok\n{record}\n"),
        Err(error) => format!("error\n{error}\n"),
    };
    if content.len() > MAXIMUM_CHILD_OUTCOME_BYTES {
        return Err(XtaskError::invalid_path(
            directory.diagnostic_path(),
            "bounded runner outcome exceeds its exact maximum",
        ));
    }
    directory.create_file(name, content.as_bytes(), MAXIMUM_CHILD_OUTCOME_BYTES)?;
    directory.sync()
}

fn require_normal_component(value: &str, label: &str) -> Result<(), XtaskError> {
    let mut components = Path::new(value).components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        return Ok(());
    }
    Err(XtaskError::invalid(
        "bounded runner child arguments",
        format!("{label} identity is not one normal path component"),
    ))
}

fn open_owned_outcome_directory(path: &Path) -> Result<DirectoryCapability, XtaskError> {
    let root = std::env::current_dir()
        .map_err(|source| XtaskError::io("resolve bounded runner workspace", source))?;
    let temporary_root = fs::canonicalize(root.join("target/quality/tmp"))
        .map_err(|source| XtaskError::io("resolve owned quality temporary root", source))?;
    let canonical = fs::canonicalize(path)
        .map_err(|source| XtaskError::io("resolve bounded runner outcome ticket", source))?;
    if canonical != path
        || !canonical.starts_with(&temporary_root)
        || canonical
            .strip_prefix(&temporary_root)
            .ok()
            .is_none_or(|relative| {
                !relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
            })
    {
        return Err(XtaskError::invalid_path(
            path,
            "bounded runner outcome ticket escaped its owned canonical temporary root",
        ));
    }
    DirectoryCapability::open(&canonical, "bounded runner outcome ticket")
}
