//! Frozen Dynamic Quality target descriptors.
//!
//! This module owns the bounded registry used by `EG-DYNAMIC`.  It keeps
//! detector choice, retained seed/corpus identity, and command construction
//! independent from the general quality aggregation layer.  Future owners add
//! a descriptor for a real property, state-model, fuzz, corpus, Miri,
//! sanitizer, or Loom target; they do not add an ad-hoc command path.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::error::XtaskError;
use crate::quality::Profile;

const REGISTRY_PATH: &str = "qualification/engineering/dynamic-targets.tsv";
const REGISTRY_HEADER: &str = "target_id\tgate_id\tkind\tstages\ttool\targuments\tcorpus\tseed\tschedule\tminimized_failure\toutput_protocol\ttimeout_seconds";
const MAXIMUM_REGISTRY_BYTES: usize = 16_384;
const MAXIMUM_TARGETS: usize = 32;
const MAXIMUM_FIELD_BYTES: usize = 256;
const DYNAMIC_GATE: &str = "EG-DYNAMIC";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicKind {
    Property,
    StateModel,
    Fuzz,
    Corpus,
    Miri,
    Sanitizer,
    Loom,
}

impl DynamicKind {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "property" => Ok(Self::Property),
            "state-model" => Ok(Self::StateModel),
            "fuzz" => Ok(Self::Fuzz),
            "corpus" => Ok(Self::Corpus),
            "miri" => Ok(Self::Miri),
            "sanitizer" => Ok(Self::Sanitizer),
            "loom" => Ok(Self::Loom),
            _ => Err(XtaskError::invalid(
                "dynamic target registry",
                format!("unknown dynamic detector kind `{value}`"),
            )),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Property => "property",
            Self::StateModel => "state-model",
            Self::Fuzz => "fuzz",
            Self::Corpus => "corpus",
            Self::Miri => "miri",
            Self::Sanitizer => "sanitizer",
            Self::Loom => "loom",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicOutputProtocol {
    ExitStatusV1,
    ExactLineV1,
}

impl DynamicOutputProtocol {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "exit-status-v1" => Ok(Self::ExitStatusV1),
            "exact-line-v1" => Ok(Self::ExactLineV1),
            _ => Err(XtaskError::invalid(
                "dynamic target registry",
                format!("unknown dynamic target output protocol `{value}`"),
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ExitStatusV1 => "exit-status-v1",
            Self::ExactLineV1 => "exact-line-v1",
        }
    }
}

#[derive(Debug)]
pub(crate) struct DynamicTarget {
    id: String,
    kind: DynamicKind,
    stages: BTreeSet<String>,
    tool: String,
    arguments: Vec<String>,
    corpus: String,
    seed: String,
    schedule: String,
    minimized_failure: String,
    output_protocol: DynamicOutputProtocol,
    timeout: Duration,
}

impl DynamicTarget {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn kind(&self) -> DynamicKind {
        self.kind
    }

    pub(crate) fn tool_id(&self) -> &str {
        &self.tool
    }

    pub(crate) fn arguments_slice(&self) -> &[String] {
        &self.arguments
    }

    pub(crate) fn corpus(&self) -> &str {
        &self.corpus
    }

    pub(crate) fn seed(&self) -> &str {
        &self.seed
    }

    pub(crate) fn schedule(&self) -> &str {
        &self.schedule
    }

    pub(crate) fn minimized_failure(&self) -> &str {
        &self.minimized_failure
    }

    pub(crate) fn output_protocol_label(&self) -> &'static str {
        self.output_protocol.label()
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn validate_output(&self, stdout: &str) -> Result<(), XtaskError> {
        match self.output_protocol {
            DynamicOutputProtocol::ExitStatusV1 => Ok(()),
            DynamicOutputProtocol::ExactLineV1
                if stdout.trim() == "dynamic-target-result-v1;status=passed" =>
            {
                Ok(())
            },
            DynamicOutputProtocol::ExactLineV1 => Err(XtaskError::invalid(
                "dynamic target output",
                "dynamic target result is malformed or does not match the registered exact-line-v1 protocol",
            )),
        }
    }

    pub(crate) fn retained_identity(&self) -> String {
        format!(
            "target={};kind={};corpus={};seed={};schedule={};minimized-failure={};output-protocol={}",
            self.id,
            self.kind.label(),
            self.corpus,
            self.seed,
            self.schedule,
            self.minimized_failure,
            self.output_protocol.label(),
        )
    }

    fn selected_by(&self, profile: Profile) -> bool {
        match profile {
            Profile::PreCommit => false,
            Profile::Pr => self.stages.contains("PR"),
            Profile::Ext => self.stages.contains("PR") || self.stages.contains("EXT"),
            Profile::Qual => {
                self.stages.contains("PR")
                    || self.stages.contains("EXT")
                    || self.stages.contains("QUAL")
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct FrozenDynamicTargets {
    targets: Vec<DynamicTarget>,
}

impl FrozenDynamicTargets {
    pub(crate) fn load(
        root: &Path,
        owning_gate_stages: &BTreeSet<String>,
    ) -> Result<Self, XtaskError> {
        let path = root.join(REGISTRY_PATH);
        let bytes = fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                &path,
                format!("dynamic target registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| XtaskError::invalid_path(&path, "dynamic target registry is not UTF-8"))?;
        let mut lines = text.lines();
        let Some(header) = lines.next() else {
            return Err(XtaskError::invalid_path(
                &path,
                "dynamic target registry is empty",
            ));
        };
        if header != REGISTRY_HEADER {
            return Err(XtaskError::invalid_path(
                &path,
                "dynamic target registry header does not match the registered schema",
            ));
        }

        let mut ids = BTreeSet::new();
        let mut targets = Vec::new();
        for (index, line) in lines.enumerate() {
            if targets.len() >= MAXIMUM_TARGETS {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("dynamic target registry exceeds {MAXIMUM_TARGETS} targets"),
                ));
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                id,
                gate,
                kind,
                stages,
                tool,
                arguments,
                corpus,
                seed,
                schedule,
                minimized_failure,
                output_protocol,
                timeout_seconds,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "dynamic target registry row {} has the wrong field count",
                        index + 2
                    ),
                ));
            };
            for field in [
                *id,
                *gate,
                *kind,
                *stages,
                *tool,
                *arguments,
                *corpus,
                *seed,
                *schedule,
                *minimized_failure,
                *output_protocol,
                *timeout_seconds,
            ] {
                if field.is_empty() || field.len() > MAXIMUM_FIELD_BYTES {
                    return Err(XtaskError::invalid_path(
                        &path,
                        format!(
                            "dynamic target registry row {} contains an invalid bounded field",
                            index + 2
                        ),
                    ));
                }
            }
            if *gate != DYNAMIC_GATE {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("dynamic target `{id}` is assigned to an unsupported gate"),
                ));
            }
            if !ids.insert((*id).to_owned()) {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("dynamic target registry repeats target `{id}`"),
                ));
            }
            for (label, value) in [
                ("corpus", *corpus),
                ("seed", *seed),
                ("schedule", *schedule),
                ("minimized failure", *minimized_failure),
            ] {
                validate_input_identity(&path, label, value)?;
            }
            let stages = parse_stages(&path, stages)?;
            if !stages.is_subset(owning_gate_stages) {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "dynamic target stages must be an exact nonempty subset of owning gate stages `{}`",
                        display_stages(owning_gate_stages),
                    ),
                ));
            }
            let arguments = parse_arguments(&path, arguments)?;
            let timeout = parse_timeout(&path, timeout_seconds)?;
            targets.push(DynamicTarget {
                id: (*id).to_owned(),
                kind: DynamicKind::parse(kind)?,
                stages,
                tool: (*tool).to_owned(),
                arguments,
                corpus: (*corpus).to_owned(),
                seed: (*seed).to_owned(),
                schedule: (*schedule).to_owned(),
                minimized_failure: (*minimized_failure).to_owned(),
                output_protocol: DynamicOutputProtocol::parse(output_protocol)?,
                timeout,
            });
        }
        if targets.is_empty() {
            return Err(XtaskError::invalid_path(
                &path,
                "dynamic target registry requires at least one target",
            ));
        }
        Ok(Self { targets })
    }

    pub(crate) fn selected(&self, profile: Profile) -> impl Iterator<Item = &DynamicTarget> {
        self.targets
            .iter()
            .filter(move |target| target.selected_by(profile))
    }
}

fn validate_input_identity(path: &Path, label: &str, value: &str) -> Result<(), XtaskError> {
    if value == "-"
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(XtaskError::invalid_path(
            path,
            format!("dynamic target {label} identity must be a concrete bounded input"),
        ));
    }
    Ok(())
}

fn display_stages(stages: &BTreeSet<String>) -> String {
    ["PR", "EXT", "QUAL"]
        .into_iter()
        .filter(|stage| stages.contains(*stage))
        .collect::<Vec<_>>()
        .join("|")
}

fn parse_stages(path: &Path, value: &str) -> Result<BTreeSet<String>, XtaskError> {
    let stages = value.split('|').map(str::to_owned).collect::<BTreeSet<_>>();
    if stages.is_empty()
        || stages
            .iter()
            .any(|stage| !matches!(stage.as_str(), "PR" | "EXT" | "QUAL"))
    {
        return Err(XtaskError::invalid_path(
            path,
            "dynamic target stages must contain only PR, EXT, or QUAL",
        ));
    }
    Ok(stages)
}

fn parse_arguments(path: &Path, value: &str) -> Result<Vec<String>, XtaskError> {
    let arguments = value.split('|').map(str::to_owned).collect::<Vec<_>>();
    if arguments.is_empty()
        || arguments
            .iter()
            .any(|argument| argument.is_empty() || argument.len() > MAXIMUM_FIELD_BYTES)
    {
        return Err(XtaskError::invalid_path(
            path,
            "dynamic target arguments must be a non-empty bounded canonical list",
        ));
    }
    Ok(arguments)
}

fn parse_timeout(path: &Path, value: &str) -> Result<Duration, XtaskError> {
    let seconds = value.parse::<u64>().map_err(|_| {
        XtaskError::invalid_path(
            path,
            "dynamic target timeout is not a canonical positive unsigned value",
        )
    })?;
    if seconds == 0 || value != seconds.to_string() {
        return Err(XtaskError::invalid_path(
            path,
            "dynamic target timeout is not a canonical positive unsigned value",
        ));
    }
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::{DynamicKind, DynamicOutputProtocol};

    #[test]
    fn every_registered_dynamic_detector_kind_has_a_closed_parser_label_pair() {
        for value in [
            "property",
            "state-model",
            "fuzz",
            "corpus",
            "miri",
            "sanitizer",
            "loom",
        ] {
            let parsed = DynamicKind::parse(value);
            assert!(parsed.is_ok(), "registered kind `{value}` must parse");
            if let Ok(kind) = parsed {
                assert_eq!(kind.label(), value);
            }
        }
        assert!(DynamicKind::parse("best-effort").is_err());
    }

    #[test]
    fn dynamic_output_protocols_are_closed_and_versioned() {
        assert!(DynamicOutputProtocol::parse("exit-status-v1").is_ok());
        assert!(DynamicOutputProtocol::parse("exact-line-v1").is_ok());
        assert!(DynamicOutputProtocol::parse("best-effort").is_err());
    }
}
