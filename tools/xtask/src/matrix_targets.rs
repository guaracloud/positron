//! Frozen diagnostic exact-target descriptors for `EG-MATRIX`.
//!
//! These rows are a closed M0 runner-capability matrix. They name the target
//! shapes that later exact-artifact qualification will bind, but cannot
//! themselves advance a Qualification Cell.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;
use crate::quality::Profile;
use crate::registry::Gate;

const PATH: &str = "qualification/engineering/exact-targets.tsv";
const HEADER: &str =
    "target_id\tkind\tmode\tgate_id\tstages\towner\tidentity\tdiagnostic\ttimeout_seconds";
const OWNER: &str = "Quality Engineering";
const GATE: &str = "EG-MATRIX";
const STAGES: &str = "PR";
const DIAGNOSTIC: &str = "diagnostic-only";
const RUNNER_CAPABILITY: &str = "runner-capability";
const MAXIMUM_BYTES: usize = 16_384;
const MAXIMUM_FIELD_BYTES: usize = 256;
const MAXIMUM_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MatrixKind {
    Compile,
    Contract,
    Protocol,
    Producer,
    Provider,
    Platform,
    Architecture,
    Filesystem,
    StorageClass,
    Registry,
    Distribution,
    Sdk,
    Compatibility,
    Evidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MatrixTargetMode {
    RunnerCapability,
}

impl MatrixTargetMode {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            RUNNER_CAPABILITY => Ok(Self::RunnerCapability),
            _ => Err(XtaskError::invalid(
                "exact target registry",
                format!("unknown matrix target mode `{value}`"),
            )),
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::RunnerCapability => RUNNER_CAPABILITY,
        }
    }
}

impl MatrixKind {
    pub(crate) const ALL: [Self; 14] = [
        Self::Compile,
        Self::Contract,
        Self::Protocol,
        Self::Producer,
        Self::Provider,
        Self::Platform,
        Self::Architecture,
        Self::Filesystem,
        Self::StorageClass,
        Self::Registry,
        Self::Distribution,
        Self::Sdk,
        Self::Compatibility,
        Self::Evidence,
    ];

    pub(crate) fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "compile" => Ok(Self::Compile),
            "contract" => Ok(Self::Contract),
            "protocol" => Ok(Self::Protocol),
            "producer" => Ok(Self::Producer),
            "provider" => Ok(Self::Provider),
            "platform" => Ok(Self::Platform),
            "architecture" => Ok(Self::Architecture),
            "filesystem" => Ok(Self::Filesystem),
            "storage-class" => Ok(Self::StorageClass),
            "registry" => Ok(Self::Registry),
            "distribution" => Ok(Self::Distribution),
            "sdk" => Ok(Self::Sdk),
            "compatibility" => Ok(Self::Compatibility),
            "evidence" => Ok(Self::Evidence),
            _ => Err(XtaskError::invalid(
                "exact target registry",
                format!("unknown matrix kind `{value}`"),
            )),
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Contract => "contract",
            Self::Protocol => "protocol",
            Self::Producer => "producer",
            Self::Provider => "provider",
            Self::Platform => "platform",
            Self::Architecture => "architecture",
            Self::Filesystem => "filesystem",
            Self::StorageClass => "storage-class",
            Self::Registry => "registry",
            Self::Distribution => "distribution",
            Self::Sdk => "sdk",
            Self::Compatibility => "compatibility",
            Self::Evidence => "evidence",
        }
    }
}

#[derive(Debug)]
pub(crate) struct MatrixTarget {
    id: String,
    kind: MatrixKind,
    mode: MatrixTargetMode,
    identity: String,
    timeout: Duration,
    registry_digest: String,
}

impl MatrixTarget {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn kind(&self) -> MatrixKind {
        self.kind
    }
    pub(crate) fn mode(&self) -> MatrixTargetMode {
        self.mode
    }
    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }
    pub(crate) fn registry_digest(&self) -> &str {
        &self.registry_digest
    }

    pub(crate) fn validate_output(&self, stdout: &str) -> Result<(), XtaskError> {
        let mut fields = stdout.split_ascii_whitespace();
        if fields.next() == Some("cargo")
            && fields.next() == Some("1.96.0")
            && fields.next().is_none_or(|field| field.starts_with('('))
        {
            return Ok(());
        }
        Err(XtaskError::invalid(
            "exact target output",
            format!(
                "diagnostic target `{}` returned a malformed cargo-version-v1 result",
                self.id
            ),
        ))
    }

    pub(crate) fn retained_identity(&self) -> String {
        format!(
            "target={};kind={};mode={};identity={};diagnostic=diagnostic-only;timeout-seconds={}",
            self.id,
            self.kind.label(),
            self.mode.label(),
            self.identity,
            self.timeout.as_secs()
        )
    }
}

#[derive(Debug)]
pub(crate) struct FrozenMatrixTargets {
    targets: Vec<MatrixTarget>,
}

impl FrozenMatrixTargets {
    pub(crate) fn load(root: &Path, gate: &Gate) -> Result<Self, XtaskError> {
        if gate.id != GATE
            || gate.coordinator != OWNER
            || !gate.stages.contains("PR")
            || !gate.stages.contains("EXT")
            || !gate.stages.contains("QUAL")
        {
            return Err(XtaskError::invalid(
                "exact target registry",
                "EG-MATRIX does not retain its registered owner and PR|EXT|QUAL gate boundary",
            ));
        }
        let path = root.join(PATH);
        let bytes = fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        if bytes.len() > MAXIMUM_BYTES {
            return Err(XtaskError::invalid_path(
                &path,
                format!("exact target registry exceeds {MAXIMUM_BYTES} bytes"),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| XtaskError::invalid_path(&path, "exact target registry is not UTF-8"))?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(XtaskError::invalid_path(
                &path,
                "exact target registry header does not match the registered schema",
            ));
        }
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        let mut ids = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        let mut targets = Vec::with_capacity(MatrixKind::ALL.len());
        for (offset, line) in lines.enumerate() {
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                id,
                kind,
                mode,
                gate_id,
                stages,
                owner,
                identity,
                diagnostic,
                timeout,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "exact target registry row {} has the wrong field count",
                        offset + 2
                    ),
                ));
            };
            if fields
                .iter()
                .any(|field| field.is_empty() || field.len() > MAXIMUM_FIELD_BYTES)
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "exact target registry row {} contains an invalid bounded field",
                        offset + 2
                    ),
                ));
            }
            let kind = MatrixKind::parse(kind)?;
            let mode = MatrixTargetMode::parse(mode)?;
            let expected_kind = MatrixKind::ALL.get(offset).copied();
            let expected_descriptor = canonical_descriptor(kind);
            if expected_kind != Some(kind)
                || expected_descriptor != Some((*id, *identity))
                || mode != MatrixTargetMode::RunnerCapability
                || *gate_id != GATE
                || *stages != STAGES
                || *owner != OWNER
                || *diagnostic != DIAGNOSTIC
                || !ids.insert((*id).to_owned())
                || !kinds.insert(kind.label())
                || !valid_identity(identity)
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "exact target `{id}` violates its closed M0 diagnostic descriptor contract"
                    ),
                ));
            }
            let seconds = timeout.parse::<u64>().map_err(|_| {
                XtaskError::invalid_path(
                    &path,
                    "exact target timeout is not a canonical positive unsigned value",
                )
            })?;
            if seconds == 0 || seconds > MAXIMUM_TIMEOUT_SECONDS || *timeout != seconds.to_string()
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    "exact target timeout is not a canonical bounded unsigned value",
                ));
            }
            targets.push(MatrixTarget {
                id: (*id).to_owned(),
                kind,
                mode,
                identity: (*identity).to_owned(),
                timeout: Duration::from_secs(seconds),
                registry_digest: digest.clone(),
            });
        }
        if targets.len() != MatrixKind::ALL.len() || kinds.len() != MatrixKind::ALL.len() {
            return Err(XtaskError::invalid_path(
                &path,
                "exact target registry must contain every closed matrix kind exactly once",
            ));
        }
        Ok(Self { targets })
    }

    pub(crate) fn selected(&self, profile: Profile) -> impl Iterator<Item = &MatrixTarget> {
        self.targets
            .iter()
            .filter(move |_| matches!(profile, Profile::Pr))
    }
}

fn valid_identity(value: &str) -> bool {
    value != "-"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn canonical_descriptor(kind: MatrixKind) -> Option<(&'static str, &'static str)> {
    match kind {
        MatrixKind::Compile => Some(("rust-host-1", "rust-2024-host-v1")),
        MatrixKind::Contract => Some(("api-contract-1", "canonical-api-v1")),
        MatrixKind::Protocol => Some(("otlp-protocol-1", "otlp-grpc-v1")),
        MatrixKind::Producer => Some(("producer-fixture-1", "producer-fixture-v1")),
        MatrixKind::Provider => Some(("provider-fixture-1", "provider-fixture-v1")),
        MatrixKind::Platform => Some(("macos-host-1", "macos-host-v1")),
        MatrixKind::Architecture => Some(("crate-graph-1", "architecture-edges-v1")),
        MatrixKind::Filesystem => Some(("local-fs-1", "local-filesystem-v1")),
        MatrixKind::StorageClass => Some(("storage-class-1", "storage-class-fixture-v1")),
        MatrixKind::Registry => Some(("sdk-registry-1", "sdk-registry-fixture-v1")),
        MatrixKind::Distribution => Some(("native-archive-1", "native-archive-fixture-v1")),
        MatrixKind::Sdk => Some(("generated-sdk-1", "generated-sdk-fixture-v1")),
        MatrixKind::Compatibility => Some(("old-new-api-1", "old-new-api-fixture-v1")),
        MatrixKind::Evidence => Some(("evidence-schema-1", "evidence-schema-v3")),
    }
}

#[cfg(test)]
mod tests {
    use super::MatrixKind;
    #[test]
    fn closed_matrix_kind_parser_rejects_best_effort_labels() {
        assert_eq!(MatrixKind::ALL.len(), 14);
        assert!(MatrixKind::parse("compatibility").is_ok());
        assert!(MatrixKind::parse("best-effort").is_err());
    }
}
