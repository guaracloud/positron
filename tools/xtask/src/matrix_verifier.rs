//! Independent retained-evidence expectations for `EG-MATRIX`.
//!
//! This verifier re-parses the frozen target catalog and derives command and
//! evidence identities without using the runner's plan builder or serializer.

use std::fs;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;
use crate::matrix_product_target::{MatrixProductOutcome, load as load_product_target};
use crate::matrix_targets::FrozenMatrixTargets;
use crate::quality::Profile;
use crate::registry::{Gate, Registry};

const TOOL_ID: &str = "cargo";
const TOOL_VERSION: &str = "1.96.0";
const GENERATION_ARTIFACTS: [&str; 8] = [
    "api/positron/v1/http.json",
    "api/positron/v1/openapi.json",
    "api/positron/v1/schema.sha256",
    "api/positron/v1/validation-fixtures.json",
    "configuration/reference.md",
    "configuration/schema.json",
    "configuration/validation-fixtures.json",
    "crates/positron-api/src/generated.rs",
];

#[derive(Debug)]
pub(crate) struct ExpectedMatrixStep {
    program: String,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    maximum_timeout: Duration,
    binding_manifest: Vec<u8>,
}

impl ExpectedMatrixStep {
    pub(crate) fn program(&self) -> &str {
        &self.program
    }
    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }
    pub(crate) fn maximum_timeout(&self) -> Duration {
        self.maximum_timeout
    }
    pub(crate) fn binding_manifest(&self) -> &[u8] {
        &self.binding_manifest
    }
    pub(crate) fn invocation_environment_digest(&self, snapshot_digest: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"positron-matrix-invocation-environment-v1\0");
        hasher.update(snapshot_digest.as_bytes());
        hasher.update(b"\0");
        for (name, value) in &self.environment {
            hasher.update(name.as_bytes());
            hasher.update(b"=");
            hasher.update(value.as_bytes());
            hasher.update(b"\0");
        }
        format!("sha256:{:x}", hasher.finalize())
    }
}

#[derive(Debug)]
pub(crate) struct ExpectedMatrixGate {
    steps: Vec<ExpectedMatrixStep>,
    product_outcome: MatrixProductOutcome,
    binding_root: String,
    generation_root: Option<String>,
}

impl ExpectedMatrixGate {
    pub(crate) fn capture(
        root: &Path,
        gate: &Gate,
        profile: Profile,
        registry: &Registry,
    ) -> Result<Self, XtaskError> {
        let targets = FrozenMatrixTargets::load(root, gate)?;
        let cargo = registry
            .tools
            .iter()
            .find(|tool| tool.id == TOOL_ID)
            .ok_or_else(|| {
                XtaskError::invalid(
                    "matrix retained-evidence verifier",
                    "missing registered cargo tool",
                )
            })?;
        if cargo.command != "cargo"
            || cargo.version != TOOL_VERSION
            || cargo
                .version_arguments
                .iter()
                .map(String::as_str)
                .ne(["--version"])
        {
            return Err(XtaskError::invalid(
                "matrix retained-evidence verifier",
                "registered cargo tool does not match the frozen exact-target contract",
            ));
        }
        let mut steps = Vec::new();
        for target in targets
            .iter()
            .filter(|_| matches!(profile, Profile::Pr | Profile::Ext))
        {
            let environment = vec![
                (
                    "POSITRON_MATRIX_TARGET_ID".to_owned(),
                    target.id().to_owned(),
                ),
                (
                    "POSITRON_MATRIX_KIND".to_owned(),
                    target.kind().label().to_owned(),
                ),
                (
                    "POSITRON_MATRIX_MODE".to_owned(),
                    target.mode().label().to_owned(),
                ),
                (
                    "POSITRON_MATRIX_TARGET_IDENTITY".to_owned(),
                    target.identity().to_owned(),
                ),
                (
                    "POSITRON_MATRIX_DIAGNOSTIC".to_owned(),
                    "diagnostic-only".to_owned(),
                ),
            ];
            let base_argv = vec!["--version".to_owned()];
            let argv_digest = independent_sequence_digest(b"positron-matrix-argv-v1\0", &base_argv);
            let environment_digest =
                independent_pair_digest(b"positron-matrix-environment-v1\0", &environment);
            let input_digest = independent_sequence_digest(
                b"positron-matrix-input-v1\0",
                &[target.identity().to_owned()],
            );
            let plan_digest = independent_sequence_digest(
                b"positron-matrix-plan-v1\0",
                &[
                    "matrix-execution-plan-v1".to_owned(),
                    target.id().to_owned(),
                    target.kind().label().to_owned(),
                    target.mode().label().to_owned(),
                    TOOL_ID.to_owned(),
                    TOOL_VERSION.to_owned(),
                    cargo.command.clone(),
                    argv_digest.clone(),
                    environment_digest.clone(),
                    input_digest.clone(),
                    target.registry_digest().to_owned(),
                ],
            );
            let binding_manifest = format!(
                "binding=matrix-target-binding-v1;target-id={};descriptor-identity={};stages={};mode={};tool-id={TOOL_ID};tool-version={TOOL_VERSION};program={};argv-digest={argv_digest};environment-digest={environment_digest};input-identity={};input-digest={input_digest};registry-digest={};plan-digest={plan_digest}",
                target.id(),
                target.identity(),
                target.stages(),
                target.mode().label(),
                cargo.command,
                target.identity(),
                target.registry_digest(),
            )
            .into_bytes();
            let binding_digest = format!("sha256:{:x}", Sha256::digest(&binding_manifest));
            let arguments = vec![
                "--config".to_owned(),
                format!("env.POSITRON_MATRIX_BINDING_DIGEST=\"{binding_digest}\""),
                "--version".to_owned(),
            ];
            steps.push(ExpectedMatrixStep {
                program: cargo.command.clone(),
                arguments,
                environment,
                maximum_timeout: target.timeout(),
                binding_manifest,
            });
        }
        let binding_root =
            independent_binding_root(steps.iter().map(ExpectedMatrixStep::binding_manifest));
        let product_outcome = expected_product_outcome(root, registry, profile)?;
        let generation_root = matches!(profile, Profile::Pr | Profile::Ext)
            .then(|| independent_generation_root(root))
            .transpose()?;
        Ok(Self {
            steps,
            product_outcome,
            binding_root,
            generation_root,
        })
    }
    pub(crate) fn steps(&self) -> &[ExpectedMatrixStep] {
        &self.steps
    }

    pub(crate) fn product_outcome(&self) -> MatrixProductOutcome {
        self.product_outcome
    }

    pub(crate) fn binding_root(&self) -> &str {
        &self.binding_root
    }

    pub(crate) fn generation_root(&self) -> Option<&str> {
        self.generation_root.as_deref()
    }
}

fn independent_sequence_digest(domain: &[u8], values: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for value in values {
        hasher.update(value.as_bytes());
        hasher.update(b"\0");
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn independent_pair_digest(domain: &[u8], values: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for (name, value) in values {
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update(b"\0");
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn independent_binding_root<'manifest>(manifests: impl Iterator<Item = &'manifest [u8]>) -> String {
    let manifests = manifests.collect::<Vec<_>>();
    if manifests.is_empty() {
        return "not-applicable".to_owned();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"positron-matrix-binding-root-v1\0");
    for manifest in manifests {
        hasher.update(manifest);
        hasher.update(b"\0");
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn independent_generation_root(root: &Path) -> Result<String, XtaskError> {
    let mut hasher = Sha256::new();
    for relative in GENERATION_ARTIFACTS {
        let path = root.join(relative);
        let contents = fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        let path_length = u64::try_from(relative.len()).map_err(|_| {
            XtaskError::invalid_path(&path, "artifact path length exceeds the digest format")
        })?;
        let content_length = u64::try_from(contents.len()).map_err(|_| {
            XtaskError::invalid_path(&path, "artifact byte length exceeds the digest format")
        })?;
        hasher.update(path_length.to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(content_length.to_le_bytes());
        hasher.update(contents);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn expected_product_outcome(
    root: &Path,
    registry: &Registry,
    profile: Profile,
) -> Result<MatrixProductOutcome, XtaskError> {
    let Some(target) = load_product_target(root)? else {
        return Ok(MatrixProductOutcome::Missing);
    };
    if !matches!(profile, Profile::Pr)
        || !registry.has_active_artifact_scope(target.artifact_scope())
    {
        return Ok(MatrixProductOutcome::Inactive);
    }
    Ok(MatrixProductOutcome::Diagnostic)
}
