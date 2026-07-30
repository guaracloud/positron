//! Independent retained-evidence expectations for `EG-MATRIX`.
//!
//! This verifier re-parses the frozen target catalog and derives command and
//! evidence identities without using the runner's plan builder or serializer.

use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;
use crate::matrix_targets::FrozenMatrixTargets;
use crate::quality::Profile;
use crate::registry::{Gate, Tool};

const TOOL_ID: &str = "cargo";
const TOOL_VERSION: &str = "1.96.0";

#[derive(Debug)]
pub(crate) struct ExpectedMatrixStep {
    program: String,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    maximum_timeout: Duration,
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
    passed_detail: String,
}

impl ExpectedMatrixGate {
    pub(crate) fn capture(
        root: &Path,
        gate: &Gate,
        profile: Profile,
        tools: &[Tool],
    ) -> Result<Self, XtaskError> {
        let targets = FrozenMatrixTargets::load(root, gate)?;
        let cargo = tools
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
        let mut identities = Vec::new();
        for target in targets.selected(profile) {
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
                    "POSITRON_MATRIX_TARGET_IDENTITY".to_owned(),
                    target.identity().to_owned(),
                ),
                (
                    "POSITRON_MATRIX_DIAGNOSTIC".to_owned(),
                    "diagnostic-only".to_owned(),
                ),
            ];
            let argv = vec!["--version".to_owned()];
            let argv_digest = digest_sequence(b"positron-matrix-argv-v1\0", &argv);
            let environment_digest =
                digest_pairs(b"positron-matrix-environment-v1\0", &environment);
            let input_digest = digest_sequence(
                b"positron-matrix-input-v1\0",
                &[target.identity().to_owned()],
            );
            let plan_digest = digest_sequence(
                b"positron-matrix-plan-v1\0",
                &[
                    "matrix-execution-plan-v1".to_owned(),
                    target.id().to_owned(),
                    target.kind().label().to_owned(),
                    TOOL_ID.to_owned(),
                    TOOL_VERSION.to_owned(),
                    cargo.command.clone(),
                    argv_digest.clone(),
                    environment_digest.clone(),
                    input_digest.clone(),
                    target.registry_digest().to_owned(),
                ],
            );
            identities.push(format!("{}; plan=matrix-execution-plan-v1;tool-id={TOOL_ID};tool-version={TOOL_VERSION};program={};argv-digest={argv_digest};environment-digest={environment_digest};input-digest={input_digest};registry-digest={};plan-digest={plan_digest}", target.retained_identity(), cargo.command, target.registry_digest()));
            steps.push(ExpectedMatrixStep {
                program: cargo.command.clone(),
                arguments: argv,
                environment,
                maximum_timeout: target.timeout(),
            });
        }
        Ok(Self {
            steps,
            passed_detail: identities.join(" | "),
        })
    }
    pub(crate) fn steps(&self) -> &[ExpectedMatrixStep] {
        &self.steps
    }
    pub(crate) fn passed_detail(&self) -> &str {
        &self.passed_detail
    }
}

fn digest_sequence(domain: &[u8], values: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for value in values {
        hasher.update(value.as_bytes());
        hasher.update(b"\0");
    }
    format!("sha256:{:x}", hasher.finalize())
}
fn digest_pairs(domain: &[u8], values: &[(String, String)]) -> String {
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
