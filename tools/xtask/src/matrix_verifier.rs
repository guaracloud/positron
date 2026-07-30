//! Independent retained-evidence expectations for `EG-MATRIX`.
//!
//! This verifier re-parses the frozen target catalog and derives command and
//! evidence identities without using the runner's plan builder or serializer.

use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;
use crate::matrix_product_target::load as load_product_target;
use crate::matrix_targets::FrozenMatrixTargets;
use crate::quality::Profile;
use crate::registry::{Gate, Registry};

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
    product_outcome: String,
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
            let argv = vec!["--version".to_owned()];
            steps.push(ExpectedMatrixStep {
                program: cargo.command.clone(),
                arguments: argv,
                environment,
                maximum_timeout: target.timeout(),
            });
        }
        let product_outcome = expected_product_outcome(root, registry, profile)?;
        Ok(Self {
            steps,
            product_outcome,
        })
    }
    pub(crate) fn steps(&self) -> &[ExpectedMatrixStep] {
        &self.steps
    }

    pub(crate) fn product_outcome(&self) -> &str {
        &self.product_outcome
    }
}

fn expected_product_outcome(
    root: &Path,
    registry: &Registry,
    profile: Profile,
) -> Result<String, XtaskError> {
    let Some(target) = load_product_target(root)? else {
        return Ok("product-target=none; outcome=NoActiveProductTarget; qualification=no-product-qualification".to_owned());
    };
    if !matches!(profile, Profile::Pr)
        || !registry.has_active_artifact_scope(target.artifact_scope())
    {
        return Ok(format!(
            "product-target={}; identity={}; outcome=NoActiveProductTarget; qualification=no-product-qualification",
            target.id(),
            target.identity(),
        ));
    }
    Ok(format!(
        "product-target={}; identity={}; outcome=ProductTargetDiagnostic; qualification=no-product-qualification; canonical generation parity is clean across configuration, Rust, HTTP/JSON, OpenAPI, Schema Digest, and validation fixtures; ",
        target.id(),
        target.identity(),
    ))
}
