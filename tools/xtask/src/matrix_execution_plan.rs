//! Canonical controlled plans for diagnostic `EG-MATRIX` targets.
//!
//! The plan binds each exact descriptor to one pinned tool, argv, environment,
//! input identity, timeout, and retained digest before process launch.

use sha2::{Digest, Sha256};

use crate::error::XtaskError;
use crate::matrix_targets::MatrixTarget;
use crate::registry::Tool;

const PLAN_VERSION: &str = "matrix-execution-plan-v1";
const TOOL_ID: &str = "cargo";
const TOOL_VERSION: &str = "1.96.0";

#[derive(Debug)]
pub(crate) struct MatrixExecutionPlan {
    program: String,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    timeout: std::time::Duration,
    retained_identity: String,
    binding_manifest: Vec<u8>,
}

impl MatrixExecutionPlan {
    pub(crate) fn capture(target: &MatrixTarget, tools: &[Tool]) -> Result<Self, XtaskError> {
        let tool = tools
            .iter()
            .find(|tool| tool.id == TOOL_ID)
            .ok_or_else(|| {
                XtaskError::invalid(
                    "matrix execution plan",
                    "exact target requires missing registered cargo tool",
                )
            })?;
        if tool.command != "cargo"
            || tool.version != TOOL_VERSION
            || tool
                .version_arguments
                .iter()
                .map(String::as_str)
                .ne(["--version"])
        {
            return Err(XtaskError::invalid(
                "matrix execution plan",
                "exact target cargo tool binding drifted from the frozen contract",
            ));
        }
        let base_arguments = vec!["--version".to_owned()];
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
        let argv_digest = digest_sequence(b"positron-matrix-argv-v1\0", &base_arguments);
        let environment_digest = digest_pairs(b"positron-matrix-environment-v1\0", &environment);
        let input_digest = digest_sequence(
            b"positron-matrix-input-v1\0",
            &[target.identity().to_owned()],
        );
        let plan_digest = digest_sequence(
            b"positron-matrix-plan-v1\0",
            &[
                PLAN_VERSION.to_owned(),
                target.id().to_owned(),
                target.kind().label().to_owned(),
                target.mode().label().to_owned(),
                TOOL_ID.to_owned(),
                TOOL_VERSION.to_owned(),
                tool.command.clone(),
                argv_digest.clone(),
                environment_digest.clone(),
                input_digest.clone(),
                target.registry_digest().to_owned(),
            ],
        );
        let retained_identity = format!(
            "{}; plan={PLAN_VERSION};tool-id={TOOL_ID};tool-version={TOOL_VERSION};program={};argv-digest={argv_digest};environment-digest={environment_digest};input-digest={input_digest};registry-digest={};plan-digest={plan_digest}",
            target.retained_identity(),
            tool.command,
            target.registry_digest(),
        );
        let binding_manifest = format!(
            "binding=matrix-target-binding-v1;target-id={};descriptor-identity={};stages={};mode={};tool-id={TOOL_ID};tool-version={TOOL_VERSION};program={};argv-digest={argv_digest};environment-digest={environment_digest};input-identity={};input-digest={input_digest};registry-digest={};plan-digest={plan_digest}",
            target.id(),
            target.identity(),
            target.stages(),
            target.mode().label(),
            tool.command,
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
        Ok(Self {
            program: tool.command.clone(),
            arguments,
            environment,
            timeout: target.timeout(),
            retained_identity,
            binding_manifest,
        })
    }

    pub(crate) fn program(&self) -> &str {
        &self.program
    }
    pub(crate) fn arguments(&self) -> impl Iterator<Item = &str> {
        self.arguments.iter().map(String::as_str)
    }
    pub(crate) fn environment(&self) -> &[(String, String)] {
        &self.environment
    }
    pub(crate) fn timeout(&self) -> std::time::Duration {
        self.timeout
    }
    pub(crate) fn retained_identity(&self) -> &str {
        &self.retained_identity
    }
    pub(crate) fn binding_manifest(&self) -> &[u8] {
        &self.binding_manifest
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
