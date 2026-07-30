//! Independent retained-evidence expectations for `EG-DYNAMIC`.
//!
//! This owner re-captures the frozen registries and independently parses each
//! detector grammar and recomputes every plan identity. It deliberately does
//! not call the runner's execution-plan builder or retained serializer.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::dynamic_catalog::{DynamicKind, FrozenDynamicCatalog};
use crate::dynamic_quality::{DynamicTarget, FrozenDynamicTargets};
use crate::error::XtaskError;
use crate::quality::Profile;
use crate::registry::Tool;

const PLAN_VERSION: &str = "dynamic-execution-plan-v1";
const NIGHTLY: &str = "+nightly-2026-07-20";

#[derive(Debug)]
pub(crate) struct ExpectedDynamicStep {
    program: String,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    maximum_timeout: Duration,
}

impl ExpectedDynamicStep {
    pub(crate) fn program(&self) -> &str {
        &self.program
    }

    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub(crate) fn invocation_environment_digest(&self, snapshot_digest: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"positron-dynamic-invocation-environment-v1\0");
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

    pub(crate) fn maximum_timeout(&self) -> Duration {
        self.maximum_timeout
    }
}

#[derive(Debug)]
pub(crate) struct ExpectedDynamicGate {
    steps: Vec<ExpectedDynamicStep>,
    passed_detail: String,
}

impl ExpectedDynamicGate {
    pub(crate) fn capture(
        root: &Path,
        owning_gate_stages: &BTreeSet<String>,
        profile: Profile,
        tools: &[Tool],
    ) -> Result<Self, XtaskError> {
        let catalog = FrozenDynamicCatalog::load(root, tools)?;
        let targets = FrozenDynamicTargets::load(root, owning_gate_stages, &catalog)?;
        let selected = targets
            .all()
            .iter()
            .filter(|target| independently_selected(target, profile))
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Err(XtaskError::invalid(
                "dynamic retained-evidence verifier",
                "selected EG-DYNAMIC profile has no independently registered targets",
            ));
        }
        let mut steps = Vec::with_capacity(selected.len());
        let mut identities = Vec::with_capacity(selected.len());
        for target in selected {
            let (step, plan_identity) = derive_step(target, tools)?;
            steps.push(step);
            identities.push(format!("{}; {plan_identity}", target_identity(target)));
        }
        Ok(Self {
            steps,
            passed_detail: identities.join(" | "),
        })
    }

    pub(crate) fn steps(&self) -> &[ExpectedDynamicStep] {
        &self.steps
    }

    pub(crate) fn passed_detail(&self) -> &str {
        &self.passed_detail
    }
}

fn derive_step(
    target: &DynamicTarget,
    tools: &[Tool],
) -> Result<(ExpectedDynamicStep, String), XtaskError> {
    if !arguments_match(target.kind(), target.arguments_slice(), target.corpus()) {
        return Err(XtaskError::invalid(
            "dynamic retained-evidence verifier",
            format!(
                "target `{}` violates the independently parsed `{}` argument grammar",
                target.id(),
                target.kind().label()
            ),
        ));
    }
    if target.capability_id() != target.kind().label() {
        return Err(XtaskError::invalid(
            "dynamic retained-evidence verifier",
            format!(
                "target `{}` capability identity is noncanonical",
                target.id()
            ),
        ));
    }
    let expected_tool_id = match target.kind() {
        DynamicKind::Fuzz | DynamicKind::Corpus => "cargo-fuzz",
        DynamicKind::Miri => "miri-nightly",
        DynamicKind::Property
        | DynamicKind::StateModel
        | DynamicKind::Sanitizer
        | DynamicKind::Loom => "cargo",
    };
    if target.tool_id() != expected_tool_id {
        return Err(XtaskError::invalid(
            "dynamic retained-evidence verifier",
            format!("target `{}` tool identity is noncanonical", target.id()),
        ));
    }
    let tool = tools
        .iter()
        .find(|tool| tool.id == expected_tool_id)
        .ok_or_else(|| {
            XtaskError::invalid(
                "dynamic retained-evidence verifier",
                format!("target `{}` references a missing tool", target.id()),
            )
        })?;
    let expected_version_arguments: &[&str] = match target.kind() {
        DynamicKind::Fuzz | DynamicKind::Corpus => &["fuzz", "--version"],
        DynamicKind::Miri => &[NIGHTLY, "miri", "--version"],
        DynamicKind::Property
        | DynamicKind::StateModel
        | DynamicKind::Sanitizer
        | DynamicKind::Loom => &["--version"],
    };
    if tool.command != "cargo"
        || tool.version != target.tool_version()
        || tool
            .version_arguments
            .iter()
            .map(String::as_str)
            .ne(expected_version_arguments.iter().copied())
    {
        return Err(XtaskError::invalid(
            "dynamic retained-evidence verifier",
            format!(
                "target `{}` tool version changed after capture",
                target.id()
            ),
        ));
    }
    let environment = expected_environment(target);
    let arguments = target.arguments_slice().to_vec();
    let argv_digest = digest_sequence(b"positron-dynamic-argv-v1\0", &arguments);
    let environment_digest = digest_pairs(b"positron-dynamic-environment-v1\0", &environment);
    let input_digest = digest_pairs(
        b"positron-dynamic-input-v1\0",
        &[
            ("corpus".to_owned(), target.corpus().to_owned()),
            ("seed".to_owned(), target.seed().to_owned()),
            ("schedule".to_owned(), target.schedule().to_owned()),
            (
                "minimized-failure".to_owned(),
                target.minimized_failure().to_owned(),
            ),
        ],
    );
    let plan_digest = digest_sequence(
        b"positron-dynamic-plan-v1\0",
        &[
            PLAN_VERSION.to_owned(),
            target.kind().label().to_owned(),
            target.capability_id().to_owned(),
            tool.id.clone(),
            tool.version.clone(),
            tool.command.clone(),
            argv_digest.clone(),
            environment_digest.clone(),
            input_digest.clone(),
            target.output_protocol_label().to_owned(),
            target.catalog_digest().to_owned(),
            target.registry_digest().to_owned(),
        ],
    );
    let identity = format!(
        "plan={PLAN_VERSION};tool-id={};tool-version={};program={};argv-digest={argv_digest};environment-digest={environment_digest};input-digest={input_digest};catalog-digest={};target-registry-digest={};plan-digest={plan_digest}",
        tool.id,
        tool.version,
        tool.command,
        target.catalog_digest(),
        target.registry_digest(),
    );
    Ok((
        ExpectedDynamicStep {
            program: tool.command.clone(),
            arguments,
            environment,
            maximum_timeout: target.timeout(),
        },
        identity,
    ))
}

fn independently_selected(target: &DynamicTarget, profile: Profile) -> bool {
    match profile {
        Profile::PreCommit => false,
        Profile::Pr => target.stages().contains("PR"),
        Profile::Ext => target.stages().contains("PR") || target.stages().contains("EXT"),
        Profile::Qual => target.stages().contains("QUAL"),
    }
}

fn target_identity(target: &DynamicTarget) -> String {
    format!(
        "target={};kind={};capability={};corpus={};seed={};schedule={};minimized-failure={};output-protocol={}",
        target.id(),
        target.kind().label(),
        target.capability_id(),
        target.corpus(),
        target.seed(),
        target.schedule(),
        target.minimized_failure(),
        target.output_protocol_label(),
    )
}

fn expected_environment(target: &DynamicTarget) -> Vec<(String, String)> {
    let mut values = vec![
        (
            "POSITRON_DYNAMIC_TARGET_ID".to_owned(),
            target.id().to_owned(),
        ),
        (
            "POSITRON_DYNAMIC_KIND".to_owned(),
            target.kind().label().to_owned(),
        ),
        (
            "POSITRON_DYNAMIC_CORPUS_ID".to_owned(),
            target.corpus().to_owned(),
        ),
        ("POSITRON_DYNAMIC_SEED".to_owned(), target.seed().to_owned()),
        (
            "POSITRON_DYNAMIC_SCHEDULE".to_owned(),
            target.schedule().to_owned(),
        ),
        (
            "POSITRON_DYNAMIC_MINIMIZED_FAILURE_ID".to_owned(),
            target.minimized_failure().to_owned(),
        ),
    ];
    if target.kind() == DynamicKind::Sanitizer {
        values.push(("RUSTFLAGS".to_owned(), "-Zsanitizer=address".to_owned()));
    }
    values
}

fn arguments_match(kind: DynamicKind, arguments: &[String], corpus: &str) -> bool {
    match kind {
        DynamicKind::Property => match arguments {
            [test, locked, package_flag, package, test_flag, target] => {
                test == "test"
                    && locked == "--locked"
                    && package_flag == "--package"
                    && !package.is_empty()
                    && test_flag == "--test"
                    && target.ends_with("_properties")
            },
            _ => false,
        },
        DynamicKind::StateModel => match arguments {
            [
                test,
                locked,
                package_flag,
                package,
                test_flag,
                target,
                model,
                separator,
                exact,
            ] => {
                test == "test"
                    && locked == "--locked"
                    && package_flag == "--package"
                    && !package.is_empty()
                    && test_flag == "--test"
                    && !target.is_empty()
                    && !model.is_empty()
                    && separator == "--"
                    && exact == "--exact"
            },
            _ => false,
        },
        DynamicKind::Fuzz => {
            matches!(arguments, [fuzz, run, target] if fuzz == "fuzz" && run == "run" && !target.is_empty())
        },
        DynamicKind::Corpus => {
            matches!(arguments, [fuzz, run, target, value] if fuzz == "fuzz" && run == "run" && !target.is_empty() && value == corpus)
        },
        DynamicKind::Miri => {
            matches!(arguments, [nightly, miri, test, locked, package_flag, package] if nightly == NIGHTLY && miri == "miri" && test == "test" && locked == "--locked" && package_flag == "--package" && !package.is_empty())
        },
        DynamicKind::Sanitizer => {
            matches!(arguments, [nightly, test, locked, package_flag, package, test_flag, target] if nightly == NIGHTLY && test == "test" && locked == "--locked" && package_flag == "--package" && !package.is_empty() && test_flag == "--test" && !target.is_empty())
        },
        DynamicKind::Loom => {
            matches!(arguments, [test, locked, package_flag, package, features, loom, test_flag, target] if test == "test" && locked == "--locked" && package_flag == "--package" && !package.is_empty() && features == "--features" && loom == "loom" && test_flag == "--test" && !target.is_empty())
        },
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
