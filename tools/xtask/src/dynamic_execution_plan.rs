//! Typed execution plans for registered dynamic-quality targets.
//!
//! A detector kind is a closed executable contract, not an evidence label.
//! This module binds each kind to one reviewed tool identity, argv grammar,
//! explicit deterministic inputs, and a canonical retained digest.

use sha2::{Digest, Sha256};

use crate::dynamic_catalog::{ArgumentGrammar, DynamicKind};
use crate::dynamic_quality::DynamicTarget;
use crate::error::XtaskError;
use crate::registry::Tool;

const PLAN_VERSION: &str = "dynamic-execution-plan-v1";
const NIGHTLY: &str = "+nightly-2026-07-20";

#[derive(Debug)]
pub(crate) struct DynamicExecutionPlan {
    tool_id: String,
    tool_version: String,
    program: String,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    argv_digest: String,
    environment_digest: String,
    input_digest: String,
    catalog_digest: String,
    target_registry_digest: String,
    plan_digest: String,
}

impl DynamicExecutionPlan {
    pub(crate) fn capture(target: &DynamicTarget, tools: &[Tool]) -> Result<Self, XtaskError> {
        validate_arguments(
            target.kind(),
            target.capability().grammar(),
            target.arguments_slice(),
            target.corpus(),
        )?;
        let tool = tools
            .iter()
            .find(|tool| tool.id == target.tool_id())
            .ok_or_else(|| {
                XtaskError::invalid(
                    "dynamic execution plan",
                    format!(
                        "dynamic kind `{}` requires missing registered tool `{}`",
                        target.kind().label(),
                        target.tool_id(),
                    ),
                )
            })?;
        if tool.version != target.tool_version() {
            return Err(XtaskError::invalid(
                "dynamic execution plan",
                format!(
                    "dynamic capability `{}` tool version drifted after catalog capture",
                    target.capability_id(),
                ),
            ));
        }

        let environment = vec![
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
        let mut environment = environment;
        if target.kind() == DynamicKind::Sanitizer {
            environment.push(("RUSTFLAGS".to_owned(), "-Zsanitizer=address".to_owned()));
        }

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
        Ok(Self {
            tool_id: tool.id.clone(),
            tool_version: tool.version.clone(),
            program: tool.command.clone(),
            arguments,
            environment,
            argv_digest,
            environment_digest,
            input_digest,
            catalog_digest: target.catalog_digest().to_owned(),
            target_registry_digest: target.registry_digest().to_owned(),
            plan_digest,
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

    pub(crate) fn retained_identity(&self) -> String {
        format!(
            "plan={PLAN_VERSION};tool-id={};tool-version={};program={};argv-digest={};environment-digest={};input-digest={};catalog-digest={};target-registry-digest={};plan-digest={}",
            self.tool_id,
            self.tool_version,
            self.program,
            self.argv_digest,
            self.environment_digest,
            self.input_digest,
            self.catalog_digest,
            self.target_registry_digest,
            self.plan_digest,
        )
    }
}

fn validate_arguments(
    kind: DynamicKind,
    grammar: ArgumentGrammar,
    arguments: &[String],
    corpus: &str,
) -> Result<(), XtaskError> {
    let valid = match grammar {
        ArgumentGrammar::Property => {
            cargo_test_target(arguments).is_some_and(|(_, target)| target.ends_with("_properties"))
        },
        ArgumentGrammar::StateModel => state_model_target(arguments).is_some(),
        ArgumentGrammar::Fuzz => fuzz_target(arguments).is_some(),
        ArgumentGrammar::Corpus => corpus_target(arguments).is_some_and(|value| value == corpus),
        ArgumentGrammar::Miri => miri_target(arguments).is_some(),
        ArgumentGrammar::Sanitizer => sanitizer_target(arguments).is_some(),
        ArgumentGrammar::Loom => loom_target(arguments).is_some(),
    };
    if !valid {
        return Err(XtaskError::invalid(
            "dynamic execution plan",
            format!(
                "arguments do not match the canonical `{}` detector protocol",
                kind.label(),
            ),
        ));
    }
    Ok(())
}

fn cargo_test_target(arguments: &[String]) -> Option<(&str, &str)> {
    let [test, locked, package_flag, package, test_flag, target] = arguments else {
        return None;
    };
    (*test == "test"
        && *locked == "--locked"
        && *package_flag == "--package"
        && !package.is_empty()
        && *test_flag == "--test"
        && !target.is_empty())
    .then_some((package, target))
}

fn state_model_target(arguments: &[String]) -> Option<(&str, &str, &str)> {
    let [
        test,
        locked,
        package_flag,
        package,
        test_flag,
        target,
        model,
        separator,
        exact,
    ] = arguments
    else {
        return None;
    };
    (*test == "test"
        && *locked == "--locked"
        && *package_flag == "--package"
        && !package.is_empty()
        && *test_flag == "--test"
        && !target.is_empty()
        && !model.is_empty()
        && *separator == "--"
        && *exact == "--exact")
        .then_some((package, target, model))
}

fn fuzz_target(arguments: &[String]) -> Option<&str> {
    let [fuzz, run, target] = arguments else {
        return None;
    };
    (*fuzz == "fuzz" && *run == "run" && !target.is_empty()).then_some(target)
}

fn corpus_target(arguments: &[String]) -> Option<&str> {
    let [fuzz, run, target, corpus] = arguments else {
        return None;
    };
    (*fuzz == "fuzz" && *run == "run" && !target.is_empty() && !corpus.is_empty()).then_some(corpus)
}

fn miri_target(arguments: &[String]) -> Option<&str> {
    let [nightly, miri, test, locked, package_flag, package] = arguments else {
        return None;
    };
    (*nightly == NIGHTLY
        && *miri == "miri"
        && *test == "test"
        && *locked == "--locked"
        && *package_flag == "--package"
        && !package.is_empty())
    .then_some(package)
}

fn sanitizer_target(arguments: &[String]) -> Option<(&str, &str)> {
    let [
        nightly,
        test,
        locked,
        package_flag,
        package,
        test_flag,
        target,
    ] = arguments
    else {
        return None;
    };
    (*nightly == NIGHTLY
        && *test == "test"
        && *locked == "--locked"
        && *package_flag == "--package"
        && !package.is_empty()
        && *test_flag == "--test"
        && !target.is_empty())
    .then_some((package, target))
}

fn loom_target(arguments: &[String]) -> Option<(&str, &str)> {
    let [
        test,
        locked,
        package_flag,
        package,
        features,
        loom,
        test_flag,
        target,
    ] = arguments
    else {
        return None;
    };
    (*test == "test"
        && *locked == "--locked"
        && *package_flag == "--package"
        && !package.is_empty()
        && *features == "--features"
        && *loom == "loom"
        && *test_flag == "--test"
        && !target.is_empty())
    .then_some((package, target))
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
