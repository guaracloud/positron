//! Positron's authoritative engineering gate runner.
//!
//! CI and repository-managed hooks enter engineering policy through this
//! binary. Individual tools remain detectors; this runner owns selection,
//! budgets, registry validation, attempt identity, and evidence aggregation.

#![forbid(unsafe_code)]

mod api_generation;
mod bounded_input;
mod bounded_measurement_verifier;
mod bounded_runner_frames;
mod bounded_runners;
mod concurrency_source_policy;
mod config_generation;
mod controlled_execution;
mod crypto_targets;
mod dynamic_cancellation;
mod dynamic_catalog;
mod dynamic_execution_plan;
mod dynamic_quality;
mod dynamic_verifier;
mod error;
mod evidence_json;
mod framed_stdout_reader;
mod generation;
mod hooks;
mod qualification_fixtures;
mod quality;
mod registered_task_lifecycle;
mod registry;
mod security_catalog;
mod security_change_review;
mod security_harness;
mod security_threat_surface;

use std::env;
use std::process::ExitCode;

use error::XtaskError;
use quality::Profile;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask failed: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), XtaskError> {
    let mut arguments = env::args().skip(1);
    let Some(command) = arguments.next() else {
        return Err(XtaskError::usage(usage()));
    };

    match command.as_str() {
        "generate" => {
            ensure_no_more_arguments(arguments)?;
            let root = env::current_dir()
                .map_err(|source| XtaskError::io("resolve current directory", source))?;
            generation::generate(&root)
        },
        "verify-generation" => {
            ensure_no_more_arguments(arguments)?;
            let root = env::current_dir()
                .map_err(|source| XtaskError::io("resolve current directory", source))?;
            let invocation = generation::VerificationInvocation::claim(&root)?;
            let report = generation::verify(&root, invocation)?;
            println!("{}", report.display());
            Ok(())
        },
        "generate-api" => {
            ensure_no_more_arguments(arguments)?;
            let root = env::current_dir()
                .map_err(|source| XtaskError::io("resolve current directory", source))?;
            api_generation::generate(&root)
        },
        "generate-config" => {
            ensure_no_more_arguments(arguments)?;
            let root = env::current_dir()
                .map_err(|source| XtaskError::io("resolve current directory", source))?;
            config_generation::generate(&root)
        },
        "quality" => {
            let options = quality::Options::parse(arguments)?;
            quality::run(&options)
        },
        "quality-security-probe" => {
            ensure_no_more_arguments(arguments)?;
            security_harness::run_security_probe_process()
        },
        "quality-secret-canary" => {
            let artifact_root = arguments
                .next()
                .ok_or_else(|| XtaskError::usage("quality-secret-canary requires artifact root"))?;
            let canary_id = arguments.next().ok_or_else(|| {
                XtaskError::usage("quality-secret-canary requires canary identity")
            })?;
            ensure_no_more_arguments(arguments)?;
            security_harness::emit_secret_candidate(
                std::path::Path::new(&artifact_root),
                &canary_id,
            )
        },
        "quality-internal-cancel-dynamic" => dynamic_cancellation::run(arguments),
        "quality-fixture" => qualification_fixtures::run_process(arguments),
        "quality-bounded-runner" => bounded_runners::run_process(arguments),
        "setup" => {
            ensure_no_more_arguments(arguments)?;
            hooks::install()
        },
        "help" | "--help" | "-h" => {
            ensure_no_more_arguments(arguments)?;
            println!("{}", usage());
            Ok(())
        },
        unknown => Err(XtaskError::usage(format!(
            "unknown command `{unknown}`\n\n{}",
            usage()
        ))),
    }
}

fn ensure_no_more_arguments(mut arguments: impl Iterator<Item = String>) -> Result<(), XtaskError> {
    if let Some(argument) = arguments.next() {
        return Err(XtaskError::usage(format!(
            "unexpected argument `{argument}`\n\n{}",
            usage()
        )));
    }

    Ok(())
}

fn usage() -> String {
    format!(
        "Usage:\n  cargo xtask generate\n  cargo xtask verify-generation\n  cargo xtask generate-api\n  cargo xtask generate-config\n  cargo xtask quality [--profile {}] [--retain-m0-02-mutation|--retain-m0-03-mutation|--retain-m0-04-mutation]\n  cargo xtask quality-security-probe\n  cargo xtask quality-secret-canary\n  cargo xtask setup\n  cargo xtask help",
        Profile::accepted_values()
    )
}
