//! Positron's authoritative engineering gate runner.
//!
//! CI and repository-managed hooks enter engineering policy through this
//! binary. Individual tools remain detectors; this runner owns selection,
//! budgets, registry validation, attempt identity, and evidence aggregation.

#![forbid(unsafe_code)]

mod api_generation;
mod controlled_execution;
mod error;
mod hooks;
mod quality;
mod registry;

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
        "generate-api" => {
            ensure_no_more_arguments(arguments)?;
            let root = env::current_dir()
                .map_err(|source| XtaskError::io("resolve current directory", source))?;
            api_generation::generate(&root)
        },
        "quality" => {
            let options = quality::Options::parse(arguments)?;
            quality::run(&options)
        },
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
        "Usage:\n  cargo xtask generate-api\n  cargo xtask quality [--profile {}] [--retain-m0-02-mutation|--retain-m0-03-mutation]\n  cargo xtask setup\n  cargo xtask help",
        Profile::accepted_values()
    )
}
