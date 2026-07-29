//! Canonical generated-artifact registration and reproducibility checks.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::error::XtaskError;

const MAXIMUM_PARALLEL_VERIFICATIONS: u8 = 64;

/// The hand-edited Protobuf input for the public interface generator.
pub(crate) const API_INPUT: &str = "api/positron/v1/positron.proto";
/// The hand-edited Rust input for the configuration generator.
pub(crate) const CONFIGURATION_INPUT: &str = "crates/positron-config/src/contract.rs";
/// The generated Rust public-interface artifact.
pub(crate) const API_RUST: &str = "crates/positron-api/src/generated.rs";
/// The generated API Schema Digest artifact.
pub(crate) const API_SCHEMA_DIGEST: &str = "api/positron/v1/schema.sha256";
/// The generated OpenAPI artifact.
pub(crate) const API_OPENAPI: &str = "api/positron/v1/openapi.json";
/// The generated HTTP/JSON mapping artifact.
pub(crate) const API_HTTP_MAPPING: &str = "api/positron/v1/http.json";
/// The generated cross-transport API validation-fixture artifact.
pub(crate) const API_VALIDATION_FIXTURES: &str = "api/positron/v1/validation-fixtures.json";
/// The generated configuration JSON Schema artifact.
pub(crate) const CONFIGURATION_SCHEMA: &str = "configuration/schema.json";
/// The generated configuration reference artifact.
pub(crate) const CONFIGURATION_REFERENCE: &str = "configuration/reference.md";
/// The generated configuration validation-fixture artifact.
pub(crate) const CONFIGURATION_VALIDATION_FIXTURES: &str = "configuration/validation-fixtures.json";
/// Every hand-edited input permitted to affect checked generated artifacts.
pub(crate) const INPUTS: [&str; 2] = [API_INPUT, CONFIGURATION_INPUT];

/// Every checked artifact owned by the canonical API and configuration inputs.
pub(crate) const ARTIFACTS: [&str; 8] = [
    API_HTTP_MAPPING,
    API_OPENAPI,
    API_SCHEMA_DIGEST,
    API_VALIDATION_FIXTURES,
    CONFIGURATION_REFERENCE,
    CONFIGURATION_SCHEMA,
    CONFIGURATION_VALIDATION_FIXTURES,
    API_RUST,
];

/// Regenerates the complete checked API and configuration artifact set.
pub(crate) fn generate(root: &Path) -> Result<(), XtaskError> {
    crate::api_generation::generate(root)?;
    crate::config_generation::generate(root)
}

/// One explicitly owned generated-artifact verification attempt.
pub(crate) struct VerificationInvocation {
    staging: PathBuf,
}

impl VerificationInvocation {
    /// Claims one root-scoped staging slot without mutable process-global state.
    pub(crate) fn claim(root: &Path) -> Result<Self, XtaskError> {
        let parent = root.join("target/quality/tmp");
        fs::create_dir_all(&parent).map_err(|source| {
            XtaskError::io(
                format!("create staging parent {}", parent.display()),
                source,
            )
        })?;
        for slot in 0..MAXIMUM_PARALLEL_VERIFICATIONS {
            let staging = parent.join(format!("verify-generation-{slot}"));
            match fs::create_dir(&staging) {
                Ok(()) => return Ok(Self { staging }),
                Err(source) if source.kind() == ErrorKind::AlreadyExists => {},
                Err(source) => {
                    return Err(XtaskError::io(
                        format!("claim staging {}", staging.display()),
                        source,
                    ));
                },
            }
        }
        Err(XtaskError::invalid(
            "canonical generation staging",
            format!("all {MAXIMUM_PARALLEL_VERIFICATIONS} bounded verification slots are occupied"),
        ))
    }
}

/// Rejects checked generated output that differs from deterministic regeneration.
pub(crate) fn verify(root: &Path, invocation: VerificationInvocation) -> Result<(), XtaskError> {
    let verification =
        validate_registered_inputs(root).and_then(|()| verify_staged(root, &invocation.staging));
    let cleanup = fs::remove_dir_all(&invocation.staging).map_err(|source| {
        XtaskError::io(
            format!("remove staging {}", invocation.staging.display()),
            source,
        )
    });
    match (verification, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(failure), Ok(())) => Err(failure),
        (Ok(()), Err(cleanup_failure)) => Err(cleanup_failure),
        (Err(failure), Err(cleanup_failure)) => Err(XtaskError::invalid(
            "canonical generation staging",
            format!("verification failed: {failure}; staging cleanup failed: {cleanup_failure}"),
        )),
    }
}

fn validate_registered_inputs(root: &Path) -> Result<(), XtaskError> {
    for input in INPUTS {
        let path = root.join(input);
        fs::metadata(&path).map_err(|source| {
            XtaskError::io(format!("read registered input {}", path.display()), source)
        })?;
    }
    Ok(())
}

fn verify_staged(root: &Path, staging: &Path) -> Result<(), XtaskError> {
    prepare_staging_inputs(root, staging)?;
    generate(staging)?;
    for relative in ARTIFACTS {
        let checked_path = root.join(relative);
        let staged_path = staging.join(relative);
        let checked = fs::read(&checked_path).map_err(|source| {
            XtaskError::io(format!("read checked {}", checked_path.display()), source)
        })?;
        let generated = fs::read(&staged_path).map_err(|source| {
            XtaskError::io(format!("read staged {}", staged_path.display()), source)
        })?;
        if checked != generated {
            return Err(XtaskError::invalid_path(
                &checked_path,
                "canonical generation is not clean and deterministic",
            ));
        }
    }
    Ok(())
}

fn prepare_staging_inputs(root: &Path, staging: &Path) -> Result<(), XtaskError> {
    for relative in INPUTS {
        let source_path = root.join(relative);
        let staged_path = staging.join(relative);
        let parent = staged_path.parent().ok_or_else(|| {
            XtaskError::invalid_path(&staged_path, "registered input has no staging parent")
        })?;
        fs::create_dir_all(parent).map_err(|source| {
            XtaskError::io(format!("create staging input {}", parent.display()), source)
        })?;
        fs::copy(&source_path, &staged_path).map_err(|source| {
            XtaskError::io(
                format!(
                    "copy registered input {} to {}",
                    source_path.display(),
                    staged_path.display()
                ),
                source,
            )
        })?;
    }
    for relative in ARTIFACTS {
        let staged_path = staging.join(relative);
        let parent = staged_path.parent().ok_or_else(|| {
            XtaskError::invalid_path(&staged_path, "registered artifact has no staging parent")
        })?;
        fs::create_dir_all(parent).map_err(|source| {
            XtaskError::io(
                format!("create staging artifact {}", parent.display()),
                source,
            )
        })?;
    }
    Ok(())
}
