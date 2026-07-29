//! Canonical generated-artifact registration and reproducibility checks.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::XtaskError;

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

/// Rejects checked generated output that differs from deterministic regeneration.
pub(crate) fn verify(root: &Path) -> Result<(), XtaskError> {
    for input in INPUTS {
        let path = root.join(input);
        fs::metadata(&path).map_err(|source| {
            XtaskError::io(format!("read registered input {}", path.display()), source)
        })?;
    }
    let before = ARTIFACTS
        .iter()
        .map(|relative| {
            let path = root.join(relative);
            let contents = fs::read(&path)
                .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
            Ok((path, contents))
        })
        .collect::<Result<Vec<(PathBuf, Vec<u8>)>, XtaskError>>()?;
    if let Err(generation_error) = generate(root) {
        return restore_after_failure(&before, generation_error);
    }
    let comparison = first_mismatch(&before);
    let mismatch = match comparison {
        Ok(mismatch) => mismatch,
        Err(comparison_error) => return restore_after_failure(&before, comparison_error),
    };
    let Some(path) = mismatch else {
        return Ok(());
    };
    if let Err(restore_error) = restore_all(&before) {
        return Err(XtaskError::invalid(
            "canonical generation rollback",
            format!(
                "detected drift at {}; restoring the complete artifact set failed: {restore_error}",
                path.display()
            ),
        ));
    }
    Err(XtaskError::invalid_path(
        &path,
        "canonical generation is not clean and deterministic",
    ))
}

fn first_mismatch(before: &[(PathBuf, Vec<u8>)]) -> Result<Option<PathBuf>, XtaskError> {
    for (path, contents) in before {
        let regenerated = fs::read(path).map_err(|source| {
            XtaskError::io(format!("read regenerated {}", path.display()), source)
        })?;
        if regenerated.as_slice() != contents.as_slice() {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}

fn restore_after_failure(
    before: &[(PathBuf, Vec<u8>)],
    failure: XtaskError,
) -> Result<(), XtaskError> {
    match restore_all(before) {
        Ok(()) => Err(failure),
        Err(restore_error) => Err(XtaskError::invalid(
            "canonical generation rollback",
            format!(
                "generation failed: {failure}; restoring every artifact failed: {restore_error}"
            ),
        )),
    }
}

fn restore_all(before: &[(PathBuf, Vec<u8>)]) -> Result<(), XtaskError> {
    let mut first_failure = None;
    for (path, contents) in before {
        if let Err(source) = fs::write(path, contents)
            && first_failure.is_none()
        {
            first_failure = Some(XtaskError::io(
                format!("restore {}", path.display()),
                source,
            ));
        }
    }
    match first_failure {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}
