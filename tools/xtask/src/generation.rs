//! Canonical generated-artifact registration and reproducibility checks.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::XtaskError;

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    let staging = create_staging_root(root)?;
    let verification = verify_staged(root, &staging);
    let cleanup = fs::remove_dir_all(&staging)
        .map_err(|source| XtaskError::io(format!("remove staging {}", staging.display()), source));
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

fn create_staging_root(root: &Path) -> Result<PathBuf, XtaskError> {
    let sequence = STAGING_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| {
            XtaskError::invalid(
                "canonical generation staging",
                "bounded staging identity space is exhausted",
            )
        })?;
    let parent = root.join("target/quality/tmp");
    fs::create_dir_all(&parent).map_err(|source| {
        XtaskError::io(
            format!("create staging parent {}", parent.display()),
            source,
        )
    })?;
    let staging = parent.join(format!(
        "verify-generation-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&staging).map_err(|source| {
        XtaskError::io(format!("create staging {}", staging.display()), source)
    })?;
    Ok(staging)
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
