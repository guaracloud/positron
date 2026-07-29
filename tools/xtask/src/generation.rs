//! Canonical generated-artifact registration and reproducibility checks.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::XtaskError;

const MAXIMUM_STAGING_SLOTS: u8 = 64;

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
    staging: [PathBuf; 2],
}

impl VerificationInvocation {
    /// Claims two root-scoped staging slots without mutable process-global state.
    pub(crate) fn claim(root: &Path) -> Result<Self, XtaskError> {
        let parent = root.join("target/quality/tmp");
        fs::create_dir_all(&parent).map_err(|source| {
            XtaskError::io(
                format!("create staging parent {}", parent.display()),
                source,
            )
        })?;
        let first = claim_staging(&parent)?;
        match claim_staging(&parent) {
            Ok(second) => Ok(Self {
                staging: [first, second],
            }),
            Err(failure) => match fs::remove_dir_all(&first) {
                Ok(()) => Err(failure),
                Err(source) => Err(XtaskError::invalid(
                    "canonical generation staging",
                    format!(
                        "second clean staging claim failed: {failure}; releasing first staging {} failed: {source}",
                        first.display()
                    ),
                )),
            },
        }
    }
}

/// Byte identity of two independent clean generated artifact sets.
pub(crate) struct VerificationReport {
    first_digest: String,
    second_digest: String,
}

impl VerificationReport {
    /// Returns the bounded human-readable parity evidence.
    pub(crate) fn display(&self) -> String {
        format!(
            "clean generation A sha256:{}; clean generation B sha256:{}; parity=byte-identical",
            self.first_digest, self.second_digest
        )
    }
}

/// Rejects checked generated output that differs from deterministic regeneration.
pub(crate) fn verify(
    root: &Path,
    invocation: VerificationInvocation,
) -> Result<VerificationReport, XtaskError> {
    let verification =
        validate_registered_inputs(root).and_then(|()| verify_staged(root, &invocation.staging));
    let cleanup = remove_staging(&invocation.staging);
    match (verification, cleanup) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(failure), Ok(())) => Err(failure),
        (Ok(_), Err(cleanup_failure)) => Err(cleanup_failure),
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

fn claim_staging(parent: &Path) -> Result<PathBuf, XtaskError> {
    for slot in 0..MAXIMUM_STAGING_SLOTS {
        let staging = parent.join(format!("verify-generation-{slot}"));
        match fs::create_dir(&staging) {
            Ok(()) => return Ok(staging),
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
        format!("all {MAXIMUM_STAGING_SLOTS} bounded verification slots are occupied"),
    ))
}

fn remove_staging(staging: &[PathBuf; 2]) -> Result<(), XtaskError> {
    let [first, second] = staging;
    let first_cleanup = fs::remove_dir_all(first);
    let second_cleanup = fs::remove_dir_all(second);
    match (first_cleanup, second_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(source), Ok(())) => Err(XtaskError::io(
            format!("remove staging {}", first.display()),
            source,
        )),
        (Ok(()), Err(source)) => Err(XtaskError::io(
            format!("remove staging {}", second.display()),
            source,
        )),
        (Err(first_source), Err(second_source)) => Err(XtaskError::invalid(
            "canonical generation staging cleanup",
            format!(
                "removing first staging {} failed: {first_source}; removing second staging {} failed: {second_source}",
                first.display(),
                second.display()
            ),
        )),
    }
}

fn verify_staged(root: &Path, staging: &[PathBuf; 2]) -> Result<VerificationReport, XtaskError> {
    let [first_root, second_root] = staging;
    for clean_root in staging {
        prepare_staging_inputs(root, clean_root)?;
        generate(clean_root)?;
    }
    for relative in ARTIFACTS {
        let first_path = first_root.join(relative);
        let second_path = second_root.join(relative);
        let first = fs::read(&first_path).map_err(|source| {
            XtaskError::io(format!("read first clean {}", first_path.display()), source)
        })?;
        let second = fs::read(&second_path).map_err(|source| {
            XtaskError::io(
                format!("read second clean {}", second_path.display()),
                source,
            )
        })?;
        if first != second {
            return Err(XtaskError::invalid_path(
                &second_path,
                "independent clean generations are not byte-identical",
            ));
        }
    }
    let report = VerificationReport {
        first_digest: artifact_set_digest(first_root)?,
        second_digest: artifact_set_digest(second_root)?,
    };
    for relative in ARTIFACTS {
        let checked_path = root.join(relative);
        let staged_path = first_root.join(relative);
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
    Ok(report)
}

fn artifact_set_digest(root: &Path) -> Result<String, XtaskError> {
    let mut digest = Sha256::new();
    for relative in ARTIFACTS {
        let path = root.join(relative);
        let contents = fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        let path_length = u64::try_from(relative.len()).map_err(|_| {
            XtaskError::invalid_path(&path, "artifact path length exceeds the digest format")
        })?;
        let content_length = u64::try_from(contents.len()).map_err(|_| {
            XtaskError::invalid_path(&path, "artifact byte length exceeds the digest format")
        })?;
        digest.update(path_length.to_le_bytes());
        digest.update(relative.as_bytes());
        digest.update(content_length.to_le_bytes());
        digest.update(contents);
    }
    Ok(format!("{:x}", digest.finalize()))
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
