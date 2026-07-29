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
/// The generated configuration JSON Schema artifact.
pub(crate) const CONFIGURATION_SCHEMA: &str = "configuration/schema.json";
/// The generated configuration reference artifact.
pub(crate) const CONFIGURATION_REFERENCE: &str = "configuration/reference.md";
/// Every hand-edited input permitted to affect checked generated artifacts.
pub(crate) const INPUTS: [&str; 2] = [API_INPUT, CONFIGURATION_INPUT];

/// Every checked artifact owned by the canonical API and configuration inputs.
pub(crate) const ARTIFACTS: [&str; 6] = [
    API_HTTP_MAPPING,
    API_OPENAPI,
    API_SCHEMA_DIGEST,
    CONFIGURATION_REFERENCE,
    CONFIGURATION_SCHEMA,
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
    generate(root)?;
    for (path, contents) in before {
        let regenerated = fs::read(&path).map_err(|source| {
            XtaskError::io(format!("read regenerated {}", path.display()), source)
        })?;
        if regenerated != contents {
            fs::write(&path, contents)
                .map_err(|source| XtaskError::io(format!("restore {}", path.display()), source))?;
            return Err(XtaskError::invalid_path(
                &path,
                "canonical generation is not clean and deterministic",
            ));
        }
    }
    Ok(())
}
