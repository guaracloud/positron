//! Closed product-target descriptor support for `EG-MATRIX`.
//!
//! Product probes are intentionally separate from the M0 diagnostic target
//! catalog: their presence never turns a runner-capability matrix into an
//! exact-artifact qualification claim.

use std::fs;
use std::path::Path;

use crate::error::XtaskError;

const PATH: &str = "qualification/engineering/matrix-product-targets.tsv";
const HEADER: &str = "target_id\tartifact_scope\tgate_id\tstages\towner\tidentity\tdiagnostic";
const ID: &str = "canonical-api-generation-1";
const ARTIFACT_SCOPE: &str = "api/positron/v1";
const IDENTITY: &str = "canonical-api-generation-v1";
const GATE: &str = "EG-MATRIX";
const STAGES: &str = "PR";
const OWNER: &str = "Quality Engineering";
const DIAGNOSTIC: &str = "diagnostic-only";
const MAXIMUM_BYTES: usize = 16_384;
const MAXIMUM_FIELD_BYTES: usize = 256;

/// The bounded public disposition of the optional product diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MatrixProductOutcome {
    Missing,
    Inactive,
    Diagnostic,
}

impl MatrixProductOutcome {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Inactive => "inactive",
            Self::Diagnostic => "diagnostic",
        }
    }
}

/// An explicitly registered product target.
#[derive(Debug)]
pub(crate) struct MatrixProductTarget {
    id: String,
    artifact_scope: String,
    identity: String,
}

impl MatrixProductTarget {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn artifact_scope(&self) -> &str {
        &self.artifact_scope
    }

    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }
}

/// Loads the sole optional product probe without expanding the diagnostic set.
pub(crate) fn load(root: &Path) -> Result<Option<MatrixProductTarget>, XtaskError> {
    let path = root.join(PATH);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(XtaskError::io(format!("read {}", path.display()), source)),
    };
    if bytes.len() > MAXIMUM_BYTES {
        return Err(XtaskError::invalid_path(
            &path,
            format!("matrix product target registry exceeds {MAXIMUM_BYTES} bytes"),
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        XtaskError::invalid_path(&path, "matrix product target registry is not UTF-8")
    })?;
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(XtaskError::invalid_path(
            &path,
            "matrix product target registry header does not match the registered schema",
        ));
    }
    let Some(row) = lines.next() else {
        return Ok(None);
    };
    if lines.next().is_some() {
        return Err(XtaskError::invalid_path(
            &path,
            "matrix product target registry permits at most one M0 product target",
        ));
    }
    let fields = row.split('\t').collect::<Vec<_>>();
    let [
        id,
        artifact_scope,
        gate_id,
        stages,
        owner,
        identity,
        diagnostic,
    ] = fields.as_slice()
    else {
        return Err(XtaskError::invalid_path(
            &path,
            "matrix product target registry row has the wrong field count",
        ));
    };
    if fields
        .iter()
        .any(|field| field.is_empty() || field.len() > MAXIMUM_FIELD_BYTES)
        || *id != ID
        || *artifact_scope != ARTIFACT_SCOPE
        || *gate_id != GATE
        || *stages != STAGES
        || *owner != OWNER
        || *identity != IDENTITY
        || *diagnostic != DIAGNOSTIC
    {
        return Err(XtaskError::invalid_path(
            &path,
            "matrix product target violates its closed M0 descriptor contract",
        ));
    }
    Ok(Some(MatrixProductTarget {
        id: (*id).to_owned(),
        artifact_scope: (*artifact_scope).to_owned(),
        identity: (*identity).to_owned(),
    }))
}
