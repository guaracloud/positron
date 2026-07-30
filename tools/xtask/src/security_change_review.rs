//! Complete revision-bound classification of M0-10 changed paths.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;
use crate::evidence_json::{JsonObject, JsonValue, take_required};

const POLICY_PATH: &str =
    "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json";
const CLASSIFICATION_RECORD: &str = "qualification/engineering/security-threat-surfaces.tsv";
const MAXIMUM_POLICY_BYTES: usize = 32_768;

pub(crate) fn validate(
    root: &Path,
    merge_base: &str,
    changed_paths: &str,
    model_coverage: &BTreeMap<String, String>,
    reviewed_non_trust: &BTreeMap<String, String>,
) -> Result<String, XtaskError> {
    let contract = load_contract(root)?;
    if merge_base != contract.merge_base {
        return invalid("merge base drifted from the reviewed changed-path contract");
    }
    if let Some(path) = model_coverage
        .keys()
        .find(|path| reviewed_non_trust.contains_key(*path))
    {
        return invalid(format!(
            "path `{path}` has conflicting model and non-trust classifications"
        ));
    }
    let mut actual = BTreeSet::new();
    for path in changed_paths.lines() {
        if path.is_empty()
            || Path::new(path).is_absolute()
            || path.split('/').any(|component| component == "..")
        {
            return invalid("changed-path output contains an invalid repository path");
        }
        if !actual.insert(path.to_owned()) {
            return invalid(format!("changed path `{path}` is duplicated"));
        }
    }
    if let Some(path) = reviewed_non_trust
        .keys()
        .find(|path| !actual.contains(*path))
    {
        return invalid(format!(
            "reviewed non-trust path `{path}` is extra or stale for the actual changed set"
        ));
    }
    let mut classifications = Vec::with_capacity(actual.len());
    for path in &actual {
        match (model_coverage.get(path), reviewed_non_trust.get(path)) {
            (Some(model), None) => classifications.push(format!("{path}\tmodel\t{model}")),
            (None, Some(review)) => {
                classifications.push(format!("{path}\treviewed-non-trust\t{review}"));
            },
            (Some(_), Some(_)) => {
                return invalid(format!(
                    "changed path `{path}` has conflicting classifications"
                ));
            },
            (None, None) => {
                return invalid(format!(
                    "actual changed path `{path}` has no owned classification"
                ));
            },
        }
    }
    let sorted_paths = actual.iter().map(String::as_str).collect::<Vec<_>>();
    let path_digest = sha256(sorted_paths.join("\n").as_bytes());
    let classification_digest = sha256(classifications.join("\n").as_bytes());
    if actual.len() != contract.path_count
        || path_digest != contract.path_set_digest
        || classification_digest != contract.classification_digest
    {
        return invalid("actual changed set or classification digest drifted from PC-0015");
    }
    Ok(format!(
        "changed-path-count={}; changed-paths={}; changed-path-set-digest={path_digest}; changed-path-classification-digest={classification_digest}",
        actual.len(),
        sorted_paths.join("|"),
    ))
}

struct Contract {
    merge_base: String,
    path_count: usize,
    path_set_digest: String,
    classification_digest: String,
}

fn load_contract(root: &Path) -> Result<Contract, XtaskError> {
    let path = root.join(POLICY_PATH);
    let content = String::from_utf8(crate::bounded_input::read(
        &path,
        MAXIMUM_POLICY_BYTES,
        "PC-0015 policy record",
    )?)
    .map_err(|source| XtaskError::invalid_path(&path, source.to_string()))?;
    let value = crate::evidence_json::parse(&content)
        .map_err(|source| XtaskError::invalid_path(&path, source.to_string()))?;
    let mut document = value
        .into_object("PC-0015")
        .map_err(|source| XtaskError::invalid_path(&path, source.to_string()))?;
    let mut change = take_object(&mut document, "change", &path)?;
    let mut contract = take_object(&mut change, "changed_path_contract", &path)?;
    let merge_base = take_string(&mut contract, "merge_base", &path)?;
    let path_count = take_usize(&mut contract, "path_count", &path)?;
    let path_set_digest = take_string(&mut contract, "path_set_digest", &path)?;
    let classification_digest = take_string(&mut contract, "classification_digest", &path)?;
    let record = take_string(&mut contract, "classification_record", &path)?;
    if record != CLASSIFICATION_RECORD {
        return Err(XtaskError::invalid_path(
            &path,
            "changed-path classification record drifted",
        ));
    }
    Ok(Contract {
        merge_base,
        path_count,
        path_set_digest,
        classification_digest,
    })
}

fn take_object(
    object: &mut JsonObject,
    field: &str,
    path: &Path,
) -> Result<JsonObject, XtaskError> {
    take_required(object, field)
        .and_then(|value| value.into_object(field))
        .map_err(|source| XtaskError::invalid_path(path, source.to_string()))
}

fn take_string(object: &mut JsonObject, field: &str, path: &Path) -> Result<String, XtaskError> {
    match take_required(object, field) {
        Ok(JsonValue::String(value)) if !value.is_empty() => Ok(value),
        Ok(_) => Err(XtaskError::invalid_path(
            path,
            format!("PC-0015 field `{field}` must be a non-empty string"),
        )),
        Err(source) => Err(XtaskError::invalid_path(path, source.to_string())),
    }
}

fn take_usize(object: &mut JsonObject, field: &str, path: &Path) -> Result<usize, XtaskError> {
    match take_required(object, field) {
        Ok(JsonValue::Integer(value)) => usize::try_from(value)
            .map_err(|_| XtaskError::invalid_path(path, format!("`{field}` exceeds usize"))),
        Ok(_) => Err(XtaskError::invalid_path(
            path,
            format!("PC-0015 field `{field}` must be an integer"),
        )),
        Err(source) => Err(XtaskError::invalid_path(path, source.to_string())),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn invalid(detail: impl Into<String>) -> Result<String, XtaskError> {
    Err(XtaskError::invalid(
        "complete changed-path classification",
        detail,
    ))
}
