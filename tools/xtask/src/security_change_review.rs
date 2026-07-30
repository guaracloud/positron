//! Revision-bound selection and validation of security change-review records.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;
use crate::evidence_json::{JsonObject, JsonValue, take_required};

const MAXIMUM_POLICY_BYTES: usize = 32_768;
const CLASSIFICATION_RECORD: &str = "qualification/engineering/security-threat-surfaces.tsv";
const M0_10_POLICY: &str =
    "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json";
const M0_11_POLICY: &str =
    "qualification/engineering/policy-changes/PC-0016-m0-11-compatibility-exact-target-matrix.json";
const M0_10_BASE: &str = "542f3835dc67f819e566e017c04e165b15416861";
const M0_11_BASE: &str = "9879d5924cb9af75e95ec2634469973e09f681e5";

#[derive(Clone, Copy)]
struct ReviewLocator {
    id: &'static str,
    path: &'static str,
    merge_base: &'static str,
    requires_revision: bool,
}

const REVIEW_LOCATORS: [ReviewLocator; 2] = [
    ReviewLocator {
        id: "PC-0015-m0-10-security-crypto-runners",
        path: M0_10_POLICY,
        merge_base: M0_10_BASE,
        requires_revision: false,
    },
    ReviewLocator {
        id: "PC-0016-m0-11-compatibility-exact-target-matrix",
        path: M0_11_POLICY,
        merge_base: M0_11_BASE,
        requires_revision: true,
    },
];

/// The one policy record bound to the exact merge base of this attempt.
#[derive(Clone, Copy)]
pub(crate) struct SelectedReview {
    locator: ReviewLocator,
}

impl SelectedReview {
    pub(crate) fn merge_base(&self) -> &str {
        self.locator.merge_base
    }

    /// Each M0-10 catalog consumer independently reads and validates the
    /// selected policy command set. This intentionally preserves the
    /// three-call accounting contract established by PC-0015.
    pub(crate) fn validate_policy_commands(
        &self,
        root: &Path,
        budget: &mut crate::quality::SecurityInputBudget,
    ) -> Result<String, XtaskError> {
        let contract = ReviewContract::load(root, self.locator, budget, true)?;
        Ok(format!("policy-command-validation={}", contract.id))
    }
}

pub(crate) fn select(merge_base: &str) -> Result<SelectedReview, XtaskError> {
    let matches = REVIEW_LOCATORS
        .iter()
        .filter(|locator| locator.merge_base == merge_base)
        .collect::<Vec<_>>();
    let [locator] = matches.as_slice() else {
        return invalid(if matches.is_empty() {
            "no security change-review record matches the exact merge base"
        } else {
            "multiple security change-review records match the exact merge base"
        });
    };
    Ok(SelectedReview { locator: **locator })
}

pub(crate) fn validate(
    root: &Path,
    merge_base: &str,
    changed_paths: &str,
    model_coverage: &BTreeMap<String, String>,
    reviewed_non_trust: &BTreeMap<String, String>,
    budget: &mut crate::quality::SecurityInputBudget,
) -> Result<String, XtaskError> {
    let selection = select(merge_base)?;
    let contract = ReviewContract::load(root, selection.locator, budget, false)?;
    let classifications = contract.classifications(model_coverage, reviewed_non_trust)?;
    validate_actual_paths(changed_paths, &classifications, &contract)
}

/// Validate every committed review record before the exact merge-base selector
/// chooses the one that governs this attempt. It deliberately validates only
/// record-owned structure, so mutable external classifications cannot preempt
/// the selected record's live changed-path verdict.
pub(crate) fn validate_committed_records(root: &Path) -> Result<String, XtaskError> {
    let mut summaries = Vec::with_capacity(REVIEW_LOCATORS.len());
    for locator in REVIEW_LOCATORS {
        let mut budget = crate::quality::SecurityInputBudget::new();
        let contract = ReviewContract::load(root, locator, &mut budget, true)?;
        summaries.push(format!(
            "static-policy={}; {}",
            contract.id,
            budget.declared_summary()?
        ));
    }
    Ok(summaries.join(" | "))
}

/// Check unselected records' immutable external references only after the
/// selected record has completed its live changed-path validation. The local
/// budget keeps this integrity check outside the selected record's frozen
/// shared-input accounting contract.
pub(crate) fn validate_unselected_external_references(
    root: &Path,
    selected: SelectedReview,
) -> Result<String, XtaskError> {
    let mut summaries = Vec::new();
    for locator in REVIEW_LOCATORS {
        if locator.id == selected.locator.id {
            continue;
        }
        let mut budget = crate::quality::SecurityInputBudget::new();
        let surfaces =
            crate::security_threat_surface::ThreatSurfaceRegistry::load(root, &mut budget)?;
        let (model_coverage, reviewed_non_trust) = surfaces.classification_maps();
        let contract = ReviewContract::load(root, locator, &mut budget, true)?;
        let classifications = contract.classifications(model_coverage, reviewed_non_trust)?;
        drop(validate_classification_contract(
            &classifications,
            &contract,
        )?);
        summaries.push(format!(
            "unselected-policy={}; {}",
            contract.id,
            budget.declared_summary()?
        ));
    }
    Ok(summaries.join(" | "))
}

struct ReviewContract {
    id: String,
    revision: Option<String>,
    path_count: usize,
    path_set_digest: String,
    classification_digest: String,
    classifications: Option<BTreeMap<String, Classification>>,
}

impl ReviewContract {
    fn load(
        root: &Path,
        locator: ReviewLocator,
        budget: &mut crate::quality::SecurityInputBudget,
        validate_commands: bool,
    ) -> Result<Self, XtaskError> {
        let path = root.join(locator.path);
        let subject = match locator.id {
            "PC-0015-m0-10-security-crypto-runners" => "PC-0015 policy record",
            "PC-0016-m0-11-compatibility-exact-target-matrix" => "PC-0016 policy record",
            _ => return Err(XtaskError::invalid_path(&path, "unknown policy record")),
        };
        let content = String::from_utf8(crate::quality::read_external_input(
            &path,
            MAXIMUM_POLICY_BYTES,
            subject,
            budget,
        )?)
        .map_err(|source| XtaskError::invalid_path(&path, source.to_string()))?;
        let value = crate::evidence_json::parse(&content)
            .map_err(|source| XtaskError::invalid_path(&path, source.to_string()))?;
        let mut document = value
            .into_object(locator.id)
            .map_err(|source| XtaskError::invalid_path(&path, source.to_string()))?;
        if take_string(&mut document, "id", &path)? != locator.id {
            return Err(XtaskError::invalid_path(
                &path,
                "security change-review record id drifted from its registry binding",
            ));
        }
        let focused_validation = take_required(&mut document, "focused_validation")
            .map_err(|source| XtaskError::invalid_path(&path, source.to_string()))?;
        let mut initial_red = take_object(&mut document, "initial_red", &path)?;
        let initial_red_command = take_string(&mut initial_red, "command", &path)?;
        let mut change = take_object(&mut document, "change", &path)?;
        let mut contract = take_object(&mut change, "changed_path_contract", &path)?;
        let reviewed_base = take_string(&mut contract, "merge_base", &path)?;
        if reviewed_base != locator.merge_base {
            return invalid("merge base drifted from the reviewed changed-path contract");
        }
        let revision = take_optional_string(&mut contract, "implementation_revision", &path)?;
        if locator.requires_revision && !revision.as_deref().is_some_and(valid_hex_identity) {
            return Err(XtaskError::invalid_path(
                &path,
                "security change-review record has no exact reviewed implementation revision identity",
            ));
        }
        let path_count = take_usize(&mut contract, "path_count", &path)?;
        let path_set_digest = take_string(&mut contract, "path_set_digest", &path)?;
        let classification_digest = take_string(&mut contract, "classification_digest", &path)?;
        if !valid_sha256_digest(&path_set_digest) || !valid_sha256_digest(&classification_digest) {
            return Err(XtaskError::invalid_path(
                &path,
                "changed-path contract has an invalid SHA-256 digest",
            ));
        }
        let record = take_string(&mut contract, "classification_record", &path)?;
        if record != CLASSIFICATION_RECORD {
            return Err(XtaskError::invalid_path(
                &path,
                "changed-path classification record drifted",
            ));
        }
        let classifications = match contract.remove("classifications") {
            Some(JsonValue::Array(rows)) => Some(parse_classifications(rows, &path)?),
            Some(_) => {
                return Err(XtaskError::invalid_path(
                    &path,
                    "changed-path classifications must be an array",
                ));
            },
            None => None,
        };
        crate::evidence_json::reject_unknown_fields(contract, "changed-path contract")
            .map_err(|source| XtaskError::invalid_path(&path, source.to_string()))?;
        apply_input_budget_contract(change, &path, budget)?;
        if validate_commands {
            validate_policy_commands(locator, &initial_red_command, focused_validation, &path)?;
        }
        Ok(Self {
            id: locator.id.to_owned(),
            revision,
            path_count,
            path_set_digest,
            classification_digest,
            classifications,
        })
    }

    fn classifications(
        &self,
        model_coverage: &BTreeMap<String, String>,
        reviewed_non_trust: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, Classification>, XtaskError> {
        if let Some(classifications) = &self.classifications {
            return Ok(classifications.clone());
        }
        let mut resolved = BTreeMap::new();
        for (path, owner) in model_coverage {
            resolved.insert(path.clone(), Classification::Model(owner.clone()));
        }
        for (path, review) in reviewed_non_trust {
            if resolved
                .insert(
                    path.clone(),
                    Classification::ReviewedNonTrust(review.clone()),
                )
                .is_some()
            {
                return invalid(format!(
                    "path `{path}` has conflicting model and non-trust classifications"
                ));
            }
        }
        Ok(resolved)
    }
}

#[derive(Clone)]
enum Classification {
    Model(String),
    ReviewedNonTrust(String),
}

impl Classification {
    fn record(&self, path: &str) -> String {
        match self {
            Self::Model(value) => format!("{path}\tmodel\t{value}"),
            Self::ReviewedNonTrust(value) => format!("{path}\treviewed-non-trust\t{value}"),
        }
    }
}

fn validate_actual_paths(
    changed_paths: &str,
    classifications: &BTreeMap<String, Classification>,
    contract: &ReviewContract,
) -> Result<String, XtaskError> {
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
    if let Some((path, classification)) = classifications
        .iter()
        .find(|(path, _)| !actual.contains(*path))
    {
        let detail = if contract.id == "PC-0015-m0-10-security-crypto-runners" {
            match classification {
                Classification::Model(_) => {
                    format!(
                        "model-classified path `{path}` is extra or stale for the actual changed set"
                    )
                },
                Classification::ReviewedNonTrust(_) => {
                    format!(
                        "reviewed non-trust path `{path}` is extra or stale for the actual changed set"
                    )
                },
            }
        } else {
            format!("reviewed path `{path}` is extra or stale for the actual changed set")
        };
        return invalid(detail);
    }
    let mut scoped = BTreeMap::new();
    for path in &actual {
        let Some(classification) = classifications.get(path) else {
            return invalid(format!(
                "actual changed path `{path}` has no owned classification"
            ));
        };
        scoped.insert(path.clone(), classification.clone());
    }
    validate_classification_contract(&scoped, contract)
}

fn validate_classification_contract(
    classifications: &BTreeMap<String, Classification>,
    contract: &ReviewContract,
) -> Result<String, XtaskError> {
    let records = classifications
        .iter()
        .map(|(path, classification)| classification.record(path))
        .collect::<Vec<_>>();
    let sorted_paths = classifications
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let path_digest = sha256(sorted_paths.join("\n").as_bytes());
    let classification_digest = sha256(records.join("\n").as_bytes());
    if classifications.len() != contract.path_count
        || path_digest != contract.path_set_digest
        || classification_digest != contract.classification_digest
    {
        let legacy_model_detail = if contract.id == "PC-0015-m0-10-security-crypto-runners"
            && classifications
                .values()
                .any(|classification| matches!(classification, Classification::Model(_)))
        {
            "model-classified path contract"
        } else {
            "actual changed set"
        };
        return invalid(format!(
            "{legacy_model_detail} or classification digest drifted from {}; implementation-revision={}; actual-paths={}; actual-path-set-digest={path_digest}; actual-classification-digest={classification_digest}",
            contract.id,
            contract.revision.as_deref().unwrap_or("legacy-none"),
            sorted_paths.join("|")
        ));
    }
    Ok(format!(
        "change-review={}; implementation-revision={}; changed-path-count={}; changed-paths={}; changed-path-set-digest={path_digest}; changed-path-classification-digest={classification_digest}",
        contract.id,
        contract.revision.as_deref().unwrap_or("legacy-none"),
        classifications.len(),
        sorted_paths.join("|"),
    ))
}

fn parse_classifications(
    rows: Vec<JsonValue>,
    path: &Path,
) -> Result<BTreeMap<String, Classification>, XtaskError> {
    if rows.is_empty() {
        return Err(XtaskError::invalid_path(
            path,
            "changed-path classifications must not be empty",
        ));
    }
    let mut classifications = BTreeMap::new();
    for row in rows {
        let mut row = row
            .into_object("changed-path classification")
            .map_err(|source| XtaskError::invalid_path(path, source.to_string()))?;
        let path_value = take_string(&mut row, "path", path)?;
        if Path::new(&path_value).is_absolute()
            || path_value.split('/').any(|component| component == "..")
        {
            return Err(XtaskError::invalid_path(
                path,
                "changed-path classification has an invalid repository path",
            ));
        }
        let disposition = take_string(&mut row, "disposition", path)?;
        let owner = take_string(&mut row, "owner", path)?;
        let rationale = take_string(&mut row, "rationale", path)?;
        let model_id = take_optional_string(&mut row, "model_id", path)?;
        crate::evidence_json::reject_unknown_fields(row, "changed-path classification")
            .map_err(|source| XtaskError::invalid_path(path, source.to_string()))?;
        let value = match disposition.as_str() {
            "model" => Classification::Model(format!(
                "{owner}\t{}",
                model_id.ok_or_else(|| {
                    XtaskError::invalid_path(
                        path,
                        "model changed-path classification omits its threat-model identity",
                    )
                })?
            )),
            "reviewed-non-trust" if model_id.is_none() => {
                Classification::ReviewedNonTrust(format!("{owner}\t{rationale}"))
            },
            "reviewed-non-trust" => {
                return Err(XtaskError::invalid_path(
                    path,
                    "reviewed non-trust changed-path classification must not name a threat model",
                ));
            },
            _ => {
                return Err(XtaskError::invalid_path(
                    path,
                    "changed-path classification disposition is not recognized",
                ));
            },
        };
        if classifications.insert(path_value.clone(), value).is_some() {
            return Err(XtaskError::invalid_path(
                path,
                format!("changed-path classification duplicates `{path_value}`"),
            ));
        }
    }
    Ok(classifications)
}

fn apply_input_budget_contract(
    mut change: JsonObject,
    path: &Path,
    budget: &mut crate::quality::SecurityInputBudget,
) -> Result<(), XtaskError> {
    let mut limits = take_object(&mut change, "external_input_budget", path)?;
    let maximum_count = take_usize(&mut limits, "maximum_count", path)?;
    let maximum_bytes = take_usize(&mut limits, "maximum_aggregate_bytes", path)?;
    budget.apply_declared_limits(maximum_count, maximum_bytes)
}

fn validate_policy_commands(
    locator: ReviewLocator,
    initial_red_command: &str,
    focused_validation: JsonValue,
    path: &Path,
) -> Result<(), XtaskError> {
    let expected = match locator.id {
        "PC-0015-m0-10-security-crypto-runners" => M0_10_POLICY_COMMANDS.as_slice(),
        "PC-0016-m0-11-compatibility-exact-target-matrix" => M0_11_POLICY_COMMANDS.as_slice(),
        _ => {
            return Err(XtaskError::invalid_path(
                path,
                "unknown policy command contract",
            ));
        },
    };
    let JsonValue::Array(entries) = focused_validation else {
        return Err(XtaskError::invalid_path(
            path,
            format!(
                "{} focused validation commands must be an array",
                locator.id
            ),
        ));
    };
    let mut commands = entries
        .into_iter()
        .map(|entry| match entry {
            JsonValue::String(command) => Ok(command),
            _ => Err(XtaskError::invalid_path(
                path,
                format!("{} focused validation command is not a string", locator.id),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    commands.push(initial_red_command.to_owned());
    let policy_name = match locator.id {
        "PC-0015-m0-10-security-crypto-runners" => "PC-0015",
        "PC-0016-m0-11-compatibility-exact-target-matrix" => "PC-0016",
        _ => {
            return Err(XtaskError::invalid_path(
                path,
                "unknown policy command contract",
            ));
        },
    };
    let Some(initial_expected) = expected.first() else {
        return Err(XtaskError::invalid_path(
            path,
            "policy command contract has no initial validation command",
        ));
    };
    if !initial_red_command.contains(initial_expected) {
        return Err(XtaskError::invalid_path(
            path,
            format!("{policy_name} validation command `{initial_expected}` does not resolve"),
        ));
    }
    for command in expected {
        if !commands.iter().any(|actual| actual.contains(command)) {
            return Err(XtaskError::invalid_path(
                path,
                format!("{policy_name} validation command `{command}` does not resolve"),
            ));
        }
    }
    Ok(())
}

const M0_10_POLICY_COMMANDS: [&str; 17] = [
    "m0_10_security_crypto::quality_orchestrates_security_crypto_and_secret_canary_descriptors_through_the_public_seam",
    "m0_10_security_crypto::quality_rejects_a_drifted_security_crypto_or_secret_canary_descriptor",
    "m0_10_security_crypto::quality_retains_parent_owned_candidate_artifact_scan_evidence",
    "m0_10_security_crypto::quality_rejects_executable_intentional_leak_with_retained_failed_evidence",
    "m0_10_security_crypto::quality_rejects_missing_merge_base_and_uncovered_security_changes",
    "m0_10_final_blockers::quality_rejects_an_actual_changed_path_without_owned_classification",
    "m0_10_final_blockers::quality_retains_the_complete_sorted_changed_path_classification",
    "m0_10_final_blockers::quality_rejects_stale_conflicting_or_unowned_path_dispositions",
    "m0_10_final_blockers::quality_rejects_an_extra_stale_model_classification",
    "m0_10_final_blockers::quality_enforces_the_shared_external_input_count_boundary",
    "m0_10_final_blockers::quality_enforces_the_shared_external_input_aggregate_boundary",
    "m0_10_final_blockers::quality_uses_the_actual_m0_09_merge_base_and_rejects_the_old_base_pin",
    "m0_10_final_blockers::policy_and_catalog_inputs_enforce_exact_bounds",
    "m0_10_final_blockers::threat_model_inputs_enforce_exact_bounds",
    "m0_10_final_blockers::target_registry_inputs_enforce_exact_bounds",
    "m0_10_final_blockers::canary_fixture_inputs_enforce_exact_bounds",
    "security_harness::tests::crypto_self_test_covers_the_registered_harness_obligations",
];

const M0_11_POLICY_COMMANDS: [&str; 4] = [
    "cargo test --locked --package xtask --test foundational_scope_activation m0_11_matrix::quality_executes_every_exact_diagnostic_target_with_independent_retained_identity -- --exact",
    "cargo test --locked --package xtask --test foundational_scope_activation m0_11_matrix:: -- --nocapture",
    "cargo test --locked --package xtask --bin xtask matrix_targets::tests -- --nocapture",
    "cargo fmt --check",
];

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
            format!("security change-review field `{field}` must be a non-empty string"),
        )),
        Err(source) => Err(XtaskError::invalid_path(path, source.to_string())),
    }
}

fn take_optional_string(
    object: &mut JsonObject,
    field: &str,
    path: &Path,
) -> Result<Option<String>, XtaskError> {
    match object.remove(field) {
        Some(JsonValue::String(value)) if !value.is_empty() => Ok(Some(value)),
        Some(_) => Err(XtaskError::invalid_path(
            path,
            format!("security change-review field `{field}` must be a non-empty string"),
        )),
        None => Ok(None),
    }
}

fn take_usize(object: &mut JsonObject, field: &str, path: &Path) -> Result<usize, XtaskError> {
    match take_required(object, field) {
        Ok(JsonValue::Integer(value)) => usize::try_from(value)
            .map_err(|_| XtaskError::invalid_path(path, format!("`{field}` exceeds usize"))),
        Ok(_) => Err(XtaskError::invalid_path(
            path,
            format!("security change-review field `{field}` must be an integer"),
        )),
        Err(source) => Err(XtaskError::invalid_path(path, source.to_string())),
    }
}

fn valid_hex_identity(value: &str) -> bool {
    (40..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn invalid<T>(detail: impl Into<String>) -> Result<T, XtaskError> {
    Err(XtaskError::invalid(
        "complete changed-path classification",
        detail,
    ))
}
