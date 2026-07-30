//! Frozen ownership and revision-bound changed-surface coverage for M0-10.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;

const PATH: &str = "qualification/engineering/security-threat-surfaces.tsv";
const HEADER: &str = "record_id\trecord_kind\tmodel_id\tsemantic_owner\ttrust_boundary\tsurface_paths\tchanged_model_paths\tchange_set\treview_disposition\trationale";
const OWNER: &str = "Security and Key Management";
const CHANGE_SET: &str = "m0-10-pr-166@542f3835dc67f819e566e017c04e165b15416861";
const DISPOSITION: &str = "reviewed-m0-10";
const MODEL_RATIONALE: &str = "owned versioned threat model";
const MAXIMUM_REGISTRY_BYTES: usize = 16_384;
const MAXIMUM_MODEL_BYTES: usize = 8_192;
const CONTRACTS: [(&str, &str, &str, &str); 3] = [
    (
        "security-runner-v1",
        "TM-0001-m0-04-toml-parser",
        "configuration-parser-before-typed-construction-v1",
        "crates/positron-config/src/lib.rs|qualification/engineering/security/TM-0001-m0-04-toml-parser.json",
    ),
    (
        "crypto-runner-v1",
        "TM-0010-m0-10-runner-crypto",
        "xtask-crypto-known-answer-provider-boundary-v1",
        "tools/xtask/src/security_harness/crypto.rs|tools/xtask/src/crypto_targets.rs|tools/xtask/src/quality.rs|qualification/engineering/security-crypto-targets.tsv",
    ),
    (
        "secret-canary-runner-v1",
        "TM-0011-m0-10-runner-artifacts",
        "xtask-candidate-artifact-disclosure-boundary-v1",
        "tools/xtask/src/security_harness.rs|tools/xtask/src/security_harness/canary.rs|tools/xtask/src/security_harness/canary_budget.rs|qualification/engineering/security-canary-targets.tsv",
    ),
];

pub(crate) struct ThreatSurfaceRegistry {
    summaries: BTreeMap<String, String>,
    model_coverage: BTreeMap<String, String>,
    reviewed_non_trust: BTreeMap<String, String>,
}

impl ThreatSurfaceRegistry {
    pub(crate) fn load(
        root: &Path,
        budget: &mut crate::bounded_input::ExternalInputBudget,
    ) -> Result<Self, XtaskError> {
        crate::security_change_review::validate_policy_commands(root, budget)?;
        let path = root.join(PATH);
        let bytes = crate::bounded_input::read_external(
            &path,
            MAXIMUM_REGISTRY_BYTES,
            "security threat-surface registry",
            budget,
        )?;
        let text = std::str::from_utf8(&bytes).map_err(|source| {
            XtaskError::invalid_path(&path, format!("registry is not UTF-8: {source}"))
        })?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(XtaskError::invalid_path(
                &path,
                "security threat-surface registry header drifted",
            ));
        }
        let mut summaries = BTreeMap::new();
        let mut model_coverage = BTreeMap::new();
        let mut reviewed_non_trust = BTreeMap::new();
        let mut record_ids = BTreeSet::new();
        for line in lines {
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                record_id,
                record_kind,
                model,
                owner,
                boundary,
                paths,
                changed_model_paths,
                change_set,
                disposition,
                rationale,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    &path,
                    "security threat-surface registry row has the wrong field count",
                ));
            };
            if !record_ids.insert(*record_id) {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("security threat-surface registry duplicates `{record_id}`"),
                ));
            }
            if *change_set != CHANGE_SET || *disposition != DISPOSITION {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("security threat-surface registry has stale review for `{record_id}`"),
                ));
            }
            match *record_kind {
                "model" => {
                    let Some(contract) = CONTRACTS.iter().find(|contract| contract.0 == *record_id)
                    else {
                        return Err(XtaskError::invalid_path(
                            &path,
                            "security threat-surface registry names an unknown model runner",
                        ));
                    };
                    if (*model, *owner, *boundary, *paths, *rationale)
                        != (contract.1, OWNER, contract.2, contract.3, MODEL_RATIONALE)
                    {
                        return Err(XtaskError::invalid_path(
                            &path,
                            format!(
                                "security threat-surface registry contract drifted for `{record_id}`"
                            ),
                        ));
                    }
                    if paths
                        .split('|')
                        .any(|surface| !root.join(surface).is_file())
                    {
                        return Err(XtaskError::invalid_path(
                            &path,
                            format!(
                                "security threat-surface registry has stale coverage for `{record_id}`"
                            ),
                        ));
                    }
                    let model_digest =
                        validate_model_record(root, model, owner, boundary, paths, budget)?;
                    let registered_surface_digest =
                        format!("sha256:{:x}", Sha256::digest(paths.as_bytes()));
                    let full_surfaces = paths.split('|').collect::<BTreeSet<_>>();
                    let changed_surfaces = if *changed_model_paths == "-" {
                        Vec::new()
                    } else {
                        changed_model_paths.split('|').collect::<Vec<_>>()
                    };
                    if changed_surfaces
                        .iter()
                        .any(|surface| !full_surfaces.contains(surface))
                    {
                        return Err(XtaskError::invalid_path(
                            &path,
                            format!(
                                "changed model coverage escapes full surfaces for `{record_id}`"
                            ),
                        ));
                    }
                    for surface in changed_surfaces {
                        if model_coverage
                            .insert(surface.to_owned(), format!("{owner}\t{model}"))
                            .is_some()
                        {
                            return Err(XtaskError::invalid_path(
                                &path,
                                format!("model coverage duplicates path `{surface}`"),
                            ));
                        }
                    }
                    summaries.insert(
                        (*record_id).to_owned(),
                        format!(
                            "model={model}; model-record-digest={model_digest}; owner={owner}; trust-boundary={boundary}; registered-surfaces={paths}; changed-model-surfaces={changed_model_paths}; registered-surface-set-digest={registered_surface_digest}; change-set={change_set}; disposition={disposition}"
                        ),
                    );
                },
                "reviewed-non-trust" => {
                    if *model != "-"
                        || *boundary != "-"
                        || *changed_model_paths != "-"
                        || owner.is_empty()
                        || *owner == "-"
                        || rationale.is_empty()
                        || *rationale == "-"
                        || paths.is_empty()
                        || paths.contains('|')
                    {
                        return Err(XtaskError::invalid_path(
                            &path,
                            format!(
                                "reviewed non-trust record `{record_id}` is missing owner or rationale"
                            ),
                        ));
                    }
                    if reviewed_non_trust
                        .insert((*paths).to_owned(), format!("{owner}\t{rationale}"))
                        .is_some()
                    {
                        return Err(XtaskError::invalid_path(
                            &path,
                            format!("reviewed non-trust path `{paths}` is duplicated"),
                        ));
                    }
                },
                _ => {
                    return Err(XtaskError::invalid_path(
                        &path,
                        format!("unknown threat-surface record kind `{record_kind}`"),
                    ));
                },
            }
        }
        if summaries.len() != CONTRACTS.len() {
            return Err(XtaskError::invalid_path(
                &path,
                "security threat-surface registry has incomplete owned model coverage",
            ));
        }
        let registry_digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        for summary in summaries.values_mut() {
            summary.push_str("; threat-surface-digest=");
            summary.push_str(&registry_digest);
        }
        Ok(Self {
            summaries,
            model_coverage,
            reviewed_non_trust,
        })
    }

    pub(crate) fn summary(&self, runner: &str) -> Result<&str, XtaskError> {
        self.summaries
            .get(runner)
            .map(String::as_str)
            .ok_or_else(|| {
                XtaskError::invalid(
                    "security threat-surface registry",
                    "runner model is missing",
                )
            })
    }

    pub(crate) fn validate_changed_paths(
        &self,
        root: &Path,
        merge_base: &str,
        changed_paths: &str,
        budget: &mut crate::bounded_input::ExternalInputBudget,
    ) -> Result<String, XtaskError> {
        crate::security_change_review::validate(
            root,
            merge_base,
            changed_paths,
            &self.model_coverage,
            &self.reviewed_non_trust,
            budget,
        )
    }
}

fn validate_model_record(
    root: &Path,
    model: &str,
    owner: &str,
    boundary: &str,
    surfaces: &str,
    budget: &mut crate::bounded_input::ExternalInputBudget,
) -> Result<String, XtaskError> {
    let path = root.join(format!("qualification/engineering/security/{model}.json"));
    let bytes = crate::bounded_input::read_external(
        &path,
        MAXIMUM_MODEL_BYTES,
        "versioned threat-model record",
        budget,
    )?;
    if model == "TM-0001-m0-04-toml-parser" {
        return Ok(format!("sha256:{:x}", Sha256::digest(&bytes)));
    }
    let content = std::str::from_utf8(&bytes)
        .map_err(|source| XtaskError::invalid_path(&path, source.to_string()))?;
    for required in [
        "\"schema_version\": 1",
        "\"version\": 1",
        &format!("\"model_id\": \"{model}\""),
        &format!("\"semantic_owner\": \"{owner}\""),
        &format!("\"trust_boundaries\": [\"{boundary}\"]"),
        "\"review_disposition\": \"reviewed-m0-10\"",
        "\"review_revision\": \"542f3835dc67f819e566e017c04e165b15416861\"",
    ] {
        if !content.contains(required) {
            return Err(XtaskError::invalid_path(
                &path,
                format!("versioned threat-model record is stale or missing `{required}`"),
            ));
        }
    }
    for surface in surfaces.split('|') {
        if !content.contains(&format!("\"{surface}\"")) {
            return Err(XtaskError::invalid_path(
                &path,
                format!("versioned threat-model record does not cover `{surface}`"),
            ));
        }
    }
    let (declared_digest, expected_record_digest) = match model {
        "TM-0010-m0-10-runner-crypto" => (
            "sha256:13fc0dabcc5a71015de407eda2dd2cf36904bb1bd0b50eb1f02e17bdabe1108a",
            "sha256:56cd9ecd8f0216fb8eac4cc77e39ffd9a57bef9547a172b4ff1b600c5e6ac6bf",
        ),
        "TM-0011-m0-10-runner-artifacts" => (
            "sha256:4dd3266ba77cc7185f72d0ef2af77fc75fe032e9b14cdeaf8b82d9afa335523b",
            "sha256:d1071c8c2762b3e27e897f182e60c118179eeaceda11f5d8c64f0d8439e5e258",
        ),
        _ => {
            return Err(XtaskError::invalid_path(
                &path,
                "unknown threat-model identity",
            ));
        },
    };
    if !content.contains(&format!("\"record_digest\": \"{declared_digest}\"")) {
        return Err(XtaskError::invalid_path(
            &path,
            "versioned threat-model record digest is stale",
        ));
    }
    let actual_record_digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    if actual_record_digest != expected_record_digest {
        return Err(XtaskError::invalid_path(
            &path,
            "versioned threat-model record bytes drifted from the reviewed digest",
        ));
    }
    Ok(actual_record_digest)
}
