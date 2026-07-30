//! Frozen ownership and revision-bound changed-surface coverage for M0-10.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;

const PATH: &str = "qualification/engineering/security-threat-surfaces.tsv";
const HEADER: &str = "runner_id\tmodel_id\tsemantic_owner\ttrust_boundary\tsurface_paths\tchange_set\treview_disposition";
const OWNER: &str = "Security and Key Management";
const CHANGE_SET: &str = "m0-10-issue-11@542f383";
const DISPOSITION: &str = "reviewed-m0-10";
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
}

impl ThreatSurfaceRegistry {
    pub(crate) fn load(root: &Path) -> Result<Self, XtaskError> {
        validate_policy_commands(root)?;
        let path = root.join(PATH);
        let bytes = fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        if bytes.len() > 16_384 {
            return Err(XtaskError::invalid_path(
                &path,
                "security threat-surface registry exceeds 16384 bytes",
            ));
        }
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
        for line in lines {
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                runner,
                model,
                owner,
                boundary,
                paths,
                change_set,
                disposition,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    &path,
                    "security threat-surface registry row has the wrong field count",
                ));
            };
            let Some(contract) = CONTRACTS.iter().find(|contract| contract.0 == *runner) else {
                return Err(XtaskError::invalid_path(
                    &path,
                    "security threat-surface registry names an unknown runner",
                ));
            };
            if (*model, *owner, *boundary, *paths, *change_set, *disposition)
                != (
                    contract.1,
                    OWNER,
                    contract.2,
                    contract.3,
                    CHANGE_SET,
                    DISPOSITION,
                )
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("security threat-surface registry contract drifted for `{runner}`"),
                ));
            }
            if paths
                .split('|')
                .any(|surface| !root.join(surface).is_file())
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("security threat-surface registry has stale coverage for `{runner}`"),
                ));
            }
            let model_digest = validate_model_record(root, model, owner, boundary, paths)?;
            let registered_surface_digest =
                format!("sha256:{:x}", Sha256::digest(paths.as_bytes()));
            if summaries
                .insert(
                    (*runner).to_owned(),
                    format!(
                        "model={model}; model-record-digest={model_digest}; owner={owner}; trust-boundary={boundary}; registered-surfaces={paths}; registered-surface-set-digest={registered_surface_digest}; change-set={change_set}; disposition={disposition}"
                    ),
                )
                .is_some()
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("security threat-surface registry duplicates `{runner}`"),
                ));
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
        Ok(Self { summaries })
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
        root: &Path,
        changed_paths: &str,
    ) -> Result<String, XtaskError> {
        let registry = fs::read_to_string(root.join(PATH))
            .map_err(|source| XtaskError::io("read security threat-surface registry", source))?;
        let covered = registry
            .lines()
            .skip(1)
            .filter_map(|line| line.split('\t').nth(4))
            .flat_map(|paths| paths.split('|'))
            .collect::<std::collections::BTreeSet<_>>();
        let mut relevant = changed_paths
            .lines()
            .filter(|path| {
                covered.contains(*path)
                    || (path.starts_with("tools/xtask/src/security_harness/")
                        && !path.ends_with("_tests.rs"))
            })
            .collect::<Vec<_>>();
        relevant.sort_unstable();
        relevant.dedup();
        if let Some(uncovered) = relevant.iter().find(|path| !covered.contains(**path)) {
            return Err(XtaskError::invalid(
                "security changed-path coverage",
                format!("changed registered trust-surface path `{uncovered}` is uncovered"),
            ));
        }
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(relevant.join("\n").as_bytes())
        ))
    }
}

fn validate_model_record(
    root: &Path,
    model: &str,
    owner: &str,
    boundary: &str,
    surfaces: &str,
) -> Result<String, XtaskError> {
    let path = root.join(format!("qualification/engineering/security/{model}.json"));
    let bytes = fs::read(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
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
        "\"review_revision\": \"542f383\"",
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
            "sha256:0d818cbcfad3b505ec38974bd90171385ceddfe864e660f26c90d58f02a093b1",
        ),
        "TM-0011-m0-10-runner-artifacts" => (
            "sha256:4dd3266ba77cc7185f72d0ef2af77fc75fe032e9b14cdeaf8b82d9afa335523b",
            "sha256:85b1bd2023ef1dbea39f2d73d673e4c038214b6d94019a4ca1f584f5109bd466",
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

fn validate_policy_commands(root: &Path) -> Result<(), XtaskError> {
    let path = root.join(
        "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
    );
    let content = fs::read_to_string(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    let public_targets = [
        "m0_10_security_crypto::quality_orchestrates_security_crypto_and_secret_canary_descriptors_through_the_public_seam",
        "m0_10_security_crypto::quality_rejects_a_drifted_security_crypto_or_secret_canary_descriptor",
        "m0_10_security_crypto::quality_retains_parent_owned_candidate_artifact_scan_evidence",
        "m0_10_security_crypto::quality_rejects_executable_intentional_leak_with_retained_failed_evidence",
        "m0_10_security_crypto::quality_rejects_missing_merge_base_and_uncovered_security_changes",
    ];
    for target in public_targets {
        if !content.contains(target) {
            return Err(XtaskError::invalid_path(
                &path,
                format!("PC-0015 validation command target `{target}` does not resolve"),
            ));
        }
    }
    let target_prefix = "m0_10_security_crypto::";
    for remainder in content.split(target_prefix).skip(1) {
        let name = remainder
            .split(|character: char| character == '"' || character.is_whitespace())
            .next()
            .unwrap_or_default();
        let target = format!("{target_prefix}{name}");
        if !public_targets.contains(&target.as_str()) {
            return Err(XtaskError::invalid_path(
                &path,
                format!("PC-0015 validation command target `{target}` does not resolve"),
            ));
        }
    }
    let crypto_target =
        "security_harness::tests::crypto_self_test_covers_the_registered_harness_obligations";
    if !content.contains(crypto_target) {
        return Err(XtaskError::invalid_path(
            &path,
            format!("PC-0015 validation command target `{crypto_target}` does not resolve"),
        ));
    }
    if content.contains("security_probe_and_canary_harnesses_fail_closed") {
        return Err(XtaskError::invalid_path(
            &path,
            "PC-0015 validation command references a removed test target",
        ));
    }
    Ok(())
}
