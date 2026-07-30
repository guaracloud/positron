//! Hermetic artifact adapters and independent secret-canary recollection scan.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::canary_budget::{ArtifactBudget, MAXIMUM_ARTIFACT_BYTES};
use crate::error::XtaskError;

const GOLDEN_PATH: &str =
    "qualification/fixtures/adversarial/cryptography/m0-10-security-canary-golden.tsv";
const LEAK_PATH: &str =
    "qualification/fixtures/adversarial/cryptography/m0-10-secret-canary-leak.tsv";
const TARGET_PATH: &str = "qualification/engineering/security-canary-targets.tsv";
const MAXIMUM_FIXTURE_BYTES: usize = 4_096;
pub(super) const CANARY_ID: &str = "POSITRON_SYNTHETIC_CANARY_V1";
pub(super) const LEAK_CANARY_ID: &str = "POSITRON_SYNTHETIC_CANARY_LEAK_V1";

pub(super) fn emit_candidate(
    repository: &Path,
    artifact_root: &Path,
    canary_id: &str,
) -> Result<(), XtaskError> {
    if !matches!(canary_id, CANARY_ID | LEAK_CANARY_ID) || !artifact_root.is_dir() {
        return Err(XtaskError::invalid(
            "candidate artifact emitter",
            "unregistered canary identity or parent-owned artifact root",
        ));
    }
    let golden = Golden::load(&repository.join(GOLDEN_PATH))?;
    let intentional_leak = LeakFixture::load(&repository.join(LEAK_PATH))?;
    if intentional_leak.0 != Sink::SupportArtifacts {
        return Err(XtaskError::invalid(
            "candidate artifact emitter",
            "intentional leak fixture does not select the registered support artifact",
        ));
    }
    let leak = (canary_id == LEAK_CANARY_ID).then_some(intentional_leak.0);
    materialize(artifact_root, &golden, leak)?;
    Ok(())
}

pub(super) fn scan_candidate(
    repository: &Path,
    artifact_root: &Path,
) -> Result<String, XtaskError> {
    let target_digest = validate_target_contract(repository)?;
    let golden = Golden::load(&repository.join(GOLDEN_PATH))?;
    let _intentional_leak = LeakFixture::load(&repository.join(LEAK_PATH))?;
    let collected_root = artifact_root.join("collected");
    let mut collected = Vec::new();
    let mut budget = ArtifactBudget::candidate();
    let entries = fs::read_dir(&collected_root)
        .map_err(|source| XtaskError::io(format!("read {}", collected_root.display()), source))?;
    for entry in entries {
        let entry = entry.map_err(|source| {
            XtaskError::io(format!("read {}", collected_root.display()), source)
        })?;
        let path = entry.path();
        let Some(label) = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .and_then(|name| name.strip_suffix(".artifact"))
        else {
            return Err(XtaskError::invalid(
                "candidate artifact scanner",
                "extra candidate artifact path is not registered",
            ));
        };
        let sink = Sink::parse(label)?;
        let bytes = read_bounded(&path, MAXIMUM_ARTIFACT_BYTES, "candidate artifact")?;
        budget.charge(bytes.len())?;
        collected.push(Collected { sink, bytes });
    }
    independently_scan(&collected, &golden)?;
    let mut digest = Sha256::new();
    let paths = Sink::ALL
        .into_iter()
        .map(|sink| {
            let path = collected_root.join(format!("{}.artifact", sink.label()));
            digest.update(sink.label());
            digest.update(b"\0");
            let artifact = collected
                .iter()
                .find(|artifact| artifact.sink == sink)
                .ok_or_else(|| {
                    XtaskError::invalid("candidate artifact scanner", "registered artifact missing")
                })?;
            digest.update(&artifact.bytes);
            Ok(format!("{}={}", sink.label(), path.display()))
        })
        .collect::<Result<Vec<_>, XtaskError>>()?;
    Ok(format!(
        "candidate-target=xtask-security-runner-capability-v1; target-contract-digest={target_digest}; ownership=parent-attempt; artifact-paths={}; artifact-digest=sha256:{:x}; scanner-result=no-canary-disclosure; qualification=runner-capability-only",
        paths.join("|"),
        digest.finalize()
    ))
}

fn validate_target_contract(repository: &Path) -> Result<String, XtaskError> {
    let path = repository.join(TARGET_PATH);
    let bytes = read_fixture(&path)?;
    let expected = "target_id\trunner_id\tsemantic_owner\tcommand\tartifact_categories\tqualification\nxtask-security-runner-capability-v1\tsecret-canary-runner-v1\tQuality Engineering\tcargo run --locked --package xtask --bin xtask -- quality-secret-canary <artifact-root> POSITRON_SYNTHETIC_CANARY_V1\tlogs|errors|metrics|traces|diagnostics|evidence|binaries|packages|support-artifacts\trunner-capability-only\nxtask-security-intentional-leak-negative-v1\tsecret-canary-runner-v1\tQuality Engineering\tcargo run --locked --package xtask --bin xtask -- quality-secret-canary <artifact-root> POSITRON_SYNTHETIC_CANARY_LEAK_V1\tsupport-artifacts\tnegative-test-only\n";
    if bytes != expected.as_bytes() {
        return Err(XtaskError::invalid_path(
            &path,
            "registered candidate artifact contract drifted",
        ));
    }
    Ok(format!("sha256:{:x}", Sha256::digest(&bytes)))
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum Sink {
    Logs,
    Errors,
    Metrics,
    Traces,
    Diagnostics,
    Evidence,
    Binaries,
    Packages,
    SupportArtifacts,
}
impl Sink {
    const ALL: [Self; 9] = [
        Self::Logs,
        Self::Errors,
        Self::Metrics,
        Self::Traces,
        Self::Diagnostics,
        Self::Evidence,
        Self::Binaries,
        Self::Packages,
        Self::SupportArtifacts,
    ];
    const fn label(self) -> &'static str {
        match self {
            Self::Logs => "logs",
            Self::Errors => "errors",
            Self::Metrics => "metrics",
            Self::Traces => "traces",
            Self::Diagnostics => "diagnostics",
            Self::Evidence => "evidence",
            Self::Binaries => "binaries",
            Self::Packages => "packages",
            Self::SupportArtifacts => "support-artifacts",
        }
    }
    fn parse(label: &str) -> Result<Self, XtaskError> {
        Self::ALL
            .into_iter()
            .find(|sink| sink.label() == label)
            .ok_or_else(|| {
                XtaskError::invalid("secret canary fixture", format!("unknown sink `{label}`"))
            })
    }
}

struct Golden {
    outputs: Vec<(Sink, Vec<u8>)>,
}
impl Golden {
    fn load(path: &Path) -> Result<Self, XtaskError> {
        let bytes = read_fixture(path)?;
        let content = std::str::from_utf8(&bytes).map_err(|source| {
            XtaskError::invalid(path.display().to_string(), source.to_string())
        })?;
        let mut lines = content.lines();
        if lines.next() != Some("sink\tcollected_payload") {
            return Err(XtaskError::invalid(
                path.display().to_string(),
                "golden header drifted",
            ));
        }
        let mut outputs = Vec::new();
        let mut observed = BTreeSet::new();
        for line in lines {
            let Some((label, payload)) = line.split_once('\t') else {
                return Err(XtaskError::invalid(
                    path.display().to_string(),
                    "golden row is not tab-delimited",
                ));
            };
            let sink = Sink::parse(label)?;
            if payload != format!("REDACTED:{}", sink.label()) || !observed.insert(sink) {
                return Err(XtaskError::invalid(
                    path.display().to_string(),
                    "golden payload or sink inventory drifted",
                ));
            }
            outputs.push((sink, payload.as_bytes().to_vec()));
        }
        if observed.len() != Sink::ALL.len() || outputs.len() != Sink::ALL.len() {
            return Err(XtaskError::invalid(
                path.display().to_string(),
                "golden does not cover every canary sink",
            ));
        }
        Ok(Self { outputs })
    }
    fn output(&self, sink: Sink) -> Result<&[u8], XtaskError> {
        self.outputs
            .iter()
            .find(|(candidate, _)| *candidate == sink)
            .map(|(_, value)| value.as_slice())
            .ok_or_else(|| XtaskError::invalid("secret canary golden", "required sink is absent"))
    }
}

struct LeakFixture(Sink);
impl LeakFixture {
    fn load(path: &Path) -> Result<Self, XtaskError> {
        let bytes = read_fixture(path)?;
        let content = std::str::from_utf8(&bytes).map_err(|source| {
            XtaskError::invalid(path.display().to_string(), source.to_string())
        })?;
        let mut lines = content.lines();
        if lines.next() != Some("sink\tmode") {
            return Err(XtaskError::invalid(
                path.display().to_string(),
                "leak fixture header drifted",
            ));
        }
        let Some(row) = lines.next() else {
            return Err(XtaskError::invalid(
                path.display().to_string(),
                "leak fixture is empty",
            ));
        };
        if lines.next().is_some() {
            return Err(XtaskError::invalid(
                path.display().to_string(),
                "leak fixture has multiple rows",
            ));
        }
        let Some((label, mode)) = row.split_once('\t') else {
            return Err(XtaskError::invalid(
                path.display().to_string(),
                "leak fixture row is not tab-delimited",
            ));
        };
        if mode != "leak" {
            return Err(XtaskError::invalid(
                path.display().to_string(),
                "leak fixture mode drifted",
            ));
        }
        Sink::parse(label).map(Self)
    }
}

struct Collected {
    sink: Sink,
    bytes: Vec<u8>,
}
fn materialize(
    root: &Path,
    golden: &Golden,
    leak: Option<Sink>,
) -> Result<Vec<Collected>, XtaskError> {
    let mut collected = Vec::new();
    for sink in Sink::ALL {
        let secret = format!("POSITRON_SYNTHETIC_CANARY_V1:{}", sink.label()).into_bytes();
        let serialized = serialize(&secret);
        let artifact = if leak == Some(sink) {
            serialized
        } else {
            redact(&serialized, sink)
        };
        let written = write_adapter(root, "written", sink, &artifact)?;
        let packaged = package_adapter(root, sink, &written)?;
        let item = collect_adapter(root, sink, &packaged)?;
        if leak != Some(sink) && item.bytes != golden.output(sink)? {
            return Err(XtaskError::invalid(
                "secret canary harness",
                "adapter output drifted from committed golden input",
            ));
        }
        collected.push(item);
    }
    Ok(collected)
}
fn serialize(secret: &[u8]) -> Vec<u8> {
    secret.to_vec()
}
fn redact(serialized: &[u8], sink: Sink) -> Vec<u8> {
    if contains(serialized, b"POSITRON_SYNTHETIC_CANARY_V1:") {
        format!("REDACTED:{}", sink.label()).into_bytes()
    } else {
        serialized.to_vec()
    }
}
fn package_adapter(root: &Path, sink: Sink, written: &Path) -> Result<PathBuf, XtaskError> {
    let bytes = read_bounded(written, MAXIMUM_ARTIFACT_BYTES, "written artifact")?;
    write_adapter(root, "packaged", sink, &bytes)
}
fn collect_adapter(root: &Path, sink: Sink, packaged: &Path) -> Result<Collected, XtaskError> {
    let bytes = read_bounded(packaged, MAXIMUM_ARTIFACT_BYTES, "packaged artifact")?;
    let path = write_adapter(root, "collected", sink, &bytes)?;
    let bytes = read_bounded(&path, MAXIMUM_ARTIFACT_BYTES, "collected artifact")?;
    Ok(Collected { sink, bytes })
}
fn write_adapter(
    root: &Path,
    stage: &str,
    sink: Sink,
    bytes: &[u8],
) -> Result<PathBuf, XtaskError> {
    let directory = root.join(stage);
    fs::create_dir_all(&directory)
        .map_err(|source| XtaskError::io(format!("create {}", directory.display()), source))?;
    let path = directory.join(format!("{}.artifact", sink.label()));
    fs::write(&path, bytes)
        .map_err(|source| XtaskError::io(format!("write {}", path.display()), source))?;
    Ok(path)
}
fn independently_scan(collected: &[Collected], golden: &Golden) -> Result<(), XtaskError> {
    if collected.len() != Sink::ALL.len() {
        return Err(XtaskError::invalid(
            "secret canary scanner",
            "collected sink inventory is incomplete",
        ));
    }
    let mut observed = BTreeSet::new();
    for item in collected {
        if !observed.insert(item.sink)
            || contains(&item.bytes, b"POSITRON_SYNTHETIC_CANARY_V1:")
            || item.bytes != golden.output(item.sink)?
        {
            return Err(XtaskError::invalid(
                "secret canary scanner",
                "collected artifact exposed a canary or drifted from golden",
            ));
        }
    }
    Ok(())
}
fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
}
fn read_fixture(path: &Path) -> Result<Vec<u8>, XtaskError> {
    read_bounded(path, MAXIMUM_FIXTURE_BYTES, "committed security fixture")
}

pub(super) fn read_bounded(
    path: &Path,
    maximum: usize,
    subject: &str,
) -> Result<Vec<u8>, XtaskError> {
    crate::bounded_input::read(path, maximum, subject)
}
