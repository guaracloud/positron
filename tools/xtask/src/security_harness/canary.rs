//! Hermetic artifact adapters and independent secret-canary recollection scan.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::error::XtaskError;

const GOLDEN_PATH: &str =
    "qualification/fixtures/adversarial/cryptography/m0-10-security-canary-golden.tsv";
const LEAK_PATH: &str =
    "qualification/fixtures/adversarial/cryptography/m0-10-secret-canary-leak.tsv";
const MAXIMUM_FIXTURE_BYTES: u64 = 4_096;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn run(root: &Path) -> Result<String, XtaskError> {
    let golden = Golden::load(&root.join(GOLDEN_PATH))?;
    let leak = LeakFixture::load(&root.join(LEAK_PATH))?;
    let fixture = FixtureRoot::create(root)?;
    let result = (|| {
        let collected = materialize(&fixture.path, &golden, None)?;
        independently_scan(&collected, &golden)?;
        let leaking = materialize(
            &fixture.path.join("intentional-leak"),
            &golden,
            Some(leak.0),
        )?;
        if independently_scan(&leaking, &golden).is_ok() {
            return Err(XtaskError::invalid(
                "secret canary harness",
                "the committed intentional leak fixture was accepted",
            ));
        }
        let mut digest = Sha256::new();
        digest.update(b"positron-secret-canary-harness-v2\0");
        for artifact in &collected {
            digest.update(artifact.sink.label());
            digest.update(b"\0");
            digest.update(&artifact.bytes);
            digest.update(b"\0");
        }
        Ok(format!(
            "secret-canary-harness-v2=collected-artifacts:{}; golden=sha256:{}; negative-fixture=secret-canary-leak-rejected; digest=sha256:{:x}",
            collected.len(),
            golden.digest,
            digest.finalize()
        ))
    })();
    fixture.remove()?;
    result
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
    digest: String,
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
        Ok(Self {
            outputs,
            digest: format!("{:x}", Sha256::digest(&bytes)),
        })
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

struct FixtureRoot {
    path: PathBuf,
}
impl FixtureRoot {
    fn create(root: &Path) -> Result<Self, XtaskError> {
        let parent = root.join("target/quality/security-canary-fixtures");
        fs::create_dir_all(&parent)
            .map_err(|source| XtaskError::io(format!("create {}", parent.display()), source))?;
        for _ in 0..16 {
            let path = parent.join(format!(
                "canary-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(XtaskError::io(format!("create {}", path.display()), source));
                },
            }
        }
        Err(XtaskError::invalid(
            "secret canary fixture",
            "bounded fixture root allocation exhausted",
        ))
    }
    fn remove(self) -> Result<(), XtaskError> {
        fs::remove_dir_all(&self.path).map_err(|source| {
            XtaskError::io(format!("remove owned {}", self.path.display()), source)
        })
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
    let bytes = fs::read(written)
        .map_err(|source| XtaskError::io(format!("read {}", written.display()), source))?;
    write_adapter(root, "packaged", sink, &bytes)
}
fn collect_adapter(root: &Path, sink: Sink, packaged: &Path) -> Result<Collected, XtaskError> {
    let bytes = fs::read(packaged)
        .map_err(|source| XtaskError::io(format!("read {}", packaged.display()), source))?;
    let path = write_adapter(root, "collected", sink, &bytes)?;
    let bytes = fs::read(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
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
    let metadata = fs::metadata(path)
        .map_err(|source| XtaskError::io(format!("stat {}", path.display()), source))?;
    if metadata.len() > MAXIMUM_FIXTURE_BYTES {
        return Err(XtaskError::invalid(
            path.display().to_string(),
            "committed fixture exceeds bounded size",
        ));
    }
    fs::read(path).map_err(|source| XtaskError::io(format!("read {}", path.display()), source))
}
