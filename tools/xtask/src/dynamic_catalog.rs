//! Frozen detector-capability catalog for `EG-DYNAMIC`.
//!
//! Capability support is distinct from an active product target. The catalog
//! closes the seven supported detector protocols while the target registry
//! names only currently applicable real targets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;
use crate::registry::Tool;

const CATALOG_PATH: &str = "qualification/engineering/dynamic-detectors.tsv";
const CATALOG_HEADER: &str = "capability_id\tkind\ttool_id\tversion_source\tplan_version\targument_grammar\trequired_inputs\toutput_protocols\tevidence_schema\tmaximum_arguments\tmaximum_timeout_seconds";
const VERSION_SOURCE: &str = "qualification/engineering/toolchains.tsv";
const PLAN_VERSION: &str = "dynamic-execution-plan-v1";
const REQUIRED_INPUTS: &str = "corpus|seed|schedule|minimized-failure";
const OUTPUT_PROTOCOLS: &str = "exit-status-v1|exact-line-v1";
const EVIDENCE_SCHEMA: &str = "dynamic-controlled-step-v1";
const MAXIMUM_CATALOG_BYTES: usize = 16_384;
const MAXIMUM_FIELD_BYTES: usize = 128;
const CAPABILITY_COUNT: usize = 7;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DynamicKind {
    Property,
    StateModel,
    Fuzz,
    Corpus,
    Miri,
    Sanitizer,
    Loom,
}

impl DynamicKind {
    pub(crate) const ALL: [Self; CAPABILITY_COUNT] = [
        Self::Property,
        Self::StateModel,
        Self::Fuzz,
        Self::Corpus,
        Self::Miri,
        Self::Sanitizer,
        Self::Loom,
    ];

    pub(crate) fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "property" => Ok(Self::Property),
            "state-model" => Ok(Self::StateModel),
            "fuzz" => Ok(Self::Fuzz),
            "corpus" => Ok(Self::Corpus),
            "miri" => Ok(Self::Miri),
            "sanitizer" => Ok(Self::Sanitizer),
            "loom" => Ok(Self::Loom),
            _ => Err(XtaskError::invalid(
                "dynamic detector catalog",
                format!("unknown dynamic detector kind `{value}`"),
            )),
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Property => "property",
            Self::StateModel => "state-model",
            Self::Fuzz => "fuzz",
            Self::Corpus => "corpus",
            Self::Miri => "miri",
            Self::Sanitizer => "sanitizer",
            Self::Loom => "loom",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicOutputProtocol {
    ExitStatusV1,
    ExactLineV1,
}

impl DynamicOutputProtocol {
    pub(crate) fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "exit-status-v1" => Ok(Self::ExitStatusV1),
            "exact-line-v1" => Ok(Self::ExactLineV1),
            _ => Err(XtaskError::invalid(
                "dynamic target registry",
                format!("unknown dynamic target output protocol `{value}`"),
            )),
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ExitStatusV1 => "exit-status-v1",
            Self::ExactLineV1 => "exact-line-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArgumentGrammar {
    Property,
    StateModel,
    Fuzz,
    Corpus,
    Miri,
    Sanitizer,
    Loom,
}

impl ArgumentGrammar {
    const fn label(self) -> &'static str {
        match self {
            Self::Property => "cargo-test-properties-v1",
            Self::StateModel => "cargo-test-state-model-v1",
            Self::Fuzz => "cargo-fuzz-run-v1",
            Self::Corpus => "cargo-fuzz-corpus-v1",
            Self::Miri => "cargo-miri-test-v1",
            Self::Sanitizer => "cargo-sanitizer-test-v1",
            Self::Loom => "cargo-loom-test-v1",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DynamicCapability {
    id: String,
    kind: DynamicKind,
    tool_id: String,
    tool_version: String,
    grammar: ArgumentGrammar,
    maximum_arguments: usize,
    maximum_timeout: Duration,
}

impl DynamicCapability {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn kind(&self) -> DynamicKind {
        self.kind
    }

    pub(crate) fn tool_id(&self) -> &str {
        &self.tool_id
    }

    pub(crate) fn tool_version(&self) -> &str {
        &self.tool_version
    }

    pub(crate) fn grammar(&self) -> ArgumentGrammar {
        self.grammar
    }

    pub(crate) fn maximum_arguments(&self) -> usize {
        self.maximum_arguments
    }

    pub(crate) fn maximum_timeout(&self) -> Duration {
        self.maximum_timeout
    }
}

#[derive(Debug)]
pub(crate) struct FrozenDynamicCatalog {
    capabilities: BTreeMap<String, DynamicCapability>,
    digest: String,
}

impl FrozenDynamicCatalog {
    pub(crate) fn load(root: &Path, tools: &[Tool]) -> Result<Self, XtaskError> {
        let path = root.join(CATALOG_PATH);
        let bytes = fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        if bytes.len() > MAXIMUM_CATALOG_BYTES {
            return Err(XtaskError::invalid_path(
                &path,
                format!("dynamic detector catalog exceeds {MAXIMUM_CATALOG_BYTES} bytes"),
            ));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            XtaskError::invalid_path(&path, "dynamic detector catalog is not UTF-8")
        })?;
        let mut lines = text.lines();
        if lines.next() != Some(CATALOG_HEADER) {
            return Err(XtaskError::invalid_path(
                &path,
                "dynamic detector catalog header does not match the registered schema",
            ));
        }
        let mut capabilities = BTreeMap::new();
        let mut kinds = BTreeSet::new();
        for (offset, line) in lines.enumerate() {
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                id,
                kind,
                tool_id,
                version_source,
                plan_version,
                grammar,
                required_inputs,
                output_protocols,
                evidence_schema,
                maximum_arguments,
                maximum_timeout_seconds,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "dynamic detector catalog row {} has the wrong field count",
                        offset + 2
                    ),
                ));
            };
            if fields
                .iter()
                .any(|field| field.is_empty() || field.len() > MAXIMUM_FIELD_BYTES)
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "dynamic detector catalog row {} contains an invalid bounded field",
                        offset + 2
                    ),
                ));
            }
            let kind = DynamicKind::parse(kind)?;
            let canonical = canonical_capability(kind);
            if *id != kind.label()
                || *tool_id != canonical.tool_id
                || *version_source != VERSION_SOURCE
                || *plan_version != PLAN_VERSION
                || *grammar != canonical.grammar.label()
                || *required_inputs != REQUIRED_INPUTS
                || *output_protocols != OUTPUT_PROTOCOLS
                || *evidence_schema != EVIDENCE_SCHEMA
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("dynamic detector capability `{id}` drifted from its frozen contract"),
                ));
            }
            let maximum_arguments = parse_positive(&path, maximum_arguments, "maximum_arguments")?;
            let maximum_timeout_seconds =
                parse_positive(&path, maximum_timeout_seconds, "maximum_timeout_seconds")?;
            if maximum_arguments != canonical.maximum_arguments || maximum_timeout_seconds != 1_800
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("dynamic detector capability `{id}` has noncanonical bounds"),
                ));
            }
            let tool = tools
                .iter()
                .find(|tool| tool.id == *tool_id)
                .ok_or_else(|| {
                    XtaskError::invalid_path(
                        &path,
                        format!("dynamic detector capability `{id}` references a missing tool"),
                    )
                })?;
            validate_tool_binding(&path, kind, tool)?;
            if capabilities
                .insert(
                    (*id).to_owned(),
                    DynamicCapability {
                        id: (*id).to_owned(),
                        kind,
                        tool_id: (*tool_id).to_owned(),
                        tool_version: tool.version.clone(),
                        grammar: canonical.grammar,
                        maximum_arguments,
                        maximum_timeout: Duration::from_secs(
                            u64::try_from(maximum_timeout_seconds).map_err(|_| {
                                XtaskError::invalid_path(
                                    &path,
                                    "dynamic detector timeout exceeds u64",
                                )
                            })?,
                        ),
                    },
                )
                .is_some()
                || !kinds.insert(kind)
            {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("dynamic detector catalog repeats capability `{id}`"),
                ));
            }
        }
        if capabilities.len() != CAPABILITY_COUNT
            || DynamicKind::ALL
                .into_iter()
                .any(|kind| !kinds.contains(&kind))
        {
            return Err(XtaskError::invalid_path(
                &path,
                "dynamic detector catalog must contain exactly all seven capabilities",
            ));
        }
        Ok(Self {
            capabilities,
            digest: catalog_digest(b"positron-dynamic-detector-catalog-v1\0", &bytes),
        })
    }

    pub(crate) fn capability(&self, id: &str) -> Option<&DynamicCapability> {
        self.capabilities.get(id)
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
}

struct CanonicalCapability {
    tool_id: &'static str,
    grammar: ArgumentGrammar,
    maximum_arguments: usize,
}

const fn canonical_capability(kind: DynamicKind) -> CanonicalCapability {
    match kind {
        DynamicKind::Property => CanonicalCapability {
            tool_id: "cargo",
            grammar: ArgumentGrammar::Property,
            maximum_arguments: 6,
        },
        DynamicKind::StateModel => CanonicalCapability {
            tool_id: "cargo",
            grammar: ArgumentGrammar::StateModel,
            maximum_arguments: 9,
        },
        DynamicKind::Fuzz => CanonicalCapability {
            tool_id: "cargo-fuzz",
            grammar: ArgumentGrammar::Fuzz,
            maximum_arguments: 3,
        },
        DynamicKind::Corpus => CanonicalCapability {
            tool_id: "cargo-fuzz",
            grammar: ArgumentGrammar::Corpus,
            maximum_arguments: 4,
        },
        DynamicKind::Miri => CanonicalCapability {
            tool_id: "miri-nightly",
            grammar: ArgumentGrammar::Miri,
            maximum_arguments: 6,
        },
        DynamicKind::Sanitizer => CanonicalCapability {
            tool_id: "cargo",
            grammar: ArgumentGrammar::Sanitizer,
            maximum_arguments: 7,
        },
        DynamicKind::Loom => CanonicalCapability {
            tool_id: "cargo",
            grammar: ArgumentGrammar::Loom,
            maximum_arguments: 8,
        },
    }
}

fn validate_tool_binding(path: &Path, kind: DynamicKind, tool: &Tool) -> Result<(), XtaskError> {
    let expected_arguments: &[&str] = match kind {
        DynamicKind::Fuzz | DynamicKind::Corpus => &["fuzz", "--version"],
        DynamicKind::Miri => &["+nightly-2026-07-20", "miri", "--version"],
        DynamicKind::Property
        | DynamicKind::StateModel
        | DynamicKind::Sanitizer
        | DynamicKind::Loom => &["--version"],
    };
    if tool.command != "cargo"
        || tool
            .version_arguments
            .iter()
            .map(String::as_str)
            .ne(expected_arguments.iter().copied())
    {
        return Err(XtaskError::invalid_path(
            path,
            format!(
                "dynamic detector capability `{}` has a stale tool version source",
                kind.label()
            ),
        ));
    }
    Ok(())
}

fn parse_positive(path: &Path, value: &str, label: &str) -> Result<usize, XtaskError> {
    let parsed = value.parse::<usize>().map_err(|_| {
        XtaskError::invalid_path(path, format!("dynamic detector {label} is not canonical"))
    })?;
    if parsed == 0 || value != parsed.to_string() {
        return Err(XtaskError::invalid_path(
            path,
            format!("dynamic detector {label} is not canonical"),
        ));
    }
    Ok(parsed)
}

pub(crate) fn catalog_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}
