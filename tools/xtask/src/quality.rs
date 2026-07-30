use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::controlled_execution::{
    self, ExecutionTools, InvocationInput, InvocationSpec, OutputMode,
};
use crate::error::XtaskError;
use crate::evidence_json as bounded_json;
use crate::hooks;
use crate::qualification_fixtures::{DirectoryCapability, FileCapability};
use crate::registry::{self, Gate, Registry};

const CANONICAL_GATE_IDS: [&str; 25] = [
    "EG-00",
    "EG-ARCH",
    "EG-BUILD",
    "EG-CONCURRENCY",
    "EG-CORRECT",
    "EG-COVERAGE",
    "EG-CRYPTO",
    "EG-DEPS",
    "EG-DOCS",
    "EG-DYNAMIC",
    "EG-ERROR",
    "EG-EVIDENCE",
    "EG-FAULT",
    "EG-INTEGRITY",
    "EG-MATRIX",
    "EG-PERF",
    "EG-POLICY",
    "EG-RESOURCE",
    "EG-RUST",
    "EG-SAFETY",
    "EG-SECRETS",
    "EG-SECURITY",
    "EG-SOAK",
    "EG-SUPPLY",
    "EG-TEST",
];

const ENVIRONMENT_SNAPSHOT_VERSION: &str = "positron-quality-environment-v1";
const MAXIMUM_ENVIRONMENT_ENTRIES: usize = 10;
const MAXIMUM_ENVIRONMENT_VALUE_BYTES: usize = 4_096;
const MAXIMUM_PATH_BYTES: usize = 16_384;
const MAXIMUM_PATH_ENTRIES: usize = 128;
const MAXIMUM_SNAPSHOT_DIGEST_INPUT_BYTES: usize = 65_536;
const SNAPSHOT_DIGEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAXIMUM_CAPTURED_REPORT_STREAM_BYTES: usize = 131_072;
const MAXIMUM_RAW_REPORT_BYTES: usize = 8_388_608;
const MAXIMUM_RETAINED_EVIDENCE_BYTES: usize = 2_097_152;
const MAXIMUM_CONTROLLED_REPORT_STEPS: usize = 128;
const MAXIMUM_RETAINED_ATTEMPTS: usize = 4_096;
const MAXIMUM_REPORTS_PER_ATTEMPT: usize = CANONICAL_GATE_IDS.len();
const MAXIMUM_ATTEMPT_ID_CHARACTERS: usize = 256;
const MAXIMUM_IDENTITY_VALUE_CHARACTERS: usize = 4_096;
const MAXIMUM_GATE_DETAIL_CHARACTERS: usize = 16_384;
const MAXIMUM_GATE_ARGUMENT_CHARACTERS: usize = 4_096;
const MAXIMUM_ACTIVATION_CHARACTERS: usize = 64;
const MAXIMUM_EXCEPTION_CLASS_CHARACTERS: usize = 256;
const MAXIMUM_CONTROLLED_PROGRAM_CHARACTERS: usize = 256;
const MAXIMUM_RESOLVED_PROGRAM_CHARACTERS: usize = 4_096;
const MAXIMUM_CONTROLLED_ARGUMENTS: usize = 256;
const MAXIMUM_CONTROLLED_ARGUMENT_CHARACTERS: usize = 4_096;
const NEXTEST_PR_ARGUMENTS: [&str; 12] = [
    "nextest",
    "run",
    "--locked",
    "--workspace",
    "--all-targets",
    "--all-features",
    "--profile",
    "ci",
    "--status-level",
    "fail",
    "--final-status-level",
    "fail",
];
const EVIDENCE_V3_CONSTRAINT_OWNER: &str =
    "Constraint owner: tools/xtask/src/quality.rs EVIDENCE_V3_CONSTRAINTS_V1";
const EVIDENCE_V3_SCHEMA_SHA256: &str =
    "sha256:84d605906a62be0fbaf4cf166f34e9660206ff9a72b56cd90ed38acd2a7bae30";
const RAW_REPORT_CONTENT_TYPE: &str = "application/vnd.positron.quality-gate-report+json;version=1";
const COLLISION_SLOT_COUNT: usize = 16;
const COLLISION_OCCUPIED_SET: &str = "collision-00,collision-01,collision-02,collision-03,collision-04,collision-05,collision-06,collision-07,collision-08,collision-09,collision-10,collision-11,collision-12,collision-13,collision-14,collision-15";
const M0_01B_COVERAGE_POLICY: &str =
    "qualification/engineering/policy-changes/PC-0006-m0-01b-coverage-target-completeness.json";
const FROZEN_M0_01_COVERAGE_BASELINES: [(&str, f64); 4] = [
    ("coverage-line", 70.52266534555362),
    ("coverage-region", 69.9540018399264),
    ("coverage-branch", 57.622739018087856),
    ("coverage-changed-code", 65.97888675623801),
];
const M0_02_MUTATION_SELECTOR: &str = concat!(
    "TenantId::from_bytes|TenantId::parse_canonical|",
    "PrincipalId::from_bytes|PrincipalId::parse_canonical|",
    "TenantSlug::parse_canonical|TenantAttribution::new|parse_identifier|",
    "TenantLifecycle::active|TenantLifecycle::to_read_only|",
    "TenantLifecycle::to_suspended|TenantLifecycle::to_active|",
    "TenantLifecycle::begin_purge|TenantLifecycle::complete_purge|",
    "TenantLifecycle::transition|lifecycle_transition_is_valid|",
    "VirtualShardId::new|AssignmentEpoch::initial|AssignmentEpoch::advance_by|",
    "AssignmentEpoch::next|CommitPosition::origin|CommitPosition::advance_by|",
    "CommitPosition::next|IngestTime::from_candidate|IngestTimeCandidate::new|",
    "EventTime::received|ObservedTime::received|",
    "QueryTime::for_log|QueryTime::for_span|validate_present_source_time|",
    "ByteLimit::new|CollectionLimit::new|NestingLimit::new|",
    "RequestLimits::new|RequestLimits::exceeds|RecordLimits::new|RecordLimits::exceeds|",
    "DynamicValueLimits::new|DynamicValueLimits::exceeds|ValueLimitSet::new|",
    "ValueLimitSet::exceeds|ValueLimitProfileCandidate::validate|",
    "AttributeOccurrenceSetCandidate::validate|validate_attribute_value|",
    "validate_attribute_array|validate_key_value_list|",
    "exceeds_byte_limit|exceeds_collection_limit",
);
const M0_02_MUTATION_OUTPUT: &str = "target/quality/mutation/m0-02-domain-final-post-lint";
const M0_03_MUTATION_SELECTOR: &str = concat!(
    "RequestedApiMajor::from_major|RequestedApiMajor::major|",
    "Capability::wire_value|Capability::from_wire|",
    "SchemaDigest::canonical|SchemaDigest::as_str|",
    "ApiError::unsupported_api_version|ApiError::capability_unavailable|",
    "ApiError::capability_unsupported|ApiError::malformed|ApiError::too_large|",
    "ApiError::unknown_field|CapabilityRequest::for_version|",
    "CapabilityRequest::for_capability|CapabilityRequest::for_requested_major|",
    "CapabilityRequest::unknown|CapabilityRequest::wire_major|",
    "CapabilityResponse::availability|CapabilityResponse::api_major|",
    "CapabilityResponse::schema_digest|CapabilityResponse::refusal|",
    "CapabilityResponse::deprecation|CapabilityResponse::capability|",
    "Transport::source|EncodedRequest::push|EncodedRequest::extend|",
    "CapabilityClient::encode|CapabilityService::negotiate|",
    "CapabilityService::decode_and_negotiate|encode_grpc|encode_http|",
    "encode_varint|decode_grpc|decode_varint|decode_http|parse_json_u32",
);
const M0_03_MUTATION_OUTPUT: &str = "target/quality/mutation/m0-03-api-final";
const M0_04_MUTATION_SELECTOR: &str = concat!(
    "LogLevel::parse|ProtectedFileReference::parse|",
    "EnvironmentOverrides::try_from_pairs|CommandLineOverrides::try_from_pairs|",
    "ConfigurationInputs::try_new|EffectiveConfiguration::redacted_reference|",
    "EffectiveConfiguration::plan_update|EffectiveConfiguration::setting_differs|",
    "ConfigurationPlan::from_changes|resolve|Candidate::defaults|Candidate::apply|",
    "Candidate::validate|collect_pairs|preflight_toml|content_before_comment|",
    "preflight_table_header|unquoted_equals|preflight_key|preflight_scalar|environment_path|",
    "apply_toml|",
    "apply_toml_value|apply_environment|apply_command_line|parse_schema_version|",
    "parse_shutdown_grace_seconds|parse_canonical_u16|parse_loopback_address|checked_path|validate_path",
);
const M0_04_MUTATION_OUTPUT: &str = "target/quality/mutation/m0-04-config-final";
const M0_04_COVERAGE_FLOOR: f64 = 90.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoverageTarget {
    Test(&'static str),
    Binary(&'static str),
}

const REQUIRED_M0_01B_COVERAGE_TARGETS: [CoverageTarget; 2] = [
    CoverageTarget::Test("foundational_scope_activation"),
    CoverageTarget::Binary("xtask"),
];

#[derive(Clone, Copy, Debug)]
struct CoverageCommandSpec {
    report: &'static str,
    ignored_sources: Option<&'static str>,
    targets: &'static [CoverageTarget],
}

impl CoverageCommandSpec {
    fn arguments(self) -> Vec<&'static str> {
        let mut arguments = vec![
            "+nightly-2026-07-20",
            "llvm-cov",
            "--locked",
            "--package",
            "xtask",
        ];
        for target in self.targets {
            match target {
                CoverageTarget::Test(name) => arguments.extend(["--test", name]),
                CoverageTarget::Binary(name) => arguments.extend(["--bin", name]),
            }
        }
        arguments.extend(["--branch", "--json", "--summary-only"]);
        if let Some(ignored_sources) = self.ignored_sources {
            arguments.extend(["--ignore-filename-regex", ignored_sources]);
        }
        arguments.extend(["--output-path", self.report]);
        arguments
    }
}

fn m0_01b_coverage_command_specs() -> [CoverageCommandSpec; 2] {
    [
        CoverageCommandSpec {
            report: "target/quality/coverage/m0-01-total.json",
            ignored_sources: None,
            targets: &[
                CoverageTarget::Test("foundational_scope_activation"),
                CoverageTarget::Binary("xtask"),
            ],
        },
        CoverageCommandSpec {
            report: "target/quality/coverage/m0-01-changed-code.json",
            ignored_sources: Some("tools/xtask/src/(error|hooks|main|quality)\\.rs"),
            targets: &[
                CoverageTarget::Test("foundational_scope_activation"),
                CoverageTarget::Binary("xtask"),
            ],
        },
    ]
}

#[derive(Debug)]
struct EnvironmentSnapshot {
    values: Vec<(OsString, OsString)>,
    tools: BTreeMap<String, PathBuf>,
    execution_tools: ExecutionTools,
    temporary_root: PathBuf,
    digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Profile {
    PreCommit,
    Pr,
    Ext,
    Qual,
}

impl Profile {
    pub(crate) fn accepted_values() -> &'static str {
        "pre-commit|pr|ext|qual"
    }

    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "pre-commit" => Ok(Self::PreCommit),
            "pr" => Ok(Self::Pr),
            "ext" => Ok(Self::Ext),
            "qual" => Ok(Self::Qual),
            unknown => Err(XtaskError::usage(format!(
                "unknown quality profile `{unknown}`; expected {}",
                Self::accepted_values()
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::PreCommit => "pre-commit",
            Self::Pr => "pr",
            Self::Ext => "ext",
            Self::Qual => "qual",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Options {
    profile: Profile,
    retain_m0_02_mutation: bool,
    retain_m0_03_mutation: bool,
    retain_m0_04_mutation: bool,
}

impl Options {
    pub(crate) fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, XtaskError> {
        let mut profile = Profile::Pr;
        let mut retain_m0_02_mutation = false;
        let mut retain_m0_03_mutation = false;
        let mut retain_m0_04_mutation = false;
        let mut arguments = arguments.peekable();
        while let Some(argument) = arguments.next() {
            if argument == "--profile" {
                let Some(value) = arguments.next() else {
                    return Err(XtaskError::usage("`--profile` requires a value".to_owned()));
                };
                profile = Profile::parse(&value)?;
            } else if let Some(value) = argument.strip_prefix("--profile=") {
                profile = Profile::parse(value)?;
            } else if argument == "--retain-m0-02-mutation" {
                retain_m0_02_mutation = true;
            } else if argument == "--retain-m0-03-mutation" {
                retain_m0_03_mutation = true;
            } else if argument == "--retain-m0-04-mutation" {
                retain_m0_04_mutation = true;
            } else {
                return Err(XtaskError::usage(format!(
                    "unexpected quality argument `{argument}`"
                )));
            }
        }
        if retain_m0_02_mutation && profile != Profile::Ext {
            return Err(XtaskError::usage(
                "`--retain-m0-02-mutation` requires `--profile ext`".to_owned(),
            ));
        }
        if retain_m0_03_mutation && profile != Profile::Ext {
            return Err(XtaskError::usage(
                "`--retain-m0-03-mutation` requires `--profile ext`".to_owned(),
            ));
        }
        if retain_m0_04_mutation && profile != Profile::Ext {
            return Err(XtaskError::usage(
                "`--retain-m0-04-mutation` requires `--profile ext`".to_owned(),
            ));
        }
        if [
            retain_m0_02_mutation,
            retain_m0_03_mutation,
            retain_m0_04_mutation,
        ]
        .into_iter()
        .filter(|selected| *selected)
        .count()
            > 1
        {
            return Err(XtaskError::usage(
                "select exactly one retained focused mutation campaign per EXT attempt".to_owned(),
            ));
        }
        Ok(Self {
            profile,
            retain_m0_02_mutation,
            retain_m0_03_mutation,
            retain_m0_04_mutation,
        })
    }
}

#[derive(Clone, Debug)]
struct GateAttempt {
    gate_id: String,
    result: GateStatus,
    duration_ms: u128,
    budget_seconds: u64,
    invocation: GateInvocation,
    command_digest: String,
    owner: IdentityBinding,
    raw_report: RawReportBinding,
    raw_report_content: Option<String>,
    detail: String,
}

struct GateAttemptOutcome {
    result: GateStatus,
    duration_ms: u128,
    detail: String,
    controlled_steps: Vec<ControlledStepReport>,
}

struct GateAttemptDefinition {
    gate_id: String,
    budget_seconds: u64,
    invocation: GateInvocation,
    owner: IdentityBinding,
}

struct RawReportDocument<'report> {
    attempt_id: &'report str,
    gate_id: &'report str,
    result: GateStatus,
    duration_ms: u128,
    invocation_digest: &'report str,
    invocation: &'report GateInvocation,
    detail: &'report str,
    controlled_steps: &'report [ControlledStepReport],
}

struct InternalInvocationSpec<'invocation> {
    gate_id: &'invocation str,
    operation: &'invocation str,
    timeout_seconds: u64,
    memory_mib: u64,
    activation: &'invocation str,
    exception_class: &'invocation str,
}

#[derive(Clone, Debug)]
struct GateInvocation {
    program: String,
    arguments: Vec<String>,
    working_directory: String,
    environment_digest: String,
    timeout_seconds: u64,
    memory_mib: u64,
    activation: String,
    exception_class: String,
    controlled_steps: Vec<ControlledInvocation>,
}

#[derive(Clone, Debug)]
struct ControlledInvocation {
    program: String,
    resolved_program: String,
    arguments: Vec<String>,
    working_directory: String,
    environment_digest: String,
    timeout_ms: u128,
    input_kind: String,
    input_bytes: usize,
    input_sha256: String,
}

#[derive(Clone, Debug)]
struct ControlledStepReport {
    invocation: ControlledInvocation,
    verdict: String,
    stdout: String,
    stderr: String,
}

struct GateCapture {
    steps: Vec<ControlledStepReport>,
    charged_bytes: usize,
}

struct GateExecutionContext<'context> {
    attempt_id: &'context str,
    root: &'context Path,
    registry: &'context Registry,
    qualification_fixtures: &'context crate::qualification_fixtures::FrozenQualificationFixtures,
    options: &'context Options,
    environment: &'context EnvironmentSnapshot,
    source: &'context SourceIdentity,
    identity: &'context EvidenceIdentity,
}

impl GateCapture {
    fn new() -> Self {
        Self {
            steps: Vec::new(),
            charged_bytes: 0,
        }
    }

    fn record(
        &mut self,
        invocation: ControlledInvocation,
        verdict: &str,
        stdout: &str,
        stderr: &str,
    ) -> Result<(), XtaskError> {
        if self.steps.len() >= MAXIMUM_CONTROLLED_REPORT_STEPS {
            return Err(XtaskError::invalid(
                "gate report resource limit",
                format!("controlled step count exceeds {MAXIMUM_CONTROLLED_REPORT_STEPS}"),
            ));
        }
        if stdout.len() > MAXIMUM_CAPTURED_REPORT_STREAM_BYTES
            || stderr.len() > MAXIMUM_CAPTURED_REPORT_STREAM_BYTES
        {
            return Err(XtaskError::invalid(
                "gate report resource limit",
                format!("controlled stream exceeds {MAXIMUM_CAPTURED_REPORT_STREAM_BYTES} bytes"),
            ));
        }
        let invocation_bytes = controlled_invocation_json(&invocation).len();
        let charge = invocation_bytes
            .checked_add(verdict.len())
            .and_then(|bytes| bytes.checked_add(stdout.len()))
            .and_then(|bytes| bytes.checked_add(stderr.len()))
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| {
                XtaskError::invalid(
                    "gate report resource limit",
                    "controlled step byte accounting overflowed",
                )
            })?;
        let charged_bytes = self.charged_bytes.checked_add(charge).ok_or_else(|| {
            XtaskError::invalid(
                "gate report resource limit",
                "controlled report byte accounting overflowed",
            )
        })?;
        if charged_bytes > MAXIMUM_RAW_REPORT_BYTES {
            return Err(XtaskError::invalid(
                "gate report resource limit",
                format!("controlled report exceeds {MAXIMUM_RAW_REPORT_BYTES} bytes"),
            ));
        }
        self.charged_bytes = charged_bytes;
        self.steps.push(ControlledStepReport {
            invocation,
            verdict: verdict.to_owned(),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        });
        Ok(())
    }

    fn finish(self) -> Vec<ControlledStepReport> {
        self.steps
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RawReportBinding {
    Exact {
        path: String,
        digest: String,
        bytes: usize,
        content_type: &'static str,
    },
    NotApplicable(NotApplicableReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateStatus {
    Passed,
    Failed,
    NotSelected,
}

impl GateStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::NotSelected => "not-selected",
        }
    }
}

#[derive(Clone, Debug)]
struct SourceIdentity {
    revision: String,
    dirty: bool,
    trusted_ci: bool,
    revision_matches_ci: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NotApplicableReason {
    NoCollision,
    NoReleaseManifestForEngineeringAttempt,
    NoCandidateArtifactForEngineeringAttempt,
    NoEffectiveConfigurationForEngineeringAttempt,
    NoCorpusSelected,
    NoSeedSelected,
    NoFaultScheduleSelected,
    NoApprovalClaimed,
    NoExceptionApplied,
    GateNotSelected,
    ReportEncodingFailed,
    ReportRetentionFailed,
    UnavailableBeforeRegistryValidation,
}

impl NotApplicableReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::NoCollision => "no-collision",
            Self::NoReleaseManifestForEngineeringAttempt => {
                "no-release-manifest-for-engineering-attempt"
            },
            Self::NoCandidateArtifactForEngineeringAttempt => {
                "no-candidate-artifact-for-engineering-attempt"
            },
            Self::NoEffectiveConfigurationForEngineeringAttempt => {
                "no-effective-configuration-for-engineering-attempt"
            },
            Self::NoCorpusSelected => "no-corpus-selected",
            Self::NoSeedSelected => "no-seed-selected",
            Self::NoFaultScheduleSelected => "no-fault-schedule-selected",
            Self::NoApprovalClaimed => "no-approval-claimed",
            Self::NoExceptionApplied => "no-exception-applied",
            Self::GateNotSelected => "gate-not-selected",
            Self::ReportEncodingFailed => "report-encoding-failed",
            Self::ReportRetentionFailed => "report-retention-failed",
            Self::UnavailableBeforeRegistryValidation => "unavailable-before-registry-validation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IdentityBinding {
    Exact(String),
    NotApplicable(NotApplicableReason),
}

impl IdentityBinding {
    fn exact(value: impl Into<String>) -> Self {
        Self::Exact(value.into())
    }

    fn not_applicable(reason: NotApplicableReason) -> Self {
        Self::NotApplicable(reason)
    }
}

fn identity_binding_text(binding: &IdentityBinding) -> String {
    match binding {
        IdentityBinding::Exact(value) => format!("exact:{value}"),
        IdentityBinding::NotApplicable(reason) => {
            format!("not-applicable:{}", reason.as_str())
        },
    }
}

#[derive(Clone, Debug)]
struct EvidenceIdentity {
    release_manifest: IdentityBinding,
    artifact: IdentityBinding,
    target: IdentityBinding,
    target_registry_digest: String,
    toolchain_digest: String,
    effective_configuration: IdentityBinding,
    fixture_registry_digest: String,
    corpus: IdentityBinding,
    seed: IdentityBinding,
    fault_schedule: IdentityBinding,
    verifier: IdentityBinding,
    approval: IdentityBinding,
    exception: IdentityBinding,
}

#[derive(Clone, Debug)]
struct Evidence {
    attempt_id: String,
    collision_of: IdentityBinding,
    collision_slots: IdentityBinding,
    profile: Profile,
    result: GateStatus,
    merge_eligible: bool,
    source: SourceIdentity,
    started_unix_ms: u128,
    ended_unix_ms: u128,
    registry_digest: String,
    environment_digest: String,
    identity: EvidenceIdentity,
    gates: Vec<GateAttempt>,
}

#[derive(Debug)]
struct CommandOutcome {
    display: String,
    stdout: String,
    stderr: String,
}

#[derive(Debug)]
struct CoverageMeasurements {
    branch: f64,
    line: f64,
    region: f64,
}

struct AggregatorFailure<'failure> {
    source: SourceIdentity,
    started_unix_ms: u128,
    attempt_id: String,
    environment_digest: &'failure str,
    registry_digest: &'failure str,
    error: &'failure XtaskError,
}

fn unavailable_evidence_identity(source: &SourceIdentity) -> EvidenceIdentity {
    EvidenceIdentity {
        release_manifest: IdentityBinding::not_applicable(
            NotApplicableReason::NoReleaseManifestForEngineeringAttempt,
        ),
        artifact: IdentityBinding::not_applicable(
            NotApplicableReason::NoCandidateArtifactForEngineeringAttempt,
        ),
        target: IdentityBinding::exact("engineering-workspace"),
        target_registry_digest: "unavailable-registry-digest".to_owned(),
        toolchain_digest: "unavailable-registry-digest".to_owned(),
        effective_configuration: IdentityBinding::not_applicable(
            NotApplicableReason::NoEffectiveConfigurationForEngineeringAttempt,
        ),
        fixture_registry_digest: "unavailable-registry-digest".to_owned(),
        corpus: IdentityBinding::not_applicable(NotApplicableReason::NoCorpusSelected),
        seed: IdentityBinding::not_applicable(NotApplicableReason::NoSeedSelected),
        fault_schedule: IdentityBinding::not_applicable(
            NotApplicableReason::NoFaultScheduleSelected,
        ),
        verifier: verifier_identity(source),
        approval: IdentityBinding::not_applicable(NotApplicableReason::NoApprovalClaimed),
        exception: IdentityBinding::not_applicable(NotApplicableReason::NoExceptionApplied),
    }
}

fn verifier_identity(source: &SourceIdentity) -> IdentityBinding {
    if source.trusted_ci {
        IdentityBinding::exact("cargo-xtask-quality/github-actions")
    } else {
        IdentityBinding::exact("cargo-xtask-quality/local-diagnostic")
    }
}

fn engineering_evidence_identity(
    root: &Path,
    source: &SourceIdentity,
    environment: &EnvironmentSnapshot,
    fixtures: &crate::qualification_fixtures::FrozenQualificationFixtures,
    qualification_fixture_selected: bool,
) -> Result<EvidenceIdentity, XtaskError> {
    let target_registry_digest =
        digest_relative_files(root, environment, &["qualification/targets/registry.json"])?;
    let toolchain_digest = digest_relative_files(
        root,
        environment,
        &[
            "qualification/engineering/toolchains.tsv",
            "rust-toolchain.toml",
        ],
    )?;
    let fixture_registry_digest = digest_payload(root, environment, fixtures.identity_payload())?;
    let mut identity = EvidenceIdentity {
        target_registry_digest,
        toolchain_digest,
        fixture_registry_digest,
        ..unavailable_evidence_identity(source)
    };
    if qualification_fixture_selected {
        identity.seed = IdentityBinding::exact(fixtures.seed_digest());
        identity.fault_schedule = IdentityBinding::exact(fixtures.fault_schedule_digest());
    }
    Ok(identity)
}

fn digest_relative_files(
    root: &Path,
    environment: &EnvironmentSnapshot,
    relatives: &[&str],
) -> Result<String, XtaskError> {
    let files = relatives
        .iter()
        .map(|relative| root.join(relative))
        .collect::<Vec<_>>();
    digest_files(root, &files, environment)
}

pub(crate) fn run(options: &Options) -> Result<(), XtaskError> {
    let root = hooks::workspace_root()?;
    let started_unix_ms = unix_time_ms()?;
    let environment = EnvironmentSnapshot::capture(&root, options.profile)?;
    let source = source_identity(&root, &environment)?;
    let attempt_id = attempt_identity(&source.revision, started_unix_ms);
    if let Err(error) = validate_trusted_ci_attempt(&source) {
        return retain_aggregator_failure(
            &root,
            options.profile,
            AggregatorFailure {
                source,
                started_unix_ms,
                attempt_id,
                environment_digest: environment.digest(),
                registry_digest: "unavailable-registry-digest",
                error: &error,
            },
        );
    }
    let registry = match Registry::load(&root) {
        Ok(registry) => registry,
        Err(error) => {
            return retain_aggregator_failure(
                &root,
                options.profile,
                AggregatorFailure {
                    source,
                    started_unix_ms,
                    attempt_id,
                    environment_digest: environment.digest(),
                    registry_digest: "invalid-registry",
                    error: &error,
                },
            );
        },
    };
    let registered_gate_ids = registry
        .gates
        .iter()
        .map(|gate| gate.id.as_str())
        .collect::<BTreeSet<_>>();
    let canonical_gate_ids = CANONICAL_GATE_IDS.into_iter().collect::<BTreeSet<_>>();
    if registered_gate_ids != canonical_gate_ids {
        let error = XtaskError::invalid(
            "gate registry",
            "registered gate identities drifted from the runner's retained-failure set",
        );
        return retain_aggregator_failure(
            &root,
            options.profile,
            AggregatorFailure {
                source,
                started_unix_ms,
                attempt_id,
                environment_digest: environment.digest(),
                registry_digest: "invalid-registry",
                error: &error,
            },
        );
    }
    let registry_digest = match digest_files(&root, registry.registry_files(), &environment) {
        Ok(digest) => digest,
        Err(error) => {
            return retain_aggregator_failure(
                &root,
                options.profile,
                AggregatorFailure {
                    source,
                    started_unix_ms,
                    attempt_id,
                    environment_digest: environment.digest(),
                    registry_digest: "unavailable-registry-digest",
                    error: &error,
                },
            );
        },
    };
    let activated_risk_gates = registry.activated_risk_gates();
    let qualification_fixture_selected = registry.gates.iter().any(|gate| {
        matches!(
            gate.id.as_str(),
            "EG-CONCURRENCY" | "EG-CORRECT" | "EG-FAULT" | "EG-INTEGRITY" | "EG-RESOURCE"
        ) && gate_selected(gate, options.profile, &activated_risk_gates)
    });
    let qualification_fixtures =
        match crate::qualification_fixtures::FrozenQualificationFixtures::capture(&root) {
            Ok(fixtures) => fixtures,
            Err(error) => {
                return retain_aggregator_failure(
                    &root,
                    options.profile,
                    AggregatorFailure {
                        source,
                        started_unix_ms,
                        attempt_id,
                        environment_digest: environment.digest(),
                        registry_digest: &registry_digest,
                        error: &error,
                    },
                );
            },
        };
    let identity = match engineering_evidence_identity(
        &root,
        &source,
        &environment,
        &qualification_fixtures,
        qualification_fixture_selected,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            return retain_aggregator_failure(
                &root,
                options.profile,
                AggregatorFailure {
                    source,
                    started_unix_ms,
                    attempt_id,
                    environment_digest: environment.digest(),
                    registry_digest: &registry_digest,
                    error: &error,
                },
            );
        },
    };
    println!(
        "Positron engineering quality: profile={}, revision={}, dirty={}",
        options.profile.as_str(),
        source.revision,
        source.dirty
    );

    let mut attempts = Vec::with_capacity(registry.gates.len());
    for gate in &registry.gates {
        if !gate_selected(gate, options.profile, &activated_risk_gates) {
            attempts.push(gate_attempt(
                &attempt_id,
                gate,
                options.profile,
                environment.digest(),
                GateAttemptOutcome {
                    result: GateStatus::NotSelected,
                    duration_ms: 0,
                    detail: not_selected_reason(gate, options.profile),
                    controlled_steps: Vec::new(),
                },
            ));
            continue;
        }

        println!(
            "\n[{}] {} (budget: {}s, {} MiB declared)",
            gate.id, gate.runner, gate.timeout_seconds, gate.memory_mib
        );
        let started = Instant::now();
        let mut capture = GateCapture::new();
        let execution = execute_gate(
            GateExecutionContext {
                attempt_id: &attempt_id,
                root: &root,
                registry: &registry,
                qualification_fixtures: &qualification_fixtures,
                options,
                environment: &environment,
                source: &source,
                identity: &identity,
            },
            gate,
            &mut capture,
        );
        let controlled_steps = capture.finish();
        let duration_ms = started.elapsed().as_millis();
        match execution {
            Ok(detail) => {
                println!("[{}] passed", gate.id);
                attempts.push(gate_attempt(
                    &attempt_id,
                    gate,
                    options.profile,
                    environment.digest(),
                    GateAttemptOutcome {
                        result: GateStatus::Passed,
                        duration_ms,
                        detail: format!(
                            "{detail}; coordinator: {}; exception class: {}",
                            gate.coordinator, gate.exception_class,
                        ),
                        controlled_steps,
                    },
                ));
            },
            Err(error) => {
                eprintln!("[{}] failed: {error}", gate.id);
                attempts.push(gate_attempt(
                    &attempt_id,
                    gate,
                    options.profile,
                    environment.digest(),
                    GateAttemptOutcome {
                        result: GateStatus::Failed,
                        duration_ms,
                        detail: error.to_string(),
                        controlled_steps,
                    },
                ));
            },
        }
    }

    let failed = attempts
        .iter()
        .any(|attempt| attempt.result == GateStatus::Failed);
    let result = if failed {
        GateStatus::Failed
    } else {
        GateStatus::Passed
    };
    let ended_unix_ms = unix_time_ms()?;
    let merge_eligible = result == GateStatus::Passed
        && !source.dirty
        && source.trusted_ci
        && source.revision_matches_ci
        && matches!(
            env::var("GITHUB_EVENT_NAME").as_deref(),
            Ok("pull_request" | "merge_group")
        );
    let evidence = Evidence {
        attempt_id,
        collision_of: IdentityBinding::not_applicable(NotApplicableReason::NoCollision),
        collision_slots: IdentityBinding::not_applicable(NotApplicableReason::NoCollision),
        profile: options.profile,
        result,
        merge_eligible,
        source,
        started_unix_ms,
        ended_unix_ms,
        registry_digest,
        environment_digest: environment.digest().to_owned(),
        identity,
        gates: attempts,
    };
    let evidence_path = write_evidence(&root, &evidence)?;
    println!("\nEvidence: {}", evidence_path.display());

    if failed {
        return Err(XtaskError::invalid(
            "engineering quality attempt",
            "one or more selected gates failed; retained evidence is not merge-eligible",
        ));
    }
    println!(
        "Engineering quality passed. Merge-eligible evidence: {}",
        evidence.merge_eligible
    );
    Ok(())
}

fn retain_aggregator_failure(
    root: &Path,
    profile: Profile,
    failure: AggregatorFailure<'_>,
) -> Result<(), XtaskError> {
    let mut gates = Vec::with_capacity(CANONICAL_GATE_IDS.len());
    for gate_id in CANONICAL_GATE_IDS {
        let is_aggregator = gate_id == "EG-00";
        let result = if is_aggregator {
            GateStatus::Failed
        } else {
            GateStatus::NotSelected
        };
        let owner = if is_aggregator {
            IdentityBinding::exact("Quality Engineering")
        } else {
            IdentityBinding::not_applicable(
                NotApplicableReason::UnavailableBeforeRegistryValidation,
            )
        };
        gates.push(build_gate_attempt(
            &failure.attempt_id,
            GateAttemptDefinition {
                gate_id: gate_id.to_owned(),
                budget_seconds: 60,
                invocation: retained_internal_invocation(
                    failure.environment_digest,
                    InternalInvocationSpec {
                        gate_id,
                        operation: if is_aggregator {
                            "--aggregator-failure"
                        } else {
                            "--blocked-by-eg-00"
                        },
                        timeout_seconds: 60,
                        memory_mib: 256,
                        activation: "always",
                        exception_class: "none",
                    },
                ),
                owner,
            },
            GateAttemptOutcome {
                result,
                duration_ms: 0,
                detail: if is_aggregator {
                    failure.error.to_string()
                } else {
                    "EG-00 failed closed before gate selection; this omission is retained and cannot be interpreted as a pass."
                        .to_owned()
                },
                controlled_steps: Vec::new(),
            },
        ));
    }
    let evidence = Evidence {
        attempt_id: failure.attempt_id,
        collision_of: IdentityBinding::not_applicable(NotApplicableReason::NoCollision),
        collision_slots: IdentityBinding::not_applicable(NotApplicableReason::NoCollision),
        profile,
        result: GateStatus::Failed,
        merge_eligible: false,
        identity: unavailable_evidence_identity(&failure.source),
        source: failure.source,
        started_unix_ms: failure.started_unix_ms,
        ended_unix_ms: unix_time_ms()?,
        registry_digest: failure.registry_digest.to_owned(),
        environment_digest: failure.environment_digest.to_owned(),
        gates,
    };
    let path = write_evidence(root, &evidence)?;
    eprintln!("Retained failed aggregator evidence: {}", path.display());
    Err(XtaskError::invalid(
        "engineering quality aggregator",
        failure.error.to_string(),
    ))
}

fn gate_attempt(
    attempt_id: &str,
    gate: &Gate,
    profile: Profile,
    environment_digest: &str,
    outcome: GateAttemptOutcome,
) -> GateAttempt {
    let invocation =
        canonical_gate_invocation(gate, profile, environment_digest, &outcome.controlled_steps);
    build_gate_attempt(
        attempt_id,
        GateAttemptDefinition {
            gate_id: gate.id.clone(),
            budget_seconds: gate.timeout_seconds,
            invocation,
            owner: IdentityBinding::exact(gate.coordinator.clone()),
        },
        outcome,
    )
}

fn canonical_gate_invocation(
    gate: &Gate,
    profile: Profile,
    environment_digest: &str,
    controlled_steps: &[ControlledStepReport],
) -> GateInvocation {
    GateInvocation {
        program: "cargo-xtask-quality/internal".to_owned(),
        arguments: vec![
            "quality".to_owned(),
            "--profile".to_owned(),
            profile.as_str().to_owned(),
            "--gate".to_owned(),
            gate.id.clone(),
            "--runner".to_owned(),
            gate.runner.clone(),
        ],
        working_directory: "engineering-workspace".to_owned(),
        environment_digest: sha256_digest(environment_digest.as_bytes()),
        timeout_seconds: gate.timeout_seconds,
        memory_mib: gate.memory_mib,
        activation: gate.activation.clone(),
        exception_class: gate.exception_class.clone(),
        controlled_steps: controlled_steps
            .iter()
            .map(|step| step.invocation.clone())
            .collect(),
    }
}

fn build_gate_attempt(
    attempt_id: &str,
    definition: GateAttemptDefinition,
    outcome: GateAttemptOutcome,
) -> GateAttempt {
    build_gate_attempt_with_report_limit(attempt_id, definition, outcome, MAXIMUM_RAW_REPORT_BYTES)
}

fn build_gate_attempt_with_report_limit(
    attempt_id: &str,
    definition: GateAttemptDefinition,
    outcome: GateAttemptOutcome,
    maximum_report_bytes: usize,
) -> GateAttempt {
    let command_digest = command_digest(&definition.invocation);
    let (raw_report, raw_report_content, encoding_failure) =
        if outcome.result == GateStatus::NotSelected {
            (
                RawReportBinding::NotApplicable(NotApplicableReason::GateNotSelected),
                None,
                None,
            )
        } else {
            let report = raw_report_json_with_limit(
                RawReportDocument {
                    attempt_id,
                    gate_id: &definition.gate_id,
                    result: outcome.result,
                    duration_ms: outcome.duration_ms,
                    invocation_digest: &command_digest,
                    invocation: &definition.invocation,
                    detail: &outcome.detail,
                    controlled_steps: &outcome.controlled_steps,
                },
                maximum_report_bytes,
            );
            let path = raw_report_relative_path(attempt_id, &definition.gate_id);
            match report {
                Ok(content) => (
                    RawReportBinding::Exact {
                        path,
                        digest: sha256_digest(content.as_bytes()),
                        bytes: content.len(),
                        content_type: RAW_REPORT_CONTENT_TYPE,
                    },
                    Some(content),
                    None,
                ),
                Err(error) => (
                    RawReportBinding::NotApplicable(NotApplicableReason::ReportEncodingFailed),
                    None,
                    Some(error.to_string()),
                ),
            }
        };
    let report_encoding_failed = encoding_failure.is_some();
    GateAttempt {
        gate_id: definition.gate_id,
        result: if report_encoding_failed {
            GateStatus::Failed
        } else {
            outcome.result
        },
        duration_ms: outcome.duration_ms,
        budget_seconds: definition.budget_seconds,
        invocation: definition.invocation,
        command_digest,
        owner: definition.owner,
        raw_report,
        raw_report_content,
        detail: if let Some(error) = encoding_failure {
            bounded_detail(&format!(
                "{error}; failed closed before oversized allocation"
            ))
        } else {
            outcome.detail
        },
    }
}

fn raw_report_relative_path(attempt_id: &str, gate_id: &str) -> String {
    format!("target/quality/evidence-reports/{attempt_id}/{gate_id}.json")
}

fn command_digest(invocation: &GateInvocation) -> String {
    let canonical = gate_invocation_json(invocation);
    let mut hasher = Sha256::new();
    hasher.update(b"positron-quality-command-v2\0");
    hasher.update(canonical.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn sha256_digest(content: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(content))
}

fn invocation_environment_digest(environment: &[(OsString, OsString)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"positron-quality-invocation-environment-v1\0");
    for (name, value) in environment {
        hasher.update(name.as_encoded_bytes());
        hasher.update([0]);
        hasher.update(value.as_encoded_bytes());
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn invocation_input_identity(input: &InvocationInput) -> (&'static str, usize, String) {
    match input {
        InvocationInput::Null => ("null", 0, "-".to_owned()),
        InvocationInput::Bytes(bytes) => ("bytes", bytes.len(), sha256_digest(bytes)),
    }
}

fn controlled_invocation(
    program: &str,
    resolved_program: &OsStr,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    timeout: Duration,
    input: &InvocationInput,
) -> ControlledInvocation {
    let (input_kind, input_bytes, input_sha256) = invocation_input_identity(input);
    ControlledInvocation {
        program: program.to_owned(),
        resolved_program: resolved_program.to_string_lossy().into_owned(),
        arguments: arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect(),
        working_directory: "engineering-workspace".to_owned(),
        environment_digest: invocation_environment_digest(environment),
        timeout_ms: timeout.as_millis(),
        input_kind: input_kind.to_owned(),
        input_bytes,
        input_sha256,
    }
}

fn retained_internal_invocation(
    environment_digest: &str,
    specification: InternalInvocationSpec<'_>,
) -> GateInvocation {
    GateInvocation {
        program: "cargo-xtask-quality/internal".to_owned(),
        arguments: vec![
            "quality".to_owned(),
            specification.operation.to_owned(),
            specification.gate_id.to_owned(),
        ],
        working_directory: "engineering-workspace".to_owned(),
        environment_digest: sha256_digest(environment_digest.as_bytes()),
        timeout_seconds: specification.timeout_seconds,
        memory_mib: specification.memory_mib,
        activation: specification.activation.to_owned(),
        exception_class: specification.exception_class.to_owned(),
        controlled_steps: Vec::new(),
    }
}

fn gate_selected(gate: &Gate, profile: Profile, activated_risk_gates: &BTreeSet<String>) -> bool {
    if profile == Profile::PreCommit {
        return matches!(
            gate.id.as_str(),
            "EG-00" | "EG-ARCH" | "EG-POLICY" | "EG-RUST" | "EG-SAFETY" | "EG-SECRETS"
        );
    }

    if gate.activation == "always" {
        return true;
    }
    if !activated_risk_gates.contains(&gate.id) {
        return false;
    }
    match profile {
        Profile::Pr => gate.stages.contains("PR"),
        Profile::Ext => gate.stages.contains("PR") || gate.stages.contains("EXT"),
        Profile::Qual => true,
        Profile::PreCommit => false,
    }
}

fn not_selected_reason(gate: &Gate, profile: Profile) -> String {
    if profile == Profile::PreCommit {
        return "Not in the bounded local-feedback profile; the complete PR profile in trusted CI remains authoritative."
            .to_owned();
    }
    let stage_applies = match profile {
        Profile::Pr => gate.stages.contains("PR"),
        Profile::Ext => gate.stages.contains("PR") || gate.stages.contains("EXT"),
        Profile::Qual => true,
        Profile::PreCommit => false,
    };
    if !stage_applies {
        return format!(
            "Gate does not apply to the `{}` execution profile.",
            profile.as_str()
        );
    }
    if gate.activation == "risk" {
        return "The committed scope registry contains no active application scope selecting this risk gate; scaffold-only source validation passed."
            .to_owned();
    }
    format!(
        "Gate does not apply to the `{}` execution profile.",
        profile.as_str()
    )
}

fn execute_gate(
    context: GateExecutionContext<'_>,
    gate: &Gate,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let GateExecutionContext {
        attempt_id,
        root,
        registry,
        qualification_fixtures,
        options,
        environment,
        source,
        identity,
    } = context;
    let budget = Duration::from_secs(gate.timeout_seconds);
    match gate.runner.as_str() {
        "registry" => run_registry_gate(
            root,
            registry,
            options.profile,
            budget,
            environment,
            capture,
        ),
        "architecture" => run_architecture_gate(root, registry, budget, environment, capture),
        "build" => run_build_gate(root, options.profile, budget, environment, capture),
        "coverage" => run_coverage_gate(root, registry, budget, options, environment, capture),
        "dynamic-analysis" => {
            run_dynamic_analysis_gate(root, registry, budget, environment, capture)
        },
        "dependencies" => {
            run_dependency_gate(attempt_id, root, registry, budget, environment, capture)
        },
        "documentation" => run_documentation_gate(root, budget, environment, capture),
        "concurrency" => run_bounded_runner_gate(
            qualification_fixtures.bounded_runners(),
            root,
            gate,
            environment,
            capture,
        ),
        "correctness" => run_correctness_gate(qualification_fixtures, environment),
        "fault" => run_fault_gate(qualification_fixtures, environment),
        "integrity" => run_integrity_gate(
            qualification_fixtures,
            gate,
            options,
            environment,
            source,
            identity,
        ),
        "error-policy" => run_error_policy_gate(root, registry),
        "evidence" => run_evidence_gate(root, registry),
        "policy" => run_policy_gate(root, registry),
        "rust" => run_rust_gate(root, budget, environment, capture),
        "safety" => run_safety_gate(root, registry, budget, environment, capture),
        "security" => run_security_gate(root, registry, budget, environment, capture),
        "secrets" => run_secret_gate(root, options.profile, budget, environment, capture),
        "supply" => run_supply_gate(
            root,
            registry,
            options.profile,
            budget,
            environment,
            capture,
        ),
        "test" => run_test_gate(root, budget, environment, capture),
        "matrix" => run_generation_matrix_gate(root),
        "resource" => run_bounded_runner_gate(
            qualification_fixtures.bounded_runners(),
            root,
            gate,
            environment,
            capture,
        ),
        unsupported => Err(XtaskError::invalid(
            format!("gate runner `{unsupported}`"),
            "an active risk scope selected a gate whose executable harness has not been implemented",
        )),
    }
}

fn run_bounded_runner_gate(
    registry: &crate::bounded_runners::FrozenBoundedRunnerRegistry,
    root: &Path,
    gate: &Gate,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let execution_timeout = Duration::from_secs(gate.timeout_seconds);
    let gate_id = gate.id.as_str();
    crate::bounded_runners::validate_source_policy(registry, root)?;
    let shutdown = registry.shutdown_bound(gate_id)?;
    let program = env::current_exe()
        .map_err(|source| XtaskError::io("resolve bounded runner executable", source))?;
    if !program.is_absolute() || !program.is_file() {
        return Err(XtaskError::invalid_path(
            &program,
            "bounded runner executable is not an absolute file",
        ));
    }
    let arguments = registry.child_arguments(gate_id, execution_timeout)?;
    let retained_arguments = arguments
        .iter()
        .map(|argument| {
            argument.to_str().ok_or_else(|| {
                XtaskError::invalid(
                    "bounded runner child invocation",
                    "child argument is not canonical UTF-8",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    crate::bounded_runners::FrozenBoundedRunnerRegistry::validate_child_invocation(
        gate_id,
        execution_timeout.as_millis(),
        &retained_arguments,
    )?;
    let invocation_environment = environment.invocation_environment(&[])?;
    let input = InvocationInput::Null;
    let invocation = controlled_invocation(
        "cargo-xtask-quality/bounded-runner",
        program.as_os_str(),
        &arguments,
        &invocation_environment,
        execution_timeout,
        &input,
    );
    let outcome = controlled_execution::execute(InvocationSpec {
        program: program.as_os_str().to_owned(),
        arguments,
        current_dir: root.to_path_buf(),
        environment: invocation_environment,
        tools: environment.execution_tools(),
        input,
        output: OutputMode::FramedStdout {
            maximum_bytes: crate::bounded_runner_frames::MAXIMUM_FRAME_BYTES,
        },
        cancellation: Arc::new(AtomicBool::new(false)),
        deadline: deadline_after(execution_timeout)?,
        shutdown_timeout: shutdown,
        cancellation_marker: None,
    })
    .into_result();
    let completed_lifecycle = |phase: &str| {
        format!(
            "process-lifecycle-v1;phase={phase};termination-requested=false;process-reaped=true;live=0;shutdown-ms={};process-shutdown-elapsed-ms=0;resource-shutdown-elapsed-ms=0;shutdown-elapsed-ms=0",
            shutdown.as_millis(),
        )
    };
    let verdict = match outcome {
        Ok(verdict) => {
            let step_verdict = format!("exit-status:{}", verdict.status);
            capture.record(
                invocation,
                &step_verdict,
                &verdict.output.stdout,
                &verdict.output.stderr,
            )?;
            verdict
        },
        Err(error) => {
            let lifecycle = match error.shutdown.as_deref() {
                Some(observed) => format!(
                    "process-lifecycle-v1;phase={};termination-requested={};process-reaped={};live={};shutdown-ms={};process-shutdown-elapsed-ms={};resource-shutdown-elapsed-ms={};shutdown-elapsed-ms={}",
                    error.phase.as_str(),
                    observed.termination_requested,
                    observed.process_reaped,
                    observed.live,
                    observed.bound.as_millis(),
                    observed.process_elapsed.as_millis(),
                    observed.resource_elapsed.as_millis(),
                    observed.elapsed.as_millis(),
                ),
                None => format!(
                    "process-lifecycle-v1;phase={};termination-requested=false;process-reaped=false;live=0;shutdown-ms={};process-shutdown-elapsed-ms=0;resource-shutdown-elapsed-ms=0;shutdown-elapsed-ms=0",
                    error.phase.as_str(),
                    shutdown.as_millis(),
                ),
            };
            let reconciliation =
                error
                    .reconciliation
                    .as_deref()
                    .map_or_else(String::new, |observed| {
                        format!(
                            "; reconciliation-phase={}; reconciliation-detail={}",
                            observed.phase.as_str(),
                            observed.detail,
                        )
                    });
            let step_verdict = format!("controlled-failure:{}", error.phase.as_str());
            capture.record(
                invocation,
                &step_verdict,
                "",
                &format!("{}{}; {lifecycle}", error.detail, reconciliation),
            )?;
            return Err(XtaskError::invalid(
                "bounded runner process lifecycle",
                format!(
                    "controlled runner failed during {}: {}{}; {}",
                    error.phase.as_str(),
                    error.detail,
                    reconciliation,
                    lifecycle,
                ),
            ));
        },
    };
    let frame =
        crate::bounded_runner_frames::parse_captured(&verdict.output.stdout).map_err(|error| {
            XtaskError::invalid(
                "bounded runner process lifecycle",
                format!("{error}; {}", completed_lifecycle("malformed-output")),
            )
        })?;
    let record = match frame {
        crate::bounded_runner_frames::CapturedFrame::Outcome(record) => {
            if !verdict.status.success() {
                return Err(XtaskError::invalid(
                    "bounded runner process lifecycle",
                    format!(
                        "child returned {} after publishing a success frame; {}",
                        verdict.status,
                        completed_lifecycle("child-error"),
                    ),
                ));
            }
            record
        },
        crate::bounded_runner_frames::CapturedFrame::Error(detail) => {
            return Err(XtaskError::invalid(
                "bounded runner process lifecycle",
                format!(
                    "child returned {}: {}; {}",
                    verdict.status,
                    detail.split_whitespace().collect::<Vec<_>>().join(" "),
                    completed_lifecycle("child-error"),
                ),
            ));
        },
    };
    if record.is_empty() || record.lines().count() != 1 {
        return Err(XtaskError::invalid(
            "bounded runner process lifecycle",
            format!(
                "child omitted its exact one-line measurement; {}",
                completed_lifecycle("malformed-output"),
            ),
        ));
    }
    let verified = crate::bounded_measurement_verifier::verify(
        crate::bounded_measurement_verifier::VerificationInput {
            gate,
            scenario_registry: registry.bytes(),
            spawn_registry: registry.spawn_site_bytes(),
            measurement: &record,
            execution: &verdict,
        },
    )?;
    Ok(format!(
        "{record}; {}; {}",
        verified.evidence(),
        completed_lifecycle("completed"),
    ))
}

fn run_correctness_gate(
    fixtures: &crate::qualification_fixtures::FrozenQualificationFixtures,
    environment: &EnvironmentSnapshot,
) -> Result<String, XtaskError> {
    crate::qualification_fixtures::run_correctness(fixtures, &environment.temporary_root)
}

fn run_fault_gate(
    fixtures: &crate::qualification_fixtures::FrozenQualificationFixtures,
    environment: &EnvironmentSnapshot,
) -> Result<String, XtaskError> {
    crate::qualification_fixtures::run_fault(fixtures, &environment.temporary_root)
}

fn run_integrity_gate(
    fixtures: &crate::qualification_fixtures::FrozenQualificationFixtures,
    gate: &Gate,
    options: &Options,
    environment: &EnvironmentSnapshot,
    source: &SourceIdentity,
    identity: &EvidenceIdentity,
) -> Result<String, XtaskError> {
    let invocation = canonical_gate_invocation(gate, options.profile, environment.digest(), &[]);
    let integrity_identity = crate::qualification_fixtures::IntegrityIdentity {
        revision: source.revision.clone(),
        artifact: identity_binding_text(&identity.artifact),
        target: identity_binding_text(&identity.target),
        environment: environment.digest().to_owned(),
        command: command_digest(&invocation),
        fixtures: identity.fixture_registry_digest.clone(),
        result: GateStatus::Passed.as_str().to_owned(),
    };
    crate::qualification_fixtures::run_integrity(
        fixtures,
        &environment.temporary_root,
        &integrity_identity,
    )
}

fn run_generation_matrix_gate(root: &Path) -> Result<String, XtaskError> {
    let invocation = crate::generation::VerificationInvocation::claim(root)?;
    let report = crate::generation::verify(root, invocation)?;
    Ok(format!(
        "canonical generation parity is clean across configuration, Rust, HTTP/JSON, OpenAPI, Schema Digest, and validation fixtures; {}",
        report.display()
    ))
}

fn run_dynamic_analysis_gate(
    root: &Path,
    registry: &Registry,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    if !registry.has_m0_02_domain_types_scope() {
        return Err(XtaskError::invalid(
            "dynamic analysis runner",
            "EG-DYNAMIC was selected without an applicable registered dynamic target",
        ));
    }
    let deadline = Instant::now() + budget;
    let contract = run_status(
        root,
        environment,
        "cargo",
        [
            "test",
            "--locked",
            "--package",
            "positron-domain",
            "--test",
            "foundational_domain_types",
        ],
        remaining(deadline)?,
        capture,
    )?;
    let compile_fail = run_status(
        root,
        environment,
        "cargo",
        ["test", "--locked", "--package", "positron-domain", "--doc"],
        remaining(deadline)?,
        capture,
    )?;
    Ok(format!(
        "M0-02 Domain Types retained-seed contract/property cases: {} | compile-fail: {}",
        contract.display, compile_fail.display,
    ))
}

fn run_coverage_gate(
    root: &Path,
    registry: &Registry,
    budget: Duration,
    options: &Options,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let detector_versions =
        verify_coverage_detectors(root, registry, deadline, environment, capture)?;
    let coverage_directory = root.join("target/quality/coverage");
    fs::create_dir_all(&coverage_directory).map_err(|source| {
        XtaskError::io(format!("create {}", coverage_directory.display()), source)
    })?;
    let mut results = Vec::new();
    if registry.has_m0_02_domain_types_scope() {
        results.push(run_m0_02_domain_types_coverage(
            root,
            registry,
            deadline,
            environment,
            capture,
        )?);
    }
    if registry.has_m0_01_foundational_scope() {
        results.push(run_m0_01_coverage(
            root,
            registry,
            deadline,
            environment,
            capture,
        )?);
    }
    if registry.has_m0_03_canonical_api_scope() {
        results.push(run_m0_03_canonical_api_coverage(
            root,
            registry,
            deadline,
            environment,
            capture,
        )?);
    }
    if registry.has_m0_04_configuration_scope() {
        results.push(run_m0_04_configuration_coverage(
            root,
            deadline,
            environment,
            capture,
        )?);
    }
    if options.retain_m0_02_mutation {
        results.push(run_m0_02_mutation(
            root,
            registry,
            deadline,
            environment,
            capture,
        )?);
    }
    if options.retain_m0_03_mutation {
        results.push(run_m0_03_mutation(
            root,
            registry,
            deadline,
            environment,
            capture,
        )?);
    }
    if options.retain_m0_04_mutation {
        results.push(run_m0_04_mutation(
            root,
            registry,
            deadline,
            environment,
            capture,
        )?);
    }
    if results.is_empty() {
        return Err(XtaskError::invalid(
            "coverage runner",
            "EG-COVERAGE was selected without a registered coverage activation",
        ));
    }
    Ok(format!("{detector_versions}; {}", results.join(" | ")))
}

fn run_m0_02_mutation(
    root: &Path,
    registry: &Registry,
    deadline: Instant,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    if !registry.has_m0_02_domain_types_scope() {
        return Err(XtaskError::invalid(
            "M0-02 mutation runner",
            "the retained M0-02 mutation campaign requires the active Domain Types scope",
        ));
    }
    let tool = registry
        .tools
        .iter()
        .find(|tool| tool.id == "cargo-mutants")
        .ok_or_else(|| {
            XtaskError::invalid(
                "M0-02 mutation detector registry",
                "missing required detector `cargo-mutants`",
            )
        })?;
    let version = run_capture(
        root,
        environment,
        &tool.command,
        tool.version_arguments.iter().map(String::as_str),
        remaining(deadline)?,
        Some(&mut *capture),
    )?;
    if !version.stdout.contains(&tool.version) {
        return Err(XtaskError::invalid(
            "M0-02 mutation detector `cargo-mutants`",
            format!(
                "expected version `{}`, command reported `{}`",
                tool.version,
                one_line(&version.stdout)
            ),
        ));
    }
    let output = root.join(M0_02_MUTATION_OUTPUT);
    fs::create_dir_all(&output)
        .map_err(|source| XtaskError::io(format!("create {}", output.display()), source))?;
    let outcome = run_status(
        root,
        environment,
        "cargo",
        [
            "mutants",
            "--no-config",
            "--package",
            "positron-domain",
            "--re",
            M0_02_MUTATION_SELECTOR,
            "--test-tool",
            "cargo",
            "--output",
            M0_02_MUTATION_OUTPUT,
            "--timeout",
            "30",
            "--jobs",
            "1",
            "--no-times",
            "--",
            "--locked",
            "--test",
            "foundational_domain_types",
        ],
        remaining(deadline)?,
        capture,
    )?;
    Ok(format!(
        "cargo-mutants={}; {}",
        tool.version, outcome.display
    ))
}

fn run_m0_03_mutation(
    root: &Path,
    registry: &Registry,
    deadline: Instant,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    if !registry.has_m0_03_canonical_api_scope() {
        return Err(XtaskError::invalid(
            "M0-03 mutation runner",
            "the retained M0-03 mutation campaign requires the active canonical API scope",
        ));
    }
    let tool = registry
        .tools
        .iter()
        .find(|tool| tool.id == "cargo-mutants")
        .ok_or_else(|| {
            XtaskError::invalid(
                "M0-03 mutation detector registry",
                "missing required detector `cargo-mutants`",
            )
        })?;
    let version = run_capture(
        root,
        environment,
        &tool.command,
        tool.version_arguments.iter().map(String::as_str),
        remaining(deadline)?,
        Some(&mut *capture),
    )?;
    if !version.stdout.contains(&tool.version) {
        return Err(XtaskError::invalid(
            "M0-03 mutation detector `cargo-mutants`",
            format!(
                "expected version `{}`, command reported `{}`",
                tool.version,
                one_line(&version.stdout)
            ),
        ));
    }
    let output = root.join(M0_03_MUTATION_OUTPUT);
    fs::create_dir_all(&output)
        .map_err(|source| XtaskError::io(format!("create {}", output.display()), source))?;
    let outcome = run_status(
        root,
        environment,
        "cargo",
        [
            "mutants",
            "--no-config",
            "--package",
            "positron-api",
            "--re",
            M0_03_MUTATION_SELECTOR,
            "--test-tool",
            "cargo",
            "--output",
            M0_03_MUTATION_OUTPUT,
            "--timeout",
            "30",
            "--jobs",
            "1",
            "--no-times",
            "--",
            "--locked",
            "--test",
            "canonical_public_interface",
        ],
        remaining(deadline)?,
        capture,
    )?;
    Ok(format!(
        "cargo-mutants={}; {}",
        tool.version, outcome.display
    ))
}

fn run_m0_04_mutation(
    root: &Path,
    registry: &Registry,
    deadline: Instant,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    if !registry.has_m0_04_configuration_scope() {
        return Err(XtaskError::invalid(
            "M0-04 mutation runner",
            "the retained M0-04 mutation campaign requires the active Configuration scope",
        ));
    }
    let tool = registry
        .tools
        .iter()
        .find(|tool| tool.id == "cargo-mutants")
        .ok_or_else(|| {
            XtaskError::invalid(
                "M0-04 mutation detector registry",
                "missing required detector `cargo-mutants`",
            )
        })?;
    let version = run_capture(
        root,
        environment,
        &tool.command,
        tool.version_arguments.iter().map(String::as_str),
        remaining(deadline)?,
        Some(&mut *capture),
    )?;
    if !version.stdout.contains(&tool.version) {
        return Err(XtaskError::invalid(
            "M0-04 mutation detector `cargo-mutants`",
            format!(
                "expected version `{}`, command reported `{}`",
                tool.version,
                one_line(&version.stdout)
            ),
        ));
    }
    let output = root.join(M0_04_MUTATION_OUTPUT);
    fs::create_dir_all(&output)
        .map_err(|source| XtaskError::io(format!("create {}", output.display()), source))?;
    let outcome = run_status(
        root,
        environment,
        "cargo",
        [
            "mutants",
            "--no-config",
            "--package",
            "positron-config",
            "--re",
            M0_04_MUTATION_SELECTOR,
            "--test-tool",
            "cargo",
            "--output",
            M0_04_MUTATION_OUTPUT,
            "--timeout",
            "30",
            "--jobs",
            "1",
            "--no-times",
            "--",
            "--locked",
            "--test",
            "configuration_foundation",
        ],
        remaining(deadline)?,
        capture,
    )?;
    Ok(format!(
        "cargo-mutants={}; {}",
        tool.version, outcome.display
    ))
}

fn run_m0_01_coverage(
    root: &Path,
    registry: &Registry,
    deadline: Instant,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let specifications = m0_01b_coverage_command_specs();
    validate_m0_01b_coverage_command_specs(&specifications)?;
    let [total_specification, changed_code_specification] = specifications;
    let total = run_status(
        root,
        environment,
        "cargo",
        total_specification.arguments(),
        remaining(deadline)?,
        capture,
    )?;
    let changed_code = run_status(
        root,
        environment,
        "cargo",
        changed_code_specification.arguments(),
        remaining(deadline)?,
        capture,
    )?;

    let total_measurements = read_coverage_measurements(&root.join(total_specification.report))?;
    let changed_measurements =
        read_coverage_measurements(&root.join(changed_code_specification.report))?;
    enforce_m0_01_coverage_baselines(registry, &total_measurements, &changed_measurements)?;

    Ok(format!(
        "M0-01: {} | {}; total(branch={:.2}, line={:.2}, region={:.2}); changed-code(line={:.2})",
        total.display,
        changed_code.display,
        total_measurements.branch,
        total_measurements.line,
        total_measurements.region,
        changed_measurements.line,
    ))
}

fn run_m0_02_domain_types_coverage(
    root: &Path,
    registry: &Registry,
    deadline: Instant,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let report = "target/quality/coverage/m0-02-domain-total.json";
    let outcome = run_status(
        root,
        environment,
        "cargo",
        [
            "+nightly-2026-07-20",
            "llvm-cov",
            "--locked",
            "--package",
            "positron-domain",
            "--test",
            "foundational_domain_types",
            "--branch",
            "--json",
            "--summary-only",
            "--ignore-filename-regex",
            "crates/positron-domain/tests/.*",
            "--output-path",
            report,
        ],
        remaining(deadline)?,
        capture,
    )?;
    let measurements = read_coverage_measurements(&root.join(report))?;
    enforce_m0_02_domain_types_coverage_baselines(registry, &measurements)?;
    Ok(format!(
        "M0-02 Domain Types: {}; total(branch={:.2}, line={:.2}, region={:.2})",
        outcome.display, measurements.branch, measurements.line, measurements.region,
    ))
}

fn run_m0_03_canonical_api_coverage(
    root: &Path,
    registry: &Registry,
    deadline: Instant,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let report = "target/quality/coverage/m0-03-api.json";
    let outcome = run_status(
        root,
        environment,
        "cargo",
        [
            "+nightly-2026-07-20",
            "llvm-cov",
            "--locked",
            "--package",
            "positron-api",
            "--test",
            "canonical_public_interface",
            "--branch",
            "--json",
            "--summary-only",
            "--ignore-filename-regex",
            "crates/positron-api/tests/.*",
            "--output-path",
            report,
        ],
        remaining(deadline)?,
        capture,
    )?;
    let measurements = read_coverage_measurements(&root.join(report))?;
    enforce_m0_03_canonical_api_coverage_baselines(registry, &measurements)?;
    Ok(format!(
        "M0-03 canonical API: {}; total(branch={:.2}, line={:.2}, region={:.2})",
        outcome.display, measurements.branch, measurements.line, measurements.region,
    ))
}

fn run_m0_04_configuration_coverage(
    root: &Path,
    deadline: Instant,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let report = "target/quality/coverage/m0-04-config.json";
    let outcome = run_status(
        root,
        environment,
        "cargo",
        [
            "+nightly-2026-07-20",
            "llvm-cov",
            "--locked",
            "--package",
            "positron-config",
            "--test",
            "configuration_foundation",
            "--branch",
            "--json",
            "--summary-only",
            "--ignore-filename-regex",
            "crates/positron-config/tests/.*",
            "--output-path",
            report,
        ],
        remaining(deadline)?,
        capture,
    )?;
    let measurements = read_coverage_measurements(&root.join(report))?;
    for (actual, label) in [(measurements.line, "line"), (measurements.region, "region")] {
        if actual < M0_04_COVERAGE_FLOOR {
            return Err(XtaskError::invalid(
                "M0-04 coverage floor",
                format!(
                    "Configuration coverage {label} {actual:.2} is below the candidate floor {M0_04_COVERAGE_FLOOR:.2}"
                ),
            ));
        }
    }
    Ok(format!(
        "M0-04 Configuration: {}; total(branch={:.2}, line={:.2}, region={:.2})",
        outcome.display, measurements.branch, measurements.line, measurements.region,
    ))
}

fn verify_coverage_detectors(
    root: &Path,
    registry: &Registry,
    deadline: Instant,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let identity = "cargo-llvm-cov";
    let tool = registry
        .tools
        .iter()
        .find(|tool| tool.id == identity)
        .ok_or_else(|| {
            XtaskError::invalid(
                "coverage detector registry",
                format!("missing required detector `{identity}`"),
            )
        })?;
    let outcome = run_capture(
        root,
        environment,
        &tool.command,
        tool.version_arguments.iter().map(String::as_str),
        remaining(deadline)?,
        Some(capture),
    )?;
    if !outcome.stdout.contains(&tool.version) {
        return Err(XtaskError::invalid(
            format!("coverage detector `{identity}`"),
            format!(
                "expected version `{}`, command reported `{}`",
                tool.version,
                one_line(&outcome.stdout)
            ),
        ));
    }
    Ok(format!("{identity}={}", tool.version))
}

fn enforce_m0_01_coverage_baselines(
    registry: &Registry,
    total: &CoverageMeasurements,
    changed_code: &CoverageMeasurements,
) -> Result<(), XtaskError> {
    for (identity, actual, label) in [
        ("coverage-branch", total.branch, "branch"),
        ("coverage-line", total.line, "line"),
        ("coverage-region", total.region, "region"),
        ("coverage-changed-code", changed_code.line, "changed-code"),
    ] {
        let baseline = registry.measured_baseline(identity)?;
        if actual < baseline {
            return Err(XtaskError::invalid(
                "M0 coverage baseline",
                format!("coverage {label} {actual:.2} is below frozen M0 baseline {baseline:.2}"),
            ));
        }
    }
    Ok(())
}

fn enforce_m0_02_domain_types_coverage_baselines(
    registry: &Registry,
    measurements: &CoverageMeasurements,
) -> Result<(), XtaskError> {
    for (identity, actual, label) in [
        ("domain-coverage-branch", measurements.branch, "branch"),
        ("domain-coverage-line", measurements.line, "line"),
        ("domain-coverage-region", measurements.region, "region"),
    ] {
        let baseline = registry.measured_baseline(identity)?;
        if actual < baseline {
            return Err(XtaskError::invalid(
                "M0-02 coverage baseline",
                format!(
                    "domain coverage {label} {actual:.2} is below frozen M0-02 baseline {baseline:.2}"
                ),
            ));
        }
    }
    Ok(())
}

fn enforce_m0_03_canonical_api_coverage_baselines(
    registry: &Registry,
    measurements: &CoverageMeasurements,
) -> Result<(), XtaskError> {
    for (identity, actual, label) in [
        ("api-coverage-branch", measurements.branch, "branch"),
        ("api-coverage-line", measurements.line, "line"),
        ("api-coverage-region", measurements.region, "region"),
    ] {
        let baseline = registry.measured_baseline(identity)?;
        if actual < baseline {
            return Err(XtaskError::invalid(
                "M0-03 coverage baseline",
                format!(
                    "canonical API coverage {label} {actual:.2} is below frozen M0-03 baseline {baseline:.2}"
                ),
            ));
        }
    }
    Ok(())
}

fn read_coverage_measurements(path: &Path) -> Result<CoverageMeasurements, XtaskError> {
    let content = fs::read_to_string(path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    Ok(CoverageMeasurements {
        branch: read_coverage_percent(&content, path, "branches")?,
        line: read_coverage_percent(&content, path, "lines")?,
        region: read_coverage_percent(&content, path, "regions")?,
    })
}

fn read_coverage_percent(content: &str, path: &Path, metric: &str) -> Result<f64, XtaskError> {
    let Some((_, totals)) = content.rsplit_once("\"totals\"") else {
        return Err(XtaskError::invalid_path(
            path,
            "coverage report is missing its totals object",
        ));
    };
    let metric_marker = format!("\"{metric}\"");
    let Some((_, metric_data)) = totals.split_once(&metric_marker) else {
        return Err(XtaskError::invalid_path(
            path,
            format!("coverage report is missing `{metric}` totals"),
        ));
    };
    let Some((_, percent_data)) = metric_data.split_once("\"percent\"") else {
        return Err(XtaskError::invalid_path(
            path,
            format!("coverage report is missing `{metric}` percent"),
        ));
    };
    let Some((_, numeric)) = percent_data.split_once(':') else {
        return Err(XtaskError::invalid_path(
            path,
            format!("coverage report has malformed `{metric}` percent"),
        ));
    };
    let numeric = numeric.trim_start();
    let value = numeric
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect::<String>();
    let percentage = value.parse::<f64>().map_err(|source| {
        XtaskError::invalid_path(
            path,
            format!("coverage report has non-numeric `{metric}` percent: {source}"),
        )
    })?;
    if !percentage.is_finite() || !(0.0..=100.0).contains(&percentage) {
        return Err(XtaskError::invalid_path(
            path,
            format!("coverage report has invalid `{metric}` percent `{percentage}`"),
        ));
    }
    Ok(percentage)
}

fn run_registry_gate(
    root: &Path,
    registry: &Registry,
    profile: Profile,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    if profile == Profile::Qual {
        let targets = root.join("qualification/targets/registry.json");
        let target_registry = fs::read_to_string(&targets)
            .map_err(|source| XtaskError::io(format!("read {}", targets.display()), source))?;
        if !registry.has_active_application_scope()
            || target_registry.contains("\"qualification_claims_permitted\": false")
        {
            return Err(XtaskError::invalid(
                "qualification profile",
                "the scaffold has no candidate artifact and the target registry forbids qualification claims",
            ));
        }
    }
    let deadline = Instant::now() + budget;
    let mut checked = Vec::new();
    for tool in &registry.tools {
        if !tool_required(tool.required_profiles.iter().map(String::as_str), profile) {
            continue;
        }
        let outcome = run_capture(
            root,
            environment,
            &tool.command,
            tool.version_arguments.iter().map(String::as_str),
            remaining(deadline)?,
            Some(&mut *capture),
        )?;
        if !outcome.stdout.contains(&tool.version) {
            return Err(XtaskError::invalid(
                format!("tool `{}`", tool.id),
                format!(
                    "expected version `{}`, command reported `{}`",
                    tool.version,
                    one_line(&outcome.stdout)
                ),
            ));
        }
        checked.push(format!("{}={}", tool.id, tool.version));
    }
    if checked.is_empty() {
        return Err(XtaskError::invalid(
            "toolchain registry",
            "profile selected no tool identities",
        ));
    }
    Ok(format!("internal:registry; {}", checked.join("; ")))
}

fn tool_required<'tool>(profiles: impl Iterator<Item = &'tool str>, profile: Profile) -> bool {
    profiles.into_iter().any(|required| {
        required == profile.as_str()
            || (profile == Profile::Ext && required == "pr")
            || (profile == Profile::Qual && matches!(required, "pr" | "ext"))
    })
}

fn run_architecture_gate(
    root: &Path,
    registry: &Registry,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let workspace_packages = registry
        .scopes
        .iter()
        .map(|scope| scope.package.clone())
        .collect::<BTreeSet<_>>();
    let scaffold_packages = registry
        .scopes
        .iter()
        .filter(|scope| scope.state == "scaffold")
        .map(|scope| scope.package.clone())
        .collect::<BTreeSet<_>>();
    let mut actual_edges = BTreeSet::new();
    let mut direct_external = BTreeSet::new();
    let scope_contracts = registry
        .scopes
        .iter()
        .map(|scope| {
            format!(
                "{}:{}:{}",
                scope.package, scope.semantic_owner, scope.test_commands
            )
        })
        .collect::<Vec<_>>();

    for scope in &registry.scopes {
        let outcome = run_capture(
            root,
            environment,
            "cargo",
            [
                "tree",
                "--locked",
                "--package",
                scope.package.as_str(),
                "--depth",
                "1",
                "--edges",
                "normal,build",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ],
            remaining(deadline)?,
            Some(&mut *capture),
        )?;
        for line in outcome.stdout.lines().skip(1) {
            let Some(dependency) = line.split_whitespace().next() else {
                continue;
            };
            if workspace_packages.contains(dependency) {
                actual_edges.insert((scope.package.clone(), dependency.to_owned()));
            } else {
                direct_external.insert((scope.package.clone(), dependency.to_owned()));
            }
        }
    }

    let forbidden = actual_edges
        .difference(registry.allowed_edges())
        .map(|(caller, dependency)| format!("{caller}->{dependency}"))
        .collect::<Vec<_>>();
    if !forbidden.is_empty() {
        return Err(XtaskError::invalid(
            "resolved workspace dependency graph",
            format!("forbidden internal edges: {}", forbidden.join(", ")),
        ));
    }
    let scaffold_internal = actual_edges
        .iter()
        .filter(|(caller, _)| scaffold_packages.contains(caller))
        .map(|(caller, dependency)| format!("{caller}->{dependency}"))
        .collect::<Vec<_>>();
    let scaffold_external = direct_external
        .iter()
        .filter(|(caller, _)| scaffold_packages.contains(caller))
        .map(|(caller, dependency)| format!("{caller}->{dependency}"))
        .collect::<Vec<_>>();
    if !scaffold_internal.is_empty() || !scaffold_external.is_empty() {
        return Err(XtaskError::invalid(
            "scaffold dependency graph",
            format!(
                "scaffold-only crates must have no dependencies; internal [{}], external [{}]",
                scaffold_internal.join(", "),
                scaffold_external.join(", ")
            ),
        ));
    }
    let unreviewed = direct_external
        .iter()
        .filter(|(_, dependency)| !registry.reviewed_dependencies().contains(dependency))
        .map(|(caller, dependency)| format!("{caller}->{dependency}"))
        .collect::<Vec<_>>();
    if !unreviewed.is_empty() {
        return Err(XtaskError::invalid(
            "resolved workspace dependency graph",
            format!(
                "direct third-party dependencies lack review records: {}",
                unreviewed.join(", ")
            ),
        ));
    }

    Ok(format!(
        "cargo tree --locked per registered package; internal:allowed-edge comparison; scopes={}",
        scope_contracts.join(",")
    ))
}

fn run_build_gate(
    root: &Path,
    profile: Profile,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let mut commands = Vec::new();
    commands.push(
        run_status(
            root,
            environment,
            "cargo",
            [
                "check",
                "--locked",
                "--workspace",
                "--all-targets",
                "--all-features",
            ],
            remaining(deadline)?,
            capture,
        )?
        .display,
    );
    if matches!(profile, Profile::Ext | Profile::Qual) {
        for target in [
            "aarch64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux-gnu",
        ] {
            commands.push(
                run_status(
                    root,
                    environment,
                    "cargo",
                    [
                        "check",
                        "--locked",
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                        "--target",
                        target,
                    ],
                    remaining(deadline)?,
                    capture,
                )?
                .display,
            );
        }
    }
    Ok(commands.join(" | "))
}

fn run_dependency_gate(
    attempt_id: &str,
    root: &Path,
    registry: &Registry,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let mut commands = Vec::new();
    commands.push(
        run_dependency_metadata_capture(
            attempt_id,
            root,
            environment,
            remaining(deadline)?,
            capture,
        )?
        .display,
    );
    commands.push(
        run_status(
            root,
            environment,
            "cargo-machete",
            ["--with-metadata", "--skip-target-dir", "."],
            remaining(deadline)?,
            capture,
        )?
        .display,
    );
    commands.push(
        run_status(
            root,
            environment,
            "cargo",
            ["deny", "check", "bans", "licenses", "sources"],
            remaining(deadline)?,
            capture,
        )?
        .display,
    );
    if !registry.reviewed_dependencies().is_empty() {
        commands.push("internal:direct-dependency-review parity".to_owned());
    }
    Ok(commands.join(" | "))
}

fn run_dependency_metadata_capture(
    attempt_id: &str,
    root: &Path,
    snapshot: &EnvironmentSnapshot,
    timeout: Duration,
    capture: &mut GateCapture,
) -> Result<CommandOutcome, XtaskError> {
    let artifact = prepare_dependency_metadata_artifact(root, attempt_id)?;
    let argument_values = ["metadata", "--locked", "--format-version", "1"];
    let arguments = argument_values.map(OsString::from).to_vec();
    let resolved_program = snapshot.tool_path("cargo")?;
    let display = command_display(&resolved_program.to_string_lossy(), &arguments);
    println!("  $ {display}");
    let invocation_environment = snapshot.invocation_environment(&[])?;
    let input = InvocationInput::Null;
    let invocation = controlled_invocation(
        "cargo",
        resolved_program.as_os_str(),
        &arguments,
        &invocation_environment,
        timeout,
        &input,
    );
    let verdict = controlled_execution::execute(InvocationSpec {
        program: resolved_program,
        arguments,
        current_dir: root.to_path_buf(),
        environment: invocation_environment,
        tools: snapshot.execution_tools(),
        input,
        output: OutputMode::CaptureWithStdoutArtifact {
            artifact: artifact.artifact_output()?,
            maximum_artifact_bytes: MAXIMUM_RAW_REPORT_BYTES,
            maximum_stderr_bytes: MAXIMUM_CAPTURED_REPORT_STREAM_BYTES,
        },
        cancellation: Arc::new(AtomicBool::new(false)),
        deadline: deadline_after(timeout)?,
        shutdown_timeout: controlled_execution::DEFAULT_SHUTDOWN_TIMEOUT,
        cancellation_marker: None,
    })
    .into_result();
    let verdict = match verdict {
        Ok(verdict) => verdict,
        Err(error) => {
            let step_verdict = format!("controlled-failure:{}", error.phase.as_str());
            capture.record(invocation, &step_verdict, "", &error.detail)?;
            return Err(XtaskError::controlled_harness(error));
        },
    };
    if !verdict.status.success() {
        let step_verdict = format!("exit-status:{}", verdict.status);
        capture.record(
            invocation,
            &step_verdict,
            "",
            &bounded_stream_summary(&verdict.output.stderr),
        )?;
        return Err(XtaskError::command(
            display,
            format!(
                "exit status {}: stderr={}",
                verdict.status,
                one_line(&verdict.output.stderr)
            ),
        ));
    }
    let summary = validate_dependency_metadata_artifact(root, &artifact)?;
    capture.record(
        invocation,
        &format!("exit-status:{}", verdict.status),
        &summary,
        &bounded_stream_summary(&verdict.output.stderr),
    )?;
    Ok(CommandOutcome {
        display,
        stdout: summary,
        stderr: bounded_stream_summary(&verdict.output.stderr),
    })
}

fn bounded_stream_summary(stream: &str) -> String {
    let one_line = one_line(stream);
    one_line
        .chars()
        .take(MAXIMUM_GATE_DETAIL_CHARACTERS)
        .collect()
}

struct DependencyMetadataArtifact {
    root: DirectoryCapability,
    target: DirectoryCapability,
    quality: DirectoryCapability,
    metadata: DirectoryCapability,
    attempt: DirectoryCapability,
    file: FileCapability,
    attempt_id: String,
}

impl DependencyMetadataArtifact {
    fn diagnostic_path(&self) -> &Path {
        self.file.diagnostic_path()
    }

    fn artifact_output(&self) -> Result<crate::controlled_execution::ArtifactOutput, XtaskError> {
        self.file.artifact_output()
    }

    fn require_canonical_names(&self) -> Result<(), XtaskError> {
        self.root.require_child_directory_identity(
            "target",
            self.target.identity()?,
            "dependency metadata directory",
        )?;
        self.target.require_child_directory_identity(
            "quality",
            self.quality.identity()?,
            "dependency metadata directory",
        )?;
        self.quality.require_child_directory_identity(
            "dependency-metadata",
            self.metadata.identity()?,
            "dependency metadata directory",
        )?;
        self.metadata.require_child_directory_identity(
            &self.attempt_id,
            self.attempt.identity()?,
            "dependency metadata directory",
        )?;
        self.attempt.require_child_file_identity(
            "metadata.json",
            self.file.identity(),
            "dependency metadata artifact",
        )
    }
}

fn prepare_dependency_metadata_artifact(
    root: &Path,
    attempt_id: &str,
) -> Result<DependencyMetadataArtifact, XtaskError> {
    let root = DirectoryCapability::open(root, "dependency metadata workspace root")?;
    let target = root.open_or_create_child_directory("target", "dependency metadata target")?;
    let quality =
        target.open_or_create_child_directory("quality", "dependency metadata quality")?;
    let metadata = quality
        .open_or_create_child_directory("dependency-metadata", "dependency metadata parent")?;
    let attempt =
        metadata.create_child_directory(attempt_id, "attempt-owned dependency metadata")?;
    let file =
        attempt.create_file_capability("metadata.json", "attempt-owned dependency metadata")?;
    attempt.sync()?;
    Ok(DependencyMetadataArtifact {
        root,
        target,
        quality,
        metadata,
        attempt,
        file,
        attempt_id: attempt_id.to_owned(),
    })
}

fn validate_dependency_metadata_artifact(
    root: &Path,
    artifact: &DependencyMetadataArtifact,
) -> Result<String, XtaskError> {
    artifact.require_canonical_names()?;
    let path = artifact.diagnostic_path();
    let bytes = artifact
        .file
        .read_bounded(MAXIMUM_RAW_REPORT_BYTES, "dependency metadata artifact")?;
    let expected_bytes = bytes.len();
    if expected_bytes == 0 || expected_bytes > MAXIMUM_RAW_REPORT_BYTES {
        return Err(XtaskError::invalid(
            "dependency metadata artifact",
            format!("cargo metadata output must contain 1..={MAXIMUM_RAW_REPORT_BYTES} bytes"),
        ));
    }
    let mut digest = Sha256::new();
    for chunk in bytes.chunks(8_192) {
        digest.update(chunk);
    }
    let content = std::str::from_utf8(&bytes).map_err(|_| {
        XtaskError::invalid(
            "dependency metadata artifact",
            "cargo metadata is not UTF-8",
        )
    })?;
    let mut document = bounded_json::parse_with_maximum_bytes(content, MAXIMUM_RAW_REPORT_BYTES)
        .map_err(|error| XtaskError::invalid("dependency metadata artifact", error.to_string()))?
        .into_object("cargo metadata")
        .map_err(|error| XtaskError::invalid("dependency metadata artifact", error.to_string()))?;
    for (field, expected) in [
        ("packages", "array"),
        ("workspace_members", "array"),
        ("workspace_root", "string"),
        ("target_directory", "string"),
        ("resolve", "object"),
    ] {
        let value = bounded_json::take_required(&mut document, field).map_err(|error| {
            XtaskError::invalid("dependency metadata artifact", error.to_string())
        })?;
        let valid = matches!(
            (expected, value),
            ("array", bounded_json::JsonValue::Array(_))
                | ("string", bounded_json::JsonValue::String(_))
                | ("object", bounded_json::JsonValue::Object(_))
        );
        if !valid {
            return Err(XtaskError::invalid(
                "dependency metadata artifact",
                format!("cargo metadata field `{field}` is not a {expected}"),
            ));
        }
    }
    artifact.require_canonical_names()?;
    artifact.attempt.sync()?;
    let digest = format!("sha256:{:x}", digest.finalize());
    Ok(format!(
        "metadata-artifact={}; identity={}; bytes={}; digest={digest}; packages+workspace+resolve=validated",
        path.strip_prefix(root)
            .map_err(|_| XtaskError::invalid_path(path, "metadata artifact escaped workspace"))?
            .display(),
        artifact.file.identity().token(),
        expected_bytes,
    ))
}

fn run_documentation_gate(
    root: &Path,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    validate_local_markdown_links(root)?;
    let target = documentation_target_directory(environment)?;
    fs::create_dir(&target)
        .map_err(|source| XtaskError::io(format!("create {}", target.display()), source))?;
    let target_value = target.as_os_str().to_str().ok_or_else(|| {
        XtaskError::invalid_path(&target, "temporary documentation target is not valid UTF-8")
    })?;
    let deadline = Instant::now() + budget;
    let outcome = run_status_with_options(
        root,
        environment,
        "cargo",
        [
            "doc",
            "--locked",
            "--workspace",
            "--all-features",
            "--no-deps",
            "--document-private-items",
        ],
        StatusOptions {
            timeout: remaining(deadline)?,
            environment: &[
                ("RUSTDOCFLAGS", "-D warnings"),
                ("CARGO_TARGET_DIR", target_value),
            ],
            capture,
        },
    )
    .and_then(|outcome| {
        scan_generated_rustdoc_secrets(root, environment, &target, remaining(deadline)?, capture)
            .map(|scan| (outcome, scan))
    });
    let cleanup = fs::remove_dir_all(&target)
        .map_err(|source| XtaskError::io(format!("remove {}", target.display()), source));
    match (outcome, cleanup) {
        (Ok((outcome, scan)), Ok(())) => Ok(format!(
            "internal:local-link-check | {} | {scan}",
            outcome.display
        )),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(error), Err(cleanup)) => Err(XtaskError::invalid(
            "documentation gate",
            format!("{error}; cleanup also failed: {cleanup}"),
        )),
    }
}

fn documentation_target_directory(
    environment: &EnvironmentSnapshot,
) -> Result<PathBuf, XtaskError> {
    let nonce = unix_time_ms()?;
    Ok(environment.temporary_root().join(format!(
        "positron-quality-doc-{}-{nonce}",
        std::process::id()
    )))
}

fn scan_generated_rustdoc_secrets(
    root: &Path,
    environment: &EnvironmentSnapshot,
    target: &Path,
    budget: Duration,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let documentation_root = target.join("doc");
    if !documentation_root.is_dir() {
        return Err(XtaskError::invalid_path(
            &documentation_root,
            "rustdoc did not produce a generated documentation directory",
        ));
    }
    let documentation_value = documentation_root.as_os_str().to_str().ok_or_else(|| {
        XtaskError::invalid_path(
            &documentation_root,
            "generated documentation directory is not valid UTF-8",
        )
    })?;
    let outcome = run_status(
        root,
        environment,
        "gitleaks",
        [
            "dir",
            "--no-banner",
            "--no-color",
            "--redact=100",
            "--max-target-megabytes=20",
            documentation_value,
        ],
        budget,
        capture,
    )?;
    Ok(format!(
        "{}; full generated rustdoc root scanned without exclusions",
        outcome.display
    ))
}

fn run_error_policy_gate(root: &Path, registry: &Registry) -> Result<String, XtaskError> {
    scan_active_application_sources(
        root,
        registry,
        &[
            (".unwrap(", "unwrap is forbidden in production paths"),
            (".expect(", "expect is forbidden in production paths"),
            ("panic!(", "panic is forbidden in production paths"),
            ("todo!(", "todo is forbidden in production paths"),
            (
                "unimplemented!(",
                "unimplemented is forbidden in production paths",
            ),
            (
                "unreachable!(",
                "unreachable is forbidden in production paths",
            ),
            (
                "let _ =",
                "ignored results are forbidden in production paths",
            ),
            (
                "#[allow(",
                "blanket or unregistered lint allowances are forbidden",
            ),
        ],
    )?;
    let scope_state = if registry.has_active_application_scope() {
        "active application scopes scanned"
    } else {
        "scaffold-only application scopes structurally constrained"
    };
    Ok(format!(
        "internal:closed-error-and-panic-policy scan; {scope_state}"
    ))
}

fn run_evidence_gate(root: &Path, registry: &Registry) -> Result<String, XtaskError> {
    let path = root.join("qualification/engineering/evidence.schema.json");
    let schema = fs::read_to_string(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    validate_evidence_schema_document(&path, &schema)?;
    validate_retained_engineering_evidence(root, registry)?;
    if registry.gates.len() != 25 {
        return Err(XtaskError::invalid(
            "evidence gate set",
            "every attempt must report all 25 registered gates",
        ));
    }
    Ok("internal:evidence-schema-complete-gate-set-and-retained-report validation".to_owned())
}

#[derive(Debug)]
struct ParsedRawReportBinding {
    applicability: String,
    path: String,
    digest: String,
    bytes: usize,
    reason: String,
}

#[derive(Debug)]
struct ParsedGateRecord {
    gate_id: String,
    result: String,
    budget_seconds: u64,
    command_digest: String,
    typed_invocation: GateInvocation,
    invocation: bounded_json::JsonValue,
    controlled_steps: Vec<bounded_json::JsonValue>,
    owner: ParsedIdentityBinding,
    raw_report: ParsedRawReportBinding,
}

#[derive(Debug)]
struct ParsedEvidenceRecord {
    attempt_id: String,
    collision_of: ParsedIdentityBinding,
    collision_slots: ParsedIdentityBinding,
    profile: Profile,
    registry_digest: String,
    environment_digest: String,
    gates: Vec<ParsedGateRecord>,
}

#[derive(Debug)]
struct ParsedIdentityBinding {
    applicability: String,
    value: String,
    reason: String,
}

struct ParsedGateInvocation {
    typed: GateInvocation,
    controlled_steps: Vec<bounded_json::JsonValue>,
}

#[derive(Clone, Copy)]
enum RetainedDocumentKind {
    Evidence,
    RawReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExceptionalAttemptMode {
    Collision,
    Recovery,
}

fn retained_exceptional_mode(
    collision_of: &ParsedIdentityBinding,
    collision_slots: &ParsedIdentityBinding,
    path: &Path,
) -> Result<Option<ExceptionalAttemptMode>, XtaskError> {
    match (
        collision_of.applicability.as_str(),
        collision_slots.applicability.as_str(),
        collision_slots.value.as_str(),
    ) {
        ("not-applicable", "not-applicable", "-") => Ok(None),
        ("exact", "exact", "recovery") => Ok(Some(ExceptionalAttemptMode::Recovery)),
        ("exact", "exact", value)
            if value.starts_with("collision-") || value == COLLISION_OCCUPIED_SET =>
        {
            Ok(Some(ExceptionalAttemptMode::Collision))
        },
        _ => invalid_json(
            path,
            "retained collision identity does not name a canonical attempt mode",
        ),
    }
}

impl RetainedDocumentKind {
    fn maximum_bytes(self) -> usize {
        match self {
            Self::Evidence => MAXIMUM_RETAINED_EVIDENCE_BYTES,
            Self::RawReport => MAXIMUM_RAW_REPORT_BYTES,
        }
    }
}

fn validate_registered_gate_bindings(
    evidence: &ParsedEvidenceRecord,
    registry: &Registry,
    path: &Path,
) -> Result<(), XtaskError> {
    let registry_available = evidence.registry_digest != "invalid-registry"
        && evidence.registry_digest != "unavailable-registry-digest";
    let exceptional_mode =
        retained_exceptional_mode(&evidence.collision_of, &evidence.collision_slots, path)?;
    let activated_risk_gates = registry.activated_risk_gates();
    let expected_environment_digest = sha256_digest(evidence.environment_digest.as_bytes());

    for retained in &evidence.gates {
        let registered = registry
            .gates
            .iter()
            .find(|gate| gate.id == retained.gate_id)
            .ok_or_else(|| {
                XtaskError::invalid_path(
                    path,
                    format!(
                        "retained gate `{}` has no canonical registry entry",
                        retained.gate_id
                    ),
                )
            })?;
        if !registry_available {
            validate_pre_registry_gate_binding(retained, &expected_environment_digest, path)?;
            continue;
        }

        let expected_arguments = if let Some(mode) = exceptional_mode {
            let aggregator = retained.gate_id == "EG-00";
            let mode_argument = match (mode, aggregator) {
                (ExceptionalAttemptMode::Collision, true) => "--collision-retention",
                (ExceptionalAttemptMode::Collision, false) => "--blocked-by-collision",
                (ExceptionalAttemptMode::Recovery, true) => "--report-retention-failure",
                (ExceptionalAttemptMode::Recovery, false) => "--blocked-by-eg-00",
            };
            vec![
                "quality".to_owned(),
                mode_argument.to_owned(),
                retained.gate_id.clone(),
            ]
        } else {
            vec![
                "quality".to_owned(),
                "--profile".to_owned(),
                evidence.profile.as_str().to_owned(),
                "--gate".to_owned(),
                registered.id.clone(),
                "--runner".to_owned(),
                registered.runner.clone(),
            ]
        };
        let expected_result = if exceptional_mode.is_some() {
            if retained.gate_id == "EG-00" {
                "failed"
            } else {
                "not-selected"
            }
        } else if gate_selected(registered, evidence.profile, &activated_risk_gates) {
            if retained.result == "not-selected" {
                return invalid_json(
                    path,
                    format!(
                        "retained gate `{}` is selected by its canonical stage and activation",
                        retained.gate_id
                    ),
                );
            }
            retained.result.as_str()
        } else {
            "not-selected"
        };
        if retained.result != expected_result
            || retained.budget_seconds != registered.timeout_seconds
            || retained.owner.applicability != "exact"
            || retained.owner.value != registered.coordinator
            || retained.owner.reason != "-"
            || retained.typed_invocation.program != "cargo-xtask-quality/internal"
            || retained.typed_invocation.arguments != expected_arguments
            || retained.typed_invocation.working_directory != "engineering-workspace"
            || retained.typed_invocation.environment_digest != expected_environment_digest
            || retained.typed_invocation.timeout_seconds != registered.timeout_seconds
            || retained.typed_invocation.memory_mib != registered.memory_mib
            || retained.typed_invocation.activation != registered.activation
            || retained.typed_invocation.exception_class != registered.exception_class
        {
            return invalid_json(
                path,
                format!(
                    "retained gate `{}` does not match its canonical registered gate invocation",
                    retained.gate_id
                ),
            );
        }
        validate_registered_controlled_steps(
            registered,
            evidence.profile,
            exceptional_mode.is_some() || retained.result == "not-selected",
            retained,
            registry,
            path,
        )?;
    }
    Ok(())
}

fn validate_pre_registry_gate_binding(
    retained: &ParsedGateRecord,
    environment_digest: &str,
    path: &Path,
) -> Result<(), XtaskError> {
    let aggregator = retained.gate_id == "EG-00";
    let expected_arguments = vec![
        "quality".to_owned(),
        if aggregator {
            "--aggregator-failure".to_owned()
        } else {
            "--blocked-by-eg-00".to_owned()
        },
        retained.gate_id.clone(),
    ];
    let owner_is_valid = if aggregator {
        retained.owner.applicability == "exact"
            && retained.owner.value == "Quality Engineering"
            && retained.owner.reason == "-"
    } else {
        retained.owner.applicability == "not-applicable"
            && retained.owner.value == "-"
            && retained.owner.reason == "unavailable-before-registry-validation"
    };
    if retained.result != if aggregator { "failed" } else { "not-selected" }
        || retained.budget_seconds != 60
        || !owner_is_valid
        || retained.typed_invocation.program != "cargo-xtask-quality/internal"
        || retained.typed_invocation.arguments != expected_arguments
        || retained.typed_invocation.working_directory != "engineering-workspace"
        || retained.typed_invocation.environment_digest != environment_digest
        || retained.typed_invocation.timeout_seconds != 60
        || retained.typed_invocation.memory_mib != 256
        || retained.typed_invocation.activation != "always"
        || retained.typed_invocation.exception_class != "none"
        || !retained.typed_invocation.controlled_steps.is_empty()
    {
        return invalid_json(
            path,
            format!(
                "retained pre-registry gate `{}` does not match its closed failure definition",
                retained.gate_id
            ),
        );
    }
    Ok(())
}

fn validate_registered_controlled_steps(
    gate: &Gate,
    profile: Profile,
    must_be_empty: bool,
    retained: &ParsedGateRecord,
    registry: &Registry,
    path: &Path,
) -> Result<(), XtaskError> {
    let retained_result = retained.result.as_str();
    let steps = &retained.typed_invocation.controlled_steps;
    if must_be_empty {
        if steps.is_empty() {
            return Ok(());
        }
        return invalid_json(
            path,
            format!(
                "retained gate `{}` records commands despite not executing",
                gate.id
            ),
        );
    }
    let expected_step_count = canonical_controlled_step_count(gate, profile, registry);
    let cardinality_matches = if expected_step_count == 0 {
        steps.is_empty()
    } else {
        match retained_result {
            "passed" => steps.len() == expected_step_count,
            "failed" => (1..=expected_step_count).contains(&steps.len()),
            _ => false,
        }
    };
    if !cardinality_matches {
        return invalid_json(
            path,
            format!(
                "retained gate `{}` does not contain its exact canonical controlled steps: result {retained_result}, expected {}, found {}",
                gate.id,
                if expected_step_count == 0 {
                    "zero canonical steps".to_owned()
                } else if retained_result == "failed" {
                    format!("a non-empty prefix of {expected_step_count}")
                } else {
                    expected_step_count.to_string()
                },
                steps.len()
            ),
        );
    }
    let maximum_timeout_ms = u128::from(gate.timeout_seconds)
        .checked_mul(1_000)
        .ok_or_else(|| {
            XtaskError::invalid_path(path, "registered gate timeout milliseconds overflow")
        })?;
    for (index, step) in steps.iter().enumerate() {
        let process_backed_runner = matches!(gate.runner.as_str(), "concurrency" | "resource");
        let registered_program = if process_backed_runner {
            step.program == "cargo-xtask-quality/bounded-runner"
        } else {
            registry
                .tools
                .iter()
                .any(|tool| tool.command == step.program)
        };
        let resolved = Path::new(&step.resolved_program);
        let resolved_matches = resolved.is_absolute()
            && if process_backed_runner {
                resolved.file_stem().and_then(OsStr::to_str) == Some("xtask")
            } else {
                resolved.file_name().and_then(OsStr::to_str) == Some(step.program.as_str())
            };
        if !registered_program
            || !resolved_matches
            || step.timeout_ms > maximum_timeout_ms
            || (process_backed_runner && step.timeout_ms != maximum_timeout_ms)
            || step.input_kind != "null"
            || step.input_bytes != 0
            || step.input_sha256 != "-"
            || !registered_runner_command_matches(
                gate.runner.as_str(),
                profile,
                index,
                step,
                registry,
            )
        {
            return invalid_json(
                path,
                format!(
                    "retained gate `{}` controlled step {index} does not match its registered command semantics",
                    gate.id
                ),
            );
        }
    }
    Ok(())
}

fn canonical_controlled_step_count(gate: &Gate, profile: Profile, registry: &Registry) -> usize {
    match gate.runner.as_str() {
        "registry" => registry
            .tools
            .iter()
            .filter(|tool| {
                tool_required(tool.required_profiles.iter().map(String::as_str), profile)
            })
            .count(),
        "architecture" => registry.scopes.len(),
        "build" => {
            if matches!(profile, Profile::Ext | Profile::Qual) {
                5
            } else {
                1
            }
        },
        "coverage" => {
            1 + usize::from(registry.has_m0_02_domain_types_scope())
                + (2 * usize::from(registry.has_m0_01_foundational_scope()))
                + usize::from(registry.has_m0_03_canonical_api_scope())
                + usize::from(registry.has_m0_04_configuration_scope())
        },
        "dynamic-analysis" => 2,
        "dependencies" => 3,
        "documentation" | "rust" | "test" => 2,
        "correctness" => 0,
        "fault" => 0,
        "integrity" => 0,
        "safety" => usize::from(registry.has_m0_04_configuration_scope()),
        "security" => 1,
        "secrets" | "supply" => {
            if matches!(profile, Profile::Ext | Profile::Qual) {
                2
            } else {
                1
            }
        },
        "concurrency" | "resource" => 1,
        "crypto" | "error-policy" | "evidence" | "matrix" | "performance" | "policy" | "soak" => 0,
        _ => 0,
    }
}

fn registered_runner_command_matches(
    runner: &str,
    profile: Profile,
    index: usize,
    step: &ControlledInvocation,
    registry: &Registry,
) -> bool {
    let program = step.program.as_str();
    let args = step
        .arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    match runner {
        "registry" => registry
            .tools
            .iter()
            .filter(|tool| {
                tool_required(tool.required_profiles.iter().map(String::as_str), profile)
            })
            .nth(index)
            .is_some_and(|tool| {
                tool.command == program
                    && tool
                        .version_arguments
                        .iter()
                        .map(String::as_str)
                        .eq(args.iter().copied())
            }),
        "architecture" => {
            program == "cargo"
                && args.len() == 12
                && args.first() == Some(&"tree")
                && args.get(1) == Some(&"--locked")
                && args.get(2) == Some(&"--package")
                && args.get(3).copied()
                    == registry
                        .scopes
                        .get(index)
                        .map(|scope| scope.package.as_str())
                && args.get(4..)
                    == Some(
                        [
                            "--depth",
                            "1",
                            "--edges",
                            "normal,build",
                            "--prefix",
                            "none",
                            "--format",
                            "{p}",
                        ]
                        .as_slice(),
                    )
        },
        "build" => match index {
            0 => {
                program == "cargo"
                    && args
                        == [
                            "check",
                            "--locked",
                            "--workspace",
                            "--all-targets",
                            "--all-features",
                        ]
            },
            1..=4 if matches!(profile, Profile::Ext | Profile::Qual) => {
                let targets = [
                    "aarch64-apple-darwin",
                    "aarch64-unknown-linux-gnu",
                    "x86_64-apple-darwin",
                    "x86_64-unknown-linux-gnu",
                ];
                program == "cargo"
                    && index
                        .checked_sub(1)
                        .and_then(|target_index| targets.get(target_index))
                        .is_some_and(|target| {
                            args == [
                                "check",
                                "--locked",
                                "--workspace",
                                "--all-targets",
                                "--all-features",
                                "--target",
                                *target,
                            ]
                        })
            },
            _ => false,
        },
        "dependencies" => registered_dependency_command_matches(index, program, &args),
        "documentation" => match index {
            0 => {
                program == "cargo"
                    && args
                        == [
                            "doc",
                            "--locked",
                            "--workspace",
                            "--all-features",
                            "--no-deps",
                            "--document-private-items",
                        ]
            },
            1 => {
                program == "gitleaks"
                    && args.starts_with(&[
                        "dir",
                        "--no-banner",
                        "--no-color",
                        "--redact=100",
                        "--max-target-megabytes=20",
                    ])
                    && args.len() == 6
            },
            _ => false,
        },
        "rust" => match index {
            0 => program == "cargo" && args == ["fmt", "--all", "--", "--check"],
            1 => {
                program == "cargo"
                    && args
                        == [
                            "clippy",
                            "--locked",
                            "--workspace",
                            "--all-targets",
                            "--all-features",
                            "--",
                            "-D",
                            "warnings",
                        ]
            },
            _ => false,
        },
        "safety" | "security" => {
            index == 0
                && program == "cargo"
                && args
                    == [
                        "test",
                        "--locked",
                        "--package",
                        "positron-config",
                        "--test",
                        "configuration_foundation",
                        "preflight_",
                    ]
        },
        "secrets" => match index {
            0 => {
                program == "gitleaks"
                    && args
                        == [
                            "dir",
                            "--no-banner",
                            "--no-color",
                            "--redact=100",
                            "--max-target-megabytes=20",
                            ".",
                        ]
            },
            1 if matches!(profile, Profile::Ext | Profile::Qual) => {
                program == "gitleaks"
                    && args
                        == [
                            "git",
                            "--no-banner",
                            "--no-color",
                            "--redact=100",
                            "--log-opts=--all",
                            ".",
                        ]
            },
            _ => false,
        },
        "supply" => match index {
            0 => program == "cargo" && args == ["audit", "--deny", "warnings"],
            1 if matches!(profile, Profile::Ext | Profile::Qual) => {
                program == "cargo" && args == ["vet", "--locked"]
            },
            _ => false,
        },
        "test" => match index {
            0 => program == "cargo" && args == NEXTEST_PR_ARGUMENTS,
            1 => {
                program == "cargo"
                    && args == ["test", "--locked", "--workspace", "--doc", "--all-features"]
            },
            _ => false,
        },
        "dynamic-analysis" => match index {
            0 => {
                program == "cargo"
                    && args
                        == [
                            "test",
                            "--locked",
                            "--package",
                            "positron-domain",
                            "--test",
                            "foundational_domain_types",
                        ]
            },
            1 => {
                program == "cargo"
                    && args == ["test", "--locked", "--package", "positron-domain", "--doc"]
            },
            _ => false,
        },
        "coverage" => {
            program == "cargo"
                && args.first() == Some(&"+nightly-2026-07-20")
                && args.get(1) == Some(&"llvm-cov")
        },
        "concurrency" => index == 0
            && program == "cargo-xtask-quality/bounded-runner"
            && crate::bounded_runners::FrozenBoundedRunnerRegistry::retained_child_invocation_matches(
                "EG-CONCURRENCY",
                step.timeout_ms,
                &args,
            ),
        "resource" => index == 0
            && program == "cargo-xtask-quality/bounded-runner"
            && crate::bounded_runners::FrozenBoundedRunnerRegistry::retained_child_invocation_matches(
                "EG-RESOURCE",
                step.timeout_ms,
                &args,
            ),
        "correctness" | "crypto" | "error-policy" | "evidence" | "fault" | "integrity"
        | "matrix" | "performance" | "policy" | "soak" => false,
        _ => false,
    }
}

fn registered_dependency_command_matches(index: usize, program: &str, args: &[&str]) -> bool {
    match index {
        0 => program == "cargo" && args == ["metadata", "--locked", "--format-version", "1"],
        1 => program == "cargo-machete" && args == ["--with-metadata", "--skip-target-dir", "."],
        2 => program == "cargo" && args == ["deny", "check", "bans", "licenses", "sources"],
        _ => false,
    }
}

fn validate_retained_engineering_evidence(
    root: &Path,
    registry: &Registry,
) -> Result<(), XtaskError> {
    let directory = root.join("target/quality/evidence");
    if !directory.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(&directory)
        .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
    let mut attempt_count = 0_usize;
    let mut retained_attempts = BTreeSet::new();
    let mut v3_attempts = BTreeSet::new();
    let mut expected_reports = BTreeSet::new();
    for entry in entries {
        let entry = entry
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        let path = entry.path();
        attempt_count = attempt_count.checked_add(1).ok_or_else(|| {
            XtaskError::invalid_path(&directory, "retained attempt count overflowed")
        })?;
        if attempt_count > MAXIMUM_RETAINED_ATTEMPTS {
            return Err(XtaskError::invalid_path(
                &directory,
                format!("retained attempt count exceeds {MAXIMUM_RETAINED_ATTEMPTS}"),
            ));
        }
        let file_type = entry.file_type().map_err(|source| {
            XtaskError::io(
                format!("inspect retained evidence {}", path.display()),
                source,
            )
        })?;
        if !file_type.is_file() || path.extension().and_then(OsStr::to_str) != Some("json") {
            return Err(XtaskError::invalid_path(
                &path,
                "retained evidence directory entry must be a regular JSON file",
            ));
        }
        let Some(attempt_id) = path.file_stem().and_then(OsStr::to_str) else {
            return Err(XtaskError::invalid_path(
                &path,
                "retained evidence filename is not valid UTF-8",
            ));
        };
        if !valid_owned_evidence_component(attempt_id) {
            return Err(XtaskError::invalid_path(
                &path,
                "retained evidence filename is not attempt-owned",
            ));
        }
        retained_attempts.insert(attempt_id.to_owned());
        let metadata = fs::metadata(&path)
            .map_err(|source| XtaskError::io(format!("inspect {}", path.display()), source))?;
        if metadata.len() > MAXIMUM_RETAINED_EVIDENCE_BYTES as u64 {
            return Err(XtaskError::invalid_path(
                &path,
                format!(
                    "retained engineering evidence exceeds {MAXIMUM_RETAINED_EVIDENCE_BYTES} bytes"
                ),
            ));
        }
        let evidence = fs::read_to_string(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        let (schema_version, recorded_attempt) = parse_retained_evidence_header(&path, &evidence)
            .map_err(|error| {
            XtaskError::invalid_path(
                &path,
                format!("retained engineering evidence is invalid: {error}"),
            )
        })?;
        match schema_version {
            1 | 2 => {},
            3 => {
                if recorded_attempt != attempt_id {
                    return Err(XtaskError::invalid_path(
                        &path,
                        "retained evidence attempt_id does not match its owned filename",
                    ));
                }
                let reports = validate_retained_v3_reports(root, registry, &path, &evidence)
                    .map_err(|error| {
                        XtaskError::invalid_path(
                            &path,
                            format!("retained engineering evidence is invalid: {error}"),
                        )
                    })?;
                v3_attempts.insert(recorded_attempt);
                expected_reports.extend(reports);
            },
            _ => {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "unsupported retained evidence schema version `{schema_version}`; only legacy versions 1/2 and current version 3 are accepted"
                    ),
                ));
            },
        }
    }
    if let Some(recovery) = retained_attempts.iter().find(|attempt| {
        attempt
            .strip_suffix("-recovery")
            .is_some_and(|primary| retained_attempts.contains(primary))
    }) {
        return Err(XtaskError::invalid_path(
            &directory.join(format!("{recovery}.json")),
            "primary evidence and its authoritative recovery marker coexist",
        ));
    }
    let actual_reports = enumerate_retained_raw_reports(root, &v3_attempts)?;
    if let Some(orphan) = actual_reports.difference(&expected_reports).next() {
        return Err(XtaskError::invalid_path(
            orphan,
            "orphan retained raw report is not bound by current schema-v3 evidence",
        ));
    }
    if let Some(missing) = expected_reports.difference(&actual_reports).next() {
        return Err(XtaskError::invalid_path(
            missing,
            "retained raw report is missing",
        ));
    }
    Ok(())
}

fn parse_retained_evidence_header(
    path: &Path,
    evidence: &str,
) -> Result<(u128, String), XtaskError> {
    let mut object = parse_object(path, evidence, "retained engineering evidence")?;
    let schema_version = require_any_integer(&mut object, "schema_version", path)?;
    let attempt_id = require_string(&mut object, "attempt_id", path)?;
    Ok((schema_version, attempt_id))
}

fn validate_retained_v3_reports(
    root: &Path,
    registry: &Registry,
    evidence_path: &Path,
    evidence: &str,
) -> Result<BTreeSet<PathBuf>, XtaskError> {
    let parsed = parse_evidence_record(evidence_path, evidence)?;
    validate_registered_gate_bindings(&parsed, registry, evidence_path)?;
    let mut expected_reports = BTreeSet::new();
    for gate in parsed.gates {
        if gate.raw_report.applicability == "not-applicable" {
            continue;
        }
        let expected_relative = raw_report_relative_path(&parsed.attempt_id, &gate.gate_id);
        let relative_path = Path::new(&gate.raw_report.path);
        if gate.raw_report.path != expected_relative
            || relative_path.is_absolute()
            || !relative_path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err(XtaskError::invalid_path(
                evidence_path,
                format!(
                    "retained gate `{}` raw_report path is not attempt-owned",
                    gate.gate_id
                ),
            ));
        }
        let report_path = root.join(relative_path);
        expected_reports.insert(report_path.clone());
        if !report_path.is_file() {
            return Err(XtaskError::invalid_path(
                &report_path,
                "retained raw report is missing",
            ));
        }
        let report_metadata = fs::metadata(&report_path).map_err(|source| {
            XtaskError::io(format!("inspect {}", report_path.display()), source)
        })?;
        if report_metadata.len() != gate.raw_report.bytes as u64 {
            if report_metadata.len() > MAXIMUM_RAW_REPORT_BYTES as u64 {
                return Err(XtaskError::invalid_path(
                    &report_path,
                    format!("retained raw report exceeds {MAXIMUM_RAW_REPORT_BYTES} bytes"),
                ));
            }
            return Err(XtaskError::invalid_path(
                &report_path,
                "retained raw report byte length does not match its evidence binding",
            ));
        }
        let report = fs::read(&report_path)
            .map_err(|source| XtaskError::io(format!("read {}", report_path.display()), source))?;
        if sha256_digest(&report) != gate.raw_report.digest {
            return Err(XtaskError::invalid_path(
                &report_path,
                "retained raw report digest does not match its evidence binding",
            ));
        }
        let report = String::from_utf8(report).map_err(|_| {
            XtaskError::invalid_path(&report_path, "retained raw report is not valid UTF-8 JSON")
        })?;
        let parsed_report = parse_raw_report_record(&report_path, &report)?;
        if parsed_report.invocation_digest != gate.command_digest {
            return Err(XtaskError::invalid_path(
                &report_path,
                "raw report invocation digest does not match its evidence command digest",
            ));
        }
        if parsed_report.attempt_id != parsed.attempt_id
            || parsed_report.gate_id != gate.gate_id
            || parsed_report.result != gate.result
            || parsed_report.invocation != gate.invocation
            || parsed_report.controlled_steps != gate.controlled_steps
        {
            return Err(XtaskError::invalid_path(
                &report_path,
                "raw report fields do not exactly cross-reference their evidence gate",
            ));
        }
    }
    Ok(expected_reports)
}

fn enumerate_retained_raw_reports(
    root: &Path,
    v3_attempts: &BTreeSet<String>,
) -> Result<BTreeSet<PathBuf>, XtaskError> {
    let directory = root.join("target/quality/evidence-reports");
    if !directory.exists() {
        return Ok(BTreeSet::new());
    }
    let attempts = fs::read_dir(&directory)
        .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
    let mut attempt_count = 0_usize;
    let mut reports = BTreeSet::new();
    for attempt in attempts {
        let attempt = attempt
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        let attempt_path = attempt.path();
        attempt_count = attempt_count.checked_add(1).ok_or_else(|| {
            XtaskError::invalid_path(&directory, "retained report attempt count overflowed")
        })?;
        if attempt_count > MAXIMUM_RETAINED_ATTEMPTS {
            return Err(XtaskError::invalid_path(
                &directory,
                format!("retained report attempt count exceeds {MAXIMUM_RETAINED_ATTEMPTS}"),
            ));
        }
        let file_type = attempt.file_type().map_err(|source| {
            XtaskError::io(
                format!("inspect retained report {}", attempt_path.display()),
                source,
            )
        })?;
        let Some(attempt_id) = attempt.file_name().to_str().map(str::to_owned) else {
            return Err(XtaskError::invalid_path(
                &attempt_path,
                "retained report attempt path is not valid UTF-8",
            ));
        };
        if !file_type.is_dir()
            || !valid_owned_evidence_component(&attempt_id)
            || !v3_attempts.contains(&attempt_id)
        {
            return Err(XtaskError::invalid_path(
                &attempt_path,
                "orphan retained raw report attempt directory is not bound by current schema-v3 evidence",
            ));
        }
        let entries = fs::read_dir(&attempt_path)
            .map_err(|source| XtaskError::io(format!("read {}", attempt_path.display()), source))?;
        let mut report_count = 0_usize;
        for entry in entries {
            let entry = entry.map_err(|source| {
                XtaskError::io(format!("read {}", attempt_path.display()), source)
            })?;
            let report_path = entry.path();
            report_count = report_count.checked_add(1).ok_or_else(|| {
                XtaskError::invalid_path(&attempt_path, "retained report count overflowed")
            })?;
            if report_count > MAXIMUM_REPORTS_PER_ATTEMPT {
                return Err(XtaskError::invalid_path(
                    &attempt_path,
                    format!(
                        "retained report count exceeds {MAXIMUM_REPORTS_PER_ATTEMPT} per attempt"
                    ),
                ));
            }
            let file_type = entry.file_type().map_err(|source| {
                XtaskError::io(
                    format!("inspect retained report {}", report_path.display()),
                    source,
                )
            })?;
            let gate_id = report_path
                .file_stem()
                .and_then(OsStr::to_str)
                .filter(|_| report_path.extension().and_then(OsStr::to_str) == Some("json"));
            if !file_type.is_file()
                || gate_id.is_none_or(|gate_id| !CANONICAL_GATE_IDS.contains(&gate_id))
            {
                return Err(XtaskError::invalid_path(
                    &report_path,
                    "orphan retained raw report path is not a canonical gate JSON file",
                ));
            }
            reports.insert(report_path);
        }
    }
    Ok(reports)
}

fn valid_owned_evidence_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug)]
struct ParsedRawReportRecord {
    attempt_id: String,
    gate_id: String,
    result: String,
    invocation_digest: String,
    invocation: bounded_json::JsonValue,
    controlled_steps: Vec<bounded_json::JsonValue>,
}

fn parse_evidence_record(path: &Path, content: &str) -> Result<ParsedEvidenceRecord, XtaskError> {
    let mut object = parse_object(path, content, "engineering evidence")?;
    require_integer(&mut object, "schema_version", path, 3)?;
    let attempt_id = require_string(&mut object, "attempt_id", path)?;
    require_character_bound(
        &attempt_id,
        1,
        MAXIMUM_ATTEMPT_ID_CHARACTERS,
        path,
        "attempt_id",
    )?;
    let collision_of =
        parse_identity_binding(take_value(&mut object, "collision_of", path)?, path)?;
    let collision_slots =
        parse_identity_binding(take_value(&mut object, "collision_slots", path)?, path)?;
    let profile = require_string(&mut object, "profile", path)?;
    let profile = Profile::parse(&profile)
        .map_err(|_| XtaskError::invalid_path(path, "profile has an invalid value"))?;
    let result = require_string(&mut object, "result", path)?;
    if !matches!(result.as_str(), "passed" | "failed") {
        return invalid_json(path, "aggregate result has an invalid value");
    }
    let merge_eligible = require_boolean(&mut object, "merge_eligible", path)?;
    let mut source = require_object(&mut object, "source", path)?;
    let revision = require_string(&mut source, "revision", path)?;
    if !valid_hex_identity(&revision) {
        return invalid_json(
            path,
            "source revision is not a complete hexadecimal identity",
        );
    }
    require_boolean(&mut source, "dirty", path)?;
    require_boolean(&mut source, "trusted_ci", path)?;
    reject_unknown(source, path, "source")?;
    let started = require_any_integer(&mut object, "started_unix_ms", path)?;
    let ended = require_any_integer(&mut object, "ended_unix_ms", path)?;
    if ended < started {
        return invalid_json(path, "evidence end time precedes its start time");
    }
    let registry_digest = require_string(&mut object, "registry_digest", path)?;
    if !valid_registry_digest(&registry_digest) {
        return invalid_json(path, "`registry_digest` is invalid");
    }
    let environment_digest = require_string(&mut object, "environment_digest", path)?;
    if !valid_registry_digest(&environment_digest) {
        return invalid_json(path, "`environment_digest` is invalid");
    }
    validate_evidence_identity_object(require_object(&mut object, "identity", path)?, path)?;
    let gates = require_array(&mut object, "gates", path)?;
    reject_unknown(object, path, "engineering evidence")?;
    if gates.len() != CANONICAL_GATE_IDS.len() {
        return invalid_json(path, "evidence must contain exactly 25 gates");
    }
    let mut parsed_gates = Vec::with_capacity(gates.len());
    let mut gate_ids = BTreeSet::new();
    for gate in gates {
        let gate = parse_gate_record(gate, path)?;
        if !gate_ids.insert(gate.gate_id.clone()) {
            return invalid_json(path, format!("duplicate gate `{}`", gate.gate_id));
        }
        parsed_gates.push(gate);
    }
    let canonical = CANONICAL_GATE_IDS.into_iter().map(str::to_owned).collect();
    if gate_ids != canonical {
        return invalid_json(path, "gate identities do not match the canonical set");
    }
    let any_failed = parsed_gates.iter().any(|gate| gate.result == "failed");
    if (result == "failed") != any_failed || (merge_eligible && result != "passed") {
        return invalid_json(
            path,
            "aggregate result does not match independent gate verdicts",
        );
    }
    Ok(ParsedEvidenceRecord {
        attempt_id,
        collision_of,
        collision_slots,
        profile,
        registry_digest,
        environment_digest,
        gates: parsed_gates,
    })
}

fn parse_gate_record(
    value: bounded_json::JsonValue,
    path: &Path,
) -> Result<ParsedGateRecord, XtaskError> {
    let mut object = value
        .into_object("gate")
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))?;
    let gate_id = require_string(&mut object, "gate_id", path)?;
    let result = require_string(&mut object, "result", path)?;
    if !matches!(result.as_str(), "passed" | "failed" | "not-selected") {
        return invalid_json(path, format!("gate `{gate_id}` has an invalid result"));
    }
    let duration = require_any_integer(&mut object, "duration_ms", path)?;
    if result == "not-selected" && duration != 0 {
        return invalid_json(
            path,
            format!("not-selected gate `{gate_id}` reports execution time"),
        );
    }
    let budget_seconds = u64::try_from(require_any_integer(&mut object, "budget_seconds", path)?)
        .map_err(|_| XtaskError::invalid_path(path, "gate budget exceeds u64"))?;
    if budget_seconds == 0 {
        return invalid_json(path, format!("gate `{gate_id}` has a zero budget"));
    }
    let invocation = take_value(&mut object, "invocation", path)?;
    let parsed_invocation = parse_gate_invocation_value(invocation.clone(), path)?;
    let recorded_command_digest = require_string(&mut object, "command_digest", path)?;
    if !valid_sha256_digest(&recorded_command_digest) {
        return invalid_json(
            path,
            format!("gate `{gate_id}` has an invalid command digest"),
        );
    }
    if recorded_command_digest != command_digest(&parsed_invocation.typed) {
        return invalid_json(
            path,
            format!(
                "gate `{gate_id}` command digest does not match its canonical structured invocation"
            ),
        );
    }
    let owner = parse_identity_binding(take_value(&mut object, "owner", path)?, path)?;
    let raw_report = parse_raw_report_binding(take_value(&mut object, "raw_report", path)?, path)?;
    let detail = require_string(&mut object, "detail", path)?;
    require_character_bound(
        &detail,
        1,
        MAXIMUM_GATE_DETAIL_CHARACTERS,
        path,
        "gate detail",
    )?;
    reject_unknown(object, path, "gate")?;
    match (result.as_str(), raw_report.applicability.as_str()) {
        ("not-selected", "not-applicable") if raw_report.reason == "gate-not-selected" => {},
        ("passed" | "failed", "exact") => {},
        ("failed", "not-applicable") if raw_report.reason == "report-encoding-failed" => {},
        ("failed", "not-applicable") if raw_report.reason == "report-retention-failed" => {},
        _ => {
            return invalid_json(
                path,
                format!("gate `{gate_id}` has inconsistent report applicability"),
            );
        },
    }
    Ok(ParsedGateRecord {
        gate_id,
        result,
        budget_seconds,
        command_digest: recorded_command_digest,
        typed_invocation: parsed_invocation.typed,
        invocation,
        controlled_steps: parsed_invocation.controlled_steps,
        owner,
        raw_report,
    })
}

fn parse_gate_invocation_value(
    value: bounded_json::JsonValue,
    path: &Path,
) -> Result<ParsedGateInvocation, XtaskError> {
    let mut object = value
        .into_object("gate invocation")
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))?;
    let program = require_string(&mut object, "program", path)?;
    let argument_values = require_array(&mut object, "arguments", path)?;
    if !(3..=16).contains(&argument_values.len()) {
        return invalid_json(path, "gate invocation arguments are out of bounds");
    }
    let arguments = bounded_string_values(
        argument_values,
        MAXIMUM_GATE_ARGUMENT_CHARACTERS,
        path,
        "gate invocation arguments",
    )?;
    let working_directory = require_string(&mut object, "working_directory", path)?;
    if program != "cargo-xtask-quality/internal" || working_directory != "engineering-workspace" {
        return invalid_json(path, "gate invocation identity is invalid");
    }
    let environment_digest = require_string(&mut object, "environment_digest", path)?;
    if !valid_sha256_digest(&environment_digest) {
        return invalid_json(path, "gate invocation environment digest is invalid");
    }
    let timeout_seconds = u64::try_from(require_any_integer(&mut object, "timeout_seconds", path)?)
        .map_err(|_| XtaskError::invalid_path(path, "gate invocation timeout exceeds u64"))?;
    let memory_mib = u64::try_from(require_any_integer(&mut object, "memory_mib", path)?)
        .map_err(|_| XtaskError::invalid_path(path, "gate invocation memory exceeds u64"))?;
    if timeout_seconds == 0 || memory_mib == 0 {
        return invalid_json(path, "gate invocation budget must be positive");
    }
    let activation = require_string(&mut object, "activation", path)?;
    require_character_bound(
        &activation,
        1,
        MAXIMUM_ACTIVATION_CHARACTERS,
        path,
        "gate invocation activation",
    )?;
    let exception_class = require_string(&mut object, "exception_class", path)?;
    require_character_bound(
        &exception_class,
        1,
        MAXIMUM_EXCEPTION_CLASS_CHARACTERS,
        path,
        "gate invocation exception_class",
    )?;
    let controlled_step_values = require_array(&mut object, "controlled_steps", path)?;
    if controlled_step_values.len() > MAXIMUM_CONTROLLED_REPORT_STEPS {
        return invalid_json(path, "gate invocation contains too many controlled steps");
    }
    let mut controlled_steps = Vec::with_capacity(controlled_step_values.len());
    for step in &controlled_step_values {
        controlled_steps.push(parse_controlled_invocation_value(step.clone(), path)?);
    }
    reject_unknown(object, path, "gate invocation")?;
    Ok(ParsedGateInvocation {
        typed: GateInvocation {
            program,
            arguments,
            working_directory,
            environment_digest,
            timeout_seconds,
            memory_mib,
            activation,
            exception_class,
            controlled_steps,
        },
        controlled_steps: controlled_step_values,
    })
}

fn parse_controlled_invocation_value(
    value: bounded_json::JsonValue,
    path: &Path,
) -> Result<ControlledInvocation, XtaskError> {
    let mut object = value
        .into_object("controlled invocation")
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))?;
    let program = require_string(&mut object, "program", path)?;
    require_character_bound(
        &program,
        1,
        MAXIMUM_CONTROLLED_PROGRAM_CHARACTERS,
        path,
        "controlled invocation program",
    )?;
    let resolved_program = require_string(&mut object, "resolved_program", path)?;
    require_character_bound(
        &resolved_program,
        1,
        MAXIMUM_RESOLVED_PROGRAM_CHARACTERS,
        path,
        "controlled invocation resolved_program",
    )?;
    let argument_values = require_array(&mut object, "arguments", path)?;
    if argument_values.len() > MAXIMUM_CONTROLLED_ARGUMENTS {
        return invalid_json(path, "controlled invocation contains too many arguments");
    }
    let arguments = bounded_string_values(
        argument_values,
        MAXIMUM_CONTROLLED_ARGUMENT_CHARACTERS,
        path,
        "controlled invocation arguments",
    )?;
    let working_directory = require_string(&mut object, "working_directory", path)?;
    if working_directory != "engineering-workspace" {
        return invalid_json(path, "controlled invocation working directory is invalid");
    }
    let digest = require_string(&mut object, "environment_digest", path)?;
    if !valid_sha256_digest(&digest) {
        return invalid_json(path, "controlled invocation environment digest is invalid");
    }
    let timeout_ms = require_any_integer(&mut object, "timeout_ms", path)?;
    if timeout_ms == 0 {
        return invalid_json(path, "controlled invocation timeout is zero");
    }
    let input_kind = require_string(&mut object, "input_kind", path)?;
    let input_bytes = require_any_integer(&mut object, "input_bytes", path)?;
    let input_sha256 = require_string(&mut object, "input_sha256", path)?;
    match input_kind.as_str() {
        "null" if input_bytes == 0 && input_sha256 == "-" => {},
        "bytes"
            if input_bytes <= MAXIMUM_RAW_REPORT_BYTES as u128
                && valid_sha256_digest(&input_sha256) => {},
        _ => return invalid_json(path, "controlled invocation input binding is invalid"),
    }
    reject_unknown(object, path, "controlled invocation")?;
    let input_bytes = usize::try_from(input_bytes)
        .map_err(|_| XtaskError::invalid_path(path, "controlled input bytes exceed usize"))?;
    Ok(ControlledInvocation {
        program,
        resolved_program,
        arguments,
        working_directory,
        environment_digest: digest,
        timeout_ms,
        input_kind,
        input_bytes,
        input_sha256,
    })
}

fn parse_raw_report_binding(
    value: bounded_json::JsonValue,
    path: &Path,
) -> Result<ParsedRawReportBinding, XtaskError> {
    let mut object = value
        .into_object("raw report binding")
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))?;
    let applicability = require_string(&mut object, "applicability", path)?;
    let report_path = require_string(&mut object, "path", path)?;
    let digest = require_string(&mut object, "sha256", path)?;
    let bytes = usize::try_from(require_any_integer(&mut object, "bytes", path)?)
        .map_err(|_| XtaskError::invalid_path(path, "raw report byte length exceeds usize"))?;
    let content_type = require_string(&mut object, "content_type", path)?;
    let reason = require_string(&mut object, "reason", path)?;
    reject_unknown(object, path, "raw report binding")?;
    if bytes > MAXIMUM_RAW_REPORT_BYTES {
        return invalid_json(
            path,
            format!("retained raw report exceeds {MAXIMUM_RAW_REPORT_BYTES} bytes"),
        );
    }
    match applicability.as_str() {
        "exact"
            if valid_raw_report_schema_path(&report_path)
                && valid_sha256_digest(&digest)
                && (1..=MAXIMUM_RAW_REPORT_BYTES).contains(&bytes)
                && content_type == RAW_REPORT_CONTENT_TYPE
                && reason == "-" => {},
        "not-applicable"
            if report_path == "-"
                && digest == "-"
                && bytes == 0
                && content_type == "-"
                && matches!(
                    reason.as_str(),
                    "gate-not-selected" | "report-encoding-failed" | "report-retention-failed"
                ) => {},
        _ => return invalid_json(path, "raw report binding is invalid"),
    }
    Ok(ParsedRawReportBinding {
        applicability,
        path: report_path,
        digest,
        bytes,
        reason,
    })
}

fn parse_raw_report_record(
    path: &Path,
    content: &str,
) -> Result<ParsedRawReportRecord, XtaskError> {
    let mut object =
        parse_retained_object(path, content, "raw report", RetainedDocumentKind::RawReport)?;
    require_integer(&mut object, "schema_version", path, 1)?;
    if require_string(&mut object, "content_type", path)? != RAW_REPORT_CONTENT_TYPE {
        return invalid_json(path, "raw report content type is invalid");
    }
    let attempt_id = require_string(&mut object, "attempt_id", path)?;
    let gate_id = require_string(&mut object, "gate_id", path)?;
    let result = require_string(&mut object, "verdict", path)?;
    if !matches!(result.as_str(), "passed" | "failed") {
        return invalid_json(path, "raw report verdict is invalid");
    }
    require_any_integer(&mut object, "duration_ms", path)?;
    let invocation_digest = require_string(&mut object, "invocation_digest", path)?;
    if !valid_sha256_digest(&invocation_digest) {
        return invalid_json(path, "raw report invocation digest is invalid");
    }
    let invocation = take_value(&mut object, "invocation", path)?;
    let parsed_invocation = parse_gate_invocation_value(invocation.clone(), path)?;
    if invocation_digest != command_digest(&parsed_invocation.typed) {
        return invalid_json(
            path,
            "raw report invocation digest does not match its canonical structured invocation",
        );
    }
    if require_string(&mut object, "detail", path)?.is_empty() {
        return invalid_json(path, "raw report detail is empty");
    }
    let controlled_step_values = require_array(&mut object, "controlled_steps", path)?;
    if controlled_step_values.len() > MAXIMUM_CONTROLLED_REPORT_STEPS {
        return invalid_json(path, "raw report contains too many controlled steps");
    }
    let mut controlled_steps = Vec::with_capacity(controlled_step_values.len());
    let mut charged_bytes = 0_usize;
    for value in controlled_step_values {
        let mut step = value
            .into_object("controlled step report")
            .map_err(|error| XtaskError::invalid_path(path, error.to_string()))?;
        let invocation = take_value(&mut step, "invocation", path)?;
        parse_controlled_invocation_value(invocation.clone(), path)?;
        let verdict = require_string(&mut step, "verdict", path)?;
        let stdout = require_string(&mut step, "stdout", path)?;
        let stderr = require_string(&mut step, "stderr", path)?;
        reject_unknown(step, path, "controlled step report")?;
        if stdout.len() > MAXIMUM_CAPTURED_REPORT_STREAM_BYTES
            || stderr.len() > MAXIMUM_CAPTURED_REPORT_STREAM_BYTES
        {
            return invalid_json(path, "controlled step stream exceeds its resource bound");
        }
        let step_bytes = verdict
            .len()
            .checked_add(stdout.len())
            .and_then(|bytes| bytes.checked_add(stderr.len()))
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| XtaskError::invalid_path(path, "raw report size overflow"))?;
        charged_bytes = charged_bytes
            .checked_add(step_bytes)
            .ok_or_else(|| XtaskError::invalid_path(path, "raw report size overflow"))?;
        if charged_bytes > MAXIMUM_RAW_REPORT_BYTES {
            return invalid_json(path, "controlled report exceeds its total resource bound");
        }
        controlled_steps.push(invocation);
    }
    reject_unknown(object, path, "raw report")?;
    if controlled_steps != parsed_invocation.controlled_steps {
        return invalid_json(
            path,
            "raw report controlled steps differ from its invocation binding",
        );
    }
    Ok(ParsedRawReportRecord {
        attempt_id,
        gate_id,
        result,
        invocation_digest,
        invocation,
        controlled_steps,
    })
}

fn validate_identity_binding(
    value: bounded_json::JsonValue,
    path: &Path,
) -> Result<(), XtaskError> {
    parse_identity_binding(value, path).map(|_| ())
}

fn parse_identity_binding(
    value: bounded_json::JsonValue,
    path: &Path,
) -> Result<ParsedIdentityBinding, XtaskError> {
    let mut object = value
        .into_object("identity binding")
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))?;
    let applicability = require_string(&mut object, "applicability", path)?;
    let value = require_string(&mut object, "value", path)?;
    let reason = require_string(&mut object, "reason", path)?;
    reject_unknown(object, path, "identity binding")?;
    match applicability.as_str() {
        "exact"
            if character_count_in_range(&value, 1, MAXIMUM_IDENTITY_VALUE_CHARACTERS)
                && value != "-"
                && reason == "-" =>
        {
            Ok(ParsedIdentityBinding {
                applicability,
                value,
                reason,
            })
        },
        "not-applicable"
            if value == "-"
                && matches!(
                    reason.as_str(),
                    "no-collision"
                        | "no-release-manifest-for-engineering-attempt"
                        | "no-candidate-artifact-for-engineering-attempt"
                        | "no-effective-configuration-for-engineering-attempt"
                        | "no-corpus-selected"
                        | "no-seed-selected"
                        | "no-fault-schedule-selected"
                        | "no-approval-claimed"
                        | "no-exception-applied"
                        | "gate-not-selected"
                        | "unavailable-before-registry-validation"
                ) =>
        {
            Ok(ParsedIdentityBinding {
                applicability,
                value,
                reason,
            })
        },
        _ => invalid_json(path, "identity binding is invalid"),
    }
}

fn validate_evidence_identity_object(
    mut object: bounded_json::JsonObject,
    path: &Path,
) -> Result<(), XtaskError> {
    for field in [
        "release_manifest",
        "artifact",
        "target",
        "effective_configuration",
        "corpus",
        "seed",
        "fault_schedule",
        "verifier",
        "approval",
        "exception",
    ] {
        validate_identity_binding(take_value(&mut object, field, path)?, path)?;
    }
    for field in [
        "target_registry_digest",
        "toolchain_digest",
        "fixture_registry_digest",
    ] {
        let digest = require_string(&mut object, field, path)?;
        if !valid_registry_digest(&digest) {
            return invalid_json(path, format!("identity `{field}` is invalid"));
        }
    }
    reject_unknown(object, path, "evidence identity")
}

fn validate_evidence_schema_document(path: &Path, content: &str) -> Result<(), XtaskError> {
    let parsed = bounded_json::parse(content)
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))?;
    for field in [
        "attempt_id",
        "collision_of",
        "collision_slots",
        "merge_eligible",
        "registry_digest",
        "release_manifest",
        "artifact",
        "target",
        "target_registry_digest",
        "environment_digest",
        "toolchain_digest",
        "effective_configuration",
        "fixture_registry_digest",
        "corpus",
        "seed",
        "fault_schedule",
        "verifier",
        "approval",
        "exception",
        "invocation",
        "controlled_steps",
        "command_digest",
        "owner",
        "raw_report",
        "content_type",
        "sha256",
        "bytes",
        "not-selected",
    ] {
        if !json_contains_field_or_string(&parsed, field) {
            return Err(XtaskError::invalid_path(
                path,
                format!("evidence schema is missing `{}`", json_string(field)),
            ));
        }
    }
    let mut schema = parsed
        .into_object("evidence schema")
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))?;
    if require_string(&mut schema, "$comment", path)? != EVIDENCE_V3_CONSTRAINT_OWNER {
        return invalid_json(path, "evidence schema constraint owner is invalid");
    }
    if require_string(&mut schema, "type", path)? != "object"
        || require_boolean(&mut schema, "additionalProperties", path)?
    {
        return invalid_json(path, "evidence schema must be a closed object");
    }
    let required = require_array(&mut schema, "required", path)?;
    let required = validate_string_values(required, path, "schema required fields")?;
    for field in [
        "schema_version",
        "attempt_id",
        "collision_of",
        "collision_slots",
        "profile",
        "result",
        "merge_eligible",
        "source",
        "started_unix_ms",
        "ended_unix_ms",
        "registry_digest",
        "environment_digest",
        "identity",
        "gates",
    ] {
        if !required.contains(field) {
            return invalid_json(path, format!("schema omits required field `{field}`"));
        }
    }
    let mut properties = require_object(&mut schema, "properties", path)?;
    let mut version = take_value(&mut properties, "schema_version", path)?
        .into_object("schema_version definition")
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))?;
    require_integer(&mut version, "const", path, 3)?;
    reject_unknown(version, path, "schema_version definition")?;
    for field in ["attempt_id", "collision_of", "collision_slots", "gates"] {
        take_value(&mut properties, field, path)?;
    }
    let definitions = require_object(&mut schema, "$defs", path)?;
    for field in [
        "registryDigest",
        "sha256Digest",
        "gateInvocation",
        "controlledInvocation",
        "rawReportBinding",
        "identityBinding",
    ] {
        if !definitions.contains_key(field) {
            return invalid_json(path, format!("schema omits definition `{field}`"));
        }
    }
    if sha256_digest(content.as_bytes()) != EVIDENCE_V3_SCHEMA_SHA256 {
        return invalid_json(
            path,
            "evidence schema differs from the canonical v3 constraint owner",
        );
    }
    Ok(())
}

fn json_contains_field_or_string(value: &bounded_json::JsonValue, expected: &str) -> bool {
    match value {
        bounded_json::JsonValue::String(value) => value == expected,
        bounded_json::JsonValue::Array(values) => values
            .iter()
            .any(|value| json_contains_field_or_string(value, expected)),
        bounded_json::JsonValue::Object(fields) => fields.iter().any(|(field, value)| {
            field == expected || json_contains_field_or_string(value, expected)
        }),
        bounded_json::JsonValue::Null
        | bounded_json::JsonValue::Boolean(_)
        | bounded_json::JsonValue::Integer(_) => false,
    }
}

fn parse_object(
    path: &Path,
    content: &str,
    subject: &str,
) -> Result<bounded_json::JsonObject, XtaskError> {
    parse_retained_object(path, content, subject, RetainedDocumentKind::Evidence)
}

fn parse_retained_object(
    path: &Path,
    content: &str,
    subject: &str,
    kind: RetainedDocumentKind,
) -> Result<bounded_json::JsonObject, XtaskError> {
    bounded_json::parse_with_maximum_bytes(content, kind.maximum_bytes())
        .and_then(|value| value.into_object(subject))
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))
}

fn take_value(
    object: &mut bounded_json::JsonObject,
    field: &str,
    path: &Path,
) -> Result<bounded_json::JsonValue, XtaskError> {
    bounded_json::take_required(object, field)
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))
}

fn require_string(
    object: &mut bounded_json::JsonObject,
    field: &str,
    path: &Path,
) -> Result<String, XtaskError> {
    match take_value(object, field, path)? {
        bounded_json::JsonValue::String(value) => Ok(value),
        _ => invalid_json(path, format!("`{field}` must be a string")),
    }
}

fn require_boolean(
    object: &mut bounded_json::JsonObject,
    field: &str,
    path: &Path,
) -> Result<bool, XtaskError> {
    match take_value(object, field, path)? {
        bounded_json::JsonValue::Boolean(value) => Ok(value),
        _ => invalid_json(path, format!("`{field}` must be a boolean")),
    }
}

fn require_any_integer(
    object: &mut bounded_json::JsonObject,
    field: &str,
    path: &Path,
) -> Result<u128, XtaskError> {
    match take_value(object, field, path)? {
        bounded_json::JsonValue::Integer(value) => Ok(value),
        _ => invalid_json(path, format!("`{field}` must be an integer")),
    }
}

fn require_integer(
    object: &mut bounded_json::JsonObject,
    field: &str,
    path: &Path,
    expected: u128,
) -> Result<(), XtaskError> {
    if require_any_integer(object, field, path)? == expected {
        Ok(())
    } else {
        invalid_json(path, format!("`{field}` must equal {expected}"))
    }
}

fn require_object(
    object: &mut bounded_json::JsonObject,
    field: &str,
    path: &Path,
) -> Result<bounded_json::JsonObject, XtaskError> {
    take_value(object, field, path)?
        .into_object(field)
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))
}

fn require_array(
    object: &mut bounded_json::JsonObject,
    field: &str,
    path: &Path,
) -> Result<Vec<bounded_json::JsonValue>, XtaskError> {
    match take_value(object, field, path)? {
        bounded_json::JsonValue::Array(value) => Ok(value),
        _ => invalid_json(path, format!("`{field}` must be an array")),
    }
}

fn validate_string_values(
    values: Vec<bounded_json::JsonValue>,
    path: &Path,
    subject: &str,
) -> Result<BTreeSet<String>, XtaskError> {
    let mut strings = BTreeSet::new();
    for value in values {
        let bounded_json::JsonValue::String(value) = value else {
            return invalid_json(path, format!("{subject} must contain only strings"));
        };
        if value.is_empty() || !strings.insert(value) {
            return invalid_json(
                path,
                format!("{subject} contains an empty or duplicate value"),
            );
        }
    }
    Ok(strings)
}

fn bounded_string_values(
    values: Vec<bounded_json::JsonValue>,
    maximum_characters: usize,
    path: &Path,
    subject: &str,
) -> Result<Vec<String>, XtaskError> {
    let mut strings = Vec::with_capacity(values.len());
    for value in values {
        let bounded_json::JsonValue::String(value) = value else {
            return invalid_json(path, format!("{subject} must contain only strings"));
        };
        require_character_bound(&value, 1, maximum_characters, path, subject)?;
        strings.push(value);
    }
    Ok(strings)
}

fn require_character_bound(
    value: &str,
    minimum: usize,
    maximum: usize,
    path: &Path,
    subject: &str,
) -> Result<(), XtaskError> {
    if character_count_in_range(value, minimum, maximum) {
        Ok(())
    } else {
        invalid_json(
            path,
            format!("{subject} must contain between {minimum} and {maximum} characters"),
        )
    }
}

fn character_count_in_range(value: &str, minimum: usize, maximum: usize) -> bool {
    let mut count = 0_usize;
    for _ in value.chars() {
        count = count.saturating_add(1);
        if count > maximum {
            return false;
        }
    }
    count >= minimum
}

fn reject_unknown(
    object: bounded_json::JsonObject,
    path: &Path,
    subject: &str,
) -> Result<(), XtaskError> {
    bounded_json::reject_unknown_fields(object, subject)
        .map_err(|error| XtaskError::invalid_path(path, error.to_string()))
}

fn invalid_json<T>(path: &Path, detail: impl Into<String>) -> Result<T, XtaskError> {
    Err(XtaskError::invalid_path(path, detail.into()))
}

fn run_policy_gate(root: &Path, registry: &Registry) -> Result<String, XtaskError> {
    validate_workflows(root)?;
    validate_local_development_configuration(root)?;
    validate_required_policy_files(root)?;
    hooks::validate_repository_hooks(root)?;
    if registry.activated_risk_gates().contains("EG-COVERAGE") {
        validate_coverage_workflow_provisioning(root)?;
        validate_m0_01b_coverage_target_completeness(root, registry)?;
    }
    Ok("internal:workflow-action-pin-branch-policy-and-required-file validation".to_owned())
}

fn validate_m0_01b_coverage_target_completeness(
    root: &Path,
    registry: &Registry,
) -> Result<(), XtaskError> {
    let policy = root.join(M0_01B_COVERAGE_POLICY);
    let policy_content = fs::read_to_string(&policy)
        .map_err(|source| XtaskError::io(format!("read {}", policy.display()), source))?;
    for required in [
        "\"id\": \"PC-0006-m0-01b-coverage-target-completeness\"",
        "\"semantic_owner\": \"Quality Engineering\"",
        "\"approval_status\": \"pending independent review; no approval is claimed by this local evidence\"",
    ] {
        if !policy_content.contains(required) {
            return Err(XtaskError::invalid_path(
                &policy,
                format!("M0-01B coverage policy record is missing `{required}`"),
            ));
        }
    }

    validate_m0_01b_coverage_command_specs(&m0_01b_coverage_command_specs())?;
    for (identity, expected) in FROZEN_M0_01_COVERAGE_BASELINES {
        let actual = registry.measured_baseline(identity)?;
        if actual.to_bits() != expected.to_bits() {
            return Err(XtaskError::invalid(
                "M0-01 coverage baseline",
                format!("frozen baseline `{identity}` drifted from its retained M0-01 value"),
            ));
        }
    }
    Ok(())
}

fn validate_m0_01b_coverage_command_specs(
    specifications: &[CoverageCommandSpec; 2],
) -> Result<(), XtaskError> {
    for specification in specifications {
        if specification.targets != REQUIRED_M0_01B_COVERAGE_TARGETS {
            return Err(XtaskError::invalid(
                "M0-01B coverage target selection",
                "M0-01B coverage target selection must run the controlled owner verdict suite in both total and changed-code campaigns",
            ));
        }
    }
    Ok(())
}

fn validate_coverage_workflow_provisioning(root: &Path) -> Result<(), XtaskError> {
    let required = [
        "rustup toolchain install nightly-2026-07-20 --profile minimal --component llvm-tools-preview",
        "cargo install --locked --version 0.8.7 cargo-llvm-cov",
    ];
    let relative = ".github/workflows/extended.yml";
    let path = root.join(relative);
    let content = fs::read_to_string(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    for command in required {
        if !content.contains(command) {
            return Err(XtaskError::invalid_path(
                &path,
                format!("coverage-selected workflow `{relative}` is missing `{command}`"),
            ));
        }
    }
    if content
        .lines()
        .any(|line| line.trim_start().starts_with("cargo mutants"))
    {
        return Err(XtaskError::invalid_path(
            &path,
            format!(
                "coverage-selected workflow `{relative}` must invoke detectors only through `cargo xtask quality`"
            ),
        ));
    }
    if !content.contains("cargo xtask quality --profile ext --retain-m0-02-mutation") {
        return Err(XtaskError::invalid_path(
            &path,
            format!(
                "coverage-selected workflow `{relative}` is missing the authoritative retained M0-02 mutation selection"
            ),
        ));
    }
    if !content.contains("cargo xtask quality --profile ext --retain-m0-03-mutation") {
        return Err(XtaskError::invalid_path(
            &path,
            format!(
                "coverage-selected workflow `{relative}` is missing the authoritative retained M0-03 mutation selection"
            ),
        ));
    }
    if !content.contains("cargo xtask quality --profile ext --retain-m0-04-mutation") {
        return Err(XtaskError::invalid_path(
            &path,
            format!(
                "coverage-selected workflow `{relative}` is missing the authoritative retained M0-04 mutation selection"
            ),
        ));
    }
    if !content
        .lines()
        .any(|line| line.trim() == "path: target/quality/")
    {
        return Err(XtaskError::invalid_path(
            &path,
            format!("coverage-selected workflow `{relative}` must retain `target/quality/`"),
        ));
    }
    Ok(())
}

fn run_rust_gate(
    root: &Path,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let format = run_status(
        root,
        environment,
        "cargo",
        ["fmt", "--all", "--", "--check"],
        remaining(deadline)?,
        capture,
    )?;
    let clippy = run_status(
        root,
        environment,
        "cargo",
        [
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        remaining(deadline)?,
        capture,
    )?;
    Ok(format!("{} | {}", format.display, clippy.display))
}

fn run_safety_gate(
    root: &Path,
    registry: &Registry,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    for scope in &registry.scopes {
        let source_root = root.join(&scope.path).join("src");
        let mut sources = Vec::new();
        registry::collect_files_with_extension(&source_root, "rs", 0, &mut sources)?;
        let mut has_forbid = false;
        for source in &sources {
            let content = fs::read_to_string(source)
                .map_err(|error| XtaskError::io(format!("read {}", source.display()), error))?;
            if content.contains("#![forbid(unsafe_code)]") {
                has_forbid = true;
            }
        }
        if !has_forbid {
            return Err(XtaskError::invalid_path(
                &source_root,
                format!(
                    "scope `{}` does not explicitly forbid owned unsafe code",
                    scope.package
                ),
            ));
        }
    }
    scan_active_application_sources(
        root,
        registry,
        &[
            ("unsafe {", "owned unsafe block is not allowlisted"),
            ("unsafe fn ", "owned unsafe function is not allowlisted"),
            (
                "unsafe impl ",
                "owned unsafe implementation is not allowlisted",
            ),
            ("unsafe trait ", "owned unsafe trait is not allowlisted"),
            (
                "tokio::sync::mpsc::unbounded_channel",
                "unbounded channels are forbidden",
            ),
            (
                "tokio::spawn",
                "direct unregistered task spawning is forbidden",
            ),
            (
                "std::thread::spawn",
                "direct unregistered thread spawning is forbidden",
            ),
        ],
    )?;
    let mut evidence = vec!["internal:forbid-unsafe-and-unbounded-source-policy scan".to_owned()];
    if registry.has_m0_04_configuration_scope() {
        evidence.push(
            run_configuration_parser_adversarial_tests(root, budget, environment, capture)?.display,
        );
    }
    Ok(evidence.join(" | "))
}

fn run_security_gate(
    root: &Path,
    registry: &Registry,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    if !registry.has_m0_04_configuration_scope() {
        return Err(XtaskError::invalid(
            "security gate",
            "EG-SECURITY was selected without an applicable active boundary",
        ));
    }
    let path = root.join("qualification/engineering/security/TM-0001-m0-04-toml-parser.json");
    let threat_model = fs::read_to_string(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    validate_configuration_parser_threat_model_text(&threat_model)?;
    let adversarial =
        run_configuration_parser_adversarial_tests(root, budget, environment, capture)?;
    Ok(format!(
        "internal:versioned-parser-threat-model-and-pending-security-owner-review validation | {}",
        adversarial.display
    ))
}

fn run_configuration_parser_adversarial_tests(
    root: &Path,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<CommandOutcome, XtaskError> {
    run_status(
        root,
        environment,
        "cargo",
        [
            "test",
            "--locked",
            "--package",
            "positron-config",
            "--test",
            "configuration_foundation",
            "preflight_",
        ],
        budget,
        capture,
    )
}

fn validate_configuration_parser_threat_model_text(content: &str) -> Result<(), XtaskError> {
    if !content.trim_start().starts_with('{') || !content.trim_end().ends_with('}') {
        return Err(XtaskError::invalid(
            "M0-04 parser threat model",
            "versioned threat-model record is not a complete JSON object",
        ));
    }
    for required in [
        "\"schema_version\": 1",
        "\"id\": \"TM-0001-m0-04-toml-parser\"",
        "\"version\": 1",
        "\"status\": \"proposed-for-security-owner-review\"",
        "\"security_owner\": \"Security and Key Management\"",
        "\"maximum_document_bytes\": 16384",
        "\"maximum_table_depth\": 1",
        "\"maximum_entries_including_table_headers\": 16",
        "\"maximum_key_bytes\": 64",
        "\"maximum_scalar_token_bytes\": 256",
        "\"failure\": \"ResourceLimit before toml::Table allocation\"",
        "\"failure\": \"Malformed before publication; standard TOML parser remains final syntax authority\"",
        "\"command\": \"cargo test --locked --package positron-config --test configuration_foundation preflight_\"",
        "\"required\": \"Security and Key Management\"",
        "\"status\": \"pending-independent-review\"",
        "\"reviewer\": \"\"",
        "\"reviewed_revision\": \"\"",
        "\"reviewed_at\": \"\"",
    ] {
        if !content.contains(required) {
            return Err(XtaskError::invalid(
                "M0-04 parser threat model",
                format!("required fail-closed field is missing or drifted: `{required}`"),
            ));
        }
    }
    Ok(())
}

fn run_secret_gate(
    root: &Path,
    profile: Profile,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let mut commands = Vec::new();
    commands.push(
        run_status(
            root,
            environment,
            "gitleaks",
            [
                "dir",
                "--no-banner",
                "--no-color",
                "--redact=100",
                "--max-target-megabytes=20",
                ".",
            ],
            remaining(deadline)?,
            capture,
        )?
        .display,
    );
    if matches!(profile, Profile::Ext | Profile::Qual) {
        commands.push(
            run_status(
                root,
                environment,
                "gitleaks",
                [
                    "git",
                    "--no-banner",
                    "--no-color",
                    "--redact=100",
                    "--log-opts=--all",
                    ".",
                ],
                remaining(deadline)?,
                capture,
            )?
            .display,
        );
    }
    Ok(commands.join(" | "))
}

fn run_supply_gate(
    root: &Path,
    registry: &Registry,
    profile: Profile,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let mut commands = Vec::new();
    commands.push(
        run_status(
            root,
            environment,
            "cargo",
            ["audit", "--deny", "warnings"],
            remaining(deadline)?,
            capture,
        )?
        .display,
    );
    if matches!(profile, Profile::Ext | Profile::Qual) {
        commands.push(
            run_status(
                root,
                environment,
                "cargo",
                ["vet", "--locked"],
                remaining(deadline)?,
                capture,
            )?
            .display,
        );
    }
    let dependency_state = if registry.reviewed_dependencies().is_empty() {
        "no direct third-party production or tooling dependencies"
    } else {
        "direct dependency reviews matched the resolved graph"
    };
    commands.push(format!("internal:{dependency_state}"));
    Ok(commands.join(" | "))
}

fn run_test_gate(
    root: &Path,
    budget: Duration,
    environment: &EnvironmentSnapshot,
    capture: &mut GateCapture,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let nextest = run_status(
        root,
        environment,
        "cargo",
        NEXTEST_PR_ARGUMENTS,
        remaining(deadline)?,
        capture,
    )?;
    let completed_test_count = nextest_completed_test_count(&nextest.stderr)?;
    let doctest = run_status(
        root,
        environment,
        "cargo",
        ["test", "--locked", "--workspace", "--doc", "--all-features"],
        remaining(deadline)?,
        capture,
    )?;
    Ok(format!(
        "{}; completed-tests={completed_test_count} | {}",
        nextest.display, doctest.display
    ))
}

fn nextest_completed_test_count(stderr: &str) -> Result<usize, XtaskError> {
    let mut summaries = stderr
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("Summary ["));
    let summary = summaries.next().ok_or_else(|| {
        XtaskError::invalid(
            "nextest result summary",
            "missing final completed-test count",
        )
    })?;
    if summaries.next().is_some() {
        return Err(XtaskError::invalid(
            "nextest result summary",
            "multiple final completed-test summaries are ambiguous",
        ));
    }
    let (_, counts) = summary.split_once("] ").ok_or_else(|| {
        XtaskError::invalid(
            "nextest result summary",
            "final summary duration delimiter is malformed",
        )
    })?;
    let (completed, outcomes) = counts.split_once(" tests run: ").ok_or_else(|| {
        XtaskError::invalid(
            "nextest result summary",
            "final completed-test count delimiter is malformed",
        )
    })?;
    let completed = completed.parse::<usize>().map_err(|error| {
        XtaskError::invalid(
            "nextest result summary",
            format!("final completed-test count is invalid: {error}"),
        )
    })?;
    if completed == 0 || outcomes != format!("{completed} passed, 0 skipped") {
        return Err(XtaskError::invalid(
            "nextest result summary",
            format!("expected every completed test to pass without skips, observed `{outcomes}`"),
        ));
    }
    Ok(completed)
}

fn scan_active_application_sources(
    root: &Path,
    registry: &Registry,
    forbidden: &[(&str, &str)],
) -> Result<(), XtaskError> {
    for scope in registry
        .scopes
        .iter()
        .filter(|scope| scope.kind == "application" && scope.state == "active")
    {
        let source_root = root.join(&scope.path).join("src");
        let mut sources = Vec::new();
        registry::collect_files_with_extension(&source_root, "rs", 0, &mut sources)?;
        for source in sources {
            let content = fs::read_to_string(&source)
                .map_err(|error| XtaskError::io(format!("read {}", source.display()), error))?;
            for (token, reason) in forbidden {
                if content.contains(token) {
                    return Err(XtaskError::invalid_path(
                        &source,
                        format!("{reason}; matched token `{token}`"),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_local_markdown_links(root: &Path) -> Result<(), XtaskError> {
    let mut markdown = Vec::new();
    collect_markdown_files(root, 0, &mut markdown)?;
    for path in markdown {
        let content = fs::read_to_string(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        for (line_index, line) in content.lines().enumerate() {
            let mut remainder = line;
            while let Some((_, after_open)) = remainder.split_once("](") {
                let Some((raw_target, after_close)) = after_open.split_once(')') else {
                    break;
                };
                remainder = after_close;
                let target = raw_target
                    .trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>');
                let target = target.split_whitespace().next().unwrap_or_default();
                if target.is_empty()
                    || target.starts_with('#')
                    || target.starts_with("http://")
                    || target.starts_with("https://")
                    || target.starts_with("mailto:")
                {
                    continue;
                }
                let file_part = target.split_once('#').map_or(target, |(file, _)| file);
                if file_part.is_empty() {
                    continue;
                }
                let Some(parent) = path.parent() else {
                    return Err(XtaskError::invalid_path(
                        &path,
                        "Markdown file has no parent directory",
                    ));
                };
                let destination = parent.join(file_part);
                if !destination.exists() {
                    return Err(XtaskError::invalid_path(
                        &path,
                        format!(
                            "line {} references missing local target `{target}`",
                            line_index + 1
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn collect_markdown_files(
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    if depth > 16 {
        return Err(XtaskError::invalid_path(
            directory,
            "documentation tree depth exceeds 16",
        ));
    }
    let entries = fs::read_dir(directory)
        .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
    for entry in entries {
        let entry = entry
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some(".git" | ".quality" | "target" | "mutants.out")
        ) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|source| XtaskError::io("read documentation entry type", source))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_markdown_files(&entry.path(), depth + 1, files)?;
        } else if file_type.is_file()
            && entry.path().extension().and_then(OsStr::to_str) == Some("md")
        {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn validate_workflows(root: &Path) -> Result<(), XtaskError> {
    let workflow_root = root.join(".github/workflows");
    let mut workflows = Vec::new();
    collect_workflows(&workflow_root, &mut workflows)?;
    if workflows.is_empty() {
        return Err(XtaskError::invalid_path(
            &workflow_root,
            "at least one trusted workflow is required",
        ));
    }
    for workflow in &workflows {
        let content = fs::read_to_string(workflow)
            .map_err(|source| XtaskError::io(format!("read {}", workflow.display()), source))?;
        if content.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("paths:") || trimmed.starts_with("paths-ignore:")
        }) {
            return Err(XtaskError::invalid_path(
                workflow,
                "path-filtered required workflows are forbidden",
            ));
        }
        for line in content.lines() {
            let trimmed = line.trim();
            let Some(action) = trimmed.strip_prefix("uses:") else {
                continue;
            };
            let Some((_, revision)) = action.trim().split_once('@') else {
                return Err(XtaskError::invalid_path(
                    workflow,
                    format!("third-party action is not pinned: `{}`", action.trim()),
                ));
            };
            let revision = revision.split_whitespace().next().unwrap_or_default();
            if revision.len() != 40
                || !revision
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
            {
                return Err(XtaskError::invalid_path(
                    workflow,
                    format!("third-party action must use a full commit SHA, found `{revision}`"),
                ));
            }
        }
    }

    let required = root.join(".github/workflows/quality.yml");
    let content = fs::read_to_string(&required)
        .map_err(|source| XtaskError::io(format!("read {}", required.display()), source))?;
    for safeguard in [
        "pull_request:",
        "merge_group:",
        "permissions:",
        "contents: read",
        "CARGO_INCREMENTAL: \"0\"",
        "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        "id: pr-tools-cache",
        "path: ~/.positron-pr-tools",
        "key: positron-pr-tools-${{ runner.os }}-${{ runner.arch }}-rust-1.96.0-nextest-0.9.138-deny-0.19.9-audit-0.22.2-machete-0.9.2",
        "if: steps.pr-tools-cache.outputs.cache-hit != 'true'",
        "if: github.event_name == 'push' && github.ref == 'refs/heads/main' && steps.pr-tools-cache.outputs.cache-hit != 'true'",
        "--root \"$HOME/.positron-pr-tools\"",
        "Verify pinned PR tools",
        "\"$tool_root/cargo-nextest\" --version",
        "\"$tool_root/cargo-deny\" --version",
        "\"$tool_root/cargo-audit\" --version",
        "\"$tool_root/cargo-machete\" --version",
        "cargo xtask quality --profile pr",
        "persist-credentials: false",
        "if: always()",
    ] {
        if !content.contains(safeguard) {
            return Err(XtaskError::invalid_path(
                &required,
                format!("required workflow safeguard `{safeguard}` is missing"),
            ));
        }
    }
    Ok(())
}

fn validate_local_development_configuration(root: &Path) -> Result<(), XtaskError> {
    let path = root.join(".cargo/config.toml");
    let content = fs::read_to_string(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    if content
        .lines()
        .any(|line| line.trim() == "incremental = false")
    {
        return Err(XtaskError::invalid_path(
            &path,
            "local development configuration must not globally disable incremental compilation",
        ));
    }
    Ok(())
}

fn collect_workflows(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), XtaskError> {
    let entries = fs::read_dir(directory)
        .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
    for entry in entries {
        let entry = entry
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        if !entry
            .file_type()
            .map_err(|source| XtaskError::io("read workflow entry type", source))?
            .is_file()
        {
            continue;
        }
        if matches!(
            entry.path().extension().and_then(OsStr::to_str),
            Some("yml" | "yaml")
        ) {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn validate_required_policy_files(root: &Path) -> Result<(), XtaskError> {
    for relative in [
        "AGENTS.md",
        "CONTRIBUTING.md",
        ".github/CODEOWNERS",
        ".github/repository-policy.json",
        ".github/BRANCH_PROTECTION.md",
        ".githooks/pre-commit",
        ".githooks/pre-push",
        "deny.toml",
        "rust-toolchain.toml",
        "qualification/engineering/policy-changes/M0-INITIAL.json",
        "supply-chain/config.toml",
        "supply-chain/audits.toml",
        "supply-chain/imports.lock",
    ] {
        let path = root.join(relative);
        if !path.is_file() {
            return Err(XtaskError::invalid_path(
                &path,
                "required engineering policy file is missing",
            ));
        }
    }
    let agent_policy = fs::read_to_string(root.join("AGENTS.md"))
        .map_err(|source| XtaskError::io("read AGENTS.md", source))?;
    let normalized_agent_policy = agent_policy
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "Do not code the application while its crate remains `scaffold`",
        "Run `cargo xtask quality`",
        "Never weaken, skip, delete, rename, path-filter",
    ] {
        if !normalized_agent_policy.contains(required) {
            return Err(XtaskError::invalid(
                "AGENTS.md",
                format!("missing agent safeguard `{required}`"),
            ));
        }
    }
    Ok(())
}

fn run_status<'argument>(
    root: &Path,
    snapshot: &EnvironmentSnapshot,
    program: &str,
    arguments: impl IntoIterator<Item = &'argument str>,
    timeout: Duration,
    capture: &mut GateCapture,
) -> Result<CommandOutcome, XtaskError> {
    run_status_with_options(
        root,
        snapshot,
        program,
        arguments,
        StatusOptions {
            timeout,
            environment: &[],
            capture,
        },
    )
}

struct StatusOptions<'environment, 'capture> {
    timeout: Duration,
    environment: &'environment [(&'environment str, &'environment str)],
    capture: &'capture mut GateCapture,
}

fn run_status_with_options<'argument>(
    root: &Path,
    snapshot: &EnvironmentSnapshot,
    program: &str,
    arguments: impl IntoIterator<Item = &'argument str>,
    options: StatusOptions<'_, '_>,
) -> Result<CommandOutcome, XtaskError> {
    let arguments = arguments
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let resolved_program = snapshot.tool_path(program)?;
    let display = command_display(&resolved_program.to_string_lossy(), &arguments);
    println!("  $ {display}");
    let invocation_environment = snapshot.invocation_environment(options.environment)?;
    let input = InvocationInput::Null;
    let invocation = controlled_invocation(
        program,
        resolved_program.as_os_str(),
        &arguments,
        &invocation_environment,
        options.timeout,
        &input,
    );
    let verdict = controlled_execution::execute(InvocationSpec {
        program: resolved_program,
        arguments,
        current_dir: root.to_path_buf(),
        environment: invocation_environment,
        tools: snapshot.execution_tools(),
        input,
        output: OutputMode::Capture {
            maximum_bytes_per_stream: MAXIMUM_CAPTURED_REPORT_STREAM_BYTES,
        },
        cancellation: Arc::new(AtomicBool::new(false)),
        deadline: deadline_after(options.timeout)?,
        shutdown_timeout: controlled_execution::DEFAULT_SHUTDOWN_TIMEOUT,
        cancellation_marker: None,
    })
    .into_result();
    let verdict = match verdict {
        Ok(verdict) => {
            print!("{}", verdict.output.stdout);
            eprint!("{}", verdict.output.stderr);
            let step_verdict = format!("exit-status:{}", verdict.status);
            options.capture.record(
                invocation,
                &step_verdict,
                &verdict.output.stdout,
                &verdict.output.stderr,
            )?;
            verdict
        },
        Err(error) => {
            let step_verdict = format!("controlled-failure:{}", error.phase.as_str());
            options
                .capture
                .record(invocation, &step_verdict, "", &error.detail)?;
            return Err(XtaskError::controlled_harness(error));
        },
    };
    if verdict.status.success() {
        return Ok(CommandOutcome {
            display,
            stdout: verdict.output.stdout,
            stderr: verdict.output.stderr,
        });
    }
    Err(XtaskError::command(
        display,
        format!("exit status {}", verdict.status),
    ))
}

fn run_capture<'argument>(
    root: &Path,
    snapshot: &EnvironmentSnapshot,
    program: &str,
    arguments: impl IntoIterator<Item = &'argument str>,
    timeout: Duration,
    capture: Option<&mut GateCapture>,
) -> Result<CommandOutcome, XtaskError> {
    run_capture_with_input(
        root,
        snapshot,
        program,
        arguments,
        CaptureOptions {
            timeout,
            environment: &[],
            input: InvocationInput::Null,
        },
        capture,
    )
}

struct CaptureOptions<'environment> {
    timeout: Duration,
    environment: &'environment [(&'environment str, &'environment str)],
    input: InvocationInput,
}

fn run_capture_with_input<'argument>(
    root: &Path,
    snapshot: &EnvironmentSnapshot,
    program: &str,
    arguments: impl IntoIterator<Item = &'argument str>,
    options: CaptureOptions<'_>,
    capture: Option<&mut GateCapture>,
) -> Result<CommandOutcome, XtaskError> {
    let arguments = arguments
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let resolved_program = snapshot.tool_path(program)?;
    let display = command_display(&resolved_program.to_string_lossy(), &arguments);
    let invocation_environment = snapshot.invocation_environment(options.environment)?;
    let invocation = controlled_invocation(
        program,
        resolved_program.as_os_str(),
        &arguments,
        &invocation_environment,
        options.timeout,
        &options.input,
    );
    let verdict = controlled_execution::execute(InvocationSpec {
        program: resolved_program,
        arguments,
        current_dir: root.to_path_buf(),
        environment: invocation_environment,
        tools: snapshot.execution_tools(),
        input: options.input,
        output: OutputMode::Capture {
            maximum_bytes_per_stream: MAXIMUM_CAPTURED_REPORT_STREAM_BYTES,
        },
        cancellation: Arc::new(AtomicBool::new(false)),
        deadline: deadline_after(options.timeout)?,
        shutdown_timeout: controlled_execution::DEFAULT_SHUTDOWN_TIMEOUT,
        cancellation_marker: None,
    })
    .into_result();
    let verdict = match verdict {
        Ok(verdict) => {
            if let Some(capture) = capture {
                let step_verdict = format!("exit-status:{}", verdict.status);
                capture.record(
                    invocation,
                    &step_verdict,
                    &verdict.output.stdout,
                    &verdict.output.stderr,
                )?;
            }
            verdict
        },
        Err(error) => {
            if let Some(capture) = capture {
                let step_verdict = format!("controlled-failure:{}", error.phase.as_str());
                capture.record(invocation, &step_verdict, "", &error.detail)?;
            }
            return Err(XtaskError::controlled_harness(error));
        },
    };
    if !verdict.status.success() {
        return Err(XtaskError::command(
            display,
            format!(
                "exit status {}: stdout={}; stderr={}",
                verdict.status,
                one_line(&verdict.output.stdout),
                one_line(&verdict.output.stderr)
            ),
        ));
    }
    Ok(CommandOutcome {
        display,
        stdout: verdict.output.stdout,
        stderr: verdict.output.stderr,
    })
}

fn command_display(program: &str, arguments: &[OsString]) -> String {
    let mut parts = Vec::with_capacity(arguments.len() + 1);
    parts.push(program.to_owned());
    parts.extend(
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned()),
    );
    parts.join(" ")
}

impl EnvironmentSnapshot {
    fn capture(root: &Path, profile: Profile) -> Result<Self, XtaskError> {
        let root = canonical_directory(root, "workspace root")?;
        let parent_path = env::var_os("PATH").ok_or_else(|| {
            XtaskError::invalid(
                "controlled harness environment",
                "PATH is required to resolve registered quality tools",
            )
        })?;
        let parent_paths = validated_parent_paths(&parent_path)?;
        let search_paths = snapshot_search_paths(&root, parent_paths)?;
        let mut tools = BTreeMap::new();
        for name in required_snapshot_tools(profile) {
            let resolved = resolve_snapshot_tool(name, &search_paths)?;
            if tools.insert(name.to_owned(), resolved).is_some() {
                return Err(XtaskError::invalid(
                    "controlled harness environment",
                    format!("duplicate required tool identity `{name}`"),
                ));
            }
        }

        let execution_tools = ExecutionTools {
            process_control: required_tool_path(&tools, "kill")?,
            capture_broker: required_tool_path(&tools, "head")?,
        };
        let temporary_root = owned_temporary_root(&root)?;
        let home = validated_home_directory("HOME", None)?;
        let cargo_home = validated_home_directory("CARGO_HOME", Some(home.join(".cargo")))?;
        let rustup_home = validated_home_directory("RUSTUP_HOME", Some(home.join(".rustup")))?;

        let path_directories = snapshot_path_directories(&tools)?;
        let path = env::join_paths(path_directories)
            .map_err(|source| XtaskError::invalid("controlled harness PATH", source.to_string()))?;
        validate_environment_value("PATH", &path, MAXIMUM_PATH_BYTES)?;

        let mut configured = BTreeMap::new();
        insert_environment_value(&mut configured, "PATH", path)?;
        insert_environment_path(&mut configured, "HOME", &home)?;
        insert_environment_path(&mut configured, "CARGO_HOME", &cargo_home)?;
        insert_environment_path(&mut configured, "RUSTUP_HOME", &rustup_home)?;
        insert_environment_path(&mut configured, "TMPDIR", &temporary_root)?;
        if let Some(path) = validated_optional_certificate_file("SSL_CERT_FILE")? {
            insert_environment_path(&mut configured, "SSL_CERT_FILE", &path)?;
        }
        if let Some(path) = validated_optional_certificate_directory("SSL_CERT_DIR")? {
            insert_environment_path(&mut configured, "SSL_CERT_DIR", &path)?;
        }
        insert_environment_value(&mut configured, "LC_ALL", OsString::from("C"))?;
        insert_environment_value(&mut configured, "LANG", OsString::from("C"))?;
        insert_environment_value(&mut configured, "TZ", OsString::from("UTC"))?;
        if configured.len() > MAXIMUM_ENVIRONMENT_ENTRIES {
            return Err(XtaskError::invalid(
                "controlled harness environment",
                format!(
                    "snapshot contains {} entries, above the bounded maximum {MAXIMUM_ENVIRONMENT_ENTRIES}",
                    configured.len()
                ),
            ));
        }
        let values = configured
            .into_iter()
            .map(|(name, value)| (OsString::from(name), value))
            .collect::<Vec<_>>();
        let digest = snapshot_digest(&root, &tools, &execution_tools, &values)?;
        Ok(Self {
            values,
            tools,
            execution_tools,
            temporary_root,
            digest,
        })
    }

    fn invocation_environment(
        &self,
        overrides: &[(&str, &str)],
    ) -> Result<Vec<(OsString, OsString)>, XtaskError> {
        let mut configured = self
            .values
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>();
        let mut override_names = BTreeSet::new();
        for (name, value) in overrides {
            if !override_names.insert(*name) {
                return Err(XtaskError::invalid(
                    "controlled harness environment",
                    format!("duplicate invocation override `{name}`"),
                ));
            }
            if !matches!(*name, "CARGO_TARGET_DIR" | "RUSTDOCFLAGS") {
                return Err(XtaskError::invalid(
                    "controlled harness environment",
                    format!("unapproved invocation override `{name}`"),
                ));
            }
            let value = OsString::from(*value);
            validate_environment_value(name, &value, MAXIMUM_ENVIRONMENT_VALUE_BYTES)?;
            if *name == "CARGO_TARGET_DIR" {
                let target = canonical_directory(Path::new(value.as_os_str()), "CARGO_TARGET_DIR")?;
                if !target.starts_with(&self.temporary_root) {
                    return Err(XtaskError::invalid(
                        "controlled harness environment",
                        "CARGO_TARGET_DIR must remain inside the owned TMPDIR",
                    ));
                }
            }
            if configured
                .iter()
                .any(|(configured_name, _)| configured_name.as_os_str() == OsStr::new(name))
            {
                return Err(XtaskError::invalid(
                    "controlled harness environment",
                    format!("invocation override `{name}` collides with the fixed snapshot"),
                ));
            }
            configured.push((OsString::from(*name), value));
        }
        if configured.len() > MAXIMUM_ENVIRONMENT_ENTRIES + 2 {
            return Err(XtaskError::invalid(
                "controlled harness environment",
                "invocation environment exceeds its bounded entry count",
            ));
        }
        Ok(configured)
    }

    fn tool_path(&self, name: &str) -> Result<OsString, XtaskError> {
        self.tools
            .get(name)
            .map(|path| path.as_os_str().to_owned())
            .ok_or_else(|| {
                XtaskError::invalid(
                    "controlled harness environment",
                    format!("program `{name}` is not in the explicit snapshot"),
                )
            })
    }

    fn execution_tools(&self) -> ExecutionTools {
        self.execution_tools.clone()
    }

    fn temporary_root(&self) -> &Path {
        &self.temporary_root
    }

    fn digest(&self) -> &str {
        &self.digest
    }
}

fn required_snapshot_tools(profile: Profile) -> BTreeSet<&'static str> {
    let mut names = BTreeSet::from(["cargo", "git", "gitleaks", "head", "kill", "rustfmt"]);
    if matches!(profile, Profile::Pr | Profile::Ext | Profile::Qual) {
        names.insert("rustc");
    }
    if matches!(profile, Profile::Pr | Profile::Ext) {
        names.insert("cargo-machete");
    }
    names
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, XtaskError> {
    if !path.is_absolute() {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("{label} must be an absolute directory"),
        ));
    }
    let resolved = fs::canonicalize(path)
        .map_err(|source| XtaskError::io(format!("canonicalize {label}"), source))?;
    if !resolved.is_dir() {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("{label} is not a directory"),
        ));
    }
    Ok(resolved)
}

fn validated_parent_paths(parent_path: &OsStr) -> Result<Vec<PathBuf>, XtaskError> {
    validate_environment_value("PATH", parent_path, MAXIMUM_PATH_BYTES)?;
    let paths = env::split_paths(parent_path).collect::<Vec<_>>();
    if paths.is_empty() || paths.len() > MAXIMUM_PATH_ENTRIES {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("PATH must contain between one and {MAXIMUM_PATH_ENTRIES} entries"),
        ));
    }

    let mut canonical = Vec::with_capacity(paths.len());
    for path in paths {
        if !path.is_absolute() {
            return Err(XtaskError::invalid(
                "controlled harness environment",
                "PATH contains a non-absolute entry",
            ));
        }
        if !path.exists() {
            continue;
        }
        let resolved = canonical_directory(&path, "PATH entry")?;
        if !canonical
            .iter()
            .any(|existing: &PathBuf| existing == &resolved)
        {
            canonical.push(resolved);
        }
    }
    if canonical.is_empty() {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            "PATH has no existing absolute directory entries",
        ));
    }
    Ok(canonical)
}

fn snapshot_search_paths(
    root: &Path,
    parent_paths: Vec<PathBuf>,
) -> Result<Vec<PathBuf>, XtaskError> {
    let local_tools = root.join("target/quality-tools/bin");
    let mut paths = Vec::with_capacity(parent_paths.len() + 1);
    if local_tools.exists() {
        paths.push(canonical_directory(
            &local_tools,
            "local quality-tool directory",
        )?);
    }
    paths.extend(parent_paths);
    Ok(paths)
}

fn resolve_snapshot_tool(name: &str, search_paths: &[PathBuf]) -> Result<PathBuf, XtaskError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("required tool name `{name}` is invalid"),
        ));
    }
    for directory in search_paths {
        let candidate = directory.join(name);
        if !candidate.exists() {
            continue;
        }
        let resolved = fs::canonicalize(&candidate)
            .map_err(|source| XtaskError::io(format!("canonicalize tool `{name}`"), source))?;
        if !resolved.is_absolute() || !resolved.is_file() {
            return Err(XtaskError::invalid(
                "controlled harness environment",
                format!("required tool `{name}` is not an absolute regular file"),
            ));
        }
        // Preserve the registered executable name for multi-call launchers
        // such as `cargo -> rustup`; canonicalization is only a validation
        // step, because using its target as argv[0] changes the command.
        return Ok(candidate);
    }
    Err(XtaskError::invalid(
        "controlled harness environment",
        format!("required tool `{name}` could not be resolved from the bounded PATH"),
    ))
}

fn required_tool_path(
    tools: &BTreeMap<String, PathBuf>,
    name: &str,
) -> Result<PathBuf, XtaskError> {
    tools.get(name).cloned().ok_or_else(|| {
        XtaskError::invalid(
            "controlled harness environment",
            format!("required controlled-execution tool `{name}` is missing"),
        )
    })
}

fn snapshot_path_directories(
    tools: &BTreeMap<String, PathBuf>,
) -> Result<Vec<PathBuf>, XtaskError> {
    let mut directories = BTreeSet::new();
    for path in tools.values() {
        let parent = path.parent().ok_or_else(|| {
            XtaskError::invalid(
                "controlled harness environment",
                format!("resolved tool {} has no parent directory", path.display()),
            )
        })?;
        directories.insert(parent.to_path_buf());
    }
    for path in [Path::new("/bin"), Path::new("/usr/bin")] {
        if path.exists() {
            directories.insert(canonical_directory(path, "system command directory")?);
        }
    }
    if directories.is_empty() || directories.len() > MAXIMUM_PATH_ENTRIES {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            "resolved controlled PATH violates its directory bound",
        ));
    }
    Ok(directories.into_iter().collect())
}

fn validated_home_directory(name: &str, fallback: Option<PathBuf>) -> Result<PathBuf, XtaskError> {
    let path = match env::var_os(name) {
        Some(value) => {
            validate_environment_value(name, &value, MAXIMUM_ENVIRONMENT_VALUE_BYTES)?;
            PathBuf::from(value)
        },
        None => fallback.ok_or_else(|| {
            XtaskError::invalid(
                "controlled harness environment",
                format!("required home directory `{name}` is absent"),
            )
        })?,
    };
    canonical_directory(&path, name)
}

fn validated_optional_certificate_file(name: &str) -> Result<Option<PathBuf>, XtaskError> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    validate_environment_value(name, &value, MAXIMUM_ENVIRONMENT_VALUE_BYTES)?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("{name} must be an absolute file path"),
        ));
    }
    let resolved = fs::canonicalize(&path)
        .map_err(|source| XtaskError::io(format!("canonicalize {name}"), source))?;
    if !resolved.is_file() {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("{name} is not a regular file"),
        ));
    }
    Ok(Some(resolved))
}

fn validated_optional_certificate_directory(name: &str) -> Result<Option<PathBuf>, XtaskError> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    validate_environment_value(name, &value, MAXIMUM_ENVIRONMENT_VALUE_BYTES)?;
    Ok(Some(canonical_directory(&PathBuf::from(value), name)?))
}

fn owned_temporary_root(root: &Path) -> Result<PathBuf, XtaskError> {
    let base = root.join("target/quality/tmp");
    fs::create_dir_all(&base)
        .map_err(|source| XtaskError::io(format!("create {}", base.display()), source))?;
    let base = canonical_directory(&base, "owned quality TMPDIR root")?;
    if !base.starts_with(root) {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            "owned quality TMPDIR root escaped the workspace",
        ));
    }
    let nonce = unix_time_ms()?;
    let directory = base.join(format!("run-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory)
        .map_err(|source| XtaskError::io(format!("create {}", directory.display()), source))?;
    canonical_directory(&directory, "owned quality TMPDIR")
}

fn insert_environment_path(
    configured: &mut BTreeMap<String, OsString>,
    name: &str,
    path: &Path,
) -> Result<(), XtaskError> {
    insert_environment_value(configured, name, path.as_os_str().to_owned())
}

fn insert_environment_value(
    configured: &mut BTreeMap<String, OsString>,
    name: &str,
    value: OsString,
) -> Result<(), XtaskError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("environment name `{name}` is invalid"),
        ));
    }
    validate_environment_value(name, &value, MAXIMUM_ENVIRONMENT_VALUE_BYTES)?;
    if configured.insert(name.to_owned(), value).is_some() {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("duplicate snapshot environment name `{name}`"),
        ));
    }
    Ok(())
}

fn validate_environment_value(
    name: &str,
    value: &OsStr,
    maximum_bytes: usize,
) -> Result<(), XtaskError> {
    if value.is_empty() || value.as_encoded_bytes().len() > maximum_bytes {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("{name} exceeds its bounded value size or is empty"),
        ));
    }
    if value.to_str().is_none() {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            format!("{name} is not valid UTF-8"),
        ));
    }
    Ok(())
}

fn snapshot_digest(
    root: &Path,
    tools: &BTreeMap<String, PathBuf>,
    execution_tools: &ExecutionTools,
    values: &[(OsString, OsString)],
) -> Result<String, XtaskError> {
    let mut payload = Vec::new();
    append_snapshot_digest_component(&mut payload, ENVIRONMENT_SNAPSHOT_VERSION)?;
    for (name, value) in values {
        let name = name.to_str().ok_or_else(|| {
            XtaskError::invalid(
                "controlled harness environment",
                "snapshot name is not valid UTF-8",
            )
        })?;
        append_snapshot_digest_component(&mut payload, name)?;
        let value = value.to_str().ok_or_else(|| {
            XtaskError::invalid(
                "controlled harness environment",
                "snapshot value is not valid UTF-8",
            )
        })?;
        let redacted_value = if name == "TMPDIR" {
            "owned-tmpdir"
        } else {
            value
        };
        append_snapshot_digest_component(&mut payload, redacted_value)?;
    }
    for (name, path) in tools {
        append_snapshot_digest_component(&mut payload, name)?;
        append_snapshot_digest_component(
            &mut payload,
            path.to_str().ok_or_else(|| {
                XtaskError::invalid(
                    "controlled harness environment",
                    "resolved tool path is not valid UTF-8",
                )
            })?,
        )?;
    }
    append_snapshot_digest_component(&mut payload, "process_control")?;
    append_snapshot_digest_component(
        &mut payload,
        execution_tools.process_control.to_str().ok_or_else(|| {
            XtaskError::invalid(
                "controlled harness environment",
                "process-control path is not valid UTF-8",
            )
        })?,
    )?;
    append_snapshot_digest_component(&mut payload, "capture_broker")?;
    append_snapshot_digest_component(
        &mut payload,
        execution_tools.capture_broker.to_str().ok_or_else(|| {
            XtaskError::invalid(
                "controlled harness environment",
                "capture-broker path is not valid UTF-8",
            )
        })?,
    )?;

    let git = required_tool_path(tools, "git")?;
    let verdict = controlled_execution::execute(InvocationSpec {
        program: git.as_os_str().to_owned(),
        arguments: vec![OsString::from("hash-object"), OsString::from("--stdin")],
        current_dir: root.to_path_buf(),
        environment: values.to_vec(),
        tools: execution_tools.clone(),
        input: InvocationInput::Bytes(payload),
        output: OutputMode::Capture {
            maximum_bytes_per_stream: 1_024,
        },
        cancellation: Arc::new(AtomicBool::new(false)),
        deadline: deadline_after(SNAPSHOT_DIGEST_TIMEOUT)?,
        shutdown_timeout: controlled_execution::DEFAULT_SHUTDOWN_TIMEOUT,
        cancellation_marker: None,
    })
    .into_result()
    .map_err(XtaskError::controlled_harness)?;
    if !verdict.status.success() {
        return Err(XtaskError::command(
            "git hash-object --stdin".to_owned(),
            format!("exit status {}", verdict.status),
        ));
    }
    let value = verdict.output.stdout.trim();
    if !valid_hex_identity(value) {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            "snapshot digest tool returned an invalid object identity",
        ));
    }
    Ok(format!("git-object:{value}"))
}

fn append_snapshot_digest_component(payload: &mut Vec<u8>, value: &str) -> Result<(), XtaskError> {
    let next_length = payload
        .len()
        .checked_add(value.len())
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| {
            XtaskError::invalid(
                "controlled harness environment",
                "snapshot digest input length overflowed",
            )
        })?;
    if next_length > MAXIMUM_SNAPSHOT_DIGEST_INPUT_BYTES {
        return Err(XtaskError::invalid(
            "controlled harness environment",
            "snapshot digest input exceeds its bounded size",
        ));
    }
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
    Ok(())
}

fn deadline_after(timeout: Duration) -> Result<Instant, XtaskError> {
    Instant::now().checked_add(timeout).ok_or_else(|| {
        XtaskError::invalid(
            "controlled harness execution",
            "the declared timeout cannot be represented by the monotonic clock",
        )
    })
}

fn remaining(deadline: Instant) -> Result<Duration, XtaskError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| XtaskError::invalid("gate budget", "no execution time remains"))
}

fn source_identity(
    root: &Path,
    environment: &EnvironmentSnapshot,
) -> Result<SourceIdentity, XtaskError> {
    let revision = run_capture(
        root,
        environment,
        "git",
        ["rev-parse", "HEAD"],
        Duration::from_secs(10),
        None,
    )?
    .stdout
    .trim()
    .to_owned();
    if revision.is_empty() {
        return Err(XtaskError::invalid(
            "source revision",
            "git returned an empty revision",
        ));
    }
    let status = run_capture(
        root,
        environment,
        "git",
        ["status", "--porcelain=v1", "--untracked-files=all"],
        Duration::from_secs(10),
        None,
    )?
    .stdout;
    let dirty = !status.trim().is_empty();
    let trusted_ci = env::var("GITHUB_ACTIONS").as_deref() == Ok("true");
    let revision_matches_ci = env::var("GITHUB_SHA").map_or(!trusted_ci, |sha| sha == revision);
    Ok(SourceIdentity {
        revision,
        dirty,
        trusted_ci,
        revision_matches_ci,
    })
}

fn validate_trusted_ci_attempt(source: &SourceIdentity) -> Result<(), XtaskError> {
    if !source.trusted_ci {
        return Ok(());
    }
    if !source.revision_matches_ci {
        return Err(XtaskError::invalid(
            "trusted CI evidence",
            "trusted CI revision does not match the executing source",
        ));
    }
    match env::var("GITHUB_RUN_ATTEMPT").as_deref() {
        Ok("1") => Ok(()),
        Ok(_) => Err(XtaskError::invalid(
            "trusted CI evidence",
            "trusted CI retry attempts are not accepted as fresh evidence",
        )),
        Err(_) => Err(XtaskError::invalid(
            "trusted CI evidence",
            "trusted CI evidence is missing its run-attempt identity",
        )),
    }
}

fn digest_files(
    root: &Path,
    files: &[PathBuf],
    environment: &EnvironmentSnapshot,
) -> Result<String, XtaskError> {
    let mut payload = Vec::new();
    for path in files {
        let relative = path.strip_prefix(root).map_err(|source| {
            XtaskError::invalid_path(path, format!("registry is outside workspace: {source}"))
        })?;
        payload.extend_from_slice(relative.as_os_str().as_encoded_bytes());
        payload.push(0);
        let content = fs::read(path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        payload.extend_from_slice(&content);
        payload.push(0);
    }

    digest_payload(root, environment, payload)
}

fn digest_payload(
    root: &Path,
    environment: &EnvironmentSnapshot,
    payload: Vec<u8>,
) -> Result<String, XtaskError> {
    let output = run_capture_with_input(
        root,
        environment,
        "git",
        ["hash-object", "--stdin"],
        CaptureOptions {
            timeout: Duration::from_secs(10),
            environment: &[],
            input: InvocationInput::Bytes(payload),
        },
        None,
    )?;
    if output.stdout.is_empty() {
        return Err(XtaskError::command(
            "git hash-object --stdin",
            "the controlled invocation returned no standard output",
        ));
    }
    let digest = output.stdout.trim().to_owned();
    if digest.is_empty() {
        return Err(XtaskError::invalid(
            "registry digest",
            "git returned an empty digest",
        ));
    }
    Ok(format!("git-object:{digest}"))
}

fn attempt_identity(revision: &str, started_unix_ms: u128) -> String {
    let revision_prefix = revision.chars().take(12).collect::<String>();
    format!("{started_unix_ms}-{revision_prefix}-{}", std::process::id())
}

fn unix_time_ms() -> Result<u128, XtaskError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|source| XtaskError::invalid("system clock", source.to_string()))
}

fn write_evidence(root: &Path, evidence: &Evidence) -> Result<PathBuf, XtaskError> {
    let directory = root.join("target/quality/evidence");
    let owned_directories =
        OwnedDirectoryChain::create(root, &directory, OwnedLeaf::ExistingAllowed)?;
    let reservation = match AttemptReservation::reserve(root, &directory, evidence) {
        Ok(ReservationOutcome::Claimed(reservation)) => *reservation,
        Ok(ReservationOutcome::RetainedCollision { path }) => {
            return Err(collision_error(evidence, &path));
        },
        Err(error) => return Err(owned_directories.reconcile_failure(error)),
    };
    let collided = reservation.collided;
    let retained = reservation.commit(root)?;
    if collided {
        return Err(collision_error(evidence, &retained));
    }
    Ok(retained)
}

struct AttemptReservation {
    path: PathBuf,
    file: fs::File,
    recovery_path: PathBuf,
    recovery_bytes: String,
    report_staging_path: PathBuf,
    report_final_path: PathBuf,
    report_staging_files: Vec<PathBuf>,
    report_final_files: Vec<PathBuf>,
    report_staging_directories: OwnedDirectoryChain,
    report_final_directories: OwnedDirectoryChain,
    evidence: Evidence,
    collided: bool,
}

enum ReservationOutcome {
    Claimed(Box<AttemptReservation>),
    RetainedCollision { path: PathBuf },
}

enum CandidateReservation {
    Claimed(Box<AttemptReservation>),
    RecoveryOccupied { path: PathBuf },
    PrimaryOccupied { recovery_path: PathBuf },
}

impl AttemptReservation {
    fn reserve(
        root: &Path,
        directory: &Path,
        attempted: &Evidence,
    ) -> Result<ReservationOutcome, XtaskError> {
        for candidate in 0..=(COLLISION_SLOT_COUNT + 1) {
            let (path, evidence, collided, final_candidate) = if candidate == 0 {
                (
                    directory.join(format!("{}.json", attempted.attempt_id)),
                    attempted.clone(),
                    false,
                    false,
                )
            } else if candidate <= COLLISION_SLOT_COUNT {
                let slot = candidate - 1;
                let collision_id = format!("{}-collision-{slot:02}", attempted.attempt_id);
                (
                    directory.join(format!("{collision_id}.json")),
                    collision_evidence(
                        attempted,
                        collision_id,
                        format!("collision-{slot:02}"),
                        "engineering evidence attempt collision; original bytes preserved",
                    )?,
                    true,
                    false,
                )
            } else {
                let exhaustion_id = format!("{}-collision-exhausted", attempted.attempt_id);
                (
                    directory.join(format!("{exhaustion_id}.json")),
                    collision_evidence(
                        attempted,
                        exhaustion_id,
                        COLLISION_OCCUPIED_SET.to_owned(),
                        "all 16 deterministic collision slots were already occupied; every existing byte was preserved",
                    )?,
                    true,
                    true,
                )
            };
            match Self::try_new(root, path, evidence, collided)? {
                CandidateReservation::Claimed(reservation) => {
                    return Ok(ReservationOutcome::Claimed(reservation));
                },
                CandidateReservation::RecoveryOccupied { path } if final_candidate => {
                    return Ok(ReservationOutcome::RetainedCollision { path });
                },
                CandidateReservation::RecoveryOccupied { .. } => {},
                CandidateReservation::PrimaryOccupied { recovery_path } => {
                    return Ok(ReservationOutcome::RetainedCollision {
                        path: recovery_path,
                    });
                },
            }
        }
        Err(XtaskError::invalid(
            "engineering evidence attempt reservation",
            "bounded reservation state machine exhausted without a retained outcome",
        ))
    }

    fn try_new(
        root: &Path,
        path: PathBuf,
        evidence: Evidence,
        collided: bool,
    ) -> Result<CandidateReservation, XtaskError> {
        if !valid_owned_evidence_component(&evidence.attempt_id) {
            return Err(XtaskError::invalid(
                "engineering evidence attempt reservation",
                "reserved attempt identity cannot own a report directory",
            ));
        }
        let recovery_id = format!("{}-recovery", evidence.attempt_id);
        if !valid_owned_evidence_component(&recovery_id) {
            return Err(XtaskError::invalid(
                "engineering evidence recovery reservation",
                "reserved attempt identity cannot own a recovery record",
            ));
        }
        let recovery_path = path
            .parent()
            .ok_or_else(|| XtaskError::invalid_path(&path, "reserved evidence path has no parent"))?
            .join(format!("{recovery_id}.json"));
        let mut recovery_source = evidence.clone();
        recovery_source.attempt_id = recovery_id;
        recovery_source.collision_of = IdentityBinding::exact(evidence.attempt_id.clone());
        recovery_source.collision_slots = IdentityBinding::exact("recovery");
        let recovery_error = XtaskError::invalid(
            "engineering evidence recovery reservation",
            "primary evidence publication has not committed",
        );
        let recovery = report_retention_failure_evidence(&recovery_source, &recovery_error)?;
        let recovery_bytes = evidence_json(&recovery);
        validate_serialized_evidence(&recovery, &recovery_bytes)?;
        let mut recovery_file = match reserve_new_file(&recovery_path) {
            Ok(file) => file,
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                return Ok(CandidateReservation::RecoveryOccupied {
                    path: recovery_path,
                });
            },
            Err(source) => {
                return Err(XtaskError::io(
                    format!("reserve recovery evidence {}", recovery_path.display()),
                    source,
                ));
            },
        };
        if let Err(source) = recovery_file
            .write_all(recovery_bytes.as_bytes())
            .and_then(|()| recovery_file.flush())
            .and_then(|()| recovery_file.sync_all())
        {
            let error = XtaskError::io(
                format!("write recovery evidence {}", recovery_path.display()),
                source,
            );
            return Err(reconcile_owned_file_failure(&recovery_path, error));
        }
        let evidence_directory = recovery_path.parent().ok_or_else(|| {
            XtaskError::invalid_path(&recovery_path, "recovery evidence path has no parent")
        })?;
        sync_directory(evidence_directory)?;
        let file = match reserve_new_file(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                return Ok(CandidateReservation::PrimaryOccupied { recovery_path });
            },
            Err(source) => {
                return Err(XtaskError::io(
                    format!("reserve primary engineering evidence {}", path.display()),
                    source,
                ));
            },
        };
        Ok(CandidateReservation::Claimed(Box::new(Self {
            path,
            file,
            recovery_path,
            recovery_bytes,
            report_staging_path: root
                .join("target/quality/evidence-report-staging")
                .join(&evidence.attempt_id),
            report_final_path: root
                .join("target/quality/evidence-reports")
                .join(&evidence.attempt_id),
            report_staging_files: Vec::new(),
            report_final_files: Vec::new(),
            report_staging_directories: OwnedDirectoryChain::default(),
            report_final_directories: OwnedDirectoryChain::default(),
            evidence,
            collided,
        })))
    }

    fn commit(mut self, root: &Path) -> Result<PathBuf, XtaskError> {
        let serialized = evidence_json(&self.evidence);
        validate_serialized_evidence(&self.evidence, &serialized)?;
        let publication = self.publish_primary(root, &serialized);
        if let Err(error) = publication {
            return Err(self.reconcile_failed_publication(error));
        }
        Ok(self.path)
    }

    fn publish_primary(&mut self, root: &Path, serialized: &str) -> Result<(), XtaskError> {
        let final_parent = self.report_final_path.parent().ok_or_else(|| {
            XtaskError::invalid_path(&self.report_final_path, "report path has no parent")
        })?;
        self.report_final_directories =
            OwnedDirectoryChain::create(root, final_parent, OwnedLeaf::ExistingAllowed)?;
        self.report_staging_directories =
            OwnedDirectoryChain::create(root, &self.report_staging_path, OwnedLeaf::MustCreate)?;
        stage_raw_reports(
            &self.report_staging_path,
            &self.evidence,
            &mut self.report_staging_files,
        )?;
        sync_directory(&self.report_staging_path)?;
        claim_final_report_directory(
            &self.report_final_path,
            final_parent,
            &mut self.report_final_directories,
        )?;
        publish_staged_reports(
            &self.report_staging_files,
            &self.report_final_path,
            &mut self.report_final_files,
        )?;
        sync_directory(&self.report_final_path)?;
        sync_directory(final_parent)?;
        cleanup_owned_report_files(&self.report_staging_files)?;
        self.report_staging_directories.cleanup_empty()?;
        self.file
            .write_all(serialized.as_bytes())
            .and_then(|()| self.file.flush())
            .and_then(|()| self.file.sync_all())
            .map_err(|source| {
                XtaskError::io(
                    format!("write engineering evidence {}", self.path.display()),
                    source,
                )
            })?;
        cleanup_recovery_marker(&self.recovery_path)?;
        let evidence_parent = self.path.parent().ok_or_else(|| {
            XtaskError::invalid_path(&self.path, "primary evidence path has no parent")
        })?;
        if let Err(error) = sync_directory(evidence_parent) {
            let restoration =
                restore_recovery_marker(&self.recovery_path, self.recovery_bytes.as_bytes());
            return match restoration {
                Ok(()) => Err(error),
                Err(restoration_error) => Err(XtaskError::invalid(
                    "engineering evidence recovery restoration",
                    format!("{error}; recovery restoration also failed: {restoration_error}"),
                )),
            };
        }
        Ok(())
    }

    fn reconcile_failed_publication(&self, error: XtaskError) -> XtaskError {
        let mut cleanup_errors = Vec::new();
        for cleanup in [
            cleanup_owned_report_files(&self.report_staging_files),
            cleanup_owned_report_files(&self.report_final_files),
            cleanup_primary_evidence(&self.path),
            self.report_staging_directories.cleanup_empty(),
            self.report_final_directories.cleanup_empty(),
        ] {
            if let Err(cleanup_error) = cleanup {
                cleanup_errors.push(cleanup_error.to_string());
            }
        }
        if let Err(recovery_error) =
            ensure_recovery_marker(&self.recovery_path, self.recovery_bytes.as_bytes())
        {
            cleanup_errors.push(recovery_error.to_string());
        }
        if cleanup_errors.is_empty() {
            error
        } else {
            XtaskError::invalid(
                "engineering evidence publication recovery",
                format!(
                    "{error}; cleanup also failed: {}; immutable recovery retained at {}",
                    cleanup_errors.join("; "),
                    self.recovery_path.display()
                ),
            )
        }
    }
}

fn path_exists(path: &Path) -> Result<bool, XtaskError> {
    path.try_exists()
        .map_err(|source| XtaskError::io(format!("inspect {}", path.display()), source))
}

fn sync_directory(path: &Path) -> Result<(), XtaskError> {
    let directory = fs::File::open(path)
        .map_err(|source| XtaskError::io(format!("open directory {}", path.display()), source))?;
    directory
        .sync_all()
        .map_err(|source| XtaskError::io(format!("sync directory {}", path.display()), source))
}

#[derive(Default)]
struct OwnedDirectoryChain {
    created: Vec<PathBuf>,
}

#[derive(Clone, Copy)]
enum OwnedLeaf {
    ExistingAllowed,
    MustCreate,
}

impl OwnedDirectoryChain {
    fn create(root: &Path, target: &Path, leaf: OwnedLeaf) -> Result<Self, XtaskError> {
        let relative = target.strip_prefix(root).map_err(|source| {
            XtaskError::invalid_path(
                target,
                format!("owned directory target is outside its evidence root: {source}"),
            )
        })?;
        let mut chain = Self::default();
        let mut current = root.to_path_buf();
        let component_count = relative.components().count();
        if component_count == 0 {
            return Err(XtaskError::invalid_path(
                target,
                "owned directory target must be below its evidence root",
            ));
        }

        for (index, component) in relative.components().enumerate() {
            let Component::Normal(name) = component else {
                return Err(chain.reconcile_failure(XtaskError::invalid_path(
                    target,
                    "owned directory target contains a non-normal path component",
                )));
            };
            let parent = current.clone();
            current.push(name);
            let is_leaf = index + 1 == component_count;
            match fs::create_dir(&current) {
                Ok(()) => {
                    chain.created.push(current.clone());
                    if let Err(error) = sync_owned_directory_entry(&parent, &current) {
                        return Err(chain.reconcile_failure(error));
                    }
                },
                Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                    if is_leaf && matches!(leaf, OwnedLeaf::MustCreate) {
                        return Err(chain.reconcile_failure(XtaskError::invalid_path(
                            &current,
                            "owned evidence directory is already occupied",
                        )));
                    }
                    if !current.is_dir() {
                        return Err(chain.reconcile_failure(XtaskError::invalid_path(
                            &current,
                            "owned evidence directory component is not a directory",
                        )));
                    }
                },
                Err(source) => {
                    return Err(chain.reconcile_failure(XtaskError::io(
                        format!("create owned evidence directory {}", current.display()),
                        source,
                    )));
                },
            }
        }
        Ok(chain)
    }

    fn adopt_created_directory(&mut self, directory: &Path) {
        self.created.push(directory.to_path_buf());
    }

    fn reconcile_failure(self, error: XtaskError) -> XtaskError {
        match self.cleanup_empty() {
            Ok(()) => error,
            Err(cleanup) => XtaskError::invalid(
                "owned evidence directory reconciliation",
                format!("{error}; cleanup also failed: {cleanup}"),
            ),
        }
    }

    fn cleanup_empty(&self) -> Result<(), XtaskError> {
        for (depth, directory) in self.created.iter().rev().enumerate() {
            match fs::remove_dir(directory) {
                Ok(()) => {
                    let parent = directory.parent().ok_or_else(|| {
                        XtaskError::invalid_path(
                            directory,
                            "owned evidence directory has no parent",
                        )
                    })?;
                    sync_directory(parent)?;
                },
                Err(source) if source.kind() == ErrorKind::NotFound => {},
                Err(source) if source.kind() == ErrorKind::DirectoryNotEmpty && depth > 0 => {
                    break;
                },
                Err(source) if source.kind() == ErrorKind::DirectoryNotEmpty => {
                    return Err(XtaskError::io(
                        format!(
                            "preserve non-owned content in owned directory {}",
                            directory.display()
                        ),
                        source,
                    ));
                },
                Err(source) => {
                    return Err(XtaskError::io(
                        format!("remove owned evidence directory {}", directory.display()),
                        source,
                    ));
                },
            }
        }
        Ok(())
    }
}

fn sync_owned_directory_entry(parent: &Path, child: &Path) -> Result<(), XtaskError> {
    sync_directory(child)?;
    sync_directory(parent)
}

fn reserve_new_file(path: &Path) -> Result<fs::File, std::io::Error> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

fn reconcile_owned_file_failure(path: &Path, error: XtaskError) -> XtaskError {
    let cleanup = match fs::remove_file(path) {
        Ok(()) => path
            .parent()
            .ok_or_else(|| XtaskError::invalid_path(path, "owned file has no parent"))
            .and_then(sync_directory),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(XtaskError::io(
            format!("remove owned file {}", path.display()),
            source,
        )),
    };
    match cleanup {
        Ok(()) => error,
        Err(cleanup_error) => XtaskError::invalid(
            "owned evidence file reconciliation",
            format!("{error}; cleanup also failed: {cleanup_error}"),
        ),
    }
}

fn collision_evidence(
    attempted: &Evidence,
    attempt_id: String,
    collision_slots: String,
    detail: &str,
) -> Result<Evidence, XtaskError> {
    let mut collision = attempted.clone();
    collision.attempt_id = attempt_id;
    collision.collision_of = IdentityBinding::exact(attempted.attempt_id.clone());
    collision.collision_slots = IdentityBinding::exact(collision_slots);
    collision.result = GateStatus::Failed;
    collision.merge_eligible = false;
    collision.ended_unix_ms = unix_time_ms()?;
    collision.gates = exceptional_gate_attempts(
        ExceptionalAttemptMode::Collision,
        &collision.attempt_id,
        &attempted.gates,
        detail,
    );
    Ok(collision)
}

fn report_retention_failure_evidence(
    reserved: &Evidence,
    error: &XtaskError,
) -> Result<Evidence, XtaskError> {
    let mut failed = reserved.clone();
    failed.result = GateStatus::Failed;
    failed.merge_eligible = false;
    failed.ended_unix_ms = unix_time_ms()?;
    let detail = bounded_detail(&format!("raw report retention failed closed: {error}"));
    failed.gates = exceptional_gate_attempts(
        ExceptionalAttemptMode::Recovery,
        &failed.attempt_id,
        &reserved.gates,
        &detail,
    );
    for gate in &mut failed.gates {
        if gate.gate_id == "EG-00" {
            gate.raw_report =
                RawReportBinding::NotApplicable(NotApplicableReason::ReportRetentionFailed);
            gate.raw_report_content = None;
            gate.detail.clone_from(&detail);
        }
    }
    Ok(failed)
}

fn bounded_detail(detail: &str) -> String {
    detail.chars().take(16_384).collect()
}

fn collision_error(evidence: &Evidence, retained: &Path) -> XtaskError {
    XtaskError::invalid(
        "engineering evidence attempt collision",
        format!(
            "attempt `{}` already exists; every original byte was preserved and the failed collision verdict is retained at {}",
            evidence.attempt_id,
            retained.display()
        ),
    )
}

fn stage_raw_reports(
    staging_path: &Path,
    evidence: &Evidence,
    owned_files: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    for gate in &evidence.gates {
        let RawReportBinding::Exact { .. } = &gate.raw_report else {
            continue;
        };
        let content = gate.raw_report_content.as_ref().ok_or_else(|| {
            XtaskError::invalid(
                "engineering evidence raw report",
                format!(
                    "selected gate `{}` omitted its report content",
                    gate.gate_id
                ),
            )
        })?;
        validate_raw_report_binding(&evidence.attempt_id, gate)?;
        let report_path = staging_path.join(format!("{}.json", gate.gate_id));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&report_path)
            .map_err(|source| {
                XtaskError::io(
                    format!(
                        "engineering evidence raw report: create new {}",
                        report_path.display()
                    ),
                    source,
                )
            })?;
        owned_files.push(report_path.clone());
        file.write_all(content.as_bytes())
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|source| XtaskError::io(format!("write {}", report_path.display()), source))?;
        let retained = fs::read(&report_path)
            .map_err(|source| XtaskError::io(format!("read {}", report_path.display()), source))?;
        if retained != content.as_bytes() {
            return Err(XtaskError::invalid_path(
                &report_path,
                "retained raw report bytes differ from the validated report",
            ));
        }
    }
    Ok(())
}

fn claim_final_report_directory(
    final_path: &Path,
    final_parent: &Path,
    owned_directories: &mut OwnedDirectoryChain,
) -> Result<(), XtaskError> {
    match fs::create_dir(final_path) {
        Ok(()) => {
            owned_directories.adopt_created_directory(final_path);
            sync_owned_directory_entry(final_parent, final_path)
        },
        Err(source) if source.kind() == ErrorKind::AlreadyExists => Err(XtaskError::invalid_path(
            final_path,
            "engineering evidence raw report attempt path is already occupied",
        )),
        Err(source) => Err(XtaskError::io(
            format!(
                "claim engineering evidence raw report attempt path {}",
                final_path.display()
            ),
            source,
        )),
    }
}

fn publish_staged_reports(
    staging_files: &[PathBuf],
    final_path: &Path,
    owned_files: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    for staging_file in staging_files {
        let name = staging_file.file_name().ok_or_else(|| {
            XtaskError::invalid_path(staging_file, "staged report file has no filename")
        })?;
        let final_file = final_path.join(name);
        match fs::hard_link(staging_file, &final_file) {
            Ok(()) => owned_files.push(final_file.clone()),
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                return Err(XtaskError::invalid_path(
                    &final_file,
                    "engineering evidence raw report final path is already occupied",
                ));
            },
            Err(source) => {
                return Err(XtaskError::io(
                    format!(
                        "publish staged report {} to {}",
                        staging_file.display(),
                        final_file.display()
                    ),
                    source,
                ));
            },
        }
        fs::File::open(&final_file)
            .and_then(|file| file.sync_all())
            .map_err(|source| {
                XtaskError::io(
                    format!("synchronize published report {}", final_file.display()),
                    source,
                )
            })?;
    }
    Ok(())
}

fn cleanup_owned_report_files(paths: &[PathBuf]) -> Result<(), XtaskError> {
    for path in paths {
        match fs::remove_file(path) {
            Ok(()) => {
                let parent = path.parent().ok_or_else(|| {
                    XtaskError::invalid_path(path, "owned report file has no parent")
                })?;
                sync_directory(parent)?;
            },
            Err(source) if source.kind() == ErrorKind::NotFound => {},
            Err(source) => {
                return Err(XtaskError::io(
                    format!("remove owned report file {}", path.display()),
                    source,
                ));
            },
        }
    }
    Ok(())
}

fn cleanup_primary_evidence(path: &Path) -> Result<(), XtaskError> {
    match fs::remove_file(path) {
        Ok(()) => {
            let parent = path.parent().ok_or_else(|| {
                XtaskError::invalid_path(path, "incomplete primary evidence has no parent")
            })?;
            sync_directory(parent).map_err(|error| {
                XtaskError::invalid(
                    "incomplete primary evidence cleanup",
                    format!(
                        "removed {} but could not synchronize its parent: {error}",
                        path.display()
                    ),
                )
            })
        },
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(XtaskError::io(
            format!("remove incomplete primary evidence {}", path.display()),
            source,
        )),
    }
}

fn cleanup_recovery_marker(path: &Path) -> Result<(), XtaskError> {
    fs::remove_file(path).map_err(|source| {
        XtaskError::io(
            format!("reconcile recovery evidence {}", path.display()),
            source,
        )
    })
}

fn ensure_recovery_marker(path: &Path, bytes: &[u8]) -> Result<(), XtaskError> {
    if path_exists(path)? {
        return Ok(());
    }
    restore_recovery_marker(path, bytes)
}

fn restore_recovery_marker(path: &Path, bytes: &[u8]) -> Result<(), XtaskError> {
    let mut file = reserve_new_file(path).map_err(|source| {
        XtaskError::io(
            format!("restore recovery evidence {}", path.display()),
            source,
        )
    })?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|source| {
            XtaskError::io(
                format!("restore recovery evidence {}", path.display()),
                source,
            )
        })?;
    let parent = path.parent().ok_or_else(|| {
        XtaskError::invalid_path(path, "recovery evidence path has no parent directory")
    })?;
    sync_directory(parent)
}

fn exceptional_gate_attempts(
    mode: ExceptionalAttemptMode,
    attempt_id: &str,
    attempts: &[GateAttempt],
    aggregator_detail: &str,
) -> Vec<GateAttempt> {
    attempts
        .iter()
        .map(|attempt| {
            let is_aggregator = attempt.gate_id == "EG-00";
            let result = if is_aggregator {
                GateStatus::Failed
            } else {
                GateStatus::NotSelected
            };
            let mut invocation = attempt.invocation.clone();
            let mode_argument = match (mode, is_aggregator) {
                (ExceptionalAttemptMode::Collision, true) => "--collision-retention",
                (ExceptionalAttemptMode::Collision, false) => "--blocked-by-collision",
                (ExceptionalAttemptMode::Recovery, true) => "--report-retention-failure",
                (ExceptionalAttemptMode::Recovery, false) => "--blocked-by-eg-00",
            };
            invocation.arguments = vec![
                "quality".to_owned(),
                mode_argument.to_owned(),
                attempt.gate_id.clone(),
            ];
            invocation.controlled_steps.clear();
            build_gate_attempt(
                attempt_id,
                GateAttemptDefinition {
                    gate_id: attempt.gate_id.clone(),
                    budget_seconds: attempt.budget_seconds,
                    invocation,
                    owner: attempt.owner.clone(),
                },
                GateAttemptOutcome {
                    result,
                    duration_ms: 0,
                    detail: if is_aggregator {
                        aggregator_detail.to_owned()
                    } else {
                        match mode {
                            ExceptionalAttemptMode::Collision => {
                                "EG-00 failed closed during collision retention; gate was not selected"
                            }
                            ExceptionalAttemptMode::Recovery => {
                                "EG-00 failed closed during publication recovery; gate was not selected"
                            }
                        }
                        .to_owned()
                    },
                    controlled_steps: Vec::new(),
                },
            )
        })
        .collect()
}

fn validate_serialized_evidence(evidence: &Evidence, serialized: &str) -> Result<(), XtaskError> {
    if evidence.gates.len() != 25 {
        return Err(XtaskError::invalid(
            "engineering evidence",
            format!(
                "attempt contains {} gates, schema requires 25",
                evidence.gates.len()
            ),
        ));
    }
    let gate_ids = evidence
        .gates
        .iter()
        .map(|gate| gate.gate_id.clone())
        .collect::<BTreeSet<_>>();
    if gate_ids != CANONICAL_GATE_IDS.into_iter().map(str::to_owned).collect() {
        return Err(XtaskError::invalid(
            "engineering evidence",
            "attempt gate identities do not match the complete canonical gate set",
        ));
    }
    if evidence.attempt_id.is_empty()
        || !valid_hex_identity(&evidence.source.revision)
        || !valid_registry_digest(&evidence.registry_digest)
        || !valid_registry_digest(&evidence.environment_digest)
        || !valid_registry_digest(&evidence.identity.target_registry_digest)
        || !valid_registry_digest(&evidence.identity.toolchain_digest)
        || !valid_registry_digest(&evidence.identity.fixture_registry_digest)
        || evidence.ended_unix_ms < evidence.started_unix_ms
    {
        return Err(XtaskError::invalid(
            "engineering evidence",
            "attempt identity, source, digest, and time ordering must be complete",
        ));
    }
    validate_evidence_identity(evidence)?;
    let any_failed = evidence
        .gates
        .iter()
        .any(|gate| gate.result == GateStatus::Failed);
    if (evidence.result == GateStatus::Failed) != any_failed
        || evidence.result == GateStatus::NotSelected
        || (evidence.merge_eligible && evidence.result != GateStatus::Passed)
    {
        return Err(XtaskError::invalid(
            "engineering evidence",
            "aggregate result does not match the independent gate verdicts",
        ));
    }
    for gate in &evidence.gates {
        if gate.gate_id.is_empty()
            || gate.budget_seconds == 0
            || gate.command_digest != command_digest(&gate.invocation)
            || gate.detail.is_empty()
        {
            return Err(XtaskError::invalid(
                "engineering evidence",
                format!("gate `{}` contains an empty required field", gate.gate_id),
            ));
        }
        if gate.result == GateStatus::NotSelected && gate.duration_ms != 0 {
            return Err(XtaskError::invalid(
                "engineering evidence",
                format!(
                    "not-selected gate `{}` cannot report execution time",
                    gate.gate_id
                ),
            ));
        }
        match (&gate.owner, gate.result) {
            (IdentityBinding::Exact(owner), _) if !owner.is_empty() => {},
            (
                IdentityBinding::NotApplicable(
                    NotApplicableReason::UnavailableBeforeRegistryValidation,
                ),
                GateStatus::NotSelected,
            ) => {},
            _ => {
                return Err(XtaskError::invalid(
                    "engineering evidence",
                    format!(
                        "gate `{}` has no applicable accountable owner",
                        gate.gate_id
                    ),
                ));
            },
        }
        validate_gate_invocation(gate)?;
        match (&gate.raw_report, &gate.raw_report_content, gate.result) {
            (
                RawReportBinding::NotApplicable(NotApplicableReason::GateNotSelected),
                None,
                GateStatus::NotSelected,
            ) => {},
            (
                RawReportBinding::NotApplicable(NotApplicableReason::ReportRetentionFailed),
                None,
                GateStatus::Failed,
            ) if gate.gate_id == "EG-00" => {},
            (
                RawReportBinding::NotApplicable(NotApplicableReason::ReportEncodingFailed),
                None,
                GateStatus::Failed,
            ) => {},
            (RawReportBinding::Exact { .. }, Some(_), GateStatus::Passed | GateStatus::Failed) => {
                validate_raw_report_binding(&evidence.attempt_id, gate)?;
            },
            _ => {
                return Err(XtaskError::invalid(
                    "engineering evidence",
                    format!(
                        "gate `{}` has inconsistent raw-report applicability",
                        gate.gate_id
                    ),
                ));
            },
        }
    }
    parse_evidence_record(Path::new("in-memory-engineering-evidence.json"), serialized)?;
    Ok(())
}

fn validate_gate_invocation(gate: &GateAttempt) -> Result<(), XtaskError> {
    let invocation = &gate.invocation;
    if invocation.program != "cargo-xtask-quality/internal"
        || invocation.arguments.is_empty()
        || invocation.arguments.first().map(String::as_str) != Some("quality")
        || invocation.working_directory != "engineering-workspace"
        || !valid_sha256_digest(&invocation.environment_digest)
        || invocation.timeout_seconds != gate.budget_seconds
        || invocation.memory_mib == 0
        || invocation.activation.is_empty()
        || invocation.exception_class.is_empty()
    {
        return Err(XtaskError::invalid(
            "engineering evidence invocation",
            format!(
                "gate `{}` has an incomplete structured invocation",
                gate.gate_id
            ),
        ));
    }
    for step in &invocation.controlled_steps {
        if step.program.is_empty()
            || step.resolved_program.is_empty()
            || step.arguments.iter().any(String::is_empty)
            || step.working_directory != "engineering-workspace"
            || !valid_sha256_digest(&step.environment_digest)
            || step.timeout_ms == 0
            || !matches!(step.input_kind.as_str(), "null" | "bytes")
            || (step.input_kind == "null" && (step.input_bytes != 0 || step.input_sha256 != "-"))
            || (step.input_kind == "bytes" && !valid_sha256_digest(&step.input_sha256))
        {
            return Err(XtaskError::invalid(
                "engineering evidence invocation",
                format!(
                    "gate `{}` has an incomplete controlled invocation step",
                    gate.gate_id
                ),
            ));
        }
    }
    Ok(())
}

fn validate_raw_report_binding(attempt_id: &str, gate: &GateAttempt) -> Result<(), XtaskError> {
    let RawReportBinding::Exact {
        path,
        digest,
        bytes,
        content_type,
    } = &gate.raw_report
    else {
        return Err(XtaskError::invalid(
            "engineering evidence raw report",
            format!(
                "selected gate `{}` omitted exact report binding",
                gate.gate_id
            ),
        ));
    };
    let content = gate.raw_report_content.as_ref().ok_or_else(|| {
        XtaskError::invalid(
            "engineering evidence raw report",
            format!("selected gate `{}` omitted report content", gate.gate_id),
        )
    })?;
    if path.as_str() != raw_report_relative_path(attempt_id, &gate.gate_id)
        || !valid_sha256_digest(digest)
        || *content_type != RAW_REPORT_CONTENT_TYPE
    {
        return Err(XtaskError::invalid(
            "engineering evidence raw report",
            format!(
                "gate `{}` has an invalid exact report binding",
                gate.gate_id
            ),
        ));
    }
    if *bytes > MAXIMUM_RAW_REPORT_BYTES || content.len() > MAXIMUM_RAW_REPORT_BYTES {
        return Err(XtaskError::invalid(
            "engineering evidence raw report",
            format!(
                "gate `{}` raw report exceeds {MAXIMUM_RAW_REPORT_BYTES} bytes",
                gate.gate_id
            ),
        ));
    }
    if *bytes != content.len() || digest != &sha256_digest(content.as_bytes()) {
        return Err(XtaskError::invalid(
            "engineering evidence raw report",
            format!(
                "gate `{}` raw report bytes or digest do not match its content",
                gate.gate_id
            ),
        ));
    }
    let parsed = parse_raw_report_record(Path::new(path), content)?;
    let invocation =
        bounded_json::parse(&gate_invocation_json(&gate.invocation)).map_err(|error| {
            XtaskError::invalid(
                "engineering evidence raw report",
                format!("gate invocation cannot be parsed: {error}"),
            )
        })?;
    let controlled_steps = gate
        .invocation
        .controlled_steps
        .iter()
        .map(controlled_invocation_json)
        .map(|step| {
            bounded_json::parse(&step).map_err(|error| {
                XtaskError::invalid(
                    "engineering evidence raw report",
                    format!("controlled invocation cannot be parsed: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.attempt_id != attempt_id
        || parsed.gate_id != gate.gate_id
        || parsed.result != gate.result.as_str()
        || parsed.invocation_digest != gate.command_digest
        || parsed.invocation != invocation
        || parsed.controlled_steps != controlled_steps
    {
        return Err(XtaskError::invalid(
            "engineering evidence raw report",
            format!(
                "gate `{}` report does not exactly cross-reference its evidence",
                gate.gate_id
            ),
        ));
    }
    Ok(())
}

fn validate_evidence_identity(evidence: &Evidence) -> Result<(), XtaskError> {
    for (field, binding, expected) in [
        (
            "release_manifest",
            &evidence.identity.release_manifest,
            NotApplicableReason::NoReleaseManifestForEngineeringAttempt,
        ),
        (
            "artifact",
            &evidence.identity.artifact,
            NotApplicableReason::NoCandidateArtifactForEngineeringAttempt,
        ),
        (
            "effective_configuration",
            &evidence.identity.effective_configuration,
            NotApplicableReason::NoEffectiveConfigurationForEngineeringAttempt,
        ),
        (
            "corpus",
            &evidence.identity.corpus,
            NotApplicableReason::NoCorpusSelected,
        ),
        (
            "approval",
            &evidence.identity.approval,
            NotApplicableReason::NoApprovalClaimed,
        ),
        (
            "exception",
            &evidence.identity.exception,
            NotApplicableReason::NoExceptionApplied,
        ),
    ] {
        if binding != &IdentityBinding::not_applicable(expected) {
            return Err(XtaskError::invalid(
                "engineering evidence",
                format!("`{field}` must use its exact not-applicable reason"),
            ));
        }
    }
    let qualification_fixture_selected = evidence.gates.iter().any(|gate| {
        matches!(
            gate.gate_id.as_str(),
            "EG-CONCURRENCY" | "EG-CORRECT" | "EG-FAULT" | "EG-INTEGRITY" | "EG-RESOURCE"
        ) && gate.result != GateStatus::NotSelected
    });
    match (
        qualification_fixture_selected,
        &evidence.identity.seed,
        &evidence.identity.fault_schedule,
    ) {
        (_, IdentityBinding::Exact(seed), IdentityBinding::Exact(schedule))
            if valid_sha256_digest(seed) && valid_sha256_digest(schedule) => {},
        (
            false,
            IdentityBinding::NotApplicable(NotApplicableReason::NoSeedSelected),
            IdentityBinding::NotApplicable(NotApplicableReason::NoFaultScheduleSelected),
        ) => {},
        _ => {
            return Err(XtaskError::invalid(
                "engineering evidence",
                format!(
                    "fixture-selected attempts and their recovery records require exact seed and fault-schedule digests; selected={qualification_fixture_selected}, seed={}, schedule={}",
                    identity_binding_text(&evidence.identity.seed),
                    identity_binding_text(&evidence.identity.fault_schedule),
                ),
            ));
        },
    }
    if evidence.identity.target != IdentityBinding::exact("engineering-workspace")
        || evidence.identity.verifier != verifier_identity(&evidence.source)
    {
        return Err(XtaskError::invalid(
            "engineering evidence",
            "target or verifier identity does not match the engineering invocation",
        ));
    }
    match (&evidence.collision_of, &evidence.collision_slots) {
        (
            IdentityBinding::NotApplicable(NotApplicableReason::NoCollision),
            IdentityBinding::NotApplicable(NotApplicableReason::NoCollision),
        ) => {},
        (IdentityBinding::Exact(original), IdentityBinding::Exact(slots))
            if !original.is_empty()
                && evidence
                    .attempt_id
                    .strip_prefix(original)
                    .is_some_and(|suffix| suffix.starts_with("-collision-"))
                && ((!evidence.attempt_id.ends_with("-collision-exhausted")
                    && evidence
                        .attempt_id
                        .strip_prefix(&format!("{original}-"))
                        .is_some_and(|suffix| slots == suffix))
                    || (evidence.attempt_id.ends_with("-collision-exhausted")
                        && slots == COLLISION_OCCUPIED_SET))
                && evidence.result == GateStatus::Failed => {},
        (IdentityBinding::Exact(original), IdentityBinding::Exact(slots))
            if !original.is_empty()
                && evidence.attempt_id == format!("{original}-recovery")
                && slots == "recovery"
                && evidence.result == GateStatus::Failed => {},
        _ => {
            return Err(XtaskError::invalid(
                "engineering evidence",
                "collision identity or occupied-slot binding is malformed or inconsistent with the failed verdict",
            ));
        },
    }
    Ok(())
}

fn valid_hex_identity(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_registry_digest(value: &str) -> bool {
    matches!(value, "invalid-registry" | "unavailable-registry-digest")
        || value
            .strip_prefix("git-object:")
            .is_some_and(valid_hex_identity)
}

fn valid_raw_report_schema_path(value: &str) -> bool {
    let Some(relative) = value.strip_prefix("target/quality/evidence-reports/") else {
        return false;
    };
    let Some((attempt_id, report)) = relative.split_once('/') else {
        return false;
    };
    if !valid_owned_evidence_component(attempt_id) || relative.matches('/').count() != 1 {
        return false;
    }
    let Some(gate_id) = report.strip_suffix(".json") else {
        return false;
    };
    gate_id == "EG-00"
        || gate_id.strip_prefix("EG-").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_uppercase())
        })
}

fn evidence_json(evidence: &Evidence) -> String {
    let mut output = String::new();
    output.push_str("{\n");
    output.push_str("  \"schema_version\": 3,\n");
    output.push_str(&format!(
        "  \"attempt_id\": {},\n",
        json_string(&evidence.attempt_id)
    ));
    push_identity_binding(&mut output, 2, "collision_of", &evidence.collision_of, true);
    push_identity_binding(
        &mut output,
        2,
        "collision_slots",
        &evidence.collision_slots,
        true,
    );
    output.push_str(&format!(
        "  \"profile\": {},\n",
        json_string(evidence.profile.as_str())
    ));
    output.push_str(&format!(
        "  \"result\": {},\n",
        json_string(evidence.result.as_str())
    ));
    output.push_str(&format!(
        "  \"merge_eligible\": {},\n",
        evidence.merge_eligible
    ));
    output.push_str("  \"source\": {\n");
    output.push_str(&format!(
        "    \"revision\": {},\n",
        json_string(&evidence.source.revision)
    ));
    output.push_str(&format!("    \"dirty\": {},\n", evidence.source.dirty));
    output.push_str(&format!(
        "    \"trusted_ci\": {}\n",
        evidence.source.trusted_ci
    ));
    output.push_str("  },\n");
    output.push_str(&format!(
        "  \"started_unix_ms\": {},\n",
        evidence.started_unix_ms
    ));
    output.push_str(&format!(
        "  \"ended_unix_ms\": {},\n",
        evidence.ended_unix_ms
    ));
    output.push_str(&format!(
        "  \"registry_digest\": {},\n",
        json_string(&evidence.registry_digest)
    ));
    output.push_str(&format!(
        "  \"environment_digest\": {},\n",
        json_string(&evidence.environment_digest)
    ));
    output.push_str("  \"identity\": {\n");
    push_identity_binding(
        &mut output,
        4,
        "release_manifest",
        &evidence.identity.release_manifest,
        true,
    );
    push_identity_binding(
        &mut output,
        4,
        "artifact",
        &evidence.identity.artifact,
        true,
    );
    push_identity_binding(&mut output, 4, "target", &evidence.identity.target, true);
    output.push_str(&format!(
        "    \"target_registry_digest\": {},\n",
        json_string(&evidence.identity.target_registry_digest)
    ));
    output.push_str(&format!(
        "    \"toolchain_digest\": {},\n",
        json_string(&evidence.identity.toolchain_digest)
    ));
    push_identity_binding(
        &mut output,
        4,
        "effective_configuration",
        &evidence.identity.effective_configuration,
        true,
    );
    output.push_str(&format!(
        "    \"fixture_registry_digest\": {},\n",
        json_string(&evidence.identity.fixture_registry_digest)
    ));
    push_identity_binding(&mut output, 4, "corpus", &evidence.identity.corpus, true);
    push_identity_binding(&mut output, 4, "seed", &evidence.identity.seed, true);
    push_identity_binding(
        &mut output,
        4,
        "fault_schedule",
        &evidence.identity.fault_schedule,
        true,
    );
    push_identity_binding(
        &mut output,
        4,
        "verifier",
        &evidence.identity.verifier,
        true,
    );
    push_identity_binding(
        &mut output,
        4,
        "approval",
        &evidence.identity.approval,
        true,
    );
    push_identity_binding(
        &mut output,
        4,
        "exception",
        &evidence.identity.exception,
        false,
    );
    output.push_str("  },\n");
    output.push_str("  \"gates\": [\n");
    let mut first = true;
    for gate in &evidence.gates {
        if !first {
            output.push_str(",\n");
        }
        first = false;
        output.push_str("    {\n");
        output.push_str(&format!(
            "      \"gate_id\": {},\n",
            json_string(&gate.gate_id)
        ));
        output.push_str(&format!(
            "      \"result\": {},\n",
            json_string(gate.result.as_str())
        ));
        output.push_str(&format!("      \"duration_ms\": {},\n", gate.duration_ms));
        output.push_str(&format!(
            "      \"budget_seconds\": {},\n",
            gate.budget_seconds
        ));
        output.push_str("      \"invocation\": ");
        output.push_str(&gate_invocation_json(&gate.invocation));
        output.push_str(",\n");
        output.push_str(&format!(
            "      \"command_digest\": {},\n",
            json_string(&gate.command_digest)
        ));
        push_identity_binding(&mut output, 6, "owner", &gate.owner, true);
        push_raw_report_binding(&mut output, 6, "raw_report", &gate.raw_report, true);
        output.push_str(&format!(
            "      \"detail\": {}\n",
            json_string(&gate.detail)
        ));
        output.push_str("    }");
    }
    output.push_str("\n  ]\n");
    output.push_str("}\n");
    output
}

fn gate_invocation_json(invocation: &GateInvocation) -> String {
    let arguments = invocation
        .arguments
        .iter()
        .map(|argument| json_string(argument))
        .collect::<Vec<_>>()
        .join(",");
    let steps = invocation
        .controlled_steps
        .iter()
        .map(controlled_invocation_json)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"program\":{},\"arguments\":[{arguments}],\"working_directory\":{},\"environment_digest\":{},\"timeout_seconds\":{},\"memory_mib\":{},\"activation\":{},\"exception_class\":{},\"controlled_steps\":[{steps}]}}",
        json_string(&invocation.program),
        json_string(&invocation.working_directory),
        json_string(&invocation.environment_digest),
        invocation.timeout_seconds,
        invocation.memory_mib,
        json_string(&invocation.activation),
        json_string(&invocation.exception_class),
    )
}

fn controlled_invocation_json(invocation: &ControlledInvocation) -> String {
    let arguments = invocation
        .arguments
        .iter()
        .map(|argument| json_string(argument))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"program\":{},\"resolved_program\":{},\"arguments\":[{arguments}],\"working_directory\":{},\"environment_digest\":{},\"timeout_ms\":{},\"input_kind\":{},\"input_bytes\":{},\"input_sha256\":{}}}",
        json_string(&invocation.program),
        json_string(&invocation.resolved_program),
        json_string(&invocation.working_directory),
        json_string(&invocation.environment_digest),
        invocation.timeout_ms,
        json_string(&invocation.input_kind),
        invocation.input_bytes,
        json_string(&invocation.input_sha256),
    )
}

fn raw_report_json_with_limit(
    report: RawReportDocument<'_>,
    maximum_bytes: usize,
) -> Result<String, XtaskError> {
    let mut output = BoundedJsonWriter::new(maximum_bytes);
    output.push_literal("{\n  \"schema_version\": 1,\n  \"content_type\": ")?;
    output.push_json_string(RAW_REPORT_CONTENT_TYPE)?;
    output.push_literal(",\n  \"attempt_id\": ")?;
    output.push_json_string(report.attempt_id)?;
    output.push_literal(",\n  \"gate_id\": ")?;
    output.push_json_string(report.gate_id)?;
    output.push_literal(",\n  \"verdict\": ")?;
    output.push_json_string(report.result.as_str())?;
    output.push_literal(",\n  \"duration_ms\": ")?;
    output.push_number(report.duration_ms)?;
    output.push_literal(",\n  \"invocation_digest\": ")?;
    output.push_json_string(report.invocation_digest)?;
    output.push_literal(",\n  \"invocation\": ")?;
    push_gate_invocation_json(&mut output, report.invocation)?;
    output.push_literal(",\n  \"detail\": ")?;
    output.push_json_string(report.detail)?;
    output.push_literal(",\n  \"controlled_steps\": [")?;
    for (index, step) in report.controlled_steps.iter().enumerate() {
        if index != 0 {
            output.push_literal(",")?;
        }
        output.push_literal("{\"invocation\":")?;
        push_controlled_invocation_json(&mut output, &step.invocation)?;
        output.push_literal(",\"verdict\":")?;
        output.push_json_string(&step.verdict)?;
        output.push_literal(",\"stdout\":")?;
        output.push_json_string(&step.stdout)?;
        output.push_literal(",\"stderr\":")?;
        output.push_json_string(&step.stderr)?;
        output.push_literal("}")?;
    }
    output.push_literal("]\n}\n")?;
    Ok(output.finish())
}

fn push_gate_invocation_json(
    output: &mut BoundedJsonWriter,
    invocation: &GateInvocation,
) -> Result<(), XtaskError> {
    output.push_literal("{\"program\":")?;
    output.push_json_string(&invocation.program)?;
    output.push_literal(",\"arguments\":[")?;
    for (index, argument) in invocation.arguments.iter().enumerate() {
        if index != 0 {
            output.push_literal(",")?;
        }
        output.push_json_string(argument)?;
    }
    output.push_literal("],\"working_directory\":")?;
    output.push_json_string(&invocation.working_directory)?;
    output.push_literal(",\"environment_digest\":")?;
    output.push_json_string(&invocation.environment_digest)?;
    output.push_literal(",\"timeout_seconds\":")?;
    output.push_number(invocation.timeout_seconds)?;
    output.push_literal(",\"memory_mib\":")?;
    output.push_number(invocation.memory_mib)?;
    output.push_literal(",\"activation\":")?;
    output.push_json_string(&invocation.activation)?;
    output.push_literal(",\"exception_class\":")?;
    output.push_json_string(&invocation.exception_class)?;
    output.push_literal(",\"controlled_steps\":[")?;
    for (index, step) in invocation.controlled_steps.iter().enumerate() {
        if index != 0 {
            output.push_literal(",")?;
        }
        push_controlled_invocation_json(output, step)?;
    }
    output.push_literal("]}")
}

fn push_controlled_invocation_json(
    output: &mut BoundedJsonWriter,
    invocation: &ControlledInvocation,
) -> Result<(), XtaskError> {
    output.push_literal("{\"program\":")?;
    output.push_json_string(&invocation.program)?;
    output.push_literal(",\"resolved_program\":")?;
    output.push_json_string(&invocation.resolved_program)?;
    output.push_literal(",\"arguments\":[")?;
    for (index, argument) in invocation.arguments.iter().enumerate() {
        if index != 0 {
            output.push_literal(",")?;
        }
        output.push_json_string(argument)?;
    }
    output.push_literal("],\"working_directory\":")?;
    output.push_json_string(&invocation.working_directory)?;
    output.push_literal(",\"environment_digest\":")?;
    output.push_json_string(&invocation.environment_digest)?;
    output.push_literal(",\"timeout_ms\":")?;
    output.push_number(invocation.timeout_ms)?;
    output.push_literal(",\"input_kind\":")?;
    output.push_json_string(&invocation.input_kind)?;
    output.push_literal(",\"input_bytes\":")?;
    output.push_number(invocation.input_bytes)?;
    output.push_literal(",\"input_sha256\":")?;
    output.push_json_string(&invocation.input_sha256)?;
    output.push_literal("}")
}

struct BoundedJsonWriter {
    output: String,
    maximum_bytes: usize,
}

impl BoundedJsonWriter {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            output: String::new(),
            maximum_bytes,
        }
    }

    fn push_literal(&mut self, value: &str) -> Result<(), XtaskError> {
        self.reserve(value.len())?;
        self.output.push_str(value);
        Ok(())
    }

    fn push_number(&mut self, value: impl ToString) -> Result<(), XtaskError> {
        let value = value.to_string();
        self.push_literal(&value)
    }

    fn push_json_string(&mut self, value: &str) -> Result<(), XtaskError> {
        let encoded_bytes = encoded_json_string_bytes(value)?;
        self.reserve(encoded_bytes)?;
        self.output.push('"');
        for character in value.chars() {
            match character {
                '"' => self.output.push_str("\\\""),
                '\\' => self.output.push_str("\\\\"),
                '\n' => self.output.push_str("\\n"),
                '\r' => self.output.push_str("\\r"),
                '\t' => self.output.push_str("\\t"),
                control if control.is_control() => {
                    let code = u32::from(control);
                    if code <= u32::from(u16::MAX) {
                        push_json_hex_quad(&mut self.output, code as u16);
                    } else {
                        let scalar = code - 0x1_0000;
                        let high = 0xD800 | ((scalar >> 10) as u16);
                        let low = 0xDC00 | ((scalar & 0x03FF) as u16);
                        push_json_hex_quad(&mut self.output, high);
                        push_json_hex_quad(&mut self.output, low);
                    }
                },
                other => self.output.push(other),
            }
        }
        self.output.push('"');
        Ok(())
    }

    fn reserve(&mut self, additional: usize) -> Result<(), XtaskError> {
        let encoded_bytes = self.output.len().checked_add(additional).ok_or_else(|| {
            XtaskError::invalid(
                "gate report resource limit",
                "encoded raw report byte accounting overflowed",
            )
        })?;
        if encoded_bytes > self.maximum_bytes {
            return Err(XtaskError::invalid(
                "gate report resource limit",
                format!("encoded raw report exceeds {} bytes", self.maximum_bytes),
            ));
        }
        self.output.try_reserve_exact(additional).map_err(|_| {
            XtaskError::invalid(
                "gate report resource limit",
                "encoded raw report allocation could not be reserved",
            )
        })
    }

    fn finish(self) -> String {
        self.output
    }
}

fn encoded_json_string_bytes(value: &str) -> Result<usize, XtaskError> {
    let mut bytes = 2_usize;
    for character in value.chars() {
        let encoded = match character {
            '"' | '\\' | '\n' | '\r' | '\t' => 2,
            control if control.is_control() && u32::from(control) <= u32::from(u16::MAX) => 6,
            control if control.is_control() => 12,
            other => other.len_utf8(),
        };
        bytes = bytes.checked_add(encoded).ok_or_else(|| {
            XtaskError::invalid(
                "gate report resource limit",
                "encoded JSON string byte accounting overflowed",
            )
        })?;
    }
    Ok(bytes)
}

fn push_json_hex_quad(output: &mut String, value: u16) {
    output.push_str("\\u");
    for shift in [12, 8, 4, 0] {
        let nibble = ((value >> shift) & 0x000F) as u8;
        let encoded = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        output.push(char::from(encoded));
    }
}

fn push_raw_report_binding(
    output: &mut String,
    indentation: usize,
    field: &str,
    binding: &RawReportBinding,
    trailing_comma: bool,
) {
    let spaces = " ".repeat(indentation);
    let value = match binding {
        RawReportBinding::Exact {
            path,
            digest,
            bytes,
            content_type,
        } => format!(
            "{{\"applicability\": \"exact\", \"path\": {}, \"sha256\": {}, \"bytes\": {bytes}, \"content_type\": {}, \"reason\": \"-\"}}",
            json_string(path),
            json_string(digest),
            json_string(content_type),
        ),
        RawReportBinding::NotApplicable(reason) => format!(
            "{{\"applicability\": \"not-applicable\", \"path\": \"-\", \"sha256\": \"-\", \"bytes\": 0, \"content_type\": \"-\", \"reason\": {}}}",
            json_string(reason.as_str()),
        ),
    };
    output.push_str(&format!(
        "{spaces}{}: {value}{}\n",
        json_string(field),
        if trailing_comma { "," } else { "" }
    ));
}

fn push_identity_binding(
    output: &mut String,
    indentation: usize,
    field: &str,
    binding: &IdentityBinding,
    trailing_comma: bool,
) {
    let spaces = " ".repeat(indentation);
    let (applicability, value, reason) = match binding {
        IdentityBinding::Exact(value) => ("exact", value.as_str(), "-"),
        IdentityBinding::NotApplicable(reason) => ("not-applicable", "-", reason.as_str()),
    };
    output.push_str(&format!(
        "{spaces}{}: {{\"applicability\": {}, \"value\": {}, \"reason\": {}}}{}\n",
        json_string(field),
        json_string(applicability),
        json_string(value),
        json_string(reason),
        if trailing_comma { "," } else { "" }
    ));
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control.is_control() => {
                output.push_str(&format!("\\u{:04x}", u32::from(control)));
            },
            other => output.push(other),
        }
    }
    output.push('"');
    output
}

fn one_line(value: &str) -> String {
    value
        .split_whitespace()
        .take(32)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        CANONICAL_GATE_IDS, ControlledInvocation, ControlledStepReport, EnvironmentSnapshot,
        Evidence, ExecutionTools, GateAttemptDefinition, GateAttemptOutcome, GateInvocation,
        GateStatus, IdentityBinding, M0_02_MUTATION_SELECTOR, M0_03_MUTATION_SELECTOR,
        M0_04_MUTATION_SELECTOR, MAXIMUM_ACTIVATION_CHARACTERS, MAXIMUM_ATTEMPT_ID_CHARACTERS,
        MAXIMUM_CAPTURED_REPORT_STREAM_BYTES, MAXIMUM_CONTROLLED_ARGUMENT_CHARACTERS,
        MAXIMUM_CONTROLLED_PROGRAM_CHARACTERS, MAXIMUM_EXCEPTION_CLASS_CHARACTERS,
        MAXIMUM_GATE_ARGUMENT_CHARACTERS, MAXIMUM_GATE_DETAIL_CHARACTERS,
        MAXIMUM_IDENTITY_VALUE_CHARACTERS, MAXIMUM_RESOLVED_PROGRAM_CHARACTERS,
        NEXTEST_PR_ARGUMENTS, NotApplicableReason, Options, Profile, RawReportBinding,
        RawReportDocument, SourceIdentity, build_gate_attempt_with_report_limit,
        character_count_in_range, evidence_json, gate_invocation_json, json_string,
        nextest_completed_test_count, parse_gate_invocation_value, raw_report_json_with_limit,
        registered_dependency_command_matches, registered_runner_command_matches,
        run_generation_matrix_gate, sha256_digest, unavailable_evidence_identity,
        valid_hex_identity, valid_raw_report_schema_path, valid_sha256_digest,
        validate_configuration_parser_threat_model_text, validate_serialized_evidence,
    };
    use crate::registry::Registry;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn defaults_to_the_complete_pull_request_profile() {
        let options = Options::parse(std::iter::empty());
        assert!(
            matches!(
                options,
                Ok(Options {
                    profile: Profile::Pr,
                    retain_m0_02_mutation: false,
                    retain_m0_03_mutation: false,
                    retain_m0_04_mutation: false,
                })
            ),
            "quality must default to the authoritative PR profile"
        );
    }

    #[test]
    fn retained_m0_02_mutation_requires_the_extended_profile() {
        let options = Options::parse(
            ["--profile", "ext", "--retain-m0-02-mutation"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(
            matches!(
                options,
                Ok(Options {
                    profile: Profile::Ext,
                    retain_m0_02_mutation: true,
                    retain_m0_03_mutation: false,
                    retain_m0_04_mutation: false,
                })
            ),
            "the explicit retained mutation campaign must be accepted only as an EXT option"
        );

        let rejected = Options::parse(
            ["--profile", "pr", "--retain-m0-02-mutation"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(
            rejected.is_err(),
            "routine PR quality must not select the focused mutation campaign"
        );
    }

    #[test]
    fn retained_m0_03_mutation_requires_the_extended_profile() {
        let options = Options::parse(
            ["--profile", "ext", "--retain-m0-03-mutation"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(
            matches!(
                options,
                Ok(Options {
                    profile: Profile::Ext,
                    retain_m0_02_mutation: false,
                    retain_m0_03_mutation: true,
                    retain_m0_04_mutation: false,
                })
            ),
            "the explicit M0-03 mutation campaign must be accepted only as an EXT option"
        );

        let rejected = Options::parse(
            ["--profile", "pr", "--retain-m0-03-mutation"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(
            rejected.is_err(),
            "routine PR quality must not select the M0-03 mutation campaign"
        );
    }

    #[test]
    fn retained_m0_04_mutation_requires_the_extended_profile() {
        let options = Options::parse(
            ["--profile", "ext", "--retain-m0-04-mutation"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(
            matches!(
                options,
                Ok(Options {
                    profile: Profile::Ext,
                    retain_m0_02_mutation: false,
                    retain_m0_03_mutation: false,
                    retain_m0_04_mutation: true,
                })
            ),
            "the explicit M0-04 mutation campaign must be accepted only as an EXT option"
        );

        let rejected = Options::parse(
            ["--profile", "pr", "--retain-m0-04-mutation"]
                .into_iter()
                .map(str::to_owned),
        );
        assert!(
            rejected.is_err(),
            "routine PR quality must not select the M0-04 mutation campaign"
        );
    }

    #[test]
    fn focused_m0_02_mutation_selection_covers_every_invariant_owner() {
        for owner in [
            "TenantLifecycle::transition",
            "VirtualShardId::new",
            "AssignmentEpoch::advance_by",
            "CommitPosition::advance_by",
            "IngestTime::from_candidate",
            "ByteLimit::new",
            "CollectionLimit::new",
            "NestingLimit::new",
            "RequestLimits::new",
            "RecordLimits::new",
            "DynamicValueLimits::new",
            "ValueLimitSet::new",
        ] {
            assert!(
                M0_02_MUTATION_SELECTOR.contains(owner),
                "focused mutation selection omitted invariant owner `{owner}`"
            );
        }
    }

    #[test]
    fn focused_m0_03_mutation_selection_covers_public_boundary_owners() {
        let selected = M0_03_MUTATION_SELECTOR.split('|').collect::<BTreeSet<_>>();
        for owner in [
            "RequestedApiMajor::from_major",
            "RequestedApiMajor::major",
            "Capability::from_wire",
            "ApiError::unsupported_api_version",
            "CapabilityRequest::for_version",
            "CapabilityRequest::for_requested_major",
            "CapabilityResponse::api_major",
            "CapabilityService::negotiate",
            "CapabilityService::decode_and_negotiate",
            "encode_grpc",
            "decode_grpc",
            "decode_http",
        ] {
            assert!(
                selected.contains(owner),
                "focused M0-03 mutation selection omitted public owner `{owner}`"
            );
        }
        // `ApiVersion` is the closed canonical v1 enum, so replacing
        // `ApiVersion::major` with the literal `1` is identical for its
        // complete input domain. Requested-major behavior remains observable
        // through the separately selected checked owner and request/service
        // seams.
        assert!(
            !selected.contains("ApiVersion::major"),
            "the equivalent closed-v1 accessor must not replace requested-major owners"
        );
        let generated = generated_rust_owner_names(include_str!(
            "../../../crates/positron-api/src/generated.rs"
        ));
        let stale = selected
            .iter()
            .filter(|owner| !generated.contains(**owner))
            .copied()
            .collect::<Vec<_>>();
        assert!(
            stale.is_empty(),
            "focused M0-03 mutation selection contains stale or nonexistent owners: {stale:?}"
        );
    }

    #[test]
    fn focused_m0_04_mutation_selection_covers_configuration_invariant_owners() {
        let selected = M0_04_MUTATION_SELECTOR.split('|').collect::<BTreeSet<_>>();
        for owner in [
            "EnvironmentOverrides::try_from_pairs",
            "CommandLineOverrides::try_from_pairs",
            "ConfigurationInputs::try_new",
            "EffectiveConfiguration::redacted_reference",
            "EffectiveConfiguration::plan_update",
            "ConfigurationPlan::from_changes",
            "resolve",
            "Candidate::apply",
            "Candidate::validate",
            "preflight_toml",
            "preflight_table_header",
            "preflight_scalar",
            "apply_toml",
            "apply_toml_value",
            "apply_environment",
            "apply_command_line",
            "parse_schema_version",
            "parse_loopback_address",
            "validate_path",
        ] {
            assert!(
                selected.contains(owner),
                "focused M0-04 mutation selection omitted Configuration owner `{owner}`"
            );
        }
        let owners =
            generated_rust_owner_names(include_str!("../../../crates/positron-config/src/lib.rs"));
        let stale = selected
            .iter()
            .filter(|owner| !owners.contains(**owner))
            .copied()
            .collect::<Vec<_>>();
        assert!(
            stale.is_empty(),
            "focused M0-04 mutation selection contains stale or nonexistent owners: {stale:?}"
        );
    }

    #[test]
    fn generation_matrix_rejects_configuration_artifact_drift() -> TestResult {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let fixture = std::env::temp_dir().join(format!(
            "positron-generation-matrix-{}-{timestamp}",
            std::process::id()
        ));
        for relative in [
            "api/positron/v1/positron.proto",
            "api/positron/v1/http.json",
            "api/positron/v1/openapi.json",
            "api/positron/v1/schema.sha256",
            "api/positron/v1/validation-fixtures.json",
            "configuration/reference.md",
            "configuration/schema.json",
            "configuration/validation-fixtures.json",
            "crates/positron-api/src/generated.rs",
            "crates/positron-config/src/contract.rs",
        ] {
            let destination = fixture.join(relative);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(repository.join(relative), destination)?;
        }

        let result = (|| {
            run_generation_matrix_gate(&fixture)?;
            fs::write(fixture.join("configuration/schema.json"), b"drift\n")?;
            let drift = run_generation_matrix_gate(&fixture);
            assert!(
                drift.is_err(),
                "EG-MATRIX must reject a checked configuration artifact that differs from regeneration"
            );
            Ok(())
        })();
        fs::remove_dir_all(&fixture)?;
        result
    }

    #[test]
    fn configuration_parser_threat_model_fails_closed_on_limit_or_review_drift() -> TestResult {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let threat_model = fs::read_to_string(
            repository.join("qualification/engineering/security/TM-0001-m0-04-toml-parser.json"),
        )?;
        validate_configuration_parser_threat_model_text(&threat_model)?;
        for drifted in [
            threat_model.replace(
                "\"maximum_document_bytes\": 16384",
                "\"maximum_document_bytes\": 16385",
            ),
            threat_model.replace(
                "\"reviewer\": \"\"",
                "\"reviewer\": \"implementation-author\"",
            ),
        ] {
            assert!(
                validate_configuration_parser_threat_model_text(&drifted).is_err(),
                "the M0-04 parser threat model must reject limit or owner-review drift"
            );
        }
        Ok(())
    }

    fn generated_rust_owner_names(source: &str) -> BTreeSet<String> {
        let mut owners = BTreeSet::new();
        let mut implementation = None;
        let mut implementation_depth = 0_usize;
        for line in source.lines() {
            let trimmed = line.trim();
            if implementation.is_none()
                && let Some(owner) = trimmed
                    .strip_prefix("impl ")
                    .and_then(|value| value.strip_suffix(" {"))
            {
                implementation = Some(owner);
                implementation_depth = 1;
                continue;
            }
            if let Some(name) = rust_function_name(trimmed) {
                if let Some(owner) = implementation {
                    owners.insert(format!("{owner}::{name}"));
                } else {
                    owners.insert(name.to_owned());
                }
            }
            if implementation.is_some() {
                implementation_depth =
                    implementation_depth.saturating_add(trimmed.matches('{').count());
                implementation_depth =
                    implementation_depth.saturating_sub(trimmed.matches('}').count());
                if implementation_depth == 0 {
                    implementation = None;
                }
            }
        }
        owners
    }

    fn rust_function_name(line: &str) -> Option<&str> {
        line.split_once("fn ")
            .and_then(|(_, suffix)| suffix.split_once('('))
            .map(|(name, _)| name.trim())
            .map(|name| name.split_once('<').map_or(name, |(plain, _)| plain))
            .filter(|name| !name.is_empty())
    }

    #[test]
    fn escapes_evidence_strings_without_losing_content() {
        assert_eq!(
            json_string("line\n\"secret-like\"\\path"),
            "\"line\\n\\\"secret-like\\\"\\\\path\"",
            "evidence JSON must escape control and delimiter characters"
        );
    }

    #[test]
    fn raw_report_limit_applies_to_exact_encoded_bytes() -> TestResult {
        let invocation = report_test_invocation(Vec::new());
        let control_characters = "\u{0001}".repeat(256);
        let unencoded_control_bytes = control_characters.len();
        let steps = vec![report_test_step(control_characters)];
        let encoded =
            raw_report_json_with_limit(report_test_document(&invocation, &steps), 32_768)?;
        assert!(
            encoded.len() > unencoded_control_bytes,
            "control-character expansion must be included in encoded-size accounting"
        );

        let just_under_limit = encoded.len() + 1;
        let under = raw_report_json_with_limit(
            report_test_document(&invocation, &steps),
            just_under_limit,
        )?;
        assert_eq!(under.len() + 1, just_under_limit);

        let at =
            raw_report_json_with_limit(report_test_document(&invocation, &steps), encoded.len())?;
        assert_eq!(at.len(), encoded.len());

        let over = raw_report_json_with_limit(
            report_test_document(&invocation, &steps),
            encoded.len() - 1,
        );
        assert!(
            over.as_ref().is_err_and(|error| {
                let detail = error.to_string();
                detail.contains("gate report resource limit")
                    && detail.contains("encoded raw report exceeds")
            }),
            "one encoded byte beyond the limit must fail with a typed resource error"
        );
        Ok(())
    }

    #[test]
    fn evidence_v3_constraint_owner_enforces_every_string_and_digest_boundary() {
        for maximum in [
            MAXIMUM_ATTEMPT_ID_CHARACTERS,
            MAXIMUM_IDENTITY_VALUE_CHARACTERS,
            MAXIMUM_GATE_DETAIL_CHARACTERS,
            MAXIMUM_GATE_ARGUMENT_CHARACTERS,
            MAXIMUM_ACTIVATION_CHARACTERS,
            MAXIMUM_EXCEPTION_CLASS_CHARACTERS,
            MAXIMUM_CONTROLLED_PROGRAM_CHARACTERS,
            MAXIMUM_RESOLVED_PROGRAM_CHARACTERS,
            MAXIMUM_CONTROLLED_ARGUMENT_CHARACTERS,
        ] {
            assert!(character_count_in_range(&"é".repeat(maximum), 1, maximum));
            assert!(!character_count_in_range(
                &"é".repeat(maximum + 1),
                1,
                maximum
            ));
        }
        assert!(valid_hex_identity(&"a".repeat(40)));
        assert!(valid_hex_identity(&"f".repeat(64)));
        assert!(!valid_hex_identity(&"a".repeat(39)));
        assert!(!valid_hex_identity(&"a".repeat(41)));
        assert!(!valid_hex_identity(&"A".repeat(40)));
        assert!(valid_sha256_digest(&format!("sha256:{}", "f".repeat(64))));
        assert!(!valid_sha256_digest(&format!("sha256:{}", "F".repeat(64))));
        assert!(valid_raw_report_schema_path(
            "target/quality/evidence-reports/attempt-1/EG-TEST.json"
        ));
        assert!(!valid_raw_report_schema_path(
            "target/quality/evidence-reports/attempt-1/eg-test.json"
        ));
    }

    #[test]
    fn retained_invocation_digest_parser_preserves_ordered_repeated_arguments() -> TestResult {
        let mut invocation = report_test_invocation(Vec::new());
        invocation.arguments = vec![
            "quality".to_owned(),
            "--gate".to_owned(),
            "EG-00".to_owned(),
            "--gate".to_owned(),
            "EG-00".to_owned(),
        ];
        let value = crate::evidence_json::parse(&gate_invocation_json(&invocation))?;
        let parsed =
            parse_gate_invocation_value(value, std::path::Path::new("retained-invocation.json"))?;
        assert_eq!(parsed.typed.arguments, invocation.arguments);
        Ok(())
    }

    #[test]
    fn parent_runner_verifier_requires_exact_canonical_child_arguments() -> TestResult {
        let registry = crate::bounded_runners::FrozenBoundedRunnerRegistry::capture(
            include_bytes!("../../../qualification/engineering/concurrency-fixtures.tsv").to_vec(),
            include_bytes!("../../../qualification/engineering/concurrency-spawn-sites.tsv")
                .to_vec(),
        )?;
        let mut step = report_test_step(String::new()).invocation;
        step.program = "cargo-xtask-quality/bounded-runner".to_owned();
        step.timeout_ms = 900_000;
        step.arguments = registry
            .child_arguments("EG-CONCURRENCY", Duration::from_millis(900_000))?
            .into_iter()
            .map(|argument| argument.into_string())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| std::io::Error::other("test child argument was not UTF-8"))?;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or_else(|| std::io::Error::other("test repository root is unavailable"))?;
        let quality_registry = Registry::load(root)?;
        assert!(registered_runner_command_matches(
            "concurrency",
            Profile::Pr,
            0,
            &step,
            &quality_registry,
        ));

        let timeout_argument = step
            .arguments
            .get_mut(4)
            .ok_or_else(|| std::io::Error::other("test timeout argument is unavailable"))?;
        *timeout_argument = "0900000".to_owned();
        assert!(!registered_runner_command_matches(
            "concurrency",
            Profile::Pr,
            0,
            &step,
            &quality_registry,
        ));
        let timeout_argument = step
            .arguments
            .get_mut(4)
            .ok_or_else(|| std::io::Error::other("test timeout argument is unavailable"))?;
        *timeout_argument = "900000".to_owned();
        step.arguments.push("unexpected".to_owned());
        assert!(!registered_runner_command_matches(
            "concurrency",
            Profile::Pr,
            0,
            &step,
            &quality_registry,
        ));
        Ok(())
    }

    #[test]
    fn dependency_runner_matches_each_registered_controlled_step_in_order() {
        assert!(registered_dependency_command_matches(
            0,
            "cargo",
            &["metadata", "--locked", "--format-version", "1"]
        ));
        assert!(registered_dependency_command_matches(
            1,
            "cargo-machete",
            &["--with-metadata", "--skip-target-dir", "."]
        ));
        assert!(registered_dependency_command_matches(
            2,
            "cargo",
            &["deny", "check", "bans", "licenses", "sources"]
        ));
        assert!(!registered_dependency_command_matches(
            0,
            "cargo-machete",
            &["--with-metadata", "--skip-target-dir", "."]
        ));
    }

    #[test]
    fn test_runner_preserves_full_selection_failure_visibility_and_bounded_summary() -> TestResult {
        assert_eq!(
            NEXTEST_PR_ARGUMENTS,
            [
                "nextest",
                "run",
                "--locked",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--profile",
                "ci",
                "--status-level",
                "fail",
                "--final-status-level",
                "fail",
            ],
            "the bounded reporter must not alter the full locked PR test selection"
        );
        assert!(
            !NEXTEST_PR_ARGUMENTS
                .iter()
                .any(|argument| matches!(*argument, "-E" | "--filterset" | "--skip")),
            "the bounded reporter must not filter or skip tests"
        );
        assert_eq!(
            MAXIMUM_CAPTURED_REPORT_STREAM_BYTES, 131_072,
            "the reporter change must not raise the controlled stream ceiling"
        );
        assert_eq!(
            nextest_completed_test_count(
                "Summary [ 113.160s] 317 tests run: 317 passed, 0 skipped\n"
            )?,
            317,
            "the retained human summary must expose the exact completed-test count"
        );
        assert!(
            nextest_completed_test_count(
                "Summary [ 1.000s] 317 tests run: 316 passed, 1 skipped\n"
            )
            .is_err(),
            "an ignored or skipped test must fail the summary contract"
        );
        assert!(
            nextest_completed_test_count("317 tests passed without a canonical summary").is_err(),
            "missing final count evidence must fail closed"
        );
        assert!(
            nextest_completed_test_count(
                "Summary [ 1.000s] 317 tests run: 317 passed, 0 skipped\n\
                 Summary [ 1.001s] 317 tests run: 316 passed, 1 skipped\n"
            )
            .is_err(),
            "an early passing summary must not hide a later non-canonical terminal summary"
        );
        Ok(())
    }

    #[test]
    fn report_encoding_failure_is_retained_as_schema_valid_failed_evidence() -> TestResult {
        let attempt_id = "report-encoding-failure-attempt";
        let oversized_step = report_test_step("\u{0001}".repeat(256));
        let oversized_invocation = report_test_invocation(vec![oversized_step.invocation.clone()]);
        let mut gates = Vec::with_capacity(CANONICAL_GATE_IDS.len());
        for gate_id in CANONICAL_GATE_IDS {
            let selected = gate_id == "EG-00";
            let invocation = if selected {
                oversized_invocation.clone()
            } else {
                report_test_invocation(Vec::new())
            };
            gates.push(build_gate_attempt_with_report_limit(
                attempt_id,
                GateAttemptDefinition {
                    gate_id: gate_id.to_owned(),
                    budget_seconds: 60,
                    invocation,
                    owner: if selected {
                        IdentityBinding::exact("Quality Engineering")
                    } else {
                        IdentityBinding::not_applicable(
                            NotApplicableReason::UnavailableBeforeRegistryValidation,
                        )
                    },
                },
                GateAttemptOutcome {
                    result: if selected {
                        GateStatus::Passed
                    } else {
                        GateStatus::NotSelected
                    },
                    duration_ms: if selected { 1 } else { 0 },
                    detail: if selected {
                        "encoded-size retention boundary".to_owned()
                    } else {
                        "blocked before registry validation".to_owned()
                    },
                    controlled_steps: if selected {
                        vec![oversized_step.clone()]
                    } else {
                        Vec::new()
                    },
                },
                1_024,
            ));
        }
        let source = SourceIdentity {
            revision: "0000000000000000000000000000000000000000".to_owned(),
            dirty: true,
            trusted_ci: false,
            revision_matches_ci: false,
        };
        let evidence = Evidence {
            attempt_id: attempt_id.to_owned(),
            collision_of: IdentityBinding::not_applicable(NotApplicableReason::NoCollision),
            collision_slots: IdentityBinding::not_applicable(NotApplicableReason::NoCollision),
            profile: Profile::PreCommit,
            result: GateStatus::Failed,
            merge_eligible: false,
            identity: unavailable_evidence_identity(&source),
            source,
            started_unix_ms: 1,
            ended_unix_ms: 2,
            registry_digest: "unavailable-registry-digest".to_owned(),
            environment_digest: "unavailable-registry-digest".to_owned(),
            gates,
        };
        let serialized = evidence_json(&evidence);
        validate_serialized_evidence(&evidence, &serialized)?;
        let encoding_failure = evidence
            .gates
            .iter()
            .find(|gate| gate.gate_id == "EG-00")
            .ok_or("missing EG-00 regression fixture")?;
        assert_eq!(encoding_failure.result, GateStatus::Failed);
        assert_eq!(
            encoding_failure.raw_report,
            RawReportBinding::NotApplicable(NotApplicableReason::ReportEncodingFailed)
        );
        assert!(encoding_failure.raw_report_content.is_none());
        assert!(
            encoding_failure
                .detail
                .contains("gate report resource limit"),
            "the retained failure must explain its typed resource rejection"
        );
        Ok(())
    }

    fn report_test_document<'report>(
        invocation: &'report GateInvocation,
        steps: &'report [ControlledStepReport],
    ) -> RawReportDocument<'report> {
        RawReportDocument {
            attempt_id: "encoded-boundary-attempt",
            gate_id: "EG-00",
            result: GateStatus::Passed,
            duration_ms: 1,
            invocation_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            invocation,
            detail: "encoded-size boundary",
            controlled_steps: steps,
        }
    }

    fn report_test_invocation(controlled_steps: Vec<ControlledInvocation>) -> GateInvocation {
        GateInvocation {
            program: "cargo-xtask-quality/internal".to_owned(),
            arguments: vec![
                "quality".to_owned(),
                "--report-boundary".to_owned(),
                "EG-00".to_owned(),
            ],
            working_directory: "engineering-workspace".to_owned(),
            environment_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            timeout_seconds: 60,
            memory_mib: 256,
            activation: "always".to_owned(),
            exception_class: "none".to_owned(),
            controlled_steps,
        }
    }

    fn report_test_step(stdout: String) -> ControlledStepReport {
        ControlledStepReport {
            invocation: ControlledInvocation {
                program: "cargo".to_owned(),
                resolved_program: "/usr/bin/cargo".to_owned(),
                arguments: vec!["check".to_owned()],
                working_directory: "engineering-workspace".to_owned(),
                environment_digest: sha256_digest(b"report-test-environment"),
                timeout_ms: 1,
                input_kind: "null".to_owned(),
                input_bytes: 0,
                input_sha256: "-".to_owned(),
            },
            verdict: "passed".to_owned(),
            stdout,
            stderr: String::new(),
        }
    }

    #[test]
    fn rejects_duplicate_invocation_environment_overrides() {
        let snapshot = EnvironmentSnapshot {
            values: vec![
                (OsString::from("PATH"), OsString::from("/usr/bin")),
                (OsString::from("TMPDIR"), OsString::from("/tmp/owned")),
            ],
            tools: BTreeMap::new(),
            execution_tools: ExecutionTools {
                process_control: PathBuf::from("/bin/kill"),
                capture_broker: PathBuf::from("/usr/bin/head"),
            },
            temporary_root: PathBuf::from("/tmp/owned"),
            digest: "git-object:0000000000000000000000000000000000000000".to_owned(),
        };
        let result = snapshot.invocation_environment(&[
            ("RUSTDOCFLAGS", "-D warnings"),
            ("RUSTDOCFLAGS", "-D warnings"),
        ]);
        let error = result.err().map(|error| error.to_string());
        assert!(
            error.as_deref().is_some_and(
                |detail| detail.contains("duplicate invocation override `RUSTDOCFLAGS`")
            ),
            "duplicate override rejection must expose the stable environment boundary"
        );
    }
}
