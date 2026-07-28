use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::controlled_execution::{
    self, ExecutionTools, InvocationInput, InvocationSpec, OutputMode,
};
use crate::error::XtaskError;
use crate::hooks;
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
}

impl Options {
    pub(crate) fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, XtaskError> {
        let mut profile = Profile::Pr;
        let mut retain_m0_02_mutation = false;
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
        Ok(Self {
            profile,
            retain_m0_02_mutation,
        })
    }
}

#[derive(Debug)]
struct GateAttempt {
    gate_id: String,
    result: GateStatus,
    duration_ms: u128,
    budget_seconds: u64,
    command: String,
    detail: String,
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

#[derive(Debug)]
struct SourceIdentity {
    revision: String,
    dirty: bool,
    trusted_ci: bool,
    revision_matches_ci: bool,
}

#[derive(Debug)]
struct Evidence {
    attempt_id: String,
    profile: Profile,
    result: GateStatus,
    merge_eligible: bool,
    source: SourceIdentity,
    started_unix_ms: u128,
    ended_unix_ms: u128,
    registry_digest: String,
    environment_digest: String,
    gates: Vec<GateAttempt>,
}

#[derive(Debug)]
struct CommandOutcome {
    display: String,
    stdout: String,
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

pub(crate) fn run(options: &Options) -> Result<(), XtaskError> {
    let root = hooks::workspace_root()?;
    let started_unix_ms = unix_time_ms()?;
    let environment = EnvironmentSnapshot::capture(&root, options.profile)?;
    let source = source_identity(&root, &environment)?;
    let attempt_id = attempt_identity(&source.revision, started_unix_ms);
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

    println!(
        "Positron engineering quality: profile={}, revision={}, dirty={}",
        options.profile.as_str(),
        source.revision,
        source.dirty
    );

    let mut attempts = Vec::with_capacity(registry.gates.len());
    for gate in &registry.gates {
        if !gate_selected(gate, options.profile, &activated_risk_gates) {
            attempts.push(GateAttempt {
                gate_id: gate.id.clone(),
                result: GateStatus::NotSelected,
                duration_ms: 0,
                budget_seconds: gate.timeout_seconds,
                command: format!("internal:{}", gate.runner),
                detail: not_selected_reason(gate, options.profile),
            });
            continue;
        }

        println!(
            "\n[{}] {} (budget: {}s, {} MiB declared)",
            gate.id, gate.runner, gate.timeout_seconds, gate.memory_mib
        );
        let started = Instant::now();
        let execution = execute_gate(
            &root,
            &registry,
            gate,
            options.profile,
            options.retain_m0_02_mutation,
            &environment,
        );
        let duration_ms = started.elapsed().as_millis();
        match execution {
            Ok(command) => {
                println!("[{}] passed", gate.id);
                attempts.push(GateAttempt {
                    gate_id: gate.id.clone(),
                    result: GateStatus::Passed,
                    duration_ms,
                    budget_seconds: gate.timeout_seconds,
                    command,
                    detail: format!(
                        "Coordinator: {}; exception class: {}",
                        gate.coordinator, gate.exception_class
                    ),
                });
            },
            Err(error) => {
                eprintln!("[{}] failed: {error}", gate.id);
                attempts.push(GateAttempt {
                    gate_id: gate.id.clone(),
                    result: GateStatus::Failed,
                    duration_ms,
                    budget_seconds: gate.timeout_seconds,
                    command: format!("internal:{}", gate.runner),
                    detail: error.to_string(),
                });
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
        profile: options.profile,
        result,
        merge_eligible,
        source,
        started_unix_ms,
        ended_unix_ms,
        registry_digest,
        environment_digest: environment.digest().to_owned(),
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
        gates.push(GateAttempt {
            gate_id: gate_id.to_owned(),
            result: if is_aggregator {
                GateStatus::Failed
            } else {
                GateStatus::NotSelected
            },
            duration_ms: 0,
            budget_seconds: 60,
            command: if is_aggregator {
                "internal:registry".to_owned()
            } else {
                "blocked-by:EG-00".to_owned()
            },
            detail: if is_aggregator {
                failure.error.to_string()
            } else {
                "EG-00 failed closed before gate selection; this omission is retained and cannot be interpreted as a pass."
                    .to_owned()
            },
        });
    }
    let evidence = Evidence {
        attempt_id: failure.attempt_id,
        profile,
        result: GateStatus::Failed,
        merge_eligible: false,
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
    root: &Path,
    registry: &Registry,
    gate: &Gate,
    profile: Profile,
    retain_m0_02_mutation: bool,
    environment: &EnvironmentSnapshot,
) -> Result<String, XtaskError> {
    let budget = Duration::from_secs(gate.timeout_seconds);
    match gate.runner.as_str() {
        "registry" => run_registry_gate(root, registry, profile, budget, environment),
        "architecture" => run_architecture_gate(root, registry, budget, environment),
        "build" => run_build_gate(root, profile, budget, environment),
        "coverage" => run_coverage_gate(root, registry, budget, retain_m0_02_mutation, environment),
        "dynamic-analysis" => run_dynamic_analysis_gate(root, registry, budget, environment),
        "dependencies" => run_dependency_gate(root, registry, budget, environment),
        "documentation" => run_documentation_gate(root, budget, environment),
        "error-policy" => run_error_policy_gate(root, registry),
        "evidence" => run_evidence_gate(root, registry),
        "policy" => run_policy_gate(root, registry),
        "rust" => run_rust_gate(root, budget, environment),
        "safety" => run_safety_gate(root, registry),
        "secrets" => run_secret_gate(root, profile, budget, environment),
        "supply" => run_supply_gate(root, registry, profile, budget, environment),
        "test" => run_test_gate(root, budget, environment),
        unsupported => Err(XtaskError::invalid(
            format!("gate runner `{unsupported}`"),
            "an active risk scope selected a gate whose executable harness has not been implemented",
        )),
    }
}

fn run_dynamic_analysis_gate(
    root: &Path,
    registry: &Registry,
    budget: Duration,
    environment: &EnvironmentSnapshot,
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
        &[],
    )?;
    let compile_fail = run_status(
        root,
        environment,
        "cargo",
        ["test", "--locked", "--package", "positron-domain", "--doc"],
        remaining(deadline)?,
        &[],
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
    retain_m0_02_mutation: bool,
    environment: &EnvironmentSnapshot,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let detector_versions = verify_coverage_detectors(root, registry, deadline, environment)?;
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
        )?);
    }
    if registry.has_m0_01_foundational_scope() {
        results.push(run_m0_01_coverage(root, registry, deadline, environment)?);
    }
    if retain_m0_02_mutation {
        results.push(run_m0_02_mutation(root, registry, deadline, environment)?);
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
        &[],
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
        &[],
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
        &[],
    )?;
    let changed_code = run_status(
        root,
        environment,
        "cargo",
        changed_code_specification.arguments(),
        remaining(deadline)?,
        &[],
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
        &[],
    )?;
    let measurements = read_coverage_measurements(&root.join(report))?;
    enforce_m0_02_domain_types_coverage_baselines(registry, &measurements)?;
    Ok(format!(
        "M0-02 Domain Types: {}; total(branch={:.2}, line={:.2}, region={:.2})",
        outcome.display, measurements.branch, measurements.line, measurements.region,
    ))
}

fn verify_coverage_detectors(
    root: &Path,
    registry: &Registry,
    deadline: Instant,
    environment: &EnvironmentSnapshot,
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
        &[],
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
            &[],
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
            &[],
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
            &[],
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
                    &[],
                )?
                .display,
            );
        }
    }
    Ok(commands.join(" | "))
}

fn run_dependency_gate(
    root: &Path,
    registry: &Registry,
    budget: Duration,
    environment: &EnvironmentSnapshot,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let mut commands = Vec::new();
    commands.push(
        run_capture(
            root,
            environment,
            "cargo",
            ["metadata", "--locked", "--format-version", "1"],
            remaining(deadline)?,
            &[],
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
            &[],
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
            &[],
        )?
        .display,
    );
    if !registry.reviewed_dependencies().is_empty() {
        commands.push("internal:direct-dependency-review parity".to_owned());
    }
    Ok(commands.join(" | "))
}

fn run_documentation_gate(
    root: &Path,
    budget: Duration,
    environment: &EnvironmentSnapshot,
) -> Result<String, XtaskError> {
    validate_local_markdown_links(root)?;
    let target = documentation_target_directory(environment)?;
    fs::create_dir(&target)
        .map_err(|source| XtaskError::io(format!("create {}", target.display()), source))?;
    let target_value = target.as_os_str().to_str().ok_or_else(|| {
        XtaskError::invalid_path(&target, "temporary documentation target is not valid UTF-8")
    })?;
    let deadline = Instant::now() + budget;
    let outcome = run_status(
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
        remaining(deadline)?,
        &[
            ("RUSTDOCFLAGS", "-D warnings"),
            ("CARGO_TARGET_DIR", target_value),
        ],
    )
    .and_then(|outcome| {
        scan_generated_rustdoc_secrets(root, environment, &target, remaining(deadline)?)
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
        &[],
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
    for field in [
        "\"additionalProperties\": false",
        "\"attempt_id\"",
        "\"merge_eligible\"",
        "\"registry_digest\"",
        "\"not-selected\"",
    ] {
        if !schema.contains(field) {
            return Err(XtaskError::invalid_path(
                &path,
                format!("evidence schema is missing `{field}`"),
            ));
        }
    }
    if registry.gates.len() != 25 {
        return Err(XtaskError::invalid(
            "evidence gate set",
            "every attempt must report all 25 registered gates",
        ));
    }
    Ok("internal:evidence-schema-and-complete-gate-set validation".to_owned())
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
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let format = run_status(
        root,
        environment,
        "cargo",
        ["fmt", "--all", "--", "--check"],
        remaining(deadline)?,
        &[],
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
        &[],
    )?;
    Ok(format!("{} | {}", format.display, clippy.display))
}

fn run_safety_gate(root: &Path, registry: &Registry) -> Result<String, XtaskError> {
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
    Ok("internal:forbid-unsafe-and-unbounded-source-policy scan".to_owned())
}

fn run_secret_gate(
    root: &Path,
    profile: Profile,
    budget: Duration,
    environment: &EnvironmentSnapshot,
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
            &[],
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
                &[],
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
            &[],
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
                &[],
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
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let nextest = run_status(
        root,
        environment,
        "cargo",
        [
            "nextest",
            "run",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--profile",
            "ci",
        ],
        remaining(deadline)?,
        &[],
    )?;
    let doctest = run_status(
        root,
        environment,
        "cargo",
        ["test", "--locked", "--workspace", "--doc", "--all-features"],
        remaining(deadline)?,
        &[],
    )?;
    Ok(format!("{} | {}", nextest.display, doctest.display))
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
    environment: &[(&str, &str)],
) -> Result<CommandOutcome, XtaskError> {
    let arguments = arguments
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let resolved_program = snapshot.tool_path(program)?;
    let display = command_display(&resolved_program.to_string_lossy(), &arguments);
    println!("  $ {display}");
    let verdict = controlled_execution::execute(InvocationSpec {
        program: resolved_program,
        arguments,
        current_dir: root.to_path_buf(),
        environment: snapshot.invocation_environment(environment)?,
        tools: snapshot.execution_tools(),
        input: InvocationInput::Null,
        output: OutputMode::Inherit,
        cancellation: Arc::new(AtomicBool::new(false)),
        deadline: deadline_after(timeout)?,
    })
    .into_result()
    .map_err(XtaskError::controlled_harness)?;
    if verdict.status.success() {
        return Ok(CommandOutcome {
            display,
            stdout: verdict.output.stdout,
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
    environment: &[(&str, &str)],
) -> Result<CommandOutcome, XtaskError> {
    run_capture_with_input(
        root,
        snapshot,
        program,
        arguments,
        CaptureOptions {
            timeout,
            environment,
            input: InvocationInput::Null,
        },
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
) -> Result<CommandOutcome, XtaskError> {
    let arguments = arguments
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let resolved_program = snapshot.tool_path(program)?;
    let display = command_display(&resolved_program.to_string_lossy(), &arguments);
    let verdict = controlled_execution::execute(InvocationSpec {
        program: resolved_program,
        arguments,
        current_dir: root.to_path_buf(),
        environment: snapshot.invocation_environment(options.environment)?,
        tools: snapshot.execution_tools(),
        input: options.input,
        output: OutputMode::Capture {
            maximum_bytes_per_stream: 1_048_576,
        },
        cancellation: Arc::new(AtomicBool::new(false)),
        deadline: deadline_after(options.timeout)?,
    })
    .into_result()
    .map_err(XtaskError::controlled_harness)?;
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
        &[],
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
        &[],
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
    fs::create_dir_all(&directory)
        .map_err(|source| XtaskError::io(format!("create {}", directory.display()), source))?;
    let path = directory.join(format!("{}.json", evidence.attempt_id));
    let serialized = evidence_json(evidence);
    validate_serialized_evidence(evidence, &serialized)?;
    fs::write(&path, serialized)
        .map_err(|source| XtaskError::io(format!("write {}", path.display()), source))?;
    Ok(path)
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
    if gate_ids.len() != evidence.gates.len() {
        return Err(XtaskError::invalid(
            "engineering evidence",
            "attempt contains duplicate gate identities",
        ));
    }
    if evidence.attempt_id.is_empty()
        || !valid_hex_identity(&evidence.source.revision)
        || !valid_registry_digest(&evidence.registry_digest)
        || !valid_registry_digest(&evidence.environment_digest)
        || evidence.ended_unix_ms < evidence.started_unix_ms
    {
        return Err(XtaskError::invalid(
            "engineering evidence",
            "attempt identity, source, digest, and time ordering must be complete",
        ));
    }
    for gate in &evidence.gates {
        if gate.gate_id.is_empty()
            || gate.budget_seconds == 0
            || gate.command.is_empty()
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
    }
    for required in [
        "\"schema_version\": 1",
        "\"attempt_id\"",
        "\"merge_eligible\"",
        "\"registry_digest\"",
        "\"environment_digest\"",
        "\"gates\"",
    ] {
        if !serialized.contains(required) {
            return Err(XtaskError::invalid(
                "engineering evidence serialization",
                format!("required field `{required}` is missing"),
            ));
        }
    }
    Ok(())
}

fn valid_hex_identity(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn valid_registry_digest(value: &str) -> bool {
    matches!(value, "invalid-registry" | "unavailable-registry-digest")
        || value
            .strip_prefix("git-object:")
            .is_some_and(valid_hex_identity)
}

fn evidence_json(evidence: &Evidence) -> String {
    let mut output = String::new();
    output.push_str("{\n");
    output.push_str("  \"schema_version\": 1,\n");
    output.push_str(&format!(
        "  \"attempt_id\": {},\n",
        json_string(&evidence.attempt_id)
    ));
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
        output.push_str(&format!(
            "      \"command\": {},\n",
            json_string(&gate.command)
        ));
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
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{
        EnvironmentSnapshot, ExecutionTools, M0_02_MUTATION_SELECTOR, Options, Profile, json_string,
    };

    #[test]
    fn defaults_to_the_complete_pull_request_profile() {
        let options = Options::parse(std::iter::empty());
        assert!(
            matches!(
                options,
                Ok(Options {
                    profile: Profile::Pr,
                    retain_m0_02_mutation: false,
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
    fn escapes_evidence_strings_without_losing_content() {
        assert_eq!(
            json_string("line\n\"secret-like\"\\path"),
            "\"line\\n\\\"secret-like\\\"\\\\path\"",
            "evidence JSON must escape control and delimiter characters"
        );
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
