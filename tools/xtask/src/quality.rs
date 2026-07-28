use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
}

impl Options {
    pub(crate) fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, XtaskError> {
        let mut profile = Profile::Pr;
        let mut arguments = arguments.peekable();
        while let Some(argument) = arguments.next() {
            if argument == "--profile" {
                let Some(value) = arguments.next() else {
                    return Err(XtaskError::usage("`--profile` requires a value".to_owned()));
                };
                profile = Profile::parse(&value)?;
            } else if let Some(value) = argument.strip_prefix("--profile=") {
                profile = Profile::parse(value)?;
            } else {
                return Err(XtaskError::usage(format!(
                    "unexpected quality argument `{argument}`"
                )));
            }
        }
        Ok(Self { profile })
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

pub(crate) fn run(options: &Options) -> Result<(), XtaskError> {
    let root = hooks::workspace_root()?;
    let started_unix_ms = unix_time_ms()?;
    let source = source_identity(&root)?;
    let attempt_id = attempt_identity(&source.revision, started_unix_ms);
    let registry = match Registry::load(&root) {
        Ok(registry) => registry,
        Err(error) => {
            return retain_aggregator_failure(
                &root,
                options.profile,
                source,
                started_unix_ms,
                attempt_id,
                ("invalid-registry", &error),
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
            source,
            started_unix_ms,
            attempt_id,
            ("invalid-registry", &error),
        );
    }
    let registry_digest = match digest_files(&root, registry.registry_files()) {
        Ok(digest) => digest,
        Err(error) => {
            return retain_aggregator_failure(
                &root,
                options.profile,
                source,
                started_unix_ms,
                attempt_id,
                ("unavailable-registry-digest", &error),
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
        let execution = execute_gate(&root, &registry, gate, options.profile);
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
    source: SourceIdentity,
    started_unix_ms: u128,
    attempt_id: String,
    failure_context: (&str, &XtaskError),
) -> Result<(), XtaskError> {
    let (registry_digest, failure) = failure_context;
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
                failure.to_string()
            } else {
                "EG-00 failed closed before gate selection; this omission is retained and cannot be interpreted as a pass."
                    .to_owned()
            },
        });
    }
    let evidence = Evidence {
        attempt_id,
        profile,
        result: GateStatus::Failed,
        merge_eligible: false,
        source,
        started_unix_ms,
        ended_unix_ms: unix_time_ms()?,
        registry_digest: registry_digest.to_owned(),
        gates,
    };
    let path = write_evidence(root, &evidence)?;
    eprintln!("Retained failed aggregator evidence: {}", path.display());
    Err(XtaskError::invalid(
        "engineering quality aggregator",
        failure.to_string(),
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
) -> Result<String, XtaskError> {
    let budget = Duration::from_secs(gate.timeout_seconds);
    match gate.runner.as_str() {
        "registry" => run_registry_gate(root, registry, profile, budget),
        "architecture" => run_architecture_gate(root, registry, budget),
        "build" => run_build_gate(root, profile, budget),
        "coverage" => run_coverage_gate(root, registry, budget),
        "dependencies" => run_dependency_gate(root, registry, budget),
        "documentation" => run_documentation_gate(root, budget),
        "error-policy" => run_error_policy_gate(root, registry),
        "evidence" => run_evidence_gate(root, registry),
        "policy" => run_policy_gate(root, registry),
        "rust" => run_rust_gate(root, budget),
        "safety" => run_safety_gate(root, registry),
        "secrets" => run_secret_gate(root, profile, budget),
        "supply" => run_supply_gate(root, registry, profile, budget),
        "test" => run_test_gate(root, budget),
        unsupported => Err(XtaskError::invalid(
            format!("gate runner `{unsupported}`"),
            "an active risk scope selected a gate whose executable harness has not been implemented",
        )),
    }
}

fn run_coverage_gate(
    root: &Path,
    registry: &Registry,
    budget: Duration,
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let detector_versions = verify_coverage_detectors(root, registry, deadline)?;
    let coverage_directory = root.join("target/quality/coverage");
    fs::create_dir_all(&coverage_directory).map_err(|source| {
        XtaskError::io(format!("create {}", coverage_directory.display()), source)
    })?;
    let total_report = "target/quality/coverage/m0-01-total.json";
    let changed_code_report = "target/quality/coverage/m0-01-changed-code.json";
    let total = run_status(
        root,
        "cargo",
        [
            "+nightly-2026-07-20",
            "llvm-cov",
            "--locked",
            "--package",
            "xtask",
            "--test",
            "foundational_scope_activation",
            "--branch",
            "--json",
            "--summary-only",
            "--output-path",
            total_report,
        ],
        remaining(deadline)?,
        &[],
    )?;
    let changed_code = run_status(
        root,
        "cargo",
        [
            "+nightly-2026-07-20",
            "llvm-cov",
            "--locked",
            "--package",
            "xtask",
            "--test",
            "foundational_scope_activation",
            "--branch",
            "--json",
            "--summary-only",
            "--ignore-filename-regex",
            "tools/xtask/src/(error|hooks|main|quality)\\.rs",
            "--output-path",
            changed_code_report,
        ],
        remaining(deadline)?,
        &[],
    )?;

    let total_measurements = read_coverage_measurements(&root.join(total_report))?;
    let changed_measurements = read_coverage_measurements(&root.join(changed_code_report))?;
    enforce_coverage_baselines(registry, &total_measurements, &changed_measurements)?;

    Ok(format!(
        "{}; {} | {}; total(branch={:.2}, line={:.2}, region={:.2}); changed-code(line={:.2})",
        detector_versions,
        total.display,
        changed_code.display,
        total_measurements.branch,
        total_measurements.line,
        total_measurements.region,
        changed_measurements.line,
    ))
}

fn verify_coverage_detectors(
    root: &Path,
    registry: &Registry,
    deadline: Instant,
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

fn enforce_coverage_baselines(
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

fn run_build_gate(root: &Path, profile: Profile, budget: Duration) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let mut commands = Vec::new();
    commands.push(
        run_status(
            root,
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
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let mut commands = Vec::new();
    commands.push(
        run_capture(
            root,
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

fn run_documentation_gate(root: &Path, budget: Duration) -> Result<String, XtaskError> {
    validate_local_markdown_links(root)?;
    let outcome = run_status(
        root,
        "cargo",
        [
            "doc",
            "--locked",
            "--workspace",
            "--all-features",
            "--no-deps",
            "--document-private-items",
        ],
        budget,
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    Ok(format!("internal:local-link-check | {}", outcome.display))
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
    validate_required_policy_files(root)?;
    hooks::validate_repository_hooks(root)?;
    if registry.activated_risk_gates().contains("EG-COVERAGE") {
        validate_coverage_workflow_provisioning(root)?;
    }
    Ok("internal:workflow-action-pin-branch-policy-and-required-file validation".to_owned())
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

fn run_rust_gate(root: &Path, budget: Duration) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let format = run_status(
        root,
        "cargo",
        ["fmt", "--all", "--", "--check"],
        remaining(deadline)?,
        &[],
    )?;
    let clippy = run_status(
        root,
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

fn run_secret_gate(root: &Path, profile: Profile, budget: Duration) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let mut commands = Vec::new();
    commands.push(
        run_status(
            root,
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
) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let mut commands = Vec::new();
    commands.push(
        run_status(
            root,
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

fn run_test_gate(root: &Path, budget: Duration) -> Result<String, XtaskError> {
    let deadline = Instant::now() + budget;
    let nextest = run_status(
        root,
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
    program: &str,
    arguments: impl IntoIterator<Item = &'argument str>,
    timeout: Duration,
    environment: &[(&str, &str)],
) -> Result<CommandOutcome, XtaskError> {
    let arguments = arguments
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let display = command_display(program, &arguments);
    println!("  $ {display}");
    let mut command = Command::new(program);
    command
        .current_dir(root)
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    configure_child_path(&mut command, root)?;
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command
        .spawn()
        .map_err(|source| XtaskError::io(format!("spawn `{display}`"), source))?;
    let started = Instant::now();
    loop {
        match child
            .try_wait()
            .map_err(|source| XtaskError::io(format!("wait for `{display}`"), source))?
        {
            Some(status) if status.success() => {
                return Ok(CommandOutcome {
                    display,
                    stdout: String::new(),
                });
            },
            Some(status) => {
                return Err(XtaskError::command(
                    display,
                    format!("exit status {status}"),
                ));
            },
            None if started.elapsed() >= timeout => {
                child
                    .kill()
                    .map_err(|source| XtaskError::io(format!("terminate `{display}`"), source))?;
                let _status = child
                    .wait()
                    .map_err(|source| XtaskError::io(format!("reap `{display}`"), source))?;
                return Err(XtaskError::timeout(display, timeout.as_secs()));
            },
            None => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn run_capture<'argument>(
    root: &Path,
    program: &str,
    arguments: impl IntoIterator<Item = &'argument str>,
    timeout: Duration,
    environment: &[(&str, &str)],
) -> Result<CommandOutcome, XtaskError> {
    let arguments = arguments
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let display = command_display(program, &arguments);
    let mut command = Command::new(program);
    command
        .current_dir(root)
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_path(&mut command, root)?;
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command
        .spawn()
        .map_err(|source| XtaskError::io(format!("spawn `{display}`"), source))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        XtaskError::invalid(format!("command `{display}`"), "stdout pipe is unavailable")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        XtaskError::invalid(format!("command `{display}`"), "stderr pipe is unavailable")
    })?;
    let stdout_reader = spawn_output_reader(stdout);
    let stderr_reader = spawn_output_reader(stderr);
    let started = Instant::now();
    let status = loop {
        match child
            .try_wait()
            .map_err(|source| XtaskError::io(format!("wait for `{display}`"), source))?
        {
            Some(status) => break status,
            None if started.elapsed() >= timeout => {
                child
                    .kill()
                    .map_err(|source| XtaskError::io(format!("terminate `{display}`"), source))?;
                let _status = child
                    .wait()
                    .map_err(|source| XtaskError::io(format!("reap `{display}`"), source))?;
                let _stdout = join_output_reader(stdout_reader, &display, "stdout")?;
                let _stderr = join_output_reader(stderr_reader, &display, "stderr")?;
                return Err(XtaskError::timeout(display, timeout.as_secs()));
            },
            None => thread::sleep(Duration::from_millis(25)),
        }
    };
    let mut stdout = join_output_reader(stdout_reader, &display, "stdout")?;
    let stderr = join_output_reader(stderr_reader, &display, "stderr")?;
    stdout.push_str(&stderr);
    if !status.success() {
        return Err(XtaskError::command(
            display,
            format!("exit status {status}: {}", one_line(&stdout)),
        ));
    }
    Ok(CommandOutcome { display, stdout })
}

fn spawn_output_reader(
    mut output: impl Read + Send + 'static,
) -> thread::JoinHandle<std::io::Result<String>> {
    thread::spawn(move || {
        let mut content = String::new();
        output.read_to_string(&mut content)?;
        Ok(content)
    })
}

fn join_output_reader(
    reader: thread::JoinHandle<std::io::Result<String>>,
    command: &str,
    stream: &str,
) -> Result<String, XtaskError> {
    let output = reader.join().map_err(|panic_payload| {
        let detail = if let Some(message) = panic_payload.downcast_ref::<&str>() {
            (*message).to_owned()
        } else if let Some(message) = panic_payload.downcast_ref::<String>() {
            message.clone()
        } else {
            "reader thread panicked without a string payload".to_owned()
        };
        XtaskError::invalid(
            format!("{stream} reader for `{command}`"),
            format!("reader thread failed: {detail}"),
        )
    })?;
    output.map_err(|source| XtaskError::io(format!("read {stream} from `{command}`"), source))
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

fn configure_child_path(command: &mut Command, root: &Path) -> Result<(), XtaskError> {
    let local_tools = root.join("target/quality-tools/bin");
    if !local_tools.is_dir() {
        return Ok(());
    }
    let mut paths = vec![local_tools];
    if let Some(current) = env::var_os("PATH") {
        paths.extend(env::split_paths(&current));
    }
    let joined = env::join_paths(paths)
        .map_err(|source| XtaskError::invalid("child process PATH", source.to_string()))?;
    command.env("PATH", joined);
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, XtaskError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| XtaskError::invalid("gate budget", "no execution time remains"))
}

fn source_identity(root: &Path) -> Result<SourceIdentity, XtaskError> {
    let revision = run_capture(
        root,
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

fn digest_files(root: &Path, files: &[PathBuf]) -> Result<String, XtaskError> {
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

    let mut child = Command::new("git")
        .current_dir(root)
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| XtaskError::io("spawn `git hash-object --stdin`", source))?;
    let Some(mut stdin) = child.stdin.take() else {
        return Err(XtaskError::invalid(
            "registry digest",
            "git hash-object stdin was unavailable",
        ));
    };
    stdin
        .write_all(&payload)
        .map_err(|source| XtaskError::io("write registry digest input", source))?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|source| XtaskError::io("wait for registry digest", source))?;
    if !output.status.success() {
        return Err(XtaskError::command(
            "git hash-object --stdin",
            format!("exit status {}", output.status),
        ));
    }
    let digest = String::from_utf8(output.stdout)
        .map_err(|source| XtaskError::invalid("registry digest encoding", source.to_string()))?
        .trim()
        .to_owned();
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
    use super::{Options, Profile, json_string};

    #[test]
    fn defaults_to_the_complete_pull_request_profile() {
        let options = Options::parse(std::iter::empty());
        assert!(
            matches!(
                options,
                Ok(Options {
                    profile: Profile::Pr
                })
            ),
            "quality must default to the authoritative PR profile"
        );
    }

    #[test]
    fn escapes_evidence_strings_without_losing_content() {
        assert_eq!(
            json_string("line\n\"secret-like\"\\path"),
            "\"line\\n\\\"secret-like\\\"\\\\path\"",
            "evidence JSON must escape control and delimiter characters"
        );
    }
}
