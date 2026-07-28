#![forbid(unsafe_code)]

//! Black-box contract fixtures for foundational scope activation.

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ACTIVATION_ID: &str = "M0-01";
const ACTIVATION_SET: &str = "positron-api|positron-config|positron-domain";
const POLICY_CHANGE: &str =
    "qualification/engineering/policy-changes/PC-0002-m0-01-foundational-scope-activation.json";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn quality_accepts_the_complete_atomic_foundational_activation_ledger() -> TestResult {
    let fixture = Fixture::create_with_real_git()?;
    let result = fixture.quality();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_accepts_a_scaffold_only_workspace_with_pending_thresholds() -> TestResult {
    assert_fixture_accepted(configure_scaffold_only_policy)
}

#[test]
fn quality_pr_skips_the_scheduled_coverage_campaign() -> TestResult {
    let fixture = Fixture::create()?;
    fs::write(
        fixture
            .root
            .join("target/quality-tools/reject-coverage-execution"),
        "",
    )?;
    let result = fixture.quality_profile("pr");
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_ext_executes_the_foundational_coverage_harness() -> TestResult {
    let fixture = Fixture::create()?;
    let result = fixture.quality_profile("ext");
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_ext_rejects_coverage_below_the_frozen_baseline() -> TestResult {
    assert_fixture_rejected_profile(
        "ext",
        reduce_line_coverage_measurement,
        "coverage line 99.00 is below frozen M0 baseline 100.00",
    )
}

#[test]
fn quality_ext_rejects_an_unpinned_coverage_detector() -> TestResult {
    assert_fixture_rejected_profile(
        "ext",
        make_coverage_detector_report_a_different_version,
        "coverage detector `cargo-llvm-cov`: expected version `0.8.7`",
    )
}

#[test]
fn quality_rejects_an_activation_without_a_measured_baseline() -> TestResult {
    assert_fixture_rejected(
        remove_coverage_baseline,
        "baseline `coverage-line` is not measured",
    )
}

#[test]
fn quality_rejects_a_nonfinite_measured_baseline() -> TestResult {
    assert_fixture_rejected(
        make_coverage_baseline_nonfinite,
        "measured baselines must use a non-negative numeric value",
    )
}

#[test]
fn quality_rejects_an_unrecognized_m0_threshold_state() -> TestResult {
    assert_fixture_rejected(
        |root| set_threshold_field(root, "coverage-line", "state", "unmeasured"),
        "baseline `coverage-line` is not measured",
    )
}

#[test]
fn quality_rejects_each_nonempty_activation_ledger_field_on_a_scaffold_scope() -> TestResult {
    assert_scope_fields_rejected(
        "positron-query",
        &[
            ("activation_id", "M0-01"),
            ("activation_scope_set", "positron-domain"),
            ("allowed_edges", "positron-query->positron-domain"),
            ("risk_gates", "EG-COVERAGE"),
            (
                "test_commands",
                "cargo test --locked --package xtask --test foundational_scope_activation",
            ),
            ("coverage_baseline", "coverage-line"),
            ("mutation_baseline", "mutation-score"),
            ("dependency_review", "none"),
            ("contract_evidence", POLICY_CHANGE),
        ],
        "scaffold application scopes cannot advertise activation, edges, gates, tests, baselines, reviews, or evidence",
    )
}

#[test]
fn quality_rejects_each_missing_activation_ledger_field_on_an_active_scope() -> TestResult {
    assert_scope_fields_rejected(
        "positron-domain",
        &[
            ("activation_id", "-"),
            ("activation_scope_set", "-"),
            ("allowed_edges", "-"),
            ("risk_gates", "-"),
            ("test_commands", "-"),
            ("coverage_baseline", "-"),
            ("mutation_baseline", "-"),
            ("dependency_review", "-"),
            ("contract_evidence", "-"),
        ],
        "active application scopes require an atomic activation ledger",
    )
}

#[test]
fn quality_rejects_each_application_activation_field_on_a_tooling_scope() -> TestResult {
    assert_scope_fields_rejected(
        "xtask",
        &[
            ("activation_id", "M0-01"),
            ("activation_scope_set", "positron-domain"),
            ("allowed_edges", "xtask->positron-domain"),
            ("coverage_baseline", "coverage-line"),
            ("mutation_baseline", "mutation-score"),
            ("dependency_review", "none"),
            ("contract_evidence", POLICY_CHANGE),
        ],
        "tooling scopes cannot claim application activation ledger fields",
    )
}

#[test]
fn quality_rejects_a_scope_set_that_is_neither_dash_nor_a_nonempty_set() -> TestResult {
    assert_fixture_rejected(
        |root| set_scope_field(root, "positron-query", "activation_scope_set", "|"),
        "field `activation_scope_set` must be `-` or a non-empty pipe-delimited set",
    )
}

#[test]
fn quality_rejects_malformed_activation_edges() -> TestResult {
    for malformed in [
        "->positron-domain",
        "positron-query->",
        "positron-query->positron-query",
    ] {
        assert_fixture_rejected(
            |root| set_scope_field(root, "positron-query", "allowed_edges", malformed),
            "field `allowed_edges` has an invalid edge",
        )?;
    }
    Ok(())
}

#[test]
fn quality_rejects_invalid_measured_baseline_values() -> TestResult {
    for invalid in ["not-a-number", "-1"] {
        assert_fixture_rejected(
            |root| set_threshold_field(root, "coverage-line", "value", invalid),
            "measured baselines must use a non-negative numeric value",
        )?;
    }
    Ok(())
}

#[test]
fn quality_accepts_zero_as_a_valid_measured_baseline() -> TestResult {
    assert_fixture_accepted(|root| set_threshold_field(root, "coverage-line", "value", "0"))
}

#[test]
fn quality_rejects_an_activation_group_other_than_m0_01() -> TestResult {
    assert_scope_fields_rejected(
        "positron-domain",
        &[("activation_id", "M0-02")],
        "this M0 policy may activate only the exact M0-01 foundational scope group",
    )
}

#[test]
fn quality_rejects_an_incomplete_foundational_scope_set() -> TestResult {
    assert_fixture_rejected(
        |root| {
            set_scope_field(
                root,
                "positron-domain",
                "activation_scope_set",
                "positron-api|positron-domain",
            )
        },
        "scope `positron-domain` does not declare the complete M0-01 set",
    )
}

#[test]
fn quality_rejects_a_missing_mutation_baseline_reference() -> TestResult {
    assert_fixture_rejected(
        |root| {
            set_scope_field(
                root,
                "positron-domain",
                "mutation_baseline",
                "different-score",
            )
        },
        "scope `positron-domain` is missing the complete M0 baseline set",
    )
}

#[test]
fn quality_rejects_an_unreviewed_activation_dependency() -> TestResult {
    assert_fixture_rejected(
        |root| {
            set_scope_field(
                root,
                "positron-domain",
                "dependency_review",
                "unreviewed-dependency",
            )
        },
        "scope `positron-domain` names unreviewed dependency `unreviewed-dependency`",
    )
}

#[test]
fn quality_rejects_an_activation_without_its_registered_owner() -> TestResult {
    assert_fixture_rejected(missing_domain_owner, "unknown semantic owner `-`")
}

#[test]
fn quality_rejects_an_absolute_scope_path() -> TestResult {
    assert_fixture_rejected(
        make_foundational_scope_path_absolute,
        "scope path must be repository-relative",
    )
}

#[test]
fn quality_rejects_a_forbidden_foundational_dependency_edge() -> TestResult {
    assert_fixture_rejected(
        add_forbidden_foundational_edge,
        "foundation edge `positron-domain->positron-api` is forbidden",
    )
}

#[test]
fn quality_rejects_a_missing_registered_foundational_edge() -> TestResult {
    assert_fixture_rejected(
        remove_registered_foundational_edge,
        "foundation edges for `positron-domain` do not match its activation ledger",
    )
}

#[test]
fn quality_rejects_a_cycle_in_the_registered_architecture_edges() -> TestResult {
    assert_fixture_rejected(
        add_architecture_cycle,
        "architecture edge registry: cycle reaches `positron`",
    )
}

#[test]
fn quality_rejects_a_deliberately_unregistered_source_file() -> TestResult {
    assert_fixture_rejected(
        add_unregistered_source_file,
        "code or executable source is outside every registered crate or artifact scope",
    )
}

#[test]
fn quality_rejects_behavior_in_a_remaining_scaffold_crate() -> TestResult {
    assert_fixture_rejected(
        add_behavior_to_scaffold_crate,
        "adds behavior to scaffold-only scope `positron-query`",
    )
}

#[test]
fn quality_rejects_a_pass_through_module_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_pass_through_reexport,
        "pass-through module surface is forbidden",
    )
}

#[test]
fn quality_rejects_a_deferred_runtime_symbol_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_deferred_metrics_symbol,
        "deferred runtime symbol `MetricsStore` is forbidden",
    )
}

#[test]
fn quality_rejects_a_hidden_feature_flag_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_hidden_feature_flag,
        "scope `positron-domain` declares `[features]` despite its `none` dependency review",
    )
}

#[test]
fn quality_rejects_a_placeholder_api_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_placeholder_api,
        "activation-only scope `positron-domain` contains behavior or a placeholder API",
    )
}

#[test]
fn quality_rejects_a_disabled_deferred_module_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_disabled_deferred_module,
        "activation-only scope `positron-domain` contains behavior or a placeholder API",
    )
}

#[test]
fn quality_rejects_an_extra_doc_only_source_in_an_activation_only_scope() -> TestResult {
    assert_fixture_rejected(
        add_extra_doc_only_activation_source,
        "activation-only scope `positron-domain` must retain exactly its crate root source",
    )
}

#[test]
fn quality_does_not_misclassify_a_symbol_with_a_deferred_prefix() -> TestResult {
    assert_fixture_rejected(
        add_non_deferred_symbol_with_a_deferred_prefix,
        "activation-only scope `positron-domain` contains behavior or a placeholder API",
    )
}

#[test]
fn quality_rejects_an_activated_coverage_gate_without_ci_tool_provisioning() -> TestResult {
    assert_fixture_rejected(
        remove_coverage_tool_provisioning,
        "coverage-selected workflow `.github/workflows/extended.yml` is missing",
    )
}

#[test]
fn quality_rejects_a_coverage_workflow_that_does_not_retain_raw_reports() -> TestResult {
    assert_fixture_rejected(
        remove_raw_coverage_report_retention,
        "coverage-selected workflow `.github/workflows/extended.yml` must retain `target/quality/`",
    )
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn create() -> TestResult<Self> {
        Self::create_with_identity(false)
    }

    fn create_with_real_git() -> TestResult<Self> {
        Self::create_with_identity(true)
    }

    fn create_with_identity(real_git: bool) -> TestResult<Self> {
        let root = temporary_root()?;
        let source = repository_root()?;
        copy_tree(&source, &root)?;
        configure_activation_ledger(&root)?;
        install_fixture_tools(&root, real_git)?;
        if real_git {
            initialize_git_repository(&root)?;
        }
        Ok(Self { root })
    }

    fn quality(&self) -> TestResult {
        let output = self.quality_output()?;
        if output.status.success() {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(std::io::Error::other(format!(
            "the public quality runner rejected the complete activation fixture: {stdout}\n{stderr}"
        ))
        .into())
    }

    fn quality_profile(&self, profile: &str) -> TestResult {
        let output = self.quality_output_for(profile)?;
        if output.status.success() {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(std::io::Error::other(format!(
            "the public quality runner rejected the complete activation fixture: {stdout}\n{stderr}"
        ))
        .into())
    }

    fn quality_output(&self) -> TestResult<std::process::Output> {
        self.quality_output_for("pre-commit")
    }

    fn quality_output_for(&self, profile: &str) -> TestResult<std::process::Output> {
        let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .current_dir(&self.root)
            .args(["quality", "--profile", profile])
            .output()?;
        Ok(output)
    }

    fn remove(self) -> TestResult {
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }
}

fn assert_fixture_rejected(
    mutate: impl FnOnce(&Path) -> TestResult,
    expected_failure: &str,
) -> TestResult {
    assert_fixture_rejected_profile("pre-commit", mutate, expected_failure)
}

fn assert_fixture_rejected_profile(
    profile: &str,
    mutate: impl FnOnce(&Path) -> TestResult,
    expected_failure: &str,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        mutate(&fixture.root)?;
        assert_existing_fixture_rejected(&fixture, profile, expected_failure)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_existing_fixture_rejected(
    fixture: &Fixture,
    profile: &str,
    expected_failure: &str,
) -> TestResult {
    let output = fixture.quality_output_for(profile)?;
    if output.status.success() {
        return Err(std::io::Error::other(
            "the public quality runner accepted an invalid activation fixture",
        )
        .into());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    if !combined.contains(expected_failure) {
        return Err(std::io::Error::other(format!(
            "quality failed for the wrong reason; expected `{expected_failure}`, got `{combined}`"
        ))
        .into());
    }
    Ok(())
}

fn assert_fixture_accepted(mutate: impl FnOnce(&Path) -> TestResult) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        mutate(&fixture.root)?;
        fixture.quality()
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_scope_fields_rejected(
    package: &str,
    fields: &[(&str, &str)],
    expected_failure: &str,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        for (field, value) in fields {
            configure_activation_ledger(&fixture.root)?;
            set_scope_field(&fixture.root, package, field, value)?;
            assert_existing_fixture_rejected(&fixture, "pre-commit", expected_failure)?;
        }
        configure_activation_ledger(&fixture.root)?;
        fixture.quality()
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn repository_root() -> TestResult<PathBuf> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_directory
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("xtask manifest has no workspace root"))?;
    Ok(root.to_path_buf())
}

fn temporary_root() -> TestResult<PathBuf> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = env::temp_dir().join(format!(
        "positron-foundational-activation-{}-{timestamp}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn copy_tree(source: &Path, destination: &Path) -> TestResult {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_str(), Some(".git" | "target" | "mutants.out")) {
            continue;
        }
        let target = destination.join(&name);
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(std::io::Error::other(format!(
                "fixture source contains an unsupported symlink: {}",
                entry.path().display()
            ))
            .into());
        }
        if file_type.is_dir() {
            fs::create_dir_all(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn configure_activation_ledger(root: &Path) -> TestResult {
    rewrite_scopes(root)?;
    rewrite_edges(root)?;
    rewrite_thresholds(root)?;
    write_policy_change(root)?;
    remove_scaffold_markers(root)?;
    Ok(())
}

fn configure_scaffold_only_policy(root: &Path) -> TestResult {
    for package in ["positron-domain", "positron-api", "positron-config"] {
        set_scope_field(root, package, "state", "scaffold")?;
        for field in [
            "activation_id",
            "activation_scope_set",
            "allowed_edges",
            "risk_gates",
            "test_commands",
            "coverage_baseline",
            "mutation_baseline",
            "dependency_review",
            "contract_evidence",
        ] {
            set_scope_field(root, package, field, "-")?;
        }
        restore_scaffold_marker(root, package)?;
    }
    for threshold in [
        "coverage-line",
        "coverage-region",
        "coverage-branch",
        "coverage-changed-code",
        "mutation-score",
    ] {
        set_threshold_field(root, threshold, "state", "pending-measured-baseline")?;
        set_threshold_field(root, threshold, "value", "-")?;
        set_threshold_field(root, threshold, "scope", "active-application-code")?;
        set_threshold_field(root, threshold, "evidence", "-")?;
    }
    Ok(())
}

fn remove_coverage_baseline(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/thresholds.tsv"),
        "coverage-line\tmeasured-baseline\t100.00",
        "coverage-line\tpending-measured-baseline\t-",
    )
}

fn make_coverage_baseline_nonfinite(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/thresholds.tsv"),
        "coverage-line\tmeasured-baseline\t100.00",
        "coverage-line\tmeasured-baseline\tNaN",
    )
}

fn missing_domain_owner(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/scopes.tsv"),
        "positron-domain\tcrates/positron-domain\tArchitecture",
        "positron-domain\tcrates/positron-domain\t-",
    )
}

fn make_foundational_scope_path_absolute(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/scopes.tsv"),
        "positron-domain\tcrates/positron-domain",
        "positron-domain\t/activation-must-not-escape-the-repository",
    )
}

fn add_forbidden_foundational_edge(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/architecture-edges.tsv");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("positron-domain\tpositron-api\tM0-01\n");
    fs::write(path, content)?;
    Ok(())
}

fn remove_registered_foundational_edge(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/architecture-edges.tsv"),
        "positron-runtime\tpositron-domain\tM0-01\n",
        "",
    )
}

fn add_architecture_cycle(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/architecture-edges.tsv");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("positron-backup\tpositron\t-\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_unregistered_source_file(root: &Path) -> TestResult {
    fs::write(root.join("unregistered.rs"), "fn forbidden() {}\n")?;
    Ok(())
}

fn add_behavior_to_scaffold_crate(root: &Path) -> TestResult {
    let path = root.join("crates/positron-query/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub fn behavior_is_not_legal_here() {}\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_pass_through_reexport(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub use positron_api::GeneratedMessage;\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_deferred_metrics_symbol(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub struct MetricsStore;\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_hidden_feature_flag(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/Cargo.toml");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\n[features]\ndeferred-metrics = []\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_placeholder_api(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub struct PlaceholderApi;\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_disabled_deferred_module(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\n#[cfg(feature = \"deferred-metrics\")]\nmod metrics;\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_extra_doc_only_activation_source(root: &Path) -> TestResult {
    fs::write(
        root.join("crates/positron-domain/src/extra.rs"),
        "//! This source file is deliberately documentation-only.\n",
    )?;
    Ok(())
}

fn add_non_deferred_symbol_with_a_deferred_prefix(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub struct MetricsStorehouse;\n");
    fs::write(path, content)?;
    Ok(())
}

fn remove_coverage_tool_provisioning(root: &Path) -> TestResult {
    let path = root.join(".github/workflows/extended.yml");
    let content = fs::read_to_string(&path)?;
    let content = content
        .replace(
            "      - name: Install pinned branch-coverage toolchain\n        run: rustup toolchain install nightly-2026-07-20 --profile minimal --component llvm-tools-preview\n\n",
            "",
        )
        .replace(
            "          cargo install --locked --version 0.8.7 cargo-llvm-cov\n",
            "",
        );
    fs::write(path, content)?;
    Ok(())
}

fn remove_raw_coverage_report_retention(root: &Path) -> TestResult {
    replace_once(
        &root.join(".github/workflows/extended.yml"),
        "path: target/quality/",
        "path: target/quality/coverage/",
    )?;
    Ok(())
}

fn reduce_line_coverage_measurement(root: &Path) -> TestResult {
    replace_once(
        &root.join("target/quality-tools/bin/cargo"),
        "\"lines\":{\"percent\":100.0}",
        "\"lines\":{\"percent\":99.0}",
    )
}

fn make_coverage_detector_report_a_different_version(root: &Path) -> TestResult {
    replace_once(
        &root.join("target/quality-tools/bin/cargo"),
        "cargo-llvm-cov 0.8.7",
        "cargo-llvm-cov 0.8.6",
    )
}

fn replace_once(path: &Path, before: &str, after: &str) -> TestResult {
    let content = fs::read_to_string(path)?;
    let Some((prefix, suffix)) = content.split_once(before) else {
        return Err(std::io::Error::other(format!(
            "fixture source {} does not contain `{before}`",
            path.display()
        ))
        .into());
    };
    fs::write(path, format!("{prefix}{after}{suffix}"))?;
    Ok(())
}

fn set_scope_field(root: &Path, package: &str, field: &str, value: &str) -> TestResult {
    set_tsv_field(
        &root.join("qualification/engineering/scopes.tsv"),
        "package",
        package,
        field,
        value,
    )
}

fn set_threshold_field(root: &Path, threshold_id: &str, field: &str, value: &str) -> TestResult {
    set_tsv_field(
        &root.join("qualification/engineering/thresholds.tsv"),
        "threshold_id",
        threshold_id,
        field,
        value,
    )
}

fn set_tsv_field(
    path: &Path,
    identity_field: &str,
    identity: &str,
    field: &str,
    value: &str,
) -> TestResult {
    let content = fs::read_to_string(path)?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| std::io::Error::other(format!("{} has no header", path.display())))?;
    let headers = header.split('\t').collect::<Vec<_>>();
    let identity_index = headers
        .iter()
        .position(|header| *header == identity_field)
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "{} has no `{identity_field}` column",
                path.display()
            ))
        })?;
    let field_index = headers
        .iter()
        .position(|header| *header == field)
        .ok_or_else(|| {
            std::io::Error::other(format!("{} has no `{field}` column", path.display()))
        })?;
    let mut rewritten = vec![header.to_owned()];
    let mut replaced = false;
    for line in lines {
        let mut fields = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
        if fields.len() != headers.len() {
            return Err(std::io::Error::other(format!(
                "{} has an unexpected field count",
                path.display()
            ))
            .into());
        }
        let current_value = fields.get(identity_index).ok_or_else(|| {
            std::io::Error::other(format!(
                "{} has no `{identity_field}` column value",
                path.display()
            ))
        })?;
        if current_value == identity {
            let selected_field = fields.get_mut(field_index).ok_or_else(|| {
                std::io::Error::other(format!("{} has no `{field}` column value", path.display()))
            })?;
            *selected_field = value.to_owned();
            replaced = true;
        }
        rewritten.push(fields.join("\t"));
    }
    if !replaced {
        return Err(std::io::Error::other(format!(
            "{} has no `{identity_field}` value `{identity}`",
            path.display()
        ))
        .into());
    }
    fs::write(path, format!("{}\n", rewritten.join("\n")))?;
    Ok(())
}

fn rewrite_scopes(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/scopes.tsv");
    let existing = fs::read_to_string(&path)?;
    let mut rewritten = String::from(
        "package\tpath\tsemantic_owner\tkind\tstate\tactivation_id\tactivation_scope_set\tallowed_edges\trisk_gates\ttest_commands\tcoverage_baseline\tmutation_baseline\tdependency_review\tcontract_evidence\n",
    );
    for (line_number, line) in existing.lines().enumerate() {
        if line_number == 0 {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        let (
            package,
            scope_path,
            semantic_owner,
            kind,
            existing_state,
            existing_risk_gates,
            existing_test_commands,
        ) = match fields.as_slice() {
            [
                package,
                scope_path,
                semantic_owner,
                kind,
                state,
                risk_gates,
                test_commands,
            ] => (
                *package,
                *scope_path,
                *semantic_owner,
                *kind,
                *state,
                *risk_gates,
                *test_commands,
            ),
            [
                package,
                scope_path,
                semantic_owner,
                kind,
                state,
                _,
                _,
                _,
                risk_gates,
                test_commands,
                _,
                _,
                _,
                _,
            ] => (
                *package,
                *scope_path,
                *semantic_owner,
                *kind,
                *state,
                *risk_gates,
                *test_commands,
            ),
            _ => {
                return Err(std::io::Error::other(format!(
                    "unexpected source scope field count on line {}",
                    line_number + 1
                ))
                .into());
            },
        };
        let (
            state,
            activation_id,
            scope_set,
            edges,
            risk_gates,
            test_commands,
            coverage,
            mutation,
            review,
            trace,
        ) = match package {
            "positron-domain" => (
                "active",
                ACTIVATION_ID,
                ACTIVATION_SET,
                "positron-backup->positron-domain|positron-governance->positron-domain|positron-ingest->positron-domain|positron-kernel->positron-domain|positron-query->positron-domain|positron-runtime->positron-domain|positron-signals->positron-domain",
                "EG-COVERAGE",
                "cargo test --locked --package xtask --test foundational_scope_activation",
                "coverage-branch|coverage-changed-code|coverage-line|coverage-region",
                "mutation-score",
                "none",
                POLICY_CHANGE,
            ),
            "positron-api" => (
                "active",
                ACTIVATION_ID,
                ACTIVATION_SET,
                "positron-operator->positron-api|positron-runtime->positron-api",
                "EG-COVERAGE",
                "cargo test --locked --package xtask --test foundational_scope_activation",
                "coverage-branch|coverage-changed-code|coverage-line|coverage-region",
                "mutation-score",
                "none",
                POLICY_CHANGE,
            ),
            "positron-config" => (
                "active",
                ACTIVATION_ID,
                ACTIVATION_SET,
                "positron-runtime->positron-config",
                "EG-COVERAGE",
                "cargo test --locked --package xtask --test foundational_scope_activation",
                "coverage-branch|coverage-changed-code|coverage-line|coverage-region",
                "mutation-score",
                "none",
                POLICY_CHANGE,
            ),
            _ if kind == "application" => ("scaffold", "-", "-", "-", "-", "-", "-", "-", "-", "-"),
            _ => (
                existing_state,
                "-",
                "-",
                "-",
                existing_risk_gates,
                existing_test_commands,
                "-",
                "-",
                "-",
                "-",
            ),
        };
        rewritten.push_str(&format!(
            "{}\t{}\t{}\t{}\t{state}\t{activation_id}\t{scope_set}\t{edges}\t{risk_gates}\t{test_commands}\t{coverage}\t{mutation}\t{review}\t{trace}\n",
            package, scope_path, semantic_owner, kind
        ));
    }
    fs::write(path, rewritten)?;
    Ok(())
}

fn rewrite_edges(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/architecture-edges.tsv");
    let existing = fs::read_to_string(&path)?;
    let mut rewritten = String::from("caller\tdependency\tactivation_id\n");
    for (line_number, line) in existing.lines().enumerate() {
        if line_number == 0 {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        let (caller, dependency) = match fields.as_slice() {
            [caller, dependency] | [caller, dependency, _] => (*caller, *dependency),
            _ => {
                return Err(std::io::Error::other(format!(
                    "unexpected source edge field count on line {}",
                    line_number + 1
                ))
                .into());
            },
        };
        let activation_id = if matches!(
            dependency,
            "positron-domain" | "positron-api" | "positron-config"
        ) {
            ACTIVATION_ID
        } else {
            "-"
        };
        rewritten.push_str(&format!("{caller}\t{dependency}\t{activation_id}\n"));
    }
    fs::write(path, rewritten)?;
    Ok(())
}

fn rewrite_thresholds(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/thresholds.tsv");
    let existing = fs::read_to_string(&path)?;
    let mut rewritten =
        String::from("threshold_id\tstate\tvalue\tunit\tscope\trationale\tevidence\n");
    for (line_number, line) in existing.lines().enumerate() {
        if line_number == 0 {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        let (
            threshold_id,
            existing_state,
            existing_value,
            unit,
            existing_scope,
            existing_rationale,
        ) = match fields.as_slice() {
            [threshold_id, state, value, unit, scope, rationale]
            | [threshold_id, state, value, unit, scope, rationale, _] => {
                (*threshold_id, *state, *value, *unit, *scope, *rationale)
            },
            _ => {
                return Err(std::io::Error::other(format!(
                    "unexpected source threshold field count on line {}",
                    line_number + 1
                ))
                .into());
            },
        };
        let (state, value, scope, rationale, evidence) = match threshold_id {
            "coverage-line" | "coverage-region" | "coverage-branch" | "coverage-changed-code" => (
                "measured-baseline",
                "100.00",
                "m0-01-foundational-policy",
                "Fixture measurement for the public activation-policy seam",
                POLICY_CHANGE,
            ),
            "mutation-score" => (
                "measured-baseline",
                "100.00",
                "m0-01-foundational-policy",
                "Fixture mutation measurement for the public activation-policy seam",
                POLICY_CHANGE,
            ),
            _ => (
                existing_state,
                existing_value,
                existing_scope,
                existing_rationale,
                "-",
            ),
        };
        rewritten.push_str(&format!(
            "{}\t{state}\t{value}\t{}\t{scope}\t{rationale}\t{evidence}\n",
            threshold_id, unit
        ));
    }
    fs::write(path, rewritten)?;
    Ok(())
}

fn write_policy_change(root: &Path) -> TestResult {
    let content = r#"{
  "schema_version": 1,
  "id": "PC-0002-m0-01-foundational-scope-activation",
  "status": "proposed-for-independent-review",
  "activation_id": "M0-01",
  "scope_set": ["positron-domain", "positron-api", "positron-config"],
  "baseline_evidence": "measured",
  "dependency_review": "none",
  "approvals_required": ["Architecture", "Quality Engineering"]
}
"#;
    fs::write(root.join(POLICY_CHANGE), content)?;
    Ok(())
}

fn remove_scaffold_markers(root: &Path) -> TestResult {
    for package in ["positron-domain", "positron-api", "positron-config"] {
        let path = root.join("crates").join(package).join("src/lib.rs");
        let content = fs::read_to_string(&path)?;
        fs::write(
            path,
            content.replacen("//! @positron-scaffold-only\n", "", 1),
        )?;
    }
    Ok(())
}

fn restore_scaffold_marker(root: &Path, package: &str) -> TestResult {
    let path = root.join("crates").join(package).join("src/lib.rs");
    let content = fs::read_to_string(&path)?;
    if content.starts_with("//! @positron-scaffold-only\n") {
        return Ok(());
    }
    fs::write(path, format!("//! @positron-scaffold-only\n{content}"))?;
    Ok(())
}

fn install_fixture_tools(root: &Path, real_git: bool) -> TestResult {
    let directory = root.join("target/quality-tools/bin");
    fs::create_dir_all(&directory)?;
    write_tool(
        &directory.join("rustfmt"),
        "#!/bin/sh\nprintf 'rustfmt 1.9.0-stable\\n'\n",
    )?;
    write_tool(
        &directory.join("rustc"),
        "#!/bin/sh\nprintf 'rustc 1.96.0\\n'\n",
    )?;
    write_tool(
        &directory.join("cargo-machete"),
        "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then\n  printf 'cargo-machete 0.9.2\\n'\nfi\n",
    )?;
    write_tool(
        &directory.join("cargo"),
        r#"#!/bin/sh
set -eu
command="${1:-}"
if [ "$command" = "+nightly-2026-07-20" ]; then
  shift
  command="${1:-}"
fi
case "$command" in
  --version)
    printf 'cargo 1.96.0\n'
    ;;
  clippy)
    if [ "${2:-}" = "--version" ]; then
      printf 'clippy 0.1.96\n'
    fi
    ;;
  nextest)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-nextest 0.9.138\n'
    fi
    ;;
  deny)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-deny 0.19.9\n'
    fi
    ;;
  audit)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-audit 0.22.2\n'
    fi
    ;;
  vet)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-vet 0.10.2\n'
    fi
    ;;
  llvm-cov)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-llvm-cov 0.8.7\n'
      exit 0
    fi
    if [ -f target/quality-tools/reject-coverage-execution ]; then
      printf '%s\n' 'fixture rejects routine coverage execution' >&2
      exit 75
    fi
    output=
    previous=
    for argument in "$@"; do
      if [ "$previous" = "--output-path" ]; then
        output="$argument"
        break
      fi
      previous="$argument"
    done
    if [ -n "$output" ]; then
      mkdir -p "$(dirname "$output")"
      printf '%s\n' '{"data":[{"totals":{"branches":{"percent":100.0},"lines":{"percent":100.0},"regions":{"percent":100.0}}}]}' > "$output"
    fi
    ;;
  tree)
    package=unknown
    previous=
    for argument in "$@"; do
      if [ "$previous" = "--package" ]; then
        package=$argument
        break
      fi
      previous=$argument
    done
    printf '%s v0.0.0\n' "$package"
    ;;
esac
"#,
    )?;
    write_tool(
        &directory.join("gitleaks"),
        "#!/bin/sh\nif [ \"${1:-}\" = \"version\" ]; then\n  printf '8.30.1\\n'\nfi\n",
    )?;
    if !real_git {
        write_tool(
            &directory.join("git"),
            r#"#!/bin/sh
set -eu
case "${1:-}" in
  rev-parse)
    printf '%s\n' '0000000000000000000000000000000000000000'
    ;;
  status)
    ;;
  hash-object)
    cat >/dev/null
    printf '%s\n' '1111111111111111111111111111111111111111'
    ;;
  *)
    printf 'unsupported fixture git command: %s\n' "${1:-}" >&2
    exit 2
    ;;
esac
"#,
        )?;
    }
    Ok(())
}

fn write_tool(path: &Path, content: &str) -> TestResult {
    fs::write(path, content)?;
    make_executable(path)?;
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> TestResult {
    Ok(())
}

fn initialize_git_repository(root: &Path) -> TestResult {
    run_git(root, ["init", "--quiet"])?;
    run_git(root, ["config", "user.email", "fixtures@example.invalid"])?;
    run_git(root, ["config", "user.name", "Positron fixture"])?;
    run_git(root, ["add", "."])?;
    run_git(root, ["commit", "--quiet", "-m", "fixture"])?;
    Ok(())
}

fn run_git<const N: usize>(root: &Path, arguments: [&str; N]) -> TestResult {
    let status = Command::new("git")
        .current_dir(root)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(arguments)
        .status()?;
    if status.success() {
        return Ok(());
    }
    Err(std::io::Error::other("fixture Git setup failed").into())
}
