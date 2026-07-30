use super::*;

const TARGETS: &str = "qualification/engineering/exact-targets.tsv";
const GOLDEN: &str = "tools/xtask/tests/fixtures/m0_11_exact_targets_golden.tsv";
const FAILING: &str = "tools/xtask/tests/fixtures/m0_11_exact_targets_invalid.tsv";

#[test]
fn quality_executes_every_exact_diagnostic_target_with_independent_retained_identity() -> TestResult
{
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let output = matrix_quality_output(&fixture, "pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                "matrix fixture failed; inspect its retained structured evidence",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-MATRIX")?;
        for required in [
            "target=rust-host-1",
            "target=api-contract-1",
            "target=otlp-protocol-1",
            "target=producer-fixture-1",
            "target=provider-fixture-1",
            "target=macos-host-1",
            "target=crate-graph-1",
            "target=local-fs-1",
            "target=storage-class-1",
            "target=sdk-registry-1",
            "target=native-archive-1",
            "target=generated-sdk-1",
            "target=old-new-api-1",
            "target=evidence-schema-1",
            "plan=matrix-execution-plan-v1",
            "diagnostic=diagnostic-only",
            "argv-digest=sha256:",
            "environment-digest=sha256:",
            "input-digest=sha256:",
            "registry-digest=sha256:",
            "plan-digest=sha256:",
        ] {
            if !gate.contains(required) {
                return Err(
                    std::io::Error::other(format!("matrix evidence omitted `{required}`")).into(),
                );
            }
        }
        if gate.matches("\"resolved_program\":").count() != 14 {
            return Err(std::io::Error::other(
                "matrix did not retain one controlled result per exact target",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_retained_golden_invalid_matrix_descriptor_before_execution() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let golden = fs::read_to_string(fixture.root.join(GOLDEN))?;
        let installed = fs::read_to_string(fixture.root.join(TARGETS))?;
        if golden != installed {
            return Err(std::io::Error::other(
                "M0-11 golden target fixture drifted from the registered exact matrix",
            )
            .into());
        }
        let invalid = fs::read_to_string(fixture.root.join(FAILING))?;
        fs::write(fixture.root.join(TARGETS), invalid)?;
        let output = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(
            &output,
            "must contain every closed matrix kind exactly once",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_matrix_lifecycle_failures_without_retry_or_fallback() -> TestResult {
    for (name, body, expected) in [
        ("nonzero", "exit 73", "exit status exit status: 73"),
        (
            "malformed",
            "printf 'cargo 0.0.0\\n'",
            "malformed cargo-version-v1",
        ),
    ] {
        let fixture = create_matrix_fixture()?;
        let result: TestResult = (|| {
            install_matrix_cargo_fault(&fixture, name, body)?;
            let output = matrix_quality_output(&fixture, "pr")?;
            assert_rejected_output(&output, expected)?;
            let evidence = fixture.latest_evidence()?;
            let gate = gate_record(&evidence, "EG-MATRIX")?;
            if !gate.contains("\"result\": \"failed\"")
                || gate.matches("\"resolved_program\":").count() != 1
            {
                return Err(std::io::Error::other(
                    "matrix failure did not retain exactly the first controlled target attempt",
                )
                .into());
            }
            Ok(())
        })();
        let cleanup = fixture.remove();
        cleanup?;
        result?;
    }
    Ok(())
}

#[test]
fn quality_rejects_timeout_stale_descriptor_and_capture_ceiling_without_matrix_fallback()
-> TestResult {
    for (name, registry_change, body, expected) in [
        ("timeout", Some(("\t30\n", "\t1\n")), "sleep 2", "deadline"),
        (
            "capture",
            None,
            "head -c 200000 /dev/zero | tr '\\000' x",
            "capture",
        ),
        (
            "stale",
            Some(("rust-2024-host-v1", "rust-2024-host-v0")),
            "exit 0",
            "violates its closed M0 diagnostic descriptor contract",
        ),
    ] {
        let fixture = create_matrix_fixture()?;
        let result: TestResult = (|| {
            if let Some((before, after)) = registry_change {
                replace_once(&fixture.root.join(TARGETS), before, after)?;
            }
            if name != "stale" {
                install_matrix_cargo_fault(&fixture, name, body)?;
            }
            let output = matrix_quality_output(&fixture, "pr")?;
            assert_rejected_output(&output, expected)?;
            let evidence = fixture.latest_evidence()?;
            let gate = gate_record(&evidence, "EG-MATRIX")?;
            if !gate.contains("\"result\": \"failed\"") {
                return Err(std::io::Error::other(
                    "matrix lifecycle failure did not retain failed evidence",
                )
                .into());
            }
            Ok(())
        })();
        let cleanup = fixture.remove();
        cleanup?;
        result?;
    }
    Ok(())
}

#[test]
fn quality_rejects_a_missing_matrix_tool_without_an_ambient_fallback() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result: TestResult = (|| {
        fs::remove_file(fixture.root.join("target/quality-tools/bin/cargo"))?;
        let output = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(&output, "required tool `cargo` could not be resolved")?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_routes_matrix_cancellation_through_the_shared_control_marker() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result: TestResult = (|| {
        install_matrix_cargo_fault(
            &fixture,
            "cancel",
            "printf '%s\\n' \"$$\" > target/quality-tools/matrix-cancellation.pid\n    : > target/quality-tools/matrix-cancel-marker\n    exec sleep 30",
        )?;
        let marker = fixture
            .root
            .join("target/quality-tools/matrix-cancel-marker");
        let output = Command::new(fixture.root.join("target/debug/xtask"))
            .current_dir(&fixture.root)
            .args([
                "quality-internal-cancel-dynamic",
                "--profile",
                "pr",
                "--ready-marker",
            ])
            .arg(&marker)
            .output()?;
        assert_rejected_output(
            &output,
            "controlled harness execution failed during cancellation",
        )?;
        let evidence = fixture.latest_evidence()?;
        let raw = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-MATRIX",
        )?)?;
        if !raw.contains("controlled-failure:cancellation") {
            return Err(std::io::Error::other(
                "matrix cancellation is not retained as a typed controlled outcome",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn parent_rejects_coupled_matrix_command_environment_and_result_tampering() -> TestResult {
    for (name, original, replacement, expected) in [
        (
            "command",
            "target=rust-host-1",
            "target=forged-host",
            "retained EG-MATRIX detail does not match independently derived target and plan identities",
        ),
        (
            "result",
            "\"verdict\":\"exit-status:exit status: 0\"",
            "\"verdict\":\"exit-status:exit status: 73\"",
            "passed EG-MATRIX raw report contains a non-passing controlled result",
        ),
    ] {
        let fixture = create_matrix_fixture()?;
        let result: TestResult = (|| {
            let first = matrix_quality_output(&fixture, "pr")?;
            if !first.status.success() {
                return Err(std::io::Error::other(format!(
                    "{name} baseline matrix evidence failed"
                ))
                .into());
            }
            let path = fixture.latest_evidence_path()?;
            if name == "command" {
                replace_once_after(&path, "\"gate_id\": \"EG-MATRIX\"", original, replacement)?;
            } else {
                let evidence = fixture.latest_evidence()?;
                let raw = exact_raw_report_path(&fixture.root, &evidence, "EG-MATRIX")?;
                replace_once(&raw, original, replacement)?;
                let report = fs::read_to_string(&raw)?;
                let digest = format!("sha256:{:x}", Sha256::digest(report.as_bytes()));
                rewrite_gate_field(&path, &evidence, "EG-MATRIX", "\"sha256\": \"", &digest)?;
                let rebound_evidence = fs::read_to_string(&path)?;
                rewrite_gate_field(
                    &path,
                    &rebound_evidence,
                    "EG-MATRIX",
                    "\"bytes\": ",
                    &report.len().to_string(),
                )?;
            }
            let verified = matrix_quality_output(&fixture, "pr")?;
            assert_rejected_output(&verified, expected)
        })();
        let cleanup = fixture.remove();
        cleanup?;
        result?;
    }
    Ok(())
}

#[test]
fn quality_qual_does_not_execute_diagnostic_matrix_targets_or_claim_qualification() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let marker = fixture
            .root
            .join("target/quality-tools/matrix-qual-must-not-run");
        fs::write(&marker, "matrix target must remain unexecuted\n")?;
        install_matrix_cargo_fault(
            &fixture,
            "qual",
            "rm target/quality-tools/matrix-qual-must-not-run\n    exit 73",
        )?;
        let output = matrix_quality_output(&fixture, "qual")?;
        if output.status.success() {
            return Err(std::io::Error::other(
                "QUAL must remain rejected until exact-artifact qualification is authorized",
            )
            .into());
        }
        if !marker.is_file() {
            return Err(
                std::io::Error::other("QUAL executed an M0 diagnostic matrix target").into(),
            );
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-MATRIX")?;
        if !gate.contains("exact-targets=none-for-qual-diagnostic-boundary")
            || !gate.contains("\"controlled_steps\":[]")
        {
            return Err(std::io::Error::other(
                "QUAL matrix evidence did not retain its no-qualification boundary",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn matrix_fixture_suppresses_nested_output_and_retains_structured_evidence() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let output = matrix_quality_output(&fixture, "pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                "matrix output-capture fixture failed; inspect retained structured evidence",
            )
            .into());
        }
        let console_bytes = output
            .stdout
            .len()
            .checked_add(output.stderr.len())
            .ok_or_else(|| std::io::Error::other("matrix console byte count overflowed"))?;
        if console_bytes > MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES {
            return Err(std::io::Error::other(format!(
                "successful 14-target matrix console output exceeds the {MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES}-byte limit"
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-MATRIX",
        )?)?;
        let controlled_steps = report.contains("\"controlled_steps\"");
        let resolved_programs = report.matches("\"resolved_program\"").count();
        if !controlled_steps || resolved_programs != 28 {
            return Err(std::io::Error::other(format!(
                "nested matrix runner did not retain structured controlled evidence: steps={controlled_steps}; resolved-programs={resolved_programs}"
            ))
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn matrix_failure_console_is_bounded_and_points_to_retained_evidence() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result: TestResult = (|| {
        install_matrix_cargo_fault(
            &fixture,
            "console-failure",
            "printf '%s\\n' 'matrix fixture failure' >&2\n    exit 73",
        )?;
        let output = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(&output, "[EG-MATRIX] failed")?;
        let evidence_path = fixture.latest_evidence_path()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("Evidence:")
            || !stdout.contains(evidence_path.to_string_lossy().as_ref())
        {
            return Err(std::io::Error::other(
                "bounded matrix failure console output did not point to retained evidence",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn security_review_selects_pc_0016_for_the_m0_11_merge_base_not_pc_0015() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/m0-11-current-origin-main"),
            "armed\n",
        )?;
        let legacy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
        );
        replace_once(&legacy, "\"path_count\": 26", "\"path_count\": 0")?;
        let output = matrix_quality_output(&fixture, "pr")?;
        if !output.status.success() {
            let evidence = fixture.latest_evidence()?;
            let security = gate_record(&evidence, "EG-SECURITY")?;
            return Err(std::io::Error::other(format!(
                "M0-11 security review did not complete with PC-0015 corrupted: {security}"
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-SECURITY",
        )?)?;
        if !report.contains("change-review=PC-0016-m0-11-compatibility-exact-target-matrix")
            || report.contains("change-review=PC-0015-m0-10-security-crypto-runners")
        {
            return Err(std::io::Error::other(
                "EG-SECURITY did not retain exact PC-0016 selection evidence",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn security_review_requires_pc_0016_implementation_identity_without_pin_to_final_head() -> TestResult
{
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/m0-11-current-origin-main"),
            "armed\n",
        )?;
        let baseline = matrix_quality_output(&fixture, "pr")?;
        if !baseline.status.success() {
            return Err(std::io::Error::other(
                "PC-0016 implementation identity was incorrectly compared with fixture final HEAD",
            )
            .into());
        }
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0016-m0-11-compatibility-exact-target-matrix.json",
        );
        replace_once(
            &policy,
            "\"implementation_revision\": \"2e738ea10aac13fa34d45e77582b7910467c0b83\"",
            "\"implementation_revision\": \"not-a-revision\"",
        )?;
        let stale = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(&stale, "exact reviewed implementation revision identity")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn matrix_internal_input_budget_preserves_complete_rustdoc_and_clean_generated_docs() -> TestResult
{
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let target = fixture.root.join("target/m0-11-rustdoc");
        let documentation = Command::new(env!("CARGO"))
            .current_dir(&fixture.root)
            .env("CARGO_TARGET_DIR", &target)
            .args([
                "doc",
                "--locked",
                "--workspace",
                "--all-features",
                "--no-deps",
                "--document-private-items",
            ])
            .output()?;
        if !documentation.status.success() {
            return Err(std::io::Error::other(
                "complete private-item rustdoc generation failed for the matrix internal-input owner",
            )
            .into());
        }
        let generated = target.join("doc");
        let scan = Command::new("gitleaks")
            .args([
                "dir",
                "--no-banner",
                "--no-color",
                "--redact=100",
                "--max-target-megabytes=20",
            ])
            .arg(&generated)
            .output()?;
        if !scan.status.success() {
            return Err(std::io::Error::other(
                "unchanged generated-doc gitleaks command rejected complete matrix rustdoc",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

const MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES: usize = 8_192;
const MAXIMUM_EXACT_M0_11_COHORT_STDERR_BYTES: usize = 131_072;
const EXACT_M0_11_TEST_COHORT: [&str; 13] = [
    "m0_11_matrix::quality_executes_every_exact_diagnostic_target_with_independent_retained_identity",
    "m0_11_matrix::quality_rejects_retained_golden_invalid_matrix_descriptor_before_execution",
    "m0_11_matrix::quality_rejects_matrix_lifecycle_failures_without_retry_or_fallback",
    "m0_11_matrix::quality_rejects_timeout_stale_descriptor_and_capture_ceiling_without_matrix_fallback",
    "m0_11_matrix::quality_rejects_a_missing_matrix_tool_without_an_ambient_fallback",
    "m0_11_matrix::quality_routes_matrix_cancellation_through_the_shared_control_marker",
    "m0_11_matrix::parent_rejects_coupled_matrix_command_environment_and_result_tampering",
    "m0_11_matrix::quality_qual_does_not_execute_diagnostic_matrix_targets_or_claim_qualification",
    "m0_11_matrix::matrix_fixture_suppresses_nested_output_and_retains_structured_evidence",
    "m0_11_matrix::matrix_failure_console_is_bounded_and_points_to_retained_evidence",
    "m0_11_matrix::security_review_selects_pc_0016_for_the_m0_11_merge_base_not_pc_0015",
    "m0_11_matrix::security_review_requires_pc_0016_implementation_identity_without_pin_to_final_head",
    "m0_11_matrix::matrix_internal_input_budget_preserves_complete_rustdoc_and_clean_generated_docs",
];

#[test]
fn exact_m0_11_test_cohort_retains_stderr_below_the_gate_capture_limit() -> TestResult {
    let mut stderr_bytes = 0_usize;
    for test_name in EXACT_M0_11_TEST_COHORT {
        let output = Command::new(std::env::current_exe()?)
            .args(["--exact", test_name, "--quiet"])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "exact M0-11 test `{test_name}` failed while aggregating stderr"
            ))
            .into());
        }
        stderr_bytes = stderr_bytes
            .checked_add(output.stderr.len())
            .ok_or_else(|| std::io::Error::other("M0-11 cohort stderr byte count overflowed"))?;
    }
    if stderr_bytes > MAXIMUM_EXACT_M0_11_COHORT_STDERR_BYTES {
        return Err(std::io::Error::other(format!(
            "exact M0-11 test cohort stderr exceeds the {MAXIMUM_EXACT_M0_11_COHORT_STDERR_BYTES}-byte gate capture limit"
        ))
        .into());
    }
    Ok(())
}

fn matrix_quality_output(fixture: &Fixture, profile: &str) -> TestResult<std::process::Output> {
    let controlled_path = std::env::join_paths([
        fixture.root.join("target/quality-tools/bin"),
        std::path::PathBuf::from("/usr/bin"),
        std::path::PathBuf::from("/bin"),
        std::path::PathBuf::from("/usr/sbin"),
        std::path::PathBuf::from("/sbin"),
    ])?;
    let output = Command::new(fixture.root.join("target/debug/xtask"))
        .current_dir(&fixture.root)
        .args(["quality", "--profile", profile])
        .env("PATH", controlled_path)
        .output()?;
    let bytes = output
        .stdout
        .len()
        .checked_add(output.stderr.len())
        .ok_or_else(|| std::io::Error::other("nested matrix output byte count overflowed"))?;
    if bytes > MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES {
        return Err(std::io::Error::other(format!(
            "nested matrix runner output exceeds the {MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES}-byte fixture suppression budget"
        ))
        .into());
    }
    Ok(output)
}

fn create_matrix_fixture() -> TestResult<Fixture> {
    let fixture = Fixture::create_current_registry()?;
    fixture.build_fixture_xtask()?;
    Ok(fixture)
}

fn install_matrix_cargo_fault(fixture: &Fixture, name: &str, body: &str) -> TestResult {
    let marker = format!("target/quality-tools/matrix-fault-{name}");
    let cargo = fixture.root.join("target/quality-tools/bin/cargo");
    let insertion = format!(
        "if [ -n \"${{POSITRON_MATRIX_TARGET_ID:-}}\" ] && [ -f {marker} ]; then\n  {body}\nfi\ncase \"$command\" in"
    );
    replace_once(&cargo, "case \"$command\" in", &insertion)?;
    fs::write(fixture.root.join(marker), "trigger\n")?;
    Ok(())
}

fn replace_once_after(path: &Path, marker: &str, before: &str, after: &str) -> TestResult {
    let content = fs::read_to_string(path)?;
    let (prefix, tail) = content
        .split_once(marker)
        .ok_or_else(|| std::io::Error::other("matrix evidence gate marker is missing"))?;
    let (head, suffix) = tail.split_once(before).ok_or_else(|| {
        std::io::Error::other(format!(
            "matrix evidence target field `{before}` is missing"
        ))
    })?;
    fs::write(path, format!("{prefix}{marker}{head}{after}{suffix}"))?;
    Ok(())
}
