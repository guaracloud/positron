use super::*;

include!("m0_11_matrix_execution.rs");
include!("m0_11_matrix_lifecycle.rs");
include!("m0_11_matrix_policy.rs");

const MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES: usize = 8_192;
const MAXIMUM_MATRIX_CONSOLE_BYTES: usize = 512;
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
    "m0_11_matrix::security_review_rejects_a_corrupt_unselected_pc_0015_before_pc_0016_selection",
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
    if profile == "pr" && bytes > MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES {
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
