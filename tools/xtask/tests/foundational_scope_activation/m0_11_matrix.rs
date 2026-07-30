use super::*;

const TARGETS: &str = "qualification/engineering/exact-targets.tsv";
const GOLDEN: &str = "tools/xtask/tests/fixtures/m0_11_exact_targets_golden.tsv";
const FAILING: &str = "tools/xtask/tests/fixtures/m0_11_exact_targets_invalid.tsv";

#[test]
fn quality_executes_every_exact_diagnostic_target_with_independent_retained_identity() -> TestResult
{
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "matrix fixture failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
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
    let fixture = Fixture::create_current_registry()?;
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
        let output = fixture.quality_output_for("pr")?;
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
        let fixture = Fixture::create_current_registry()?;
        let result: TestResult = (|| {
            install_matrix_cargo_fault(&fixture, name, body)?;
            let output = fixture.quality_output_for("pr")?;
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
        let fixture = Fixture::create_current_registry()?;
        let result: TestResult = (|| {
            if let Some((before, after)) = registry_change {
                replace_once(&fixture.root.join(TARGETS), before, after)?;
            }
            if name != "stale" {
                install_matrix_cargo_fault(&fixture, name, body)?;
            }
            let output = fixture.quality_output_for("pr")?;
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
    let fixture = Fixture::create_current_registry()?;
    let result: TestResult = (|| {
        fs::remove_file(fixture.root.join("target/quality-tools/bin/cargo"))?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "cargo")?;
        let evidence = fixture.latest_evidence()?;
        if !evidence.contains("\"merge_eligible\": false") {
            return Err(std::io::Error::other(
                "missing matrix tool did not retain non-merge-eligible failure evidence",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_routes_matrix_cancellation_through_the_shared_control_marker() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result: TestResult = (|| {
        install_matrix_cargo_fault(
            &fixture,
            "cancel",
            "printf '%s\\n' \"$$\" > target/quality-tools/matrix-cancellation.pid\n    : > target/quality-tools/matrix-cancel-marker\n    exec sleep 30",
        )?;
        let marker = fixture
            .root
            .join("target/quality-tools/matrix-cancel-marker");
        fixture.build_fixture_xtask()?;
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
            "\"verdict\": \"exit-status:exit status: 0\"",
            "\"verdict\": \"exit-status:exit status: 73\"",
            "passed EG-MATRIX raw report contains a non-passing controlled result",
        ),
    ] {
        let fixture = Fixture::create_current_registry()?;
        let result: TestResult = (|| {
            let first = fixture.quality_output_for("pr")?;
            if !first.status.success() {
                return Err(std::io::Error::other(format!(
                    "{name} baseline matrix evidence failed"
                ))
                .into());
            }
            let path = fixture.latest_evidence_path()?;
            replace_once_after(&path, "\"gate_id\": \"EG-MATRIX\"", original, replacement)?;
            let verified = fixture.quality_output_for("pr")?;
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
    let fixture = Fixture::create_current_registry()?;
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
        let output = fixture.quality_output_for("qual")?;
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
    let (head, suffix) = tail
        .split_once(before)
        .ok_or_else(|| std::io::Error::other("matrix evidence target field is missing"))?;
    fs::write(path, format!("{prefix}{marker}{head}{after}{suffix}"))?;
    Ok(())
}
