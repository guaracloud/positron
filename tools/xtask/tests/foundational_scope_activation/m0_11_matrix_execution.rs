const TARGETS: &str = "qualification/engineering/exact-targets.tsv";
const GOLDEN: &str = "qualification/engineering/exact-targets-golden.tsv";
const FAILING: &str = "qualification/engineering/exact-targets-invalid.tsv";
const PRODUCT_TARGET: &str = concat!(
    "target_id\tartifact_scope\tgate_id\tstages\towner\tidentity\tdiagnostic\n",
    "canonical-api-generation-1\tapi/positron/v1\tEG-MATRIX\tPR\tQuality Engineering\tcanonical-api-generation-v1\tdiagnostic-only\n",
);

#[test]
fn quality_executes_every_exact_diagnostic_target_with_independent_retained_identity() -> TestResult
{
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        install_product_target(&fixture)?;
        let output = matrix_quality_output(&fixture, "pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                "matrix fixture failed; inspect its retained structured evidence",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-MATRIX")?;
        let detail = matrix_public_detail(gate)?;
        if !detail.contains("product-outcome=diagnostic")
            || detail.contains("identity=")
            || detail.len() > MAXIMUM_MATRIX_CONSOLE_BYTES
        {
            return Err(std::io::Error::other(
                "active product matrix summary is not the bounded typed public form",
            )
            .into());
        }
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-MATRIX",
        )?)?;
        if !report.contains(&format!("\"detail\": \"{detail}\""))
            || report.matches("\"resolved_program\":").count() != 28
            || gate.matches("\"resolved_program\":").count() != 14
        {
            return Err(std::io::Error::other(
                "matrix did not retain the exact compact detail and independently verifiable controlled target plans",
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
fn matrix_product_target_is_not_applicable_when_its_artifact_scope_is_inactive() -> TestResult {
    let fixture = Fixture::create()?;
    install_product_target(&fixture)?;
    fixture.build_fixture_xtask()?;
    let result = (|| {
        let output = matrix_quality_output(&fixture, "pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                "inactive product matrix scope must retain a diagnostic-only outcome",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-MATRIX")?;
        let detail = matrix_public_detail(gate)?;
        if !detail.contains("product-outcome=inactive")
            || detail.contains("identity=")
            || detail.len() > MAXIMUM_MATRIX_CONSOLE_BYTES
        {
            return Err(std::io::Error::other(
                "inactive product matrix summary is not the bounded typed public form",
            )
            .into());
        }
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-MATRIX",
        )?)?;
        if !report.contains(detail)
            || !report.contains("qualification=no-product-qualification")
        {
            return Err(std::io::Error::other(
                "inactive product target raw report did not cross-reference its typed diagnostic outcome",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn install_product_target(fixture: &Fixture) -> TestResult {
    fs::write(
        fixture
            .root
            .join("qualification/engineering/matrix-product-targets.tsv"),
        PRODUCT_TARGET,
    )?;
    Ok(())
}

#[test]
fn matrix_product_target_missing_registry_retains_bounded_typed_outcome() -> TestResult {
    let fixture = Fixture::create()?;
    install_product_target(&fixture)?;
    fixture.build_fixture_xtask()?;
    let result = (|| {
        fs::remove_file(
            fixture
                .root
                .join("qualification/engineering/matrix-product-targets.tsv"),
        )?;
        let output = matrix_quality_output(&fixture, "pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                "missing product registry must leave the diagnostic matrix runnable",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-MATRIX")?;
        let detail = matrix_public_detail(gate)?;
        if !detail.contains("product-outcome=missing")
            || detail.contains("identity=")
            || detail.len() > MAXIMUM_MATRIX_CONSOLE_BYTES
        {
            return Err(std::io::Error::other(
                "missing product registry summary is not the bounded typed public form",
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
fn matrix_active_product_target_fails_closed_when_its_artifact_is_missing() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        install_product_target(&fixture)?;
        fs::remove_file(fixture.root.join("api/positron/v1/positron.proto"))?;
        let output = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(&output, "api/positron/v1/positron.proto")
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
            "exact-targets=14",
            "exact-targets=13",
            "retained EG-MATRIX summary does not match its bounded public contract",
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
