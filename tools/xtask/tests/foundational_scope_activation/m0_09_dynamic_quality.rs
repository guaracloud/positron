use super::*;

const DYNAMIC_TARGETS: &str = "qualification/engineering/dynamic-targets.tsv";

#[test]
fn quality_runs_each_registered_dynamic_target_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "the public dynamic runner rejected the complete fixture: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-DYNAMIC")?;
        if !gate.contains("\"result\": \"passed\"") {
            return Err(std::io::Error::other(
                "the public dynamic runner did not retain a passing gate verdict",
            )
            .into());
        }
        for required in [
            "\"command_digest\": \"sha256:",
            "\"timeout_seconds\":1800",
            "\"memory_mib\":4096",
            "\"activation\":\"risk\"",
            "Quality Engineering",
        ] {
            if !gate.contains(required) {
                return Err(std::io::Error::other(format!(
                    "the dynamic gate evidence omitted its registered descriptor binding `{required}`"
                ))
                .into());
            }
        }
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-DYNAMIC",
        )?)?;
        for required in [
            "target=domain-value-properties;kind=property;corpus=domain-value-boundaries-v1;seed=seed-domain-properties-v1;schedule=proptest-sequence-v1;minimized-failure=domain-value-minimized-v1;output-protocol=exit-status-v1",
            "target=domain-lifecycle-state-model;kind=state-model;corpus=domain-lifecycle-transitions-v1;seed=seed-domain-state-model-v1;schedule=transition-schedule-v1;minimized-failure=domain-lifecycle-minimized-v1;output-protocol=exit-status-v1",
            "tenant_lifecycle_makes_purge_one_way",
            "plan=dynamic-execution-plan-v1",
            "argv-digest=sha256:",
            "input-digest=sha256:",
            "plan-digest=sha256:",
            "\"program\":\"cargo\"",
        ] {
            if !report.contains(required) {
                return Err(std::io::Error::other(format!(
                    "the immutable dynamic report omitted `{required}`"
                ))
                .into());
            }
        }
        if report.contains("\"--doc\"") {
            return Err(std::io::Error::other(
                "the state-model descriptor executed documentation instead of lifecycle transitions",
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
fn quality_rejects_a_missing_dynamic_target_registry_without_fallback() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        fs::remove_file(fixture.root.join(DYNAMIC_TARGETS))?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "read")?;
        assert_rejected_output(&output, "dynamic-targets.tsv")?;
        assert_failed_dynamic_evidence(&fixture)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_stale_or_unknown_dynamic_detector_kind_through_the_public_seam() -> TestResult
{
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        replace_once(
            &fixture.root.join(DYNAMIC_TARGETS),
            "\tproperty\tPR|EXT\t",
            "\tobsolete-property\tPR|EXT\t",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "unknown dynamic detector kind `obsolete-property`")?;
        assert_failed_dynamic_evidence(&fixture)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_noncanonical_dynamic_timeout_before_running_the_target() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        replace_once(
            &fixture.root.join(DYNAMIC_TARGETS),
            "domain-value-minimized-v1\texit-status-v1\t300",
            "domain-value-minimized-v1\texit-status-v1\t0300",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "dynamic target timeout is not a canonical positive unsigned value",
        )?;
        assert_failed_dynamic_evidence(&fixture)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_retains_a_missing_dynamic_tool_without_fallback() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        replace_once(
            &fixture.root.join(DYNAMIC_TARGETS),
            "\tcargo\ttest|--locked|--package|positron-domain|--test|dynamic_domain_properties\t",
            "\tdefinitively-absent-dynamic-tool\ttest|--locked|--package|positron-domain|--test|dynamic_domain_properties\t",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "definitively-absent-dynamic-tool")?;
        assert_failed_dynamic_evidence(&fixture)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_oversized_dynamic_registry_before_running_a_target() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        let path = fixture.root.join(DYNAMIC_TARGETS);
        let mut content = fs::read_to_string(&path)?;
        content.push_str(&"x".repeat(16_385));
        fs::write(path, content)?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "dynamic target registry exceeds 16384 bytes")?;
        assert_failed_dynamic_evidence(&fixture)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_duplicate_dynamic_target_identity_before_running_a_target() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        let path = fixture.root.join(DYNAMIC_TARGETS);
        let content = fs::read_to_string(&path)?;
        let duplicate = content
            .lines()
            .nth(1)
            .ok_or_else(|| std::io::Error::other("dynamic registry fixture has no target"))?;
        fs::write(path, format!("{content}{duplicate}\n"))?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "dynamic target registry repeats target `domain-value-properties`",
        )?;
        assert_failed_dynamic_evidence(&fixture)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_uses_dynamic_target_bytes_captured_before_a_post_capture_registry_swap() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/quality.rs"),
            "    let selected = targets.selected(profile).collect::<Vec<_>>();\n",
            "    std::fs::write(\n        root.join(\"qualification/engineering/dynamic-targets.tsv\"),\n        b\"target_id\\tgate_id\\tkind\\tstages\\ttool\\targuments\\tcorpus\\tseed\\tschedule\\tminimized_failure\\toutput_protocol\\ttimeout_seconds\\nforged\\tEG-DYNAMIC\\tproperty\\tPR\\tcargo\\ttest\\tforged-corpus\\tforged-seed\\tforged-schedule\\tforged-minimized\\texit-status-v1\\t1\\n\",\n    )\n    .map_err(|source| XtaskError::io(\"test dynamic registry post-capture swap\", source))?;\n    let selected = targets.selected(profile).collect::<Vec<_>>();\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "the dynamic runner did not preserve captured target bytes: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-DYNAMIC",
        )?)?;
        if report.contains("forged-corpus") || !report.contains("domain-value-boundaries-v1") {
            return Err(std::io::Error::other(
                "the dynamic runner reread swapped target bytes after capture",
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
fn quality_does_not_retry_a_failed_dynamic_target_to_green() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        install_dynamic_cargo_fault(
            &fixture,
            "dynamic-fail-once",
            "rm target/quality-tools/dynamic-fail-once\n    printf '%s\\n' 'fixture dynamic target fails on its first invocation' >&2\n    exit 73",
        )?;
        fs::write(
            fixture.root.join("target/quality-tools/dynamic-fail-once"),
            "first invocation must fail\n",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "exit status exit status: 73")?;
        assert_failed_dynamic_evidence(&fixture)?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_retains_a_dynamic_target_timeout_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        install_dynamic_cargo_fault(&fixture, "dynamic-timeout", "exec sleep 2")?;
        fs::write(
            fixture.root.join("target/quality-tools/dynamic-timeout"),
            "dynamic target must time out\n",
        )?;
        replace_once(
            &fixture.root.join(DYNAMIC_TARGETS),
            "domain-value-minimized-v1\texit-status-v1\t300",
            "domain-value-minimized-v1\texit-status-v1\t1",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "controlled harness execution failed during deadline",
        )?;
        assert_failed_dynamic_evidence(&fixture)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_retains_dynamic_target_cancellation_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        install_dynamic_cargo_fault(
            &fixture,
            "dynamic-cancellation-enabled",
            "printf '%s\\n' \"$$\" > target/quality-tools/dynamic-cancellation.pid\n    : > target/quality-tools/dynamic-cancellation.ready\n    exec sleep 30",
        )?;
        fixture.build_fixture_xtask()?;
        fs::write(
            fixture
                .root
                .join("target/quality-tools/dynamic-cancellation-enabled"),
            "dynamic target cancellation must become reachable\n",
        )?;
        let ready = fixture
            .root
            .join("target/quality-tools/dynamic-cancellation.ready");
        let ready_value = ready.to_str().ok_or_else(|| {
            std::io::Error::other("dynamic cancellation readiness path is not UTF-8")
        })?;
        let output = Command::new(fixture.root.join("target/debug/xtask"))
            .current_dir(&fixture.root)
            .args([
                "quality-internal-cancel-dynamic",
                "--profile",
                "pr",
                "--ready-marker",
                ready_value,
            ])
            .output()?;
        assert_rejected_output(
            &output,
            "controlled harness execution failed during cancellation",
        )?;
        assert_failed_dynamic_evidence(&fixture)?;
        let pid = fs::read_to_string(
            fixture
                .root
                .join("target/quality-tools/dynamic-cancellation.pid"),
        )?;
        if process_is_running(pid.trim())? {
            return Err(std::io::Error::other(
                "cancelled dynamic target remained live after quality owner reconciliation",
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
fn quality_rejects_malformed_dynamic_target_output_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        replace_once(
            &fixture.root.join(DYNAMIC_TARGETS),
            "domain-value-minimized-v1\texit-status-v1\t300",
            "domain-value-minimized-v1\texact-line-v1\t300",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "dynamic target result is malformed or does not match the registered exact-line-v1 protocol",
        )?;
        assert_failed_dynamic_evidence(&fixture)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_dynamic_target_output_that_exceeds_the_bounded_capture_ceiling() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/quality.rs"),
            "                maximum_capture_bytes: MAXIMUM_CAPTURED_REPORT_STREAM_BYTES,\n",
            "                maximum_capture_bytes: 8,\n",
        )?;
        install_dynamic_cargo_fault(
            &fixture,
            "dynamic-output-ceiling",
            "printf '%s' 'dynamic-output'",
        )?;
        fs::write(
            fixture
                .root
                .join("target/quality-tools/dynamic-output-ceiling"),
            "dynamic output must exceed the controlled capture ceiling\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(
            &output,
            "controlled harness execution failed during capture",
        )?;
        assert_failed_dynamic_evidence(&fixture)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn process_is_running(pid: &str) -> TestResult<bool> {
    Ok(Command::new("kill")
        .args(["-0", pid])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

fn assert_failed_dynamic_evidence(fixture: &Fixture) -> TestResult {
    let evidence = fixture.latest_evidence()?;
    let gate = gate_record(&evidence, "EG-DYNAMIC")?;
    if gate.contains("\"result\": \"failed\"") {
        return Ok(());
    }
    Err(std::io::Error::other(
        "dynamic registry rejection did not retain a failed EG-DYNAMIC evidence record",
    )
    .into())
}

fn enable_dynamic_gate(fixture: &Fixture) -> TestResult {
    set_scope_field(
        &fixture.root,
        "xtask",
        "risk_gates",
        "EG-00|EG-ARCH|EG-BUILD|EG-DEPS|EG-DOCS|EG-DYNAMIC|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
    )
}

fn install_dynamic_cargo_fault(fixture: &Fixture, marker: &str, action: &str) -> TestResult {
    let cargo = fixture.root.join("target/quality-tools/bin/cargo");
    let injected = format!(
        "if [ \"$command\" = \"test\" ] && [ -f target/quality-tools/{marker} ]; then\n  package=\n  previous=\n  for argument in \"$@\"; do\n    if [ \"$previous\" = \"--package\" ]; then\n      package=\"$argument\"\n      break\n    fi\n    previous=\"$argument\"\n  done\n  if [ \"$package\" = \"positron-domain\" ]; then\n    {action}\n  fi\nfi\ncase \"$command\" in"
    );
    replace_once(&cargo, "case \"$command\" in", &injected)
}
