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
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-DYNAMIC",
        )?)?;
        for required in [
            "target=domain-value-properties;kind=property;corpus=domain-value-boundaries-v1;seed=seed-domain-properties-v1",
            "target=domain-lifecycle-state-model;kind=state-model;corpus=domain-lifecycle-transitions-v1;seed=seed-domain-state-model-v1",
            "\"program\":\"cargo\"",
        ] {
            if !report.contains(required) {
                return Err(std::io::Error::other(format!(
                    "the immutable dynamic report omitted `{required}`"
                ))
                .into());
            }
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
            "seed-domain-properties-v1\t300",
            "seed-domain-properties-v1\t0300",
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
            "\tcargo\ttest|--locked|--package|positron-domain|--test|foundational_domain_types\t",
            "\tdefinitively-absent-dynamic-tool\ttest|--locked|--package|positron-domain|--test|foundational_domain_types\t",
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
