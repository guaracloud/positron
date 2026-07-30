use super::*;

#[test]
fn quality_qual_does_not_select_or_execute_the_pr_ext_dynamic_gate() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        install_dynamic_execution_marker(&fixture)?;
        let marker = fixture
            .root
            .join("target/quality-tools/qual-must-not-run-dynamic");
        fs::write(&marker, "dynamic command must remain unexecuted\n")?;
        let output = fixture.quality_output_for("qual")?;
        assert_rejected_output(&output, "the target registry forbids qualification claims")?;
        if !marker.is_file() {
            return Err(std::io::Error::other(
                "QUAL executed a PR|EXT dynamic target outside its gate profile",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-DYNAMIC")?;
        if !gate.contains("\"result\": \"not-selected\"")
            || !gate.contains("\"controlled_steps\":[]")
        {
            return Err(std::io::Error::other(
                "QUAL did not retain EG-DYNAMIC as an unexecuted not-selected gate",
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
fn parent_rejects_coupled_post_run_plan_command_environment_and_result_tampering() -> TestResult {
    for (name, original, replacement, expected) in [
        (
            "plan",
            "            Ok(detail) => {\n",
            "            Ok(mut detail) => {\n                if gate.id == \"EG-DYNAMIC\" {\n                    detail.push_str(\"; forged-runner-plan\");\n                }\n",
            "detail does not match independently derived target and plan identities",
        ),
        (
            "command",
            "        let controlled_steps = capture.finish();\n",
            "        let mut controlled_steps = capture.finish();\n        if gate.id == \"EG-DYNAMIC\" {\n            if let Some(step) = controlled_steps.first_mut() {\n                step.invocation.arguments.push(\"forged-runner-argument\".to_owned());\n            }\n        }\n",
            "controlled step 0 does not match its independently derived canonical plan",
        ),
        (
            "environment",
            "        let controlled_steps = capture.finish();\n",
            "        let mut controlled_steps = capture.finish();\n        if gate.id == \"EG-DYNAMIC\" {\n            if let Some(step) = controlled_steps.first_mut() {\n                step.invocation.environment_digest = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\".to_owned();\n            }\n        }\n",
            "controlled step 0 does not match its independently derived canonical plan",
        ),
        (
            "result",
            "        let controlled_steps = capture.finish();\n",
            "        let mut controlled_steps = capture.finish();\n        if gate.id == \"EG-DYNAMIC\" {\n            if let Some(step) = controlled_steps.first_mut() {\n                step.verdict = \"exit-status:exit status: 73\".to_owned();\n            }\n        }\n",
            "passed EG-DYNAMIC raw report contains a non-passing controlled result",
        ),
    ] {
        let fixture = Fixture::create()?;
        let result = (|| {
            enable_dynamic_gate(&fixture)?;
            replace_once(
                &fixture.root.join("tools/xtask/src/quality.rs"),
                original,
                replacement,
            )?;
            let first = fixture.quality_output_from_fixture_source("pr")?;
            if !first.status.success() {
                return Err(std::io::Error::other(format!(
                    "{name} tamper fixture failed before retained verification: {}\n{}",
                    String::from_utf8_lossy(&first.stdout),
                    String::from_utf8_lossy(&first.stderr),
                ))
                .into());
            }
            let verified = fixture.quality_output_from_built_fixture("pr")?;
            assert_rejected_output(&verified, expected)
        })();
        let cleanup = fixture.remove();
        cleanup?;
        result?;
    }
    Ok(())
}

#[test]
fn parent_rejects_reordered_extra_and_missing_active_targets() -> TestResult {
    for drift in ["reordered", "extra", "missing"] {
        let fixture = Fixture::create()?;
        let result = (|| {
            enable_dynamic_gate(&fixture)?;
            let first = fixture.quality_output_for("pr")?;
            if !first.status.success() {
                return Err(std::io::Error::other("baseline dynamic evidence failed").into());
            }
            let path = fixture
                .root
                .join("qualification/engineering/dynamic-targets.tsv");
            let content = fs::read_to_string(&path)?;
            let mut lines = content.lines();
            let header = lines
                .next()
                .ok_or_else(|| std::io::Error::other("target registry header is missing"))?;
            let rows = lines.collect::<Vec<_>>();
            let first_row = rows
                .first()
                .ok_or_else(|| std::io::Error::other("first target row is missing"))?;
            let second_row = rows
                .get(1)
                .ok_or_else(|| std::io::Error::other("second target row is missing"))?;
            let changed = match drift {
                "reordered" => format!("{header}\n{second_row}\n{first_row}\n"),
                "extra" => format!(
                    "{content}{}\n",
                    first_row.replacen("domain-value-properties", "extra-properties", 1)
                ),
                "missing" => format!("{header}\n{first_row}\n"),
                _ => return Err(std::io::Error::other("unknown target drift").into()),
            };
            fs::write(path, changed)?;
            let verified = fixture.quality_output_for("pr")?;
            let expected = if drift == "reordered" {
                "retained EG-DYNAMIC detail does not match independently derived target and plan identities"
            } else {
                "retained gate `EG-DYNAMIC` does not contain the independently derived dynamic step set"
            };
            assert_rejected_output(&verified, expected)
        })();
        let cleanup = fixture.remove();
        cleanup?;
        result?;
    }
    Ok(())
}

#[test]
fn dynamic_capability_catalog_fails_closed_when_missing_duplicate_incomplete_or_stale() -> TestResult
{
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        let path = fixture
            .root
            .join("qualification/engineering/dynamic-detectors.tsv");
        let original = fs::read_to_string(&path)?;
        let first_row = original
            .lines()
            .nth(1)
            .ok_or_else(|| std::io::Error::other("capability catalog row is missing"))?;
        for (changed, expected) in [
            (
                format!("{original}{first_row}\n"),
                "repeats capability `property`",
            ),
            (
                original.lines().take(7).collect::<Vec<_>>().join("\n"),
                "must contain exactly all seven capabilities",
            ),
            (
                original.replacen("cargo-test-properties-v1", "stale-grammar-v0", 1),
                "drifted from its frozen contract",
            ),
        ] {
            fs::write(&path, changed)?;
            let output = fixture.quality_output_for("pr")?;
            assert_rejected_output(&output, expected)?;
        }
        fs::remove_file(&path)?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "dynamic-detectors.tsv")?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn enable_dynamic_gate(fixture: &Fixture) -> TestResult {
    set_scope_field(
        &fixture.root,
        "xtask",
        "risk_gates",
        "EG-00|EG-ARCH|EG-BUILD|EG-DEPS|EG-DOCS|EG-DYNAMIC|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
    )
}

fn install_dynamic_execution_marker(fixture: &Fixture) -> TestResult {
    let cargo = fixture.root.join("target/quality-tools/bin/cargo");
    replace_once(
        &cargo,
        "case \"$command\" in",
        "if [ -n \"${POSITRON_DYNAMIC_TARGET_ID:-}\" ] && [ -f target/quality-tools/qual-must-not-run-dynamic ]; then\n  rm target/quality-tools/qual-must-not-run-dynamic\n  exit 73\nfi\ncase \"$command\" in",
    )
}
