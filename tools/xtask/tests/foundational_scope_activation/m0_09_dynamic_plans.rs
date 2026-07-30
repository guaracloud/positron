use super::*;

const DYNAMIC_TARGETS: &str = "qualification/engineering/dynamic-targets.tsv";

#[test]
fn quality_executes_every_closed_dynamic_kind_through_the_public_descriptor_seam() -> TestResult {
    for capability in capability_fixtures() {
        let fixture = Fixture::create()?;
        let result: TestResult = (|| {
            enable_dynamic_gate(&fixture)?;
            install_dynamic_plan_probe(&fixture, &capability)?;
            fs::write(
                fixture.root.join(DYNAMIC_TARGETS),
                dynamic_target_registry(&capability),
            )?;
            let output = fixture.quality_output_for("pr")?;
            if !output.status.success() {
                return Err(std::io::Error::other(format!(
                    "the `{}` capability fixture failed: {}\n{}",
                    capability.kind,
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
            for required in [
                format!("kind={}", capability.kind),
                format!("capability={}", capability.kind),
                "plan=dynamic-execution-plan-v1".to_owned(),
                "argv-digest=sha256:".to_owned(),
                "environment-digest=sha256:".to_owned(),
                "input-digest=sha256:".to_owned(),
                "catalog-digest=sha256:".to_owned(),
                "target-registry-digest=sha256:".to_owned(),
                "plan-digest=sha256:".to_owned(),
            ] {
                if !report.contains(&required) {
                    return Err(std::io::Error::other(format!(
                        "the capability fixture omitted `{required}` for `{}`",
                        capability.kind
                    ))
                    .into());
                }
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
fn quality_rejects_a_cross_kind_dynamic_detector_masquerade_before_execution() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        install_dynamic_cargo_fault(
            &fixture,
            "cross-kind-masquerade",
            "rm target/quality-tools/cross-kind-masquerade\n    exit 73",
        )?;
        fs::write(
            fixture
                .root
                .join("target/quality-tools/cross-kind-masquerade"),
            "the masquerading command must not execute\n",
        )?;
        let path = fixture.root.join(DYNAMIC_TARGETS);
        let original = fs::read_to_string(&path)?;
        for (kind, expected) in [
            (
                "state-model",
                "arguments do not match the canonical `state-model` detector protocol",
            ),
            (
                "fuzz",
                "dynamic target `domain-value-properties` exceeds its capability bounds",
            ),
            (
                "corpus",
                "dynamic target `domain-value-properties` exceeds its capability bounds",
            ),
            (
                "miri",
                "arguments do not match the canonical `miri` detector protocol",
            ),
            (
                "sanitizer",
                "arguments do not match the canonical `sanitizer` detector protocol",
            ),
            (
                "loom",
                "arguments do not match the canonical `loom` detector protocol",
            ),
        ] {
            fs::write(
                &path,
                original.replacen("\tproperty\tPR|EXT\t", &format!("\t{kind}\tPR|EXT\t"), 1),
            )?;
            let output = fixture.quality_output_for("pr")?;
            assert_rejected_output(&output, expected)?;
            if !fixture
                .root
                .join("target/quality-tools/cross-kind-masquerade")
                .is_file()
            {
                return Err(std::io::Error::other(format!(
                    "the `{kind}` cross-kind masquerade reached command execution"
                ))
                .into());
            }
            assert_failed_dynamic_evidence(&fixture)?;
        }
        fs::write(path, original)?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_dynamic_profiles_outside_the_owning_gate_before_selection() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        let path = fixture.root.join(DYNAMIC_TARGETS);
        let original = fs::read_to_string(&path)?;
        for unsupported in ["QUAL", "PR|QUAL"] {
            fs::write(
                &path,
                original.replacen(
                    "\tproperty\tPR|EXT\t",
                    &format!("\tproperty\t{unsupported}\t"),
                    1,
                ),
            )?;
            let output = fixture.quality_output_for("pr")?;
            assert_rejected_output(
                &output,
                "dynamic target stages must be an exact nonempty subset of owning gate stages `PR|EXT`",
            )?;
            assert_failed_dynamic_evidence(&fixture)?;
        }
        fs::write(path, original)?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_each_missing_dynamic_execution_input_before_execution() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        let path = fixture.root.join(DYNAMIC_TARGETS);
        let original = fs::read_to_string(&path)?;
        for (value, label) in [
            ("domain-value-boundaries-v1", "corpus"),
            ("seed-domain-properties-v1", "seed"),
            ("proptest-sequence-v1", "schedule"),
            ("domain-value-minimized-v1", "minimized failure"),
        ] {
            fs::write(&path, original.replacen(value, "-", 1))?;
            let output = fixture.quality_output_for("pr")?;
            assert_rejected_output(
                &output,
                &format!("dynamic target {label} identity must be a concrete bounded input"),
            )?;
            assert_failed_dynamic_evidence(&fixture)?;
        }
        fs::write(
            &path,
            original.replacen(
                "domain-value-minimized-v1\texit-status-v1\t300\n",
                "domain-value-minimized-v1\texit-status-v1\t300\tunused-input\n",
                1,
            ),
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "dynamic target registry row 2 has the wrong field count",
        )?;
        assert_failed_dynamic_evidence(&fixture)?;
        fs::write(path, original)?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_uses_captured_tool_binding_before_a_post_capture_tool_registry_tamper() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/quality.rs"),
            "    let selected = targets.selected(profile).collect::<Vec<_>>();\n",
            "    std::fs::write(\n        root.join(\"qualification/engineering/toolchains.tsv\"),\n        b\"post-capture-tool-registry-tamper\\n\",\n    )\n    .map_err(|source| XtaskError::io(\"test tool registry post-capture tamper\", source))?;\n    let selected = targets.selected(profile).collect::<Vec<_>>();\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "the dynamic runner did not preserve its captured tool binding: {}\n{}",
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
        if !report.contains("tool-id=cargo;tool-version=1.96.0;program=cargo")
            || report.contains("post-capture-tool-registry-tamper")
        {
            return Err(std::io::Error::other(
                "the dynamic runner used post-capture tool registry bytes",
            )
            .into());
        }
        Ok(())
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
    Err(
        std::io::Error::other("dynamic plan rejection did not retain failed EG-DYNAMIC evidence")
            .into(),
    )
}

fn enable_dynamic_gate(fixture: &Fixture) -> TestResult {
    set_scope_field(
        &fixture.root,
        "xtask",
        "risk_gates",
        "EG-00|EG-ARCH|EG-BUILD|EG-DEPS|EG-DOCS|EG-DYNAMIC|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
    )
}

struct CapabilityFixture {
    kind: &'static str,
    arguments: &'static str,
    executed_arguments: &'static str,
}

fn capability_fixtures() -> [CapabilityFixture; 7] {
    [
        CapabilityFixture {
            kind: "property",
            arguments: "test|--locked|--package|positron-domain|--test|dynamic_domain_properties",
            executed_arguments: "test --locked --package positron-domain --test dynamic_domain_properties",
        },
        CapabilityFixture {
            kind: "state-model",
            arguments: "test|--locked|--package|positron-domain|--test|foundational_domain_types|tenant_lifecycle_makes_purge_one_way|--|--exact",
            executed_arguments: "test --locked --package positron-domain --test foundational_domain_types tenant_lifecycle_makes_purge_one_way -- --exact",
        },
        CapabilityFixture {
            kind: "fuzz",
            arguments: "fuzz|run|fixture-fuzz-target",
            executed_arguments: "fuzz run fixture-fuzz-target",
        },
        CapabilityFixture {
            kind: "corpus",
            arguments: "fuzz|run|fixture-corpus-target|fixture-corpus-corpus-v1",
            executed_arguments: "fuzz run fixture-corpus-target fixture-corpus-corpus-v1",
        },
        CapabilityFixture {
            kind: "miri",
            arguments: "+nightly-2026-07-20|miri|test|--locked|--package|positron-domain",
            executed_arguments: "miri test --locked --package positron-domain",
        },
        CapabilityFixture {
            kind: "sanitizer",
            arguments: "+nightly-2026-07-20|test|--locked|--package|positron-domain|--test|foundational_domain_types",
            executed_arguments: "test --locked --package positron-domain --test foundational_domain_types",
        },
        CapabilityFixture {
            kind: "loom",
            arguments: "test|--locked|--package|positron-domain|--features|loom|--test|foundational_domain_types",
            executed_arguments: "test --locked --package positron-domain --features loom --test foundational_domain_types",
        },
    ]
}

fn dynamic_target_registry(capability: &CapabilityFixture) -> String {
    format!(
        "target_id\tgate_id\tcapability_id\tstages\targuments\tcorpus\tseed\tschedule\tminimized_failure\toutput_protocol\ttimeout_seconds\nfixture-{kind}\tEG-DYNAMIC\t{kind}\tPR\t{arguments}\tfixture-corpus-{kind}-v1\tfixture-seed-{kind}-v1\tfixture-schedule-{kind}-v1\tfixture-minimized-{kind}-v1\texact-line-v1\t30\n",
        kind = capability.kind,
        arguments = capability.arguments,
    )
}

fn install_dynamic_plan_probe(fixture: &Fixture, capability: &CapabilityFixture) -> TestResult {
    let cargo = fixture.root.join("target/quality-tools/bin/cargo");
    let injected = format!(
        r#"if [ -n "${{POSITRON_DYNAMIC_TARGET_ID:-}}" ]; then
  if [ "$*" != '{arguments}' ] ||
     [ "${{POSITRON_DYNAMIC_KIND:-}}" != "{kind}" ] ||
     [ "${{POSITRON_DYNAMIC_TARGET_ID:-}}" != "fixture-{kind}" ] ||
     [ "${{POSITRON_DYNAMIC_CORPUS_ID:-}}" != "fixture-corpus-{kind}-v1" ] ||
     [ "${{POSITRON_DYNAMIC_SEED:-}}" != "fixture-seed-{kind}-v1" ] ||
     [ "${{POSITRON_DYNAMIC_SCHEDULE:-}}" != "fixture-schedule-{kind}-v1" ] ||
     [ "${{POSITRON_DYNAMIC_MINIMIZED_FAILURE_ID:-}}" != "fixture-minimized-{kind}-v1" ]; then
    printf '%s\n' 'dynamic plan or bound input mismatch' >&2
    exit 72
  fi
  printf '%s\n' 'dynamic-target-result-v1;status=passed'
  exit 0
fi
case "$command" in"#,
        arguments = capability.executed_arguments,
        kind = capability.kind,
    );
    replace_once(&cargo, "case \"$command\" in", &injected)
}

fn install_dynamic_cargo_fault(fixture: &Fixture, marker: &str, action: &str) -> TestResult {
    let cargo = fixture.root.join("target/quality-tools/bin/cargo");
    let injected = format!(
        "if [ \"$command\" = \"test\" ] && [ -f target/quality-tools/{marker} ]; then\n  package=\n  previous=\n  for argument in \"$@\"; do\n    if [ \"$previous\" = \"--package\" ]; then\n      package=\"$argument\"\n      break\n    fi\n    previous=\"$argument\"\n  done\n  if [ \"$package\" = \"positron-domain\" ]; then\n    {action}\n  fi\nfi\ncase \"$command\" in"
    );
    replace_once(&cargo, "case \"$command\" in", &injected)
}
