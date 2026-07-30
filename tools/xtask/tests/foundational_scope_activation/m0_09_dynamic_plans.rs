use super::*;

const DYNAMIC_TARGETS: &str = "qualification/engineering/dynamic-targets.tsv";

#[test]
fn quality_executes_every_closed_dynamic_kind_through_the_public_descriptor_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_dynamic_gate(&fixture)?;
        install_dynamic_plan_probe(&fixture)?;
        fs::write(
            fixture.root.join(DYNAMIC_TARGETS),
            all_dynamic_kinds_registry(),
        )?;
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "the complete dynamic-kind descriptor fixture failed: {}\n{}",
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
        for kind in [
            "property",
            "state-model",
            "fuzz",
            "corpus",
            "miri",
            "sanitizer",
            "loom",
        ] {
            for required in [
                format!("kind={kind}"),
                "plan=dynamic-execution-plan-v1".to_owned(),
                "argv-digest=sha256:".to_owned(),
                "input-digest=sha256:".to_owned(),
                "plan-digest=sha256:".to_owned(),
            ] {
                if !report.contains(&required) {
                    return Err(std::io::Error::other(format!(
                        "the complete descriptor fixture omitted `{required}` for `{kind}`"
                    ))
                    .into());
                }
            }
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
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
                "dynamic kind `fuzz` requires tool identity `cargo-fuzz`, not `cargo`",
            ),
            (
                "corpus",
                "dynamic kind `corpus` requires tool identity `cargo-fuzz`, not `cargo`",
            ),
            (
                "miri",
                "dynamic kind `miri` requires tool identity `miri-nightly`, not `cargo`",
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
        if !report.contains("tool-id=cargo;program=cargo")
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

fn all_dynamic_kinds_registry() -> String {
    let mut registry = String::from(
        "target_id\tgate_id\tkind\tstages\ttool\targuments\tcorpus\tseed\tschedule\tminimized_failure\toutput_protocol\ttimeout_seconds\n",
    );
    for (kind, tool, arguments) in [
        (
            "property",
            "cargo",
            "test|--locked|--package|positron-domain|--test|dynamic_domain_properties",
        ),
        (
            "state-model",
            "cargo",
            "test|--locked|--package|positron-domain|--test|foundational_domain_types|tenant_lifecycle_makes_purge_one_way|--|--exact",
        ),
        ("fuzz", "cargo-fuzz", "fuzz|run|fixture-fuzz-target"),
        ("corpus", "cargo-fuzz", "fuzz|run|fixture-corpus-target"),
        (
            "miri",
            "miri-nightly",
            "+nightly-2026-07-20|miri|test|--locked|--package|positron-domain",
        ),
        (
            "sanitizer",
            "cargo",
            "+nightly-2026-07-20|test|--locked|--package|positron-domain|--test|foundational_domain_types",
        ),
        (
            "loom",
            "cargo",
            "test|--locked|--package|positron-domain|--features|loom|--test|foundational_domain_types",
        ),
    ] {
        registry.push_str(&format!(
            "fixture-{kind}\tEG-DYNAMIC\t{kind}\tPR\t{tool}\t{arguments}\tfixture-corpus-{kind}-v1\tfixture-seed-{kind}-v1\tfixture-schedule-{kind}-v1\tfixture-minimized-{kind}-v1\texact-line-v1\t30\n"
        ));
    }
    registry
}

fn install_dynamic_plan_probe(fixture: &Fixture) -> TestResult {
    let cargo = fixture.root.join("target/quality-tools/bin/cargo");
    let injected = r#"if [ -n "${POSITRON_DYNAMIC_KIND:-}" ]; then
  kind="$POSITRON_DYNAMIC_KIND"
  case "$kind" in
    property) expected='test --locked --package positron-domain --test dynamic_domain_properties' ;;
    state-model) expected='test --locked --package positron-domain --test foundational_domain_types tenant_lifecycle_makes_purge_one_way -- --exact' ;;
    fuzz) expected='fuzz run fixture-fuzz-target' ;;
    corpus) expected='fuzz run fixture-corpus-target' ;;
    miri) expected='miri test --locked --package positron-domain' ;;
    sanitizer) expected='test --locked --package positron-domain --test foundational_domain_types' ;;
    loom) expected='test --locked --package positron-domain --features loom --test foundational_domain_types' ;;
    *) printf '%s\n' 'unknown dynamic kind' >&2; exit 71 ;;
  esac
  if [ "$*" != "$expected" ] ||
     [ "${POSITRON_DYNAMIC_TARGET_ID:-}" != "fixture-$kind" ] ||
     [ "${POSITRON_DYNAMIC_CORPUS_ID:-}" != "fixture-corpus-$kind-v1" ] ||
     [ "${POSITRON_DYNAMIC_SEED:-}" != "fixture-seed-$kind-v1" ] ||
     [ "${POSITRON_DYNAMIC_SCHEDULE:-}" != "fixture-schedule-$kind-v1" ] ||
     [ "${POSITRON_DYNAMIC_MINIMIZED_FAILURE_ID:-}" != "fixture-minimized-$kind-v1" ]; then
    printf '%s\n' 'dynamic plan or bound input mismatch' >&2
    exit 72
  fi
  printf '%s\n' 'dynamic-target-result-v1;status=passed'
  exit 0
fi
case "$command" in"#;
    replace_once(&cargo, "case \"$command\" in", injected)
}

fn install_dynamic_cargo_fault(fixture: &Fixture, marker: &str, action: &str) -> TestResult {
    let cargo = fixture.root.join("target/quality-tools/bin/cargo");
    let injected = format!(
        "if [ \"$command\" = \"test\" ] && [ -f target/quality-tools/{marker} ]; then\n  package=\n  previous=\n  for argument in \"$@\"; do\n    if [ \"$previous\" = \"--package\" ]; then\n      package=\"$argument\"\n      break\n    fi\n    previous=\"$argument\"\n  done\n  if [ \"$package\" = \"positron-domain\" ]; then\n    {action}\n  fi\nfi\ncase \"$command\" in"
    );
    replace_once(&cargo, "case \"$command\" in", &injected)
}
