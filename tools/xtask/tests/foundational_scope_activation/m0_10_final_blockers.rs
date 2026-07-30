use super::*;

const PATH_COUNT: &str = "changed-path-count=40";
const PATH_SET_DIGEST: &str = "changed-path-set-digest=sha256:9d8305d05177e1cb55da64f80cf46ebef16878c57f0d696f5c1b0bc0162d2c03";
const CLASSIFICATION_DIGEST: &str = "changed-path-classification-digest=sha256:e2127d638ed7714fec26221c48408761bbfdf395f7e6c055d9cfaa5fd8f2e58a";

#[test]
fn quality_rejects_an_actual_changed_path_without_owned_classification() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/m0-10-unclassified-changed-path"),
            b"armed\n",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "complete changed-path classification")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-SECURITY")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "unclassified changed path did not retain a failed EG-SECURITY verdict",
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
fn quality_retains_the_complete_sorted_changed_path_classification() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other("complete classified fixture failed").into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-SECURITY",
        )?)?;
        for expected in [
            PATH_COUNT,
            "changed-paths=crates/positron-domain/tests/dynamic_domain_properties.rs|qualification/engineering/README.md",
            "|tools/xtask/tests/foundational_scope_activation/m0_10_security_crypto.rs;",
            PATH_SET_DIGEST,
            CLASSIFICATION_DIGEST,
        ] {
            if !report.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "EG-SECURITY omitted complete changed-path evidence `{expected}`"
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
fn quality_rejects_stale_conflicting_or_unowned_path_dispositions() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let path = fixture
            .root
            .join("qualification/engineering/security-threat-surfaces.tsv");
        let original = fs::read_to_string(&path)?;
        for (drifted, expected) in [
            (
                original.replacen(
                    "tools/xtask/src/security_catalog.rs",
                    "tools/xtask/src/stale-security-catalog.rs",
                    1,
                ),
                "extra or stale",
            ),
            (
                original.replacen(
                    "tools/xtask/src/security_catalog.rs",
                    "tools/xtask/src/quality.rs",
                    1,
                ),
                "conflicting",
            ),
            (
                original.replacen("runner descriptor parser outside product runtime", "-", 1),
                "missing owner or rationale",
            ),
        ] {
            fs::write(&path, drifted)?;
            let output = fixture.quality_output_for("pr")?;
            assert_rejected_output(&output, expected)?;
        }
        fs::write(path, original)?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn policy_and_catalog_inputs_enforce_exact_bounds() -> TestResult {
    assert_external_input_bounds(&[
        (
            "qualification/engineering/security-threat-surfaces.tsv",
            16_384,
            "security threat-surface registry",
        ),
        (
            "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
            32_768,
            "PC-0015 policy record",
        ),
        (
            "qualification/engineering/security-runners.tsv",
            16_384,
            "security runner catalog",
        ),
    ])
}

#[test]
fn threat_model_inputs_enforce_exact_bounds() -> TestResult {
    assert_external_input_bounds(&[
        (
            "qualification/engineering/security/TM-0010-m0-10-runner-crypto.json",
            8_192,
            "versioned threat-model record",
        ),
        (
            "qualification/engineering/security/TM-0011-m0-10-runner-artifacts.json",
            8_192,
            "versioned threat-model record",
        ),
        (
            "qualification/engineering/security/TM-0001-m0-04-toml-parser.json",
            8_192,
            "M0-04 parser threat-model record",
        ),
    ])
}

#[test]
fn target_registry_inputs_enforce_exact_bounds() -> TestResult {
    assert_external_input_bounds(&[
        (
            "qualification/engineering/security-crypto-targets.tsv",
            4_096,
            "profile-aware crypto target registry",
        ),
        (
            "qualification/engineering/security-canary-targets.tsv",
            4_096,
            "committed security fixture",
        ),
    ])
}

#[test]
fn canary_fixture_inputs_enforce_exact_bounds() -> TestResult {
    assert_external_input_bounds(&[
        (
            "qualification/fixtures/adversarial/cryptography/m0-10-security-canary-golden.tsv",
            4_096,
            "committed security fixture",
        ),
        (
            "qualification/fixtures/adversarial/cryptography/m0-10-secret-canary-leak.tsv",
            4_096,
            "committed security fixture",
        ),
    ])
}

fn assert_external_input_bounds(inputs: &[(&str, usize, &str)]) -> TestResult {
    for &(relative, maximum, subject) in inputs {
        let boundary_output = quality_with_resized_input(relative, maximum)?;
        let exceeds = format!("{subject} exceeds {maximum} bytes");
        let boundary_detail = combined_output(&boundary_output);
        if boundary_detail.contains(&exceeds) {
            return Err(std::io::Error::other(format!(
                "{relative} rejected the exact boundary: {boundary_detail}"
            ))
            .into());
        }
        let oversized_output = quality_with_resized_input(relative, maximum + 1)?;
        if oversized_output.status.success() {
            return Err(std::io::Error::other(format!(
                "{relative} accepted an input above {maximum} bytes"
            ))
            .into());
        }
        assert_rejected_output(&oversized_output, &exceeds)?;
    }
    Ok(())
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn quality_with_resized_input(relative: &str, size: usize) -> TestResult<std::process::Output> {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let path = fixture.root.join(relative);
        let mut bytes = fs::read(&path)?;
        if bytes.len() > size {
            return Err(std::io::Error::other(format!(
                "{relative} already exceeds test size {size}"
            ))
            .into());
        }
        bytes.resize(size, b' ');
        fs::write(path, bytes)?;
        fixture.quality_output_for("pr")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}
