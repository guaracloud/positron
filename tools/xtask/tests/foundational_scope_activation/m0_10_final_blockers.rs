use super::*;

const PATH_COUNT: &str = "changed-path-count=26";
const PATH_SET_DIGEST: &str = "changed-path-set-digest=sha256:6105ea257f79be4fed8d4e5a3c31879ac4c5fbfb590c7f2f3d2e4ac67374e224";
const CLASSIFICATION_DIGEST: &str = "changed-path-classification-digest=sha256:d523f4485cd2991864ee96c3edf26c44c88696dd83b49dfc9761942a4f13130a";

#[test]
fn quality_uses_the_actual_m0_09_merge_base_and_rejects_the_old_base_pin() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/m0-10-current-origin-main"),
            b"armed\n",
        )?;
        let current = fixture.quality_output_for("pr")?;
        if !current.status.success() {
            return Err(std::io::Error::other(format!(
                "current registry rejected the actual M0-09 merge base: {}",
                combined_output(&current),
            ))
            .into());
        }
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
        );
        let original = fs::read_to_string(&policy)?;
        fs::write(
            &policy,
            original.replacen(
                "542f3835dc67f819e566e017c04e165b15416861",
                "76d784d5cfe8bcd85267a21b906d12d02af5afce",
                1,
            ),
        )?;
        let stale = fixture.quality_output_for("pr")?;
        assert_rejected_output(&stale, "merge base drifted")?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

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
            "changed-paths=qualification/engineering/README.md|qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
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
                    "tools/xtask/src/security_catalog.zz",
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
fn quality_rejects_an_extra_stale_model_classification() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let path = fixture
            .root
            .join("qualification/engineering/security-threat-surfaces.tsv");
        let original = fs::read_to_string(&path)?;
        fs::write(
            &path,
            original.replacen(
                "crates/positron-config/src/lib.rs|qualification/engineering/security/TM-0001-m0-04-toml-parser.json\t-",
                "crates/positron-config/src/lib.rs|qualification/engineering/security/TM-0001-m0-04-toml-parser.json\tcrates/positron-config/src/lib.rs",
                1,
            ),
        )?;
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
        );
        let original_policy = fs::read_to_string(&policy)?;
        fs::write(
            policy,
            original_policy.replacen(
                "\"maximum_aggregate_bytes\": 108614",
                "\"maximum_aggregate_bytes\": 108742",
                1,
            ),
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "model-classified path")?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_enforces_the_shared_external_input_count_boundary() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let current = fixture.quality_output_for("pr")?;
        if !current.status.success() {
            return Err(std::io::Error::other(format!(
                "the exact external input count boundary failed: {}",
                combined_output(&current),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-SECURITY",
        )?)?;
        if !report.contains("external-input-count=29") {
            return Err(std::io::Error::other(
                "EG-SECURITY omitted the exact shared external input count",
            )
            .into());
        }
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
        );
        let original = fs::read_to_string(&policy)?;
        fs::write(
            policy,
            original.replacen("\"maximum_count\": 29", "\"maximum_count\": 28", 1),
        )?;
        let oversized = fixture.quality_output_for("pr")?;
        assert_rejected_output(&oversized, "external input count exceeds 28")?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_enforces_the_shared_external_input_aggregate_boundary() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let current = fixture.quality_output_for("pr")?;
        if !current.status.success() {
            return Err(std::io::Error::other(format!(
                "the exact external input aggregate boundary failed: {}",
                combined_output(&current),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-SECURITY",
        )?)?;
        if !report.contains("external-input-aggregate-bytes=108614") {
            return Err(std::io::Error::other(
                "EG-SECURITY omitted the exact shared external input aggregate",
            )
            .into());
        }
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
        );
        let original = fs::read_to_string(&policy)?;
        fs::write(
            policy,
            original.replacen(
                "\"maximum_aggregate_bytes\": 108614",
                "\"maximum_aggregate_bytes\": 108613",
                1,
            ),
        )?;
        let oversized = fixture.quality_output_for("pr")?;
        assert_rejected_output(&oversized, "external input aggregate exceeds 108613 bytes")?;
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
