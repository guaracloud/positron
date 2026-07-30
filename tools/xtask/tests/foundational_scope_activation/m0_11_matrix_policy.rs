
#[test]
fn security_review_rejects_a_corrupt_unselected_pc_0015_before_pc_0016_selection() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/m0-11-current-origin-main"),
            "armed\n",
        )?;
        let legacy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
        );
        replace_once(&legacy, "\"path_count\": 26", "\"path_count\": 0")?;
        let output = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(&output, "PC-0015-m0-10-security-crypto-runners")?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn security_review_requires_pc_0016_implementation_identity_without_pin_to_final_head() -> TestResult
{
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/m0-11-current-origin-main"),
            "armed\n",
        )?;
        let baseline = matrix_quality_output(&fixture, "pr")?;
        if !baseline.status.success() {
            return Err(std::io::Error::other(
                "PC-0016 implementation identity was incorrectly compared with fixture final HEAD",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-SECURITY",
        )?)?;
        for required in [
            "change-review=PC-0016-m0-11-compatibility-exact-target-matrix",
            "policy=PC-0015-m0-10-security-crypto-runners; external-input-maximum-count=29; external-input-maximum-aggregate-bytes=108614",
            "policy=PC-0016-m0-11-compatibility-exact-target-matrix; external-input-maximum-count=48; external-input-maximum-aggregate-bytes=196608",
        ] {
            if !report.contains(required) {
                return Err(std::io::Error::other(format!(
                    "EG-SECURITY omitted committed policy validation `{required}`"
                ))
                .into());
            }
        }
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0016-m0-11-compatibility-exact-target-matrix.json",
        );
        replace_once(
            &policy,
            "\"implementation_revision\": \"2e738ea10aac13fa34d45e77582b7910467c0b83\"",
            "\"implementation_revision\": \"not-a-revision\"",
        )?;
        let stale = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(&stale, "exact reviewed implementation revision identity")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn security_review_enforces_pc_0016_selected_input_boundaries() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/m0-11-current-origin-main"),
            "armed\n",
        )?;
        let baseline = matrix_quality_output(&fixture, "pr")?;
        if !baseline.status.success() {
            return Err(
                std::io::Error::other("PC-0016 selected input baseline did not pass").into(),
            );
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-SECURITY",
        )?)?;
        for expected in [
            "policy-command-validation=PC-0016-m0-11-compatibility-exact-target-matrix",
            "external-input-count=29",
            "external-input-aggregate-bytes=97379",
            "external-input-maximum-count=48",
            "external-input-maximum-aggregate-bytes=196608",
        ] {
            if !report.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "PC-0016 selected input evidence omitted `{expected}`"
                ))
                .into());
            }
        }
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0016-m0-11-compatibility-exact-target-matrix.json",
        );
        let original = fs::read_to_string(&policy)?;
        for (from, to, expected) in [
            (
                "\"maximum_count\": 48",
                "\"maximum_count\": 28",
                "external input count exceeds 28",
            ),
            (
                "\"maximum_aggregate_bytes\": 196608",
                "\"maximum_aggregate_bytes\": 97373",
                "external input aggregate exceeds 97373 bytes",
            ),
        ] {
            let drifted = original.replacen(from, to, 1);
            if drifted == original {
                return Err(std::io::Error::other(format!(
                    "PC-0016 boundary fixture did not replace `{from}`"
                ))
                .into());
            }
            fs::write(&policy, &drifted)?;
            let rejected = matrix_quality_output(&fixture, "pr")?;
            assert_rejected_output(&rejected, expected)?;
            fs::write(&policy, &original)?;
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn matrix_internal_input_budget_preserves_complete_rustdoc_and_clean_generated_docs() -> TestResult
{
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        for target_name in ["first", "second"] {
            let target = fixture
                .root
                .join(format!("target/m0-11-rustdoc-{target_name}"));
            let documentation = Command::new(env!("CARGO"))
                .current_dir(&fixture.root)
                .env("CARGO_TARGET_DIR", &target)
                .args([
                    "doc",
                    "--locked",
                    "--workspace",
                    "--all-features",
                    "--no-deps",
                    "--document-private-items",
                ])
                .output()?;
            if !documentation.status.success() {
                return Err(std::io::Error::other(
                    "complete private-item rustdoc generation failed for the matrix internal-input owner",
                )
                .into());
            }
            let generated = target.join("doc");
            let scan = Command::new("gitleaks")
                .args([
                    "dir",
                    "--no-banner",
                    "--no-color",
                    "--redact=100",
                    "--max-target-megabytes=20",
                ])
                .arg(&generated)
                .output()?;
            if !scan.status.success() {
                return Err(std::io::Error::other(
                    "unchanged generated-doc gitleaks command rejected complete matrix rustdoc",
                )
                .into());
            }
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}
