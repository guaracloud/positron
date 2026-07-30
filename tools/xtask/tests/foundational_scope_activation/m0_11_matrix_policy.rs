
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
fn static_policy_validation_rejects_unselected_pc_0016_schema_drift() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0016-m0-11-compatibility-exact-target-matrix.json",
        );
        replace_once(
            &policy,
            "\"id\": \"PC-0016-m0-11-compatibility-exact-target-matrix\"",
            "\"id\": \"PC-0016-drifted\"",
        )?;
        // This fixture selects PC-0015. PC-0016 must still be validated as a
        // committed record, without evaluating its live path set.
        let output = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(&output, "security change-review record id drifted")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn selected_pc_0015_review_precedes_unselected_pc_0016_external_validation() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0016-m0-11-compatibility-exact-target-matrix.json",
        );
        replace_once(
            &policy,
            "qualification/engineering/security-canary-targets.tsv",
            "qualification/engineering/security-canary-targets.zz",
        )?;
        // This fixture selects PC-0015. Its live changed-path review must run
        // before the distinct PC-0016 record is checked against external
        // immutable references.
        let output = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(
            &output,
            "PC-0016-m0-11-compatibility-exact-target-matrix",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn retained_evidence_never_discloses_the_synthetic_canary() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let output = matrix_quality_output(&fixture, "pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other("canary evidence fixture baseline did not pass").into());
        }
        let canary = ["POSITRON", "SYNTHETIC", "CANARY", "V1"].join("_");
        let evidence = fixture.latest_evidence()?;
        if evidence.contains(&canary) {
            return Err(std::io::Error::other("retained evidence disclosed the synthetic canary").into());
        }
        let secrets = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-SECRETS",
        )?)?;
        if !secrets.contains("canary-selector=registered-synthetic-v1-r001")
            || !secrets.contains("canary-digest=sha256:")
        {
            return Err(std::io::Error::other(
                "retained secret evidence did not bind the registered canary selector and digest",
            )
            .into());
        }
        let reports = fixture.root.join("target/quality/evidence-reports");
        for attempt in fs::read_dir(reports)? {
            let attempt = attempt?;
            for report in fs::read_dir(attempt.path())? {
                let report = report?;
                if fs::read_to_string(report.path())?.contains(&canary) {
                    return Err(std::io::Error::other(
                        "retained raw report disclosed the synthetic canary",
                    )
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
fn registered_canary_selector_contract_preserves_the_frozen_shared_input_bytes() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let bytes = fs::read(fixture.root.join("qualification/engineering/security-canary-targets.tsv"))?;
        if bytes.len() != 628 {
            return Err(std::io::Error::other(
                "registered non-secret canary selectors changed the frozen shared input byte count",
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
        let summary = security_policy_summary(gate_record(&evidence, "EG-SECURITY")?)?;
        if summary
            != "selected=PC-0016-m0-11-compatibility-exact-target-matrix; committed-record-count=2; selected-result=passed; unselected-result=passed; external-input-count=29; external-input-aggregate-bytes=111494; external-input-maximum-count=48; external-input-maximum-aggregate-bytes=196608"
            || summary.len() > MAXIMUM_MATRIX_CONSOLE_BYTES
            || report.contains("changed-paths=")
        {
            return Err(std::io::Error::other(format!(
                "EG-SECURITY compact PC-0016 policy summary drifted: {summary}",
            ))
            .into());
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
fn security_policy_failure_console_is_bounded_and_retains_evidence_pointer() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/m0-11-current-origin-main"),
            "armed\n",
        )?;
        let policy = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0016-m0-11-compatibility-exact-target-matrix.json",
        );
        replace_once(&policy, "\"path_count\": 30", "\"path_count\": 0")?;
        let output = matrix_quality_output(&fixture, "pr")?;
        if output.status.success() {
            return Err(std::io::Error::other(
                "corrupt PC-0016 policy record unexpectedly passed",
            )
            .into());
        }
        let evidence_path = fixture.latest_evidence_path()?;
        if !String::from_utf8_lossy(&output.stdout).contains(evidence_path.to_string_lossy().as_ref())
        {
            return Err(std::io::Error::other(
                "security policy failure console was not bounded with a retained evidence pointer",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn security_policy_summary(gate: &str) -> TestResult<&str> {
    let (_, summary) = gate
        .rsplit_once("security-policy=")
        .ok_or_else(|| std::io::Error::other("EG-SECURITY omitted policy summary"))?;
    summary
        .split_once(" | ")
        .map(|(summary, _)| summary)
        .ok_or_else(|| std::io::Error::other("EG-SECURITY policy summary was not terminated"))
        .map_err(Into::into)
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
            "external-input-aggregate-bytes=111494",
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
                "\"maximum_aggregate_bytes\": 105263",
                "external input aggregate exceeds 105263 bytes",
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
