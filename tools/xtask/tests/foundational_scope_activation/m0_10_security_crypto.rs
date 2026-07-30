use super::*;

#[test]
fn quality_orchestrates_security_crypto_and_secret_canary_descriptors_through_the_public_seam()
-> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "the complete security, crypto, and canary fixture was rejected: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        for (gate, required) in [
            (
                "EG-SECURITY",
                "security-probe-result-v1=authn:unauthenticated|authz:forbidden|tenant:tenant-mismatch|allow:allowed",
            ),
            ("EG-CRYPTO", "crypto-runner-v1"),
            (
                "EG-SECRETS",
                "candidate-target=xtask-security-runner-capability-v1",
            ),
        ] {
            let report =
                fs::read_to_string(exact_raw_report_path(&fixture.root, &evidence, gate)?)?;
            if !report.contains(required) {
                return Err(std::io::Error::other(format!(
                    "{gate} did not retain its registered runner identity `{required}`"
                ))
                .into());
            }
        }
        let retained = fixture.quality_output_for("pr")?;
        if !retained.status.success() {
            return Err(std::io::Error::other(format!(
                "the retained security, crypto, and canary evidence was rejected: {}\n{}",
                String::from_utf8_lossy(&retained.stdout),
                String::from_utf8_lossy(&retained.stderr)
            ))
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_security_catalog_at_the_exact_bounded_read_ceiling() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let path = fixture
            .root
            .join("qualification/engineering/security-runners.tsv");
        let valid = fs::read(&path)?;
        let mut boundary = valid.clone();
        boundary.resize(16_384, b' ');
        fs::write(&path, boundary)?;
        let boundary_output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&boundary_output, "security runner catalog")?;
        let mut oversized = valid;
        oversized.resize(16_385, b' ');
        fs::write(&path, oversized)?;
        let oversized_output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &oversized_output,
            "security runner catalog exceeds 16384 bytes",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn current_scope_registry_selects_crypto_without_a_fixture_activation_override() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                "current registry did not run the complete quality fixture",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let crypto = gate_record(&evidence, "EG-CRYPTO")?;
        if !crypto.contains("\"result\": \"passed\"") {
            return Err(std::io::Error::other(
                "the committed xtask scope did not select EG-CRYPTO",
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
fn quality_rejects_a_drifted_security_crypto_or_secret_canary_descriptor() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let path = fixture
            .root
            .join("qualification/engineering/security-runners.tsv");
        let original = fs::read_to_string(&path)?;
        for (drift, expected_gate) in [
            ("known-answer-vectors", "EG-CRYPTO"),
            ("authn-authz", "EG-SECURITY"),
            ("support-artifacts", "EG-SECRETS"),
        ] {
            fs::write(&path, original.replacen(drift, "forged-check", 1))?;
            let output = fixture.quality_output_for("pr")?;
            assert_rejected_output(&output, "security runner descriptor")?;
            let evidence = fixture.latest_evidence()?;
            let gate = gate_record(&evidence, expected_gate)?;
            if !gate.contains("\"result\": \"failed\"") {
                return Err(std::io::Error::other(format!(
                    "drifted descriptor did not retain a failed {expected_gate} attempt"
                ))
                .into());
            }
        }
        fs::write(path, original)?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_drifted_committed_canary_golden_and_leak_fixtures() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let golden = fixture.root.join(
            "qualification/fixtures/adversarial/cryptography/m0-10-security-canary-golden.tsv",
        );
        let original_golden = fs::read_to_string(&golden)?;
        fs::write(
            &golden,
            original_golden.replacen("REDACTED:logs", "REDACTED:forged", 1),
        )?;
        let golden_output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&golden_output, "committed canary golden")?;
        fs::write(&golden, original_golden)?;

        let leak = fixture
            .root
            .join("qualification/fixtures/adversarial/cryptography/m0-10-secret-canary-leak.tsv");
        let original_leak = fs::read_to_string(&leak)?;
        fs::write(&leak, original_leak.replacen("\tleak", "\tredacted", 1))?;
        let leak_output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&leak_output, "intentional leak fixture")?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_unowned_or_stale_security_threat_surface_coverage() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let path = fixture
            .root
            .join("qualification/engineering/security-threat-surfaces.tsv");
        let original = fs::read_to_string(&path)?;
        for drifted in [
            original.replacen("Security and Key Management", "-", 1),
            original.replacen("reviewed-m0-10", "stale", 1),
        ] {
            fs::write(&path, drifted)?;
            let output = fixture.quality_output_for("pr")?;
            assert_rejected_output(&output, "security threat-surface registry")?;
        }
        fs::write(path, original)?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_retains_parent_owned_candidate_artifact_scan_evidence() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other("valid candidate-artifact fixture failed").into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-SECRETS",
        )?)?;
        for required in [
            "candidate-target=xtask-security-runner-capability-v1",
            "ownership=parent-attempt",
            "scanner-result=no-canary-disclosure",
            "qualification=runner-capability-only",
        ] {
            if !report.contains(required) {
                return Err(std::io::Error::other(format!(
                    "candidate artifact evidence omitted `{required}`"
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
fn policy_rejects_a_referenced_validation_test_target_that_does_not_resolve() -> TestResult {
    let fixture = Fixture::create_current_registry()?;
    let result = (|| {
        let path = fixture.root.join(
            "qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json",
        );
        let original = fs::read_to_string(&path)?;
        fs::write(
            &path,
            original.replacen(
                "m0_10_security_crypto::quality_orchestrates_security_crypto_and_secret_canary_descriptors_through_the_public_seam",
                "m0_10_security_crypto::nonexistent_validation_target",
                1,
            ),
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "PC-0015 validation command")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}
