#![forbid(unsafe_code)]

//! Black-box contract fixtures for foundational scope activation.

use std::env;
use std::error::Error;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ACTIVATION_ID: &str = "M0-01";
const ACTIVATION_SET: &str = "positron-api|positron-config|positron-domain";
const POLICY_CHANGE: &str =
    "qualification/engineering/policy-changes/PC-0002-m0-01-foundational-scope-activation.json";
const FROZEN_COVERAGE_LINE: &str = "70.52266534555362";
const FROZEN_COVERAGE_REGION: &str = "69.9540018399264";
const FROZEN_COVERAGE_BRANCH: &str = "57.622739018087856";
const FROZEN_COVERAGE_CHANGED_CODE: &str = "65.97888675623801";
const M0_02_ACTIVATION_ID: &str = "M0-02";
const M0_02_ACTIVATION_SET: &str = "positron-domain";
const M0_02_POLICY_CHANGE: &str =
    "qualification/engineering/policy-changes/PC-0007-m0-02-domain-types.json";
const M0_04_POLICY_CHANGE: &str =
    "qualification/engineering/policy-changes/PC-0009-m0-04-configuration-foundation.json";
const CANONICAL_CONCURRENCY_FIXTURE_REGISTRY: &[u8] = b"scenario_id\tgate_id\tspawn_site\tschedule\tseed\tmax_tasks\tqueue_capacity\treservation_capacity\tretry_limit\tshutdown_ms\texpected\nconcurrency-cancel-join\tEG-CONCURRENCY\tquality-bounded-worker-v1\tcancel-then-join-v1\tseed-concurrency-v1\t3\t1\t1\t1\t100\tcancelled-then-joined-v1\nresource-fair-pressure\tEG-RESOURCE\tquality-bounded-worker-v1\tround-robin-pressure-v1\tseed-resource-v1\t3\t3\t2\t2\t100\tfair-pressure-retry-leak-free-v1\n";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn quality_accepts_the_complete_atomic_foundational_activation_ledger() -> TestResult {
    let fixture = Fixture::create_with_real_git()?;
    let result = fixture.quality();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_relative_ambient_path_before_running_a_gate() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let output = fixture.quality_output_for_with_environment(
            "pre-commit",
            [("PATH", "relative-tool-directory")],
        )?;
        if output.status.success() {
            return Err(std::io::Error::other(
                "the public quality runner accepted a relative ambient PATH",
            )
            .into());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");
        if !combined.contains("controlled harness environment: PATH contains a non-absolute entry")
        {
            return Err(std::io::Error::other(format!(
                "quality rejected an invalid ambient PATH for the wrong reason: {combined}"
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
fn quality_rejects_an_oversized_ambient_path_before_running_a_gate() -> TestResult {
    let fixture = Fixture::create()?;
    let oversized_path = "/usr/bin:".repeat(2_049);
    let result = (|| {
        let output = fixture.quality_output_for_with_environment(
            "pre-commit",
            [("PATH", oversized_path.as_str())],
        )?;
        if output.status.success() {
            return Err(std::io::Error::other(
                "the public quality runner accepted an oversized ambient PATH",
            )
            .into());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");
        if !combined.contains("controlled harness environment: PATH exceeds its bounded value size")
        {
            return Err(std::io::Error::other(format!(
                "quality rejected an oversized PATH for the wrong reason: {combined}"
            ))
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_evidence_uses_a_stable_redacted_environment_digest() -> TestResult {
    let fixture = Fixture::create()?;
    let first_certificate = fixture.root.join("target/fixture-certificate-one.pem");
    let second_certificate = fixture.root.join("target/fixture-certificate-two.pem");
    let canary = fixture.root.join("target/ambient-path-canary");
    let result = (|| {
        fs::create_dir_all(&canary)?;
        install_ambient_path_canary_git_fixture(&fixture.root, &canary)?;
        fs::write(&first_certificate, "synthetic certificate fixture one\n")?;
        fs::write(&second_certificate, "synthetic certificate fixture two\n")?;
        let first_certificate_value = first_certificate.to_str().ok_or_else(|| {
            std::io::Error::other("first fixture certificate path is not valid UTF-8")
        })?;
        let first = fixture.quality_output_for_with_environment(
            "pre-commit",
            [("SSL_CERT_FILE", first_certificate_value)],
        )?;
        if !first.status.success() {
            return Err(std::io::Error::other(format!(
                "quality rejected the first valid certificate snapshot: {}\n{}",
                String::from_utf8_lossy(&first.stdout),
                String::from_utf8_lossy(&first.stderr)
            ))
            .into());
        }
        let baseline = fixture.latest_environment_digest()?;
        let repeated_output = fixture.quality_output_for_with_environment(
            "pre-commit",
            [("SSL_CERT_FILE", first_certificate_value)],
        )?;
        if !repeated_output.status.success() {
            return Err(std::io::Error::other(format!(
                "quality rejected a repeated valid certificate snapshot: {}\n{}",
                String::from_utf8_lossy(&repeated_output.stdout),
                String::from_utf8_lossy(&repeated_output.stderr)
            ))
            .into());
        }
        let repeated = fixture.latest_environment_digest()?;
        if baseline != repeated {
            return Err(std::io::Error::other(format!(
                "the same explicit quality environment produced unstable digests: {baseline} then {repeated}"
            ))
            .into());
        }
        let second_certificate_value = second_certificate.to_str().ok_or_else(|| {
            std::io::Error::other("second fixture certificate path is not valid UTF-8")
        })?;
        let output = fixture.quality_output_for_with_environment(
            "pre-commit",
            [("SSL_CERT_FILE", second_certificate_value)],
        )?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "quality rejected the valid certificate snapshot: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        let changed = fixture.latest_environment_digest()?;
        if changed == baseline {
            return Err(std::io::Error::other(
                "the certificate-bearing snapshot did not change its environment digest",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_does_not_reinject_an_unresolved_ambient_path_canary() -> TestResult {
    let fixture = Fixture::create()?;
    let canary = fixture.root.join("target/ambient-path-canary");
    fs::create_dir_all(&canary)?;
    let result = (|| {
        install_ambient_path_canary_git_fixture(&fixture.root, &canary)?;
        let inherited_path = env::var("PATH")?;
        let path = format!("{}:{inherited_path}", canary.display());
        fixture
            .quality_output_for_with_environment("pre-commit", [("PATH", path.as_str())])
            .and_then(|output| {
                if output.status.success() {
                    return Ok(());
                }
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(std::io::Error::other(format!(
                    "the public quality runner leaked the ambient PATH canary: {stdout}\n{stderr}"
                ))
                .into())
            })
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_returns_a_closed_failure_when_a_controlled_descendant_holds_capture_open() -> TestResult
{
    let fixture = Fixture::create()?;
    let protocol = ControlledDescriptorProtocol::create(&fixture.root)?;
    install_open_descriptor_git_fixture(&fixture.root, &protocol)?;
    let mut quality = fixture.quality_child()?;

    let result = (|| {
        protocol.wait_until_ready(Duration::from_secs(10))?;
        let status = wait_for_child_exit(&mut quality, Duration::from_secs(2))?;
        let (stdout, stderr) = read_child_output(&mut quality)?;

        if status.success() {
            return Err(std::io::Error::other(format!(
                "the public quality runner accepted an unreconciled controlled descendant: {stdout}\n{stderr}"
            ))
            .into());
        }
        if !stderr.contains("controlled harness execution failed during descendant") {
            return Err(std::io::Error::other(format!(
                "the public quality runner did not expose a controlled-harness failure: {stdout}\n{stderr}"
            ))
            .into());
        }
        if protocol.descendant_is_running()? {
            return Err(std::io::Error::other(
                "the public quality runner returned before reconciling its controlled descendant",
            )
            .into());
        }

        Ok(())
    })();
    let cleanup = protocol.cleanup(&mut quality);
    let remove = fixture.remove();
    cleanup?;
    remove?;
    result
}

#[test]
fn quality_accepts_the_narrow_m0_02_domain_types_transition() -> TestResult {
    let fixture = Fixture::create_m0_02_domain_types()?;
    let result = fixture.quality();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn live_m0_04_configuration_ledger_names_only_its_contract_and_artifact() -> TestResult {
    let root = repository_root()?;
    let scopes = fs::read_to_string(root.join("qualification/engineering/scopes.tsv"))?;
    let required = format!(
        "positron-config\tcrates/positron-config\tRecovery and Lifecycle\tapplication\tactive\tM0-04\tpositron-config\tpositron-runtime->positron-config\tEG-COVERAGE|EG-SAFETY|EG-SECURITY\tcargo test --locked --package positron-config --test configuration_foundation\tconfig-coverage-branch|config-coverage-line|config-coverage-region\tconfig-mutation-score\ttoml\t{M0_04_POLICY_CHANGE}"
    );
    if !scopes.contains(&required) {
        return Err(std::io::Error::other("live M0-04 configuration ledger drifted").into());
    }
    let artifacts = fs::read_to_string(root.join("qualification/engineering/artifact-scopes.tsv"))?;
    if !artifacts.contains("configuration-artifacts\tconfiguration\tRecovery and Lifecycle\tactive")
    {
        return Err(std::io::Error::other("M0-04 configuration artifact scope is missing").into());
    }
    Ok(())
}

#[test]
fn quality_rejects_an_unregistered_m0_02_domain_source_file() -> TestResult {
    let fixture = Fixture::create_m0_02_domain_types()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("crates/positron-domain/src/unregistered.rs"),
            "//! Unregistered M0-02 source.\n",
        )?;
        assert_existing_fixture_rejected(
            &fixture,
            "pre-commit",
            "M0-02 Domain Types source layout differs from its registered file set",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_ext_rejects_m0_02_domain_coverage_below_its_frozen_baseline() -> TestResult {
    let fixture = Fixture::create_m0_02_domain_types()?;
    let result = (|| {
        reduce_line_coverage_measurement(&fixture.root)?;
        assert_existing_fixture_rejected(
            &fixture,
            "ext",
            "domain coverage line 70.00 is below frozen M0-02 baseline 100.00",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_pr_executes_the_m0_02_domain_dynamic_harness() -> TestResult {
    let fixture = Fixture::create_m0_02_domain_types()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/reject-m0-02-dynamic-execution"),
            "",
        )?;
        assert_existing_fixture_rejected(&fixture, "pr", "fixture rejects M0-02 dynamic execution")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_snapshot_digest_that_exceeds_its_captured_output_bound() -> TestResult {
    assert_fixture_rejected(
        make_snapshot_digest_exceed_its_capture_bound,
        "controlled harness execution failed during capture",
    )
}

#[test]
fn quality_rejects_a_nonzero_snapshot_digest_with_its_closed_exit_verdict() -> TestResult {
    assert_fixture_rejected(
        make_snapshot_digest_exit_nonzero,
        "command `git hash-object --stdin` failed: exit status exit status: 79",
    )
}

#[test]
fn quality_records_explicit_not_selected_scheduled_gates_for_the_pr_profile() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality_profile("pr")?;
        let evidence = fixture.latest_evidence()?;
        for expected in [
            "\"profile\": \"pr\"",
            "\"gate_id\": \"EG-COVERAGE\"",
            "\"result\": \"not-selected\"",
            "Gate does not apply to the `pr` execution profile.",
        ] {
            if !evidence.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "PR evidence omitted the scheduled-gate verdict `{expected}`"
                ))
                .into());
            }
        }
        for (gate, owner) in [
            ("EG-00", "Quality Engineering"),
            ("EG-ARCH", "Architecture"),
            ("EG-BUILD", "Rust and Toolchain"),
            ("EG-CONCURRENCY", "Application Runtime"),
            ("EG-CORRECT", "Architecture"),
            ("EG-COVERAGE", "Quality Engineering"),
            ("EG-CRYPTO", "Security and Key Management"),
            ("EG-DEPS", "Rust and Toolchain"),
            ("EG-DOCS", "Public API and SDK"),
            ("EG-DYNAMIC", "Quality Engineering"),
            ("EG-ERROR", "Public API and SDK"),
            ("EG-EVIDENCE", "Release Engineering"),
            ("EG-FAULT", "Quality Engineering"),
            ("EG-INTEGRITY", "Security and Key Management"),
            ("EG-MATRIX", "Quality Engineering"),
            ("EG-PERF", "Performance Qualification"),
            ("EG-POLICY", "Architecture"),
            ("EG-RESOURCE", "Storage Kernel"),
            ("EG-RUST", "Rust and Toolchain"),
            ("EG-SAFETY", "Security and Key Management"),
            ("EG-SECRETS", "Security and Key Management"),
            ("EG-SECURITY", "Security and Key Management"),
            ("EG-SOAK", "Performance Qualification"),
            ("EG-SUPPLY", "Release Engineering"),
            ("EG-TEST", "Quality Engineering"),
        ] {
            assert_gate_owner_binding(&evidence, gate, owner)?;
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_runs_correctness_through_the_registered_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "registered correctness runner did not complete successfully: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = "EG-CORRECT";
        let record = gate_record(&evidence, gate)?;
        if !record.contains("\"result\": \"passed\"") {
            return Err(std::io::Error::other(
                "registered correctness runner did not retain a passing public outcome",
            )
            .into());
        }
        let report = fs::read_to_string(exact_raw_report_path(&fixture.root, &evidence, gate)?)?;
        for expected in [
            "\"schema_version\": 1",
            "\"gate_id\": \"EG-CORRECT\"",
            "\"verdict\": \"passed\"",
            "correctness-before-publication:crash-after-candidate-sync:state-v1",
            "correctness-after-publication:crash-after-publication-sync:state-v2",
        ] {
            if !report.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "correctness immutable raw report omitted `{expected}`"
                ))
                .into());
            }
        }
        for deferred_gate in ["EG-CONCURRENCY", "EG-CRYPTO", "EG-RESOURCE", "EG-SOAK"] {
            let deferred = gate_record(&evidence, deferred_gate)?;
            if !deferred.contains("\"result\": \"not-selected\"") {
                return Err(std::io::Error::other(format!(
                    "including active tooling selected unrelated deferred gate {deferred_gate}"
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

#[path = "foundational_scope_activation/m0_08_lifecycle_resource.rs"]
mod m0_08_lifecycle_resource;
#[path = "foundational_scope_activation/m0_08_parent_verifier.rs"]
mod m0_08_parent_verifier;
#[path = "foundational_scope_activation/m0_08_scanner_policy.rs"]
mod m0_08_scanner_policy;
#[path = "foundational_scope_activation/m0_08_support.rs"]
mod m0_08_support;
#[path = "foundational_scope_activation/m0_09_coverage_audit.rs"]
mod m0_09_coverage_audit;
#[path = "foundational_scope_activation/m0_09_dynamic_plans.rs"]
mod m0_09_dynamic_plans;
#[path = "foundational_scope_activation/m0_09_dynamic_quality.rs"]
mod m0_09_dynamic_quality;
#[path = "foundational_scope_activation/m0_09_dynamic_verifier.rs"]
mod m0_09_dynamic_verifier;
#[path = "foundational_scope_activation/m0_10_final_blockers.rs"]
mod m0_10_final_blockers;
#[path = "foundational_scope_activation/m0_10_security_crypto.rs"]
mod m0_10_security_crypto;
#[path = "foundational_scope_activation/m0_11_matrix.rs"]
mod m0_11_matrix;

#[cfg(unix)]
#[test]
fn quality_executes_and_binds_the_fixture_registry_bytes_captured_once() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let quality_registry_path = fixture
            .root
            .join("qualification/engineering/quality-fixtures.tsv");
        let integrity_registry_path = fixture
            .root
            .join("qualification/engineering/integrity-fixtures.tsv");
        let concurrency_registry_path = fixture
            .root
            .join("qualification/engineering/concurrency-fixtures.tsv");
        let captured_quality_registry = fs::read(&quality_registry_path)?;
        let captured_integrity_registry = fs::read(&integrity_registry_path)?;
        let captured_concurrency_registry = fs::read(&concurrency_registry_path)?;
        if captured_concurrency_registry != CANONICAL_CONCURRENCY_FIXTURE_REGISTRY {
            return Err(std::io::Error::other(
                "the canonical concurrency fixture registry changed without updating its frozen identity assertion",
            )
            .into());
        }
        let mut seed_hasher = Sha256::new();
        seed_hasher.update(b"positron-quality-fixture-seeds-v1\0");
        seed_hasher.update(&captured_quality_registry);
        seed_hasher.update(b"\0");
        seed_hasher.update(&captured_integrity_registry);
        seed_hasher.update(b"\0");
        seed_hasher.update(CANONICAL_CONCURRENCY_FIXTURE_REGISTRY);
        let expected_seed = format!("sha256:{:x}", seed_hasher.finalize());
        let mut schedule_hasher = Sha256::new();
        schedule_hasher.update(b"positron-quality-fault-schedules-v1\0");
        schedule_hasher.update(&captured_quality_registry);
        schedule_hasher.update(b"\0");
        schedule_hasher.update(&captured_integrity_registry);
        schedule_hasher.update(b"\0");
        schedule_hasher.update(CANONICAL_CONCURRENCY_FIXTURE_REGISTRY);
        let expected_schedule = format!("sha256:{:x}", schedule_hasher.finalize());

        inject_fixture_registry_capture_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        let ready = fixture
            .root
            .join("target/quality-tools/fixture-registry-capture-ready");
        wait_for_path(&ready, Duration::from_secs(30))?;
        fs::write(&quality_registry_path, b"mutated-after-capture\n")?;
        fs::write(&integrity_registry_path, b"mutated-after-capture\n")?;
        fs::write(&concurrency_registry_path, b"mutated-after-capture\n")?;
        fs::write(
            fixture
                .root
                .join("target/quality-tools/fixture-registry-capture-release"),
            b"release\n",
        )?;

        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "quality reread fixture registry bytes after capture: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let exact_seed =
            format!("\"seed\": {{\"applicability\": \"exact\", \"value\": \"{expected_seed}\"");
        if !evidence.contains(&exact_seed) {
            return Err(std::io::Error::other(format!(
                "evidence seed was not derived from the exact frozen registry bytes: expected `{exact_seed}` in {evidence}"
            ))
            .into());
        }
        let exact_schedule = format!(
            "\"fault_schedule\": {{\"applicability\": \"exact\", \"value\": \"{expected_schedule}\""
        );
        if !evidence.contains(&exact_schedule) {
            return Err(std::io::Error::other(format!(
                "evidence schedule was not derived from the exact frozen quality, integrity, and concurrency registry bytes: expected `{exact_schedule}` in {evidence}"
            ))
            .into());
        }
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-CORRECT",
        )?)?;
        if !report.contains("correctness-before-publication:crash-after-candidate-sync:state-v1") {
            return Err(std::io::Error::other(
                "correctness did not execute the typed case parsed from frozen registry bytes",
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
fn quality_proves_forced_writer_termination_and_fresh_process_recovery() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "registered process recovery runner failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-CORRECT",
        )?)?;
        for expected in [
            "process-interface=qualification/engineering/fixture-harness.tsv",
            "ack=publication-point-ready-v1",
            "writer=forcibly-terminated-and-reaped",
            "recovery=fresh-process",
            "recovery-digest=sha256:",
        ] {
            if !report.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "process recovery report omitted `{expected}`"
                ))
                .into());
            }
        }
        for outcome in report.split(',') {
            let Some((_, identities)) = outcome.split_once("writer-pid=") else {
                continue;
            };
            let Some((writer_pid, recovery)) = identities.split_once(":recovery-pid=") else {
                return Err(
                    std::io::Error::other("writer identity omitted recovery identity").into(),
                );
            };
            let recovery_pid = recovery
                .split(':')
                .next()
                .ok_or_else(|| std::io::Error::other("recovery identity was empty"))?;
            if writer_pid == recovery_pid {
                return Err(std::io::Error::other(
                    "recovery reused the forcibly terminated writer process",
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

#[test]
fn quality_fixture_rejects_trailing_arguments_before_child_dispatch() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args([
            "quality-fixture",
            "writer",
            "/owned",
            "/owned/case",
            "before-publication",
            "crash-after-candidate-sync",
            "state-v1",
            "state-v2",
            "unexpected-trailing",
            "another-trailing",
            "third-trailing",
            "fourth-trailing",
        ])
        .output()?;
    assert_rejected_output(
        &output,
        "quality-fixture argument count exceeds the exact maximum of 9",
    )
}

#[cfg(unix)]
#[test]
fn quality_rejects_a_fixture_root_symlink_race_without_touching_the_target() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        inject_fixture_root_claim_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        let ready = fixture
            .root
            .join("target/quality-tools/fixture-root-claim-ready");
        wait_for_path(&ready, Duration::from_secs(30))?;
        let temporary_root = PathBuf::from(
            fs::read_to_string(
                fixture
                    .root
                    .join("target/quality-tools/fixture-root-claim-path"),
            )?
            .trim(),
        );
        let external = fixture
            .root
            .join("target/quality-tools/fixture-root-external");
        fs::create_dir(&external)?;
        let canary = external.join("canary");
        fs::write(&canary, b"untouched\n")?;
        std::os::unix::fs::symlink(
            &external,
            temporary_root.join("qualification-fixtures-correctness"),
        )?;
        fs::write(
            fixture
                .root
                .join("target/quality-tools/fixture-root-claim-release"),
            b"release\n",
        )?;

        let output = child.wait_with_output()?;
        assert_rejected_output(
            &output,
            "owned fixture directory component is not a directory",
        )?;
        if fs::read(&canary)? != b"untouched\n" {
            return Err(
                std::io::Error::other("fixture symlink race changed the external canary").into(),
            );
        }
        let mut external_entries = fs::read_dir(&external)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        external_entries.sort();
        if external_entries != [std::ffi::OsString::from("canary")] {
            return Err(std::io::Error::other(
                "fixture symlink race created content outside the owned root",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_keeps_writer_acknowledgement_bound_after_a_post_claim_case_swap() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        inject_fixture_writer_claim_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        let tools = fixture.root.join("target/quality-tools");
        wait_for_path(
            &tools.join("fixture-writer-claim-ready"),
            Duration::from_secs(30),
        )?;
        let case_root = PathBuf::from(
            fs::read_to_string(tools.join("fixture-writer-claim-path"))?
                .trim()
                .to_owned(),
        );
        let claimed = case_root.with_file_name(format!(
            "{}-claimed",
            case_root
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| std::io::Error::other("fixture case name was not UTF-8"))?
        ));
        let external = tools.join("fixture-writer-swap-external");
        fs::create_dir(&external)?;
        let canary = external.join("canary");
        fs::write(&canary, b"untouched\n")?;
        fs::rename(&case_root, &claimed)?;
        std::os::unix::fs::symlink(&external, &case_root)?;
        fs::write(tools.join("fixture-writer-claim-release"), b"release\n")?;

        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "post-claim writer swap escaped the held case capability: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        assert_external_canary_untouched(&external, &canary)?;
        assert_no_fixture_trees(&fixture.root)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_rejects_a_symbolic_link_process_acknowledgement_after_claim() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        inject_fixture_writer_claim_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        let tools = fixture.root.join("target/quality-tools");
        wait_for_path(
            &tools.join("fixture-writer-claim-ready"),
            Duration::from_secs(30),
        )?;
        let case_root = PathBuf::from(
            fs::read_to_string(tools.join("fixture-writer-claim-path"))?
                .trim()
                .to_owned(),
        );
        let canary = tools.join("fixture-ack-symlink-canary");
        fs::write(&canary, b"untouched\n")?;
        std::os::unix::fs::symlink(&canary, case_root.join("writer.ready"))?;
        fs::write(tools.join("fixture-writer-claim-release"), b"release\n")?;

        let output = child.wait_with_output()?;
        assert_rejected_output(&output, "fixture acknowledgement is a symbolic link")?;
        if fs::read(&canary)? != b"untouched\n" {
            return Err(std::io::Error::other(
                "symbolic-link acknowledgement changed its external target",
            )
            .into());
        }
        assert_no_fixture_trees(&fixture.root)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_rejects_an_oversized_process_acknowledgement_before_allocation() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        inject_fixture_writer_claim_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        let tools = fixture.root.join("target/quality-tools");
        wait_for_path(
            &tools.join("fixture-writer-claim-ready"),
            Duration::from_secs(30),
        )?;
        let case_root = PathBuf::from(
            fs::read_to_string(tools.join("fixture-writer-claim-path"))?
                .trim()
                .to_owned(),
        );
        fs::write(case_root.join("writer.ready"), vec![b'x'; 1_025])?;
        fs::write(tools.join("fixture-writer-claim-release"), b"release\n")?;

        let output = child.wait_with_output()?;
        assert_rejected_output(&output, "fixture acknowledgement exceeds 1024 bytes")?;
        assert_no_fixture_trees(&fixture.root)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_keeps_integrity_mutations_bound_after_a_post_claim_case_swap() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-INTEGRITY|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        inject_fixture_integrity_claim_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        let tools = fixture.root.join("target/quality-tools");
        wait_for_path(
            &tools.join("fixture-integrity-claim-ready"),
            Duration::from_secs(30),
        )?;
        let case_root = PathBuf::from(
            fs::read_to_string(tools.join("fixture-integrity-claim-path"))?
                .trim()
                .to_owned(),
        );
        let claimed = case_root.with_file_name(format!(
            "{}-claimed",
            case_root
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| std::io::Error::other("integrity case name was not UTF-8"))?
        ));
        let external = tools.join("fixture-integrity-swap-external");
        fs::create_dir(&external)?;
        let canary = external.join("canary");
        fs::write(&canary, b"untouched\n")?;
        fs::rename(&case_root, &claimed)?;
        std::os::unix::fs::symlink(&external, &case_root)?;
        fs::write(tools.join("fixture-integrity-claim-release"), b"release\n")?;

        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "post-claim integrity swap escaped the held case capability: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        assert_external_canary_untouched(&external, &canary)?;
        assert_no_fixture_trees(&fixture.root)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_cleans_attempt_owned_fixture_trees_after_repeated_successes() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        for attempt in 1..=2 {
            let output = fixture.quality_output_for("pr")?;
            if !output.status.success() {
                return Err(std::io::Error::other(format!(
                    "cleanup repeat attempt {attempt} failed: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                ))
                .into());
            }
            assert_no_fixture_trees(&fixture.root)?;
            let evidence = fixture.latest_evidence()?;
            let report = fs::read_to_string(exact_raw_report_path(
                &fixture.root,
                &evidence,
                "EG-CORRECT",
            )?)?;
            if report.contains("qualification-fixtures-correctness") {
                return Err(std::io::Error::other(
                    "immutable evidence retained a mutable fixture-tree path",
                )
                .into());
            }
            if !report.contains("recovery-digest=sha256:") {
                return Err(std::io::Error::other(
                    "immutable evidence omitted the recovered-state digest",
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

#[cfg(unix)]
#[test]
fn quality_kills_reaps_and_cleans_a_timed_out_fixture_writer() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture
                .root
                .join("qualification/engineering/fixture-harness.tsv"),
            "\t5000\tforce-kill-and-reap\t",
            "\t50\tforce-kill-and-reap\t",
        )?;
        inject_fixture_writer_timeout(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let output = fixture
            .quality_child_from_built_fixture_for("pr")?
            .wait_with_output()?;
        assert_rejected_output(
            &output,
            "writer did not acknowledge its publication point before the registered deadline",
        )?;
        assert_no_fixture_trees(&fixture.root)?;
        let pid = fs::read_to_string(
            fixture
                .root
                .join("target/quality-tools/fixture-writer-timeout-pid"),
        )?;
        let status = Command::new("kill")
            .args(["-0", pid.trim()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            return Err(std::io::Error::other(
                "timed-out fixture writer remained alive after gate reconciliation",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_fails_with_bounded_evidence_when_writer_reap_observation_stalls() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture
                .root
                .join("qualification/engineering/fixture-harness.tsv"),
            "\t5000\tforce-kill-and-reap\t",
            "\t50\tforce-kill-and-reap\t",
        )?;
        inject_stalled_writer_reap_observation(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        wait_for_path(
            &fixture
                .root
                .join("target/quality-tools/fixture-writer-reap-observer-entered"),
            Duration::from_secs(30),
        )?;
        let started = Instant::now();
        let output = child.wait_with_output()?;
        if started.elapsed() >= Duration::from_secs(5) {
            return Err(std::io::Error::other(
                "stalled writer reap exceeded its bounded public failure deadline",
            )
            .into());
        }
        for expected in [
            "fixture writer process reap deadline elapsed",
            "kill-sent=true",
            "pid=",
        ] {
            assert_rejected_output(&output, expected)?;
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-CORRECT")?;
        if !gate.contains("\"result\": \"failed\"")
            || !gate.contains("fixture writer process reap deadline elapsed")
        {
            return Err(std::io::Error::other(
                "stalled writer reap did not retain its typed PID/state failure",
            )
            .into());
        }
        let pid = fs::read_to_string(
            fixture
                .root
                .join("target/quality-tools/fixture-writer-reap-stall-pid"),
        )?;
        let status = Command::new("kill")
            .args(["-0", pid.trim()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            return Err(std::io::Error::other(
                "stalled-reap fixture writer remained detached after the runner exited",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_fails_when_attempt_owned_fixture_cleanup_fails() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        inject_fixture_cleanup_failure(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let output = fixture
            .quality_child_from_built_fixture_for("pr")?
            .wait_with_output()?;
        assert_rejected_output(&output, "injected qualification fixture cleanup failure")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-CORRECT")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "fixture cleanup failure was not retained as a failed gate",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_rejects_an_ordinary_directory_replacing_the_cleaned_fixture_root() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        inject_fixture_cleanup_replacement_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        let tools = fixture.root.join("target/quality-tools");
        wait_for_path(
            &tools.join("fixture-cleanup-replacement-ready"),
            Duration::from_secs(30),
        )?;
        let canonical = PathBuf::from(
            fs::read_to_string(tools.join("fixture-cleanup-replacement-path"))?
                .trim()
                .to_owned(),
        );
        fs::create_dir(&canonical)?;
        let canary = canonical.join("canary");
        fs::write(&canary, b"untouched\n")?;
        fs::write(
            tools.join("fixture-cleanup-replacement-release"),
            b"release\n",
        )?;

        let output = child.wait_with_output()?;
        assert_rejected_output(
            &output,
            "canonical fixture root name was replaced during cleanup",
        )?;
        if fs::read(&canary)? != b"untouched\n" {
            return Err(std::io::Error::other(
                "fixture cleanup changed the unowned replacement canary",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-CORRECT")?;
        if !gate.contains("\"result\": \"failed\"")
            || !gate.contains("canonical fixture root name was replaced during cleanup")
        {
            return Err(std::io::Error::other(
                "fixture replacement cleanup failure was not retained with bounded detail",
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
fn quality_rejects_a_malformed_correctness_fixture_registry() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture
                .root
                .join("qualification/engineering/quality-fixtures.tsv"),
            "fixture_id\tgate_id\tpublication_point",
            "fixture\tgate_id\tpublication_point",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "fixture registry header is not exact")?;
        let evidence = fixture.latest_evidence()?;
        let record = gate_record(&evidence, "EG-CORRECT")?;
        if !record.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "malformed correctness registry did not retain a failed gate outcome",
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
fn quality_rejects_an_unconsumed_fixture_gate_row() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-FAULT|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let registry = fixture
            .root
            .join("qualification/engineering/quality-fixtures.tsv");
        let mut content = fs::read_to_string(&registry)?;
        content.push_str(
            "unconsumed-typo\tEG-CORREXT\tbefore-publication\tcrash-after-candidate-sync\tseed-unconsumed-v1\tstate-v1\tstate-v2\tstate-v1\n",
        );
        fs::write(&registry, content)?;

        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "fixture gate `EG-CORREXT` is not an exact consumed gate",
        )?;
        let evidence = fixture.latest_evidence()?;
        for gate in ["EG-CORRECT", "EG-FAULT"] {
            if !gate_record(&evidence, gate)?.contains("\"result\": \"failed\"") {
                return Err(std::io::Error::other(format!(
                    "unconsumed fixture row did not fail `{gate}`"
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

#[cfg(unix)]
#[test]
fn quality_rejects_a_symbolic_link_frozen_fixture_input() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let registry = fixture
            .root
            .join("qualification/engineering/quality-fixtures.tsv");
        let external = fixture
            .root
            .join("target/quality-tools/external-quality-fixtures.tsv");
        fs::write(&external, fs::read(&registry)?)?;
        fs::remove_file(&registry)?;
        std::os::unix::fs::symlink(&external, &registry)?;

        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "registry symlinks are forbidden")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_rejects_a_symbolic_link_during_frozen_fixture_capture() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let manifest = fixture
            .root
            .join("qualification/fixtures/adversarial/manifest.json");
        let external = fixture
            .root
            .join("target/quality-tools/external-adversarial-manifest.json");
        fs::write(&external, fs::read(&manifest)?)?;
        fs::remove_file(&manifest)?;
        std::os::unix::fs::symlink(&external, &manifest)?;

        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "fixture identity input is a symbolic link")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_oversized_frozen_fixture_before_allocating_its_contents() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("qualification/fixtures/adversarial/manifest.json"),
            vec![b'x'; 65_537],
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "fixture identity input exceeds 65536 bytes")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_correctness_fixture_with_a_false_reopen_oracle() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture
                .root
                .join("qualification/engineering/quality-fixtures.tsv"),
            "correctness-before-publication\tEG-CORRECT\tbefore-publication\tcrash-after-candidate-sync\tseed-correctness-before-v1\tstate-v1\tstate-v2\tstate-v1\n",
            "correctness-before-publication\tEG-CORRECT\tbefore-publication\tcrash-after-candidate-sync\tseed-correctness-before-v1\tstate-v1\tstate-v2\tstate-v2\n",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "expected reopen state does not match the registered publication-point oracle",
        )?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-CORRECT")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "false correctness oracle did not retain a failed gate outcome",
            )
            .into());
        }
        assert_no_fixture_trees(&fixture.root)?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_correctness_fixture_registry_over_its_resource_ceiling() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        fs::write(
            fixture
                .root
                .join("qualification/engineering/quality-fixtures.tsv"),
            vec![b'x'; 16_385],
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "fixture registry exceeds 16384 bytes")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-CORRECT")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "oversized correctness registry did not retain a failed gate outcome",
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
fn quality_runs_fault_through_the_registered_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-FAULT|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "registered fault runner did not complete successfully: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = "EG-FAULT";
        let record = gate_record(&evidence, gate)?;
        if !record.contains("\"result\": \"passed\"") {
            return Err(std::io::Error::other(
                "registered fault runner did not retain a passing public outcome",
            )
            .into());
        }
        let report = fs::read_to_string(exact_raw_report_path(&fixture.root, &evidence, gate)?)?;
        for expected in [
            "\"schema_version\": 1",
            "\"gate_id\": \"EG-FAULT\"",
            "\"verdict\": \"passed\"",
            "exact-fault-classes=partial-write+crash+restart+corruption+full-disk+clock+cancellation+network+provider",
            "fault-partial-write:inject-partial-write:state-v1:adapter=partial-write-adapter:injection=partial-write-injected",
            "fault-crash:inject-crash:state-v1:adapter=process-crash-adapter:injection=crash-window-open",
            "fault-restart:inject-restart:state-v2:adapter=restart-adapter:injection=successor-published",
            "fault-corruption:inject-corruption:state-v1:adapter=corruption-adapter:injection=candidate-corrupted",
            "fault-full-disk:inject-full-disk:state-v1:adapter=bounded-storage-adapter:injection=capacity-exhausted",
            "fault-clock:inject-clock:state-v1:adapter=controlled-clock-adapter:injection=clock-regressed",
            "fault-cancellation:inject-cancellation:state-v1:adapter=cancellation-adapter:injection=cancelled-before-publication",
            "fault-network:inject-network:state-v1:adapter=network-publication-adapter:injection=network-unavailable",
            "fault-provider:inject-provider:state-v1:adapter=provider-publication-adapter:injection=provider-unavailable",
            "one-to-one-publication-points=9",
        ] {
            if !report.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "fault immutable raw report omitted `{expected}`"
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

macro_rules! removed_fault_adapter_regression {
    ($name:ident, $variant:literal) => {
        #[test]
        fn $name() -> TestResult {
            assert_removed_fault_adapter_is_rejected($variant)
        }
    };
}

removed_fault_adapter_regression!(
    quality_rejects_a_removed_partial_write_adapter,
    "PartialWrite"
);
removed_fault_adapter_regression!(quality_rejects_a_removed_crash_adapter, "Crash");
removed_fault_adapter_regression!(quality_rejects_a_removed_restart_adapter, "Restart");
removed_fault_adapter_regression!(quality_rejects_a_removed_corruption_adapter, "Corruption");
removed_fault_adapter_regression!(
    quality_rejects_a_removed_bounded_storage_adapter,
    "FullDisk"
);
removed_fault_adapter_regression!(quality_rejects_a_removed_controlled_clock_adapter, "Clock");
removed_fault_adapter_regression!(
    quality_rejects_a_removed_cancellation_adapter,
    "Cancellation"
);
removed_fault_adapter_regression!(
    quality_rejects_a_removed_network_publication_adapter,
    "Network"
);
removed_fault_adapter_regression!(
    quality_rejects_a_removed_provider_publication_adapter,
    "Provider"
);

macro_rules! bypassed_fault_operation_regression {
    ($name:ident, $adapter:literal) => {
        #[test]
        fn $name() -> TestResult {
            assert_bypassed_fault_operation_is_rejected($adapter)
        }
    };
}

bypassed_fault_operation_regression!(
    quality_rejects_a_bypassed_bounded_storage_operation,
    "BoundedStorage"
);
bypassed_fault_operation_regression!(
    quality_rejects_a_bypassed_controlled_clock_operation,
    "ControlledClock"
);
bypassed_fault_operation_regression!(
    quality_rejects_a_bypassed_cancellation_operation,
    "Cancellation"
);
bypassed_fault_operation_regression!(
    quality_rejects_a_bypassed_network_publication_operation,
    "NetworkPublication"
);
bypassed_fault_operation_regression!(
    quality_rejects_a_bypassed_provider_publication_operation,
    "ProviderPublication"
);

#[cfg(unix)]
#[test]
fn quality_rejects_a_candidate_replacement_after_its_first_bounded_read() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-FAULT|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        inject_candidate_replacement_after_first_read(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let output = fixture
            .quality_child_from_built_fixture_for("pr")?
            .wait_with_output()?;
        assert_rejected_output(&output, "fixture recovery process")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-FAULT")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "candidate replacement did not retain a failed EG-FAULT verdict",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_removed_fault_adapter_is_rejected(variant: &str) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-FAULT|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        remove_fault_adapter_invocation(&fixture.root, variant)?;
        fixture.build_fixture_xtask()?;
        let output = fixture
            .quality_child_from_built_fixture_for("pr")?
            .wait_with_output()?;
        assert_rejected_output(&output, "fixture recovery process")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-FAULT")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(format!(
                "removing the {variant} adapter did not retain a failed EG-FAULT verdict"
            ))
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_bypassed_fault_operation_is_rejected(adapter: &str) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-FAULT|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        bypass_fault_operation(&fixture.root, adapter)?;
        fixture.build_fixture_xtask()?;
        let output = fixture
            .quality_child_from_built_fixture_for("pr")?
            .wait_with_output()?;
        assert_rejected_output(&output, "fixture recovery process")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-FAULT")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(format!(
                "bypassing the {adapter} operation did not retain a failed EG-FAULT verdict"
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
fn quality_rejects_a_fault_registry_without_one_schedule_per_publication_point() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-FAULT|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture
                .root
                .join("qualification/engineering/quality-fixtures.tsv"),
            "fault-provider\tEG-FAULT\tprovider-boundary\tinject-provider\tseed-fault-provider-v1\tstate-v1\tstate-v2\tstate-v1\n",
            "",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "invalid EG-FAULT fixture registry: expected exactly 9 publication-point fixtures, found 8",
        )?;
        let evidence = fixture.latest_evidence()?;
        let record = gate_record(&evidence, "EG-FAULT")?;
        if !record.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "incomplete fault registry did not retain a failed public outcome",
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
fn quality_runs_integrity_through_the_registered_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-FAULT|EG-INTEGRITY|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "registered integrity runner did not complete successfully: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = "EG-INTEGRITY";
        let record = gate_record(&evidence, gate)?;
        if !record.contains("\"result\": \"passed\"") {
            return Err(std::io::Error::other(
                "registered integrity runner did not retain a passing public outcome",
            )
            .into());
        }
        let report = fs::read_to_string(exact_raw_report_path(&fixture.root, &evidence, gate)?)?;
        for expected in [
            "\"schema_version\": 1",
            "\"gate_id\": \"EG-INTEGRITY\"",
            "\"verdict\": \"passed\"",
            "integrity-verified:verified:original-preserved",
            "integrity-corrupt-payload:digest-mismatch:original-preserved",
            "integrity-delete-object:missing-object:original-preserved",
            "identity=revision+artifact+target+environment+command+fixtures+seed+schedule+result",
        ] {
            if !report.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "integrity immutable raw report omitted `{expected}`"
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
fn quality_rejects_an_integrity_fixture_with_a_false_reopen_outcome() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-INTEGRITY|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture
                .root
                .join("qualification/engineering/integrity-fixtures.tsv"),
            "integrity-corrupt-payload\tcorrupt-payload\tseed-integrity-corrupt-v1\tdigest-mismatch\n",
            "integrity-corrupt-payload\tcorrupt-payload\tseed-integrity-corrupt-v1\tverified\n",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "registered expected outcome does not match its mutation",
        )?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-INTEGRITY")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "false integrity oracle did not retain a failed gate outcome",
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
fn quality_preserves_a_failed_correctness_attempt_before_a_later_pass() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CORRECT|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let registry = fixture
            .root
            .join("qualification/engineering/quality-fixtures.tsv");
        let valid = fs::read_to_string(&registry)?;
        fs::write(
            &registry,
            valid.replace(
                "correctness-before-publication\tEG-CORRECT\tbefore-publication\tcrash-after-candidate-sync\tseed-correctness-before-v1\tstate-v1\tstate-v2\tstate-v1\n",
                "correctness-before-publication\tEG-CORRECT\tbefore-publication\tcrash-after-candidate-sync\tseed-correctness-before-v1\tstate-v1\tstate-v2\tstate-v2\n",
            ),
        )?;
        let failed = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &failed,
            "expected reopen state does not match the registered publication-point oracle",
        )?;
        let failed_path = fixture.latest_evidence_path()?;
        let failed_bytes = fs::read(&failed_path)?;
        fs::write(&registry, valid)?;
        let passed = fixture.quality_output_for("pr")?;
        if !passed.status.success() {
            return Err(std::io::Error::other(format!(
                "corrected public quality attempt did not pass: {}\n{}",
                String::from_utf8_lossy(&passed.stdout),
                String::from_utf8_lossy(&passed.stderr),
            ))
            .into());
        }
        if fs::read(&failed_path)? != failed_bytes {
            return Err(std::io::Error::other(
                "later correctness pass rewrote the prior failed attempt",
            )
            .into());
        }
        let evidence_count = fs::read_dir(fixture.root.join("target/quality/evidence"))?
            .collect::<Result<Vec<_>, _>>()?
            .len();
        if evidence_count != 2 {
            return Err(std::io::Error::other(format!(
                "retry fixture retained {evidence_count} attempts instead of exactly 2"
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
fn quality_records_dirty_local_success_as_non_merge_eligible_evidence() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        make_fixture_git_report_dirty(&fixture.root)?;
        fixture.quality()?;
        let evidence = fixture.latest_evidence()?;
        for expected in [
            "\"result\": \"passed\"",
            "\"merge_eligible\": false",
            "\"dirty\": true",
        ] {
            if !evidence.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "local quality evidence omitted `{expected}`"
                ))
                .into());
            }
        }
        let report = exact_raw_report_path(&fixture.root, &evidence, "EG-00")?;
        let report = fs::read_to_string(report)?;
        for expected in [
            "\"schema_version\": 1",
            "\"content_type\": \"application/vnd.positron.quality-gate-report+json;version=1\"",
            "\"gate_id\": \"EG-00\"",
            "\"verdict\": \"passed\"",
            "\"invocation_digest\": \"sha256:",
            "\"controlled_steps\": [",
            "\"verdict\":\"exit-status:",
            "\"stdout\":",
            "\"stderr\":",
        ] {
            if !report.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "EG-00 raw report omitted exact retained field `{expected}`"
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
fn quality_rejects_stale_trusted_ci_source_identity() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let output = fixture.quality_output_for_with_environment(
            "pre-commit",
            [
                ("GITHUB_ACTIONS", "true"),
                ("GITHUB_SHA", "2222222222222222222222222222222222222222"),
                ("GITHUB_RUN_ATTEMPT", "1"),
            ],
        )?;
        assert_rejected_output(
            &output,
            "trusted CI revision does not match the executing source",
        )?;
        assert_failed_aggregator_evidence(
            &fixture,
            "0000000000000000000000000000000000000000",
            "trusted CI revision does not match the executing source",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_retried_trusted_ci_attempt() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let output = fixture.quality_output_for_with_environment(
            "pre-commit",
            [
                ("GITHUB_ACTIONS", "true"),
                ("GITHUB_SHA", "0000000000000000000000000000000000000000"),
                ("GITHUB_RUN_ATTEMPT", "2"),
            ],
        )?;
        assert_rejected_output(
            &output,
            "trusted CI retry attempts are not accepted as fresh evidence",
        )?;
        assert_failed_aggregator_evidence(
            &fixture,
            "0000000000000000000000000000000000000000",
            "trusted CI retry attempts are not accepted as fresh evidence",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_trusted_ci_without_a_run_attempt_identity() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let output = fixture.quality_output_for_with_environment(
            "pre-commit",
            [
                ("GITHUB_ACTIONS", "true"),
                ("GITHUB_SHA", "0000000000000000000000000000000000000000"),
            ],
        )?;
        assert_rejected_output(
            &output,
            "trusted CI evidence is missing its run-attempt identity",
        )?;
        assert_failed_aggregator_evidence(
            &fixture,
            "0000000000000000000000000000000000000000",
            "trusted CI evidence is missing its run-attempt identity",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_overwritten_engineering_evidence_attempt() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        let evidence = fixture
            .root
            .join("target/quality/evidence/1700000000000-111111111111-1.json");
        let parent = evidence.parent().ok_or_else(|| {
            std::io::Error::other("fixture evidence path has no parent directory")
        })?;
        fs::create_dir_all(parent)?;
        let original = b"{\"tampered\":true}\n";
        fs::write(&evidence, original)?;
        let recovery = parent.join("1700000000000-111111111111-1-recovery.json");
        let recovery_bytes = b"{\"schema_version\":1,\"attempt_id\":\"legacy-blocker\"}\n";
        fs::write(&recovery, recovery_bytes)?;
        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "engineering evidence attempt collision")?;
        if fs::read(&evidence)? != original {
            return Err(std::io::Error::other(
                "the colliding attempt changed the pre-existing evidence bytes",
            )
            .into());
        }
        if fs::read(&recovery)? != recovery_bytes {
            return Err(std::io::Error::other(
                "the colliding attempt changed the pre-existing recovery bytes",
            )
            .into());
        }
        let collision = fixture
            .root
            .join("target/quality/evidence/1700000000000-111111111111-1-collision-00.json");
        let retained = fs::read_to_string(&collision)?;
        assert_complete_evidence_contract(&retained)?;
        for expected in [
            "\"result\": \"failed\"",
            "\"merge_eligible\": false",
            "\"gate_id\": \"EG-00\"",
            "engineering evidence attempt collision",
            "\"collision_of\": {",
            "\"value\": \"1700000000000-111111111111-1\"",
        ] {
            if !retained.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "collision evidence omitted `{expected}`"
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
fn quality_validates_a_retained_collision_on_the_next_evidence_pass() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        let evidence_directory = fixture.root.join("target/quality/evidence");
        fs::create_dir_all(&evidence_directory)?;
        fs::write(
            evidence_directory.join("1700000000000-111111111111-1-recovery.json"),
            b"{\"schema_version\":1,\"attempt_id\":\"legacy-blocker\"}\n",
        )?;
        let collision = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&collision, "engineering evidence attempt collision")?;

        let next = fixture.quality_output_for("pr")?;
        if !next.status.success() {
            return Err(std::io::Error::other(format!(
                "the next EG-EVIDENCE pass rejected a schema-valid collision record: {}\n{}",
                String::from_utf8_lossy(&next.stdout),
                String::from_utf8_lossy(&next.stderr)
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
fn quality_retains_collision_exhaustion_without_changing_any_occupied_bytes() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        let evidence_directory = fixture.root.join("target/quality/evidence");
        fs::create_dir_all(&evidence_directory)?;
        let canonical = evidence_directory.join("1700000000000-111111111111-1.json");
        let canonical_bytes = b"{\"canonical\":\"occupied\"}\n";
        fs::write(&canonical, canonical_bytes)?;
        let canonical_recovery =
            evidence_directory.join("1700000000000-111111111111-1-recovery.json");
        let recovery_bytes = b"{\"schema_version\":1,\"attempt_id\":\"legacy-blocker\"}\n";
        fs::write(&canonical_recovery, recovery_bytes)?;
        let mut occupied = Vec::new();
        let mut occupied_recoveries = vec![(canonical_recovery, recovery_bytes.to_vec())];
        for slot in 0..16 {
            let path = evidence_directory.join(format!(
                "1700000000000-111111111111-1-collision-{slot:02}.json"
            ));
            let bytes = format!("{{\"slot\":{slot},\"occupied\":true}}\n").into_bytes();
            fs::write(&path, &bytes)?;
            occupied.push((path, bytes));
            let recovery = evidence_directory.join(format!(
                "1700000000000-111111111111-1-collision-{slot:02}-recovery.json"
            ));
            fs::write(&recovery, recovery_bytes)?;
            occupied_recoveries.push((recovery, recovery_bytes.to_vec()));
        }

        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "engineering evidence attempt collision")?;
        if fs::read(&canonical)? != canonical_bytes {
            return Err(std::io::Error::other(
                "collision exhaustion changed the canonical evidence bytes",
            )
            .into());
        }
        for (path, bytes) in &occupied {
            if fs::read(path)? != *bytes {
                return Err(std::io::Error::other(format!(
                    "collision exhaustion changed occupied slot {}",
                    path.display()
                ))
                .into());
            }
        }
        for (path, bytes) in &occupied_recoveries {
            if fs::read(path)? != *bytes {
                return Err(std::io::Error::other(format!(
                    "collision exhaustion changed occupied recovery {}",
                    path.display()
                ))
                .into());
            }
        }

        let exhausted =
            evidence_directory.join("1700000000000-111111111111-1-collision-exhausted.json");
        let retained = fs::read_to_string(&exhausted)?;
        assert_complete_evidence_contract(&retained)?;
        for expected in [
            "\"result\": \"failed\"",
            "\"merge_eligible\": false",
            "\"gate_id\": \"EG-00\"",
            "\"value\": \"1700000000000-111111111111-1\"",
            "\"collision_slots\": {",
            "\"value\": \"collision-00,collision-01,collision-02,collision-03,collision-04,collision-05,collision-06,collision-07,collision-08,collision-09,collision-10,collision-11,collision-12,collision-13,collision-14,collision-15\"",
            "all 16 deterministic collision slots were already occupied",
        ] {
            if !retained.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "collision-exhaustion evidence omitted `{expected}`"
                ))
                .into());
            }
        }

        let exhausted_bytes = fs::read(&exhausted)?;
        let second = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&second, "engineering evidence attempt collision")?;
        if fs::read(&exhausted)? != exhausted_bytes {
            return Err(std::io::Error::other(
                "a repeated exhausted collision changed the reserved evidence bytes",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_atomically_retains_one_verdict_for_each_parallel_canonical_racer() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let canonical = "1700000000000-111111111111-1";
        let outputs = run_parallel_reservation_racers(&fixture, canonical)?;
        let successful = outputs
            .iter()
            .filter(|output| output.status.success())
            .count();
        if successful != 1 {
            return Err(std::io::Error::other(format!(
                "parallel canonical racers produced {successful} successful verdicts instead of one: {}",
                outputs
                    .iter()
                    .map(|output| format!(
                        "stdout={} stderr={}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
            .into());
        }
        let failed = outputs
            .iter()
            .find(|output| !output.status.success())
            .ok_or_else(|| {
                std::io::Error::other("parallel canonical racers omitted the collision verdict")
            })?;
        assert_rejected_output(failed, "engineering evidence attempt collision")?;
        assert_exact_parallel_retained_verdicts(
            &fixture.root,
            &[
                format!("{canonical}.json"),
                format!("{canonical}-collision-00.json"),
            ],
            &[],
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_atomically_retains_one_verdict_for_each_parallel_collision_slot_racer() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let canonical = "1700000000000-111111111111-1";
        let evidence_directory = fixture.root.join("target/quality/evidence");
        fs::create_dir_all(&evidence_directory)?;
        let blocker = evidence_directory.join(format!("{canonical}-recovery.json"));
        let blocker_bytes = b"{\"schema_version\":1,\"attempt_id\":\"legacy-blocker\"}\n";
        fs::write(&blocker, blocker_bytes)?;

        let collision = format!("{canonical}-collision-00");
        let outputs = run_parallel_reservation_racers(&fixture, &collision)?;
        for output in &outputs {
            assert_rejected_output(output, "engineering evidence attempt collision")?;
        }
        if fs::read(&blocker)? != blocker_bytes {
            return Err(std::io::Error::other(
                "parallel collision racers overwrote the occupied canonical recovery bytes",
            )
            .into());
        }
        assert_exact_parallel_retained_verdicts(
            &fixture.root,
            &[
                format!("{canonical}-collision-00.json"),
                format!("{canonical}-collision-01.json"),
            ],
            &[format!("{canonical}-recovery.json")],
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_never_replaces_a_concurrently_claimed_final_report_directory() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject_final_report_claim_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture()?;
        let ready = fixture
            .root
            .join("target/quality-tools/report-publication-barrier-ready");
        wait_for_path(&ready, Duration::from_secs(30))?;

        let attempt_id = "1700000000000-111111111111-1";
        let final_path = fixture
            .root
            .join("target/quality/evidence-reports")
            .join(attempt_id);
        fs::create_dir_all(&final_path)?;
        let claimed = fs::metadata(&final_path)?;
        fs::write(
            fixture
                .root
                .join("target/quality-tools/report-publication-barrier-release"),
            b"release\n",
        )?;

        let output = child.wait_with_output()?;
        assert_rejected_output(
            &output,
            "engineering evidence raw report attempt path is already occupied",
        )?;
        let retained = fs::metadata(&final_path)?;
        if retained.dev() != claimed.dev() || retained.ino() != claimed.ino() {
            return Err(std::io::Error::other(
                "report publication replaced the concurrently claimed final directory",
            )
            .into());
        }
        if fs::read_dir(&final_path)?.next().is_some() {
            return Err(std::io::Error::other(
                "report publication wrote into the concurrently claimed final directory",
            )
            .into());
        }
        assert_schema_valid_recovery(&fixture.root, attempt_id)?;
        assert_exact_parallel_retained_verdicts(
            &fixture.root,
            &[format!("{attempt_id}-recovery.json")],
            &[],
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_synchronizes_the_evidence_parent_after_removing_an_incomplete_primary() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject_primary_evidence_write_failure(&fixture.root)?;
        inject_primary_cleanup_parent_sync_failure(&fixture.root)?;
        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "injected primary cleanup parent sync failure")?;

        let attempt_id = "1700000000000-111111111111-1";
        let primary = fixture
            .root
            .join("target/quality/evidence")
            .join(format!("{attempt_id}.json"));
        if primary.exists() {
            return Err(std::io::Error::other(
                "primary cleanup parent-sync failure left incomplete primary evidence",
            )
            .into());
        }
        assert_schema_valid_recovery(&fixture.root, attempt_id)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_primary_resurrected_next_to_its_authoritative_recovery() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        let first = fixture.quality_output_from_fixture_source("pre-commit")?;
        if !first.status.success() {
            return Err(std::io::Error::other(format!(
                "fixture could not publish primary evidence: {}\n{}",
                String::from_utf8_lossy(&first.stdout),
                String::from_utf8_lossy(&first.stderr),
            ))
            .into());
        }
        let collision = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&collision, "engineering evidence attempt collision")?;
        assert_schema_valid_recovery(&fixture.root, "1700000000000-111111111111-1")?;

        let validation = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &validation,
            "primary evidence and its authoritative recovery marker coexist",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_publishes_the_complete_exact_identity_evidence_contract() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let evidence = fixture.latest_evidence()?;
        assert_complete_evidence_contract(&evidence)?;
        for expected in [
            "\"release_manifest\": {",
            "\"reason\": \"no-release-manifest-for-engineering-attempt\"",
            "\"artifact\": {",
            "\"reason\": \"no-candidate-artifact-for-engineering-attempt\"",
            "\"target\": {",
            "\"value\": \"engineering-workspace\"",
            "\"toolchain_digest\": \"git-object:",
            "\"fixture_registry_digest\": \"git-object:",
            "\"verifier\": {",
            "\"value\": \"cargo-xtask-quality/local-diagnostic\"",
            "\"approval\": {",
            "\"reason\": \"no-approval-claimed\"",
            "\"exception\": {",
            "\"reason\": \"no-exception-applied\"",
            "\"command_digest\": \"sha256:",
            "\"owner\": {",
            "\"raw_report\": {",
            "\"applicability\": \"exact\"",
            "\"path\": \"target/quality/evidence-reports/",
            "\"content_type\": \"application/vnd.positron.quality-gate-report+json;version=1\"",
            "\"invocation\": {",
            "\"program\":\"cargo-xtask-quality/internal\"",
            "\"arguments\":[",
            "\"working_directory\":\"engineering-workspace\"",
            "\"environment_digest\":\"sha256:",
            "\"timeout_seconds\":",
            "\"memory_mib\":",
            "\"activation\":",
            "\"exception_class\":",
            "\"controlled_steps\":[",
        ] {
            if !evidence.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "engineering evidence omitted exact identity contract `{expected}`"
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
fn quality_rejects_missing_retained_raw_report_evidence() -> TestResult {
    assert_invalid_retained_raw_report(
        |fixture, _evidence_path, evidence| {
            let report = exact_raw_report_path(&fixture.root, evidence, "EG-00")?;
            fs::remove_file(report)?;
            Ok(())
        },
        "retained raw report is missing",
    )
}

#[test]
fn quality_rejects_a_retained_v3_attempt_with_its_report_directory_removed() -> TestResult {
    assert_invalid_retained_raw_report(
        |fixture, _evidence_path, evidence| {
            let report = exact_raw_report_path(&fixture.root, evidence, "EG-00")?;
            let directory = report.parent().ok_or_else(|| {
                std::io::Error::other("retained report fixture has no attempt directory")
            })?;
            fs::remove_dir_all(directory)?;
            Ok(())
        },
        "retained raw report is missing",
    )
}

#[test]
fn quality_rejects_an_orphan_report_file() -> TestResult {
    assert_invalid_retained_raw_report(
        |fixture, _evidence_path, evidence| {
            let report = exact_raw_report_path(&fixture.root, evidence, "EG-00")?;
            let directory = report.parent().ok_or_else(|| {
                std::io::Error::other("retained report fixture has no attempt directory")
            })?;
            fs::write(directory.join("EG-ORPHAN.json"), "{}\n")?;
            Ok(())
        },
        "orphan retained raw report",
    )
}

#[test]
fn quality_rejects_an_orphan_report_attempt_directory() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let orphan = fixture
            .root
            .join("target/quality/evidence-reports/orphan-attempt");
        fs::create_dir_all(&orphan)?;
        fs::write(orphan.join("EG-00.json"), "{}\n")?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "orphan retained raw report")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_adversarial_retained_evidence_filename() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let evidence = fixture
            .root
            .join("target/quality/evidence/not an owned attempt.json");
        fs::write(evidence, "{\"schema_version\":3}\n")?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "retained evidence filename is not attempt-owned")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_non_json_file_in_the_retained_evidence_root() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let evidence_directory = fixture.root.join("target/quality/evidence");
        fs::create_dir_all(&evidence_directory)?;
        fs::write(evidence_directory.join("attempt.tmp"), b"not evidence\n")?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "retained evidence directory entry must be a regular JSON file",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_directory_in_the_retained_evidence_root() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let evidence_directory = fixture.root.join("target/quality/evidence");
        fs::create_dir_all(evidence_directory.join("unexpected-entry"))?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "retained evidence directory entry must be a regular JSON file",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_rejects_a_symlink_in_the_retained_evidence_root() -> TestResult {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::create()?;
    let result = (|| {
        let evidence_directory = fixture.root.join("target/quality/evidence");
        fs::create_dir_all(&evidence_directory)?;
        let target = fixture.root.join("retained-evidence-symlink-target");
        fs::write(&target, b"not evidence\n")?;
        symlink(&target, evidence_directory.join("linked-entry.tmp"))?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "retained evidence directory entry must be a regular JSON file",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_counts_every_retained_evidence_entry_before_accepting_the_root() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let evidence_directory = fixture.root.join("target/quality/evidence");
        fs::create_dir_all(&evidence_directory)?;
        for index in 0..=4_096 {
            fs::write(
                evidence_directory.join(format!("legacy-{index:04}.json")),
                b"{\"schema_version\":1,\"attempt_id\":\"legacy\"}\n",
            )?;
        }
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "retained attempt count exceeds 4096")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_preserves_bounded_legacy_evidence_without_requiring_v3_reports() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let evidence_directory = fixture.root.join("target/quality/evidence");
        fs::create_dir_all(&evidence_directory)?;
        fs::write(
            evidence_directory.join("legacy-historical-label.json"),
            "{\"schema_version\":1,\"attempt_id\":\"legacy-embedded-attempt\"}\n",
        )?;
        fixture.quality_profile("pr")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_tampered_retained_raw_report_evidence() -> TestResult {
    assert_invalid_retained_raw_report(
        |fixture, _, evidence| {
            let report = exact_raw_report_path(&fixture.root, evidence, "EG-00")?;
            let mut bytes = fs::read(&report)?;
            let original = b"\"schema_version\": 1";
            let offset = bytes
                .windows(original.len())
                .position(|window| window == original)
                .ok_or_else(|| {
                    std::io::Error::other("raw report omitted schema_version fixture")
                })?;
            let version = bytes
                .get_mut(offset + original.len() - 1)
                .ok_or_else(|| std::io::Error::other("raw report version byte is unavailable"))?;
            *version = b'2';
            fs::write(report, bytes)?;
            Ok(())
        },
        "retained raw report digest does not match its evidence binding",
    )
}

#[test]
fn quality_rejects_an_oversized_retained_raw_report_binding() -> TestResult {
    assert_invalid_retained_raw_report(
        |_, evidence_path, evidence| {
            rewrite_gate_field(evidence_path, evidence, "EG-00", "\"bytes\": ", "8388609")
        },
        "retained raw report exceeds 8388608 bytes",
    )
}

#[test]
fn quality_accepts_a_valid_retained_raw_report_one_byte_below_its_limit() -> TestResult {
    assert_valid_large_retained_raw_report(8_388_607)
}

#[test]
fn quality_accepts_a_valid_retained_raw_report_at_its_limit() -> TestResult {
    assert_valid_large_retained_raw_report(8_388_608)
}

#[test]
fn quality_rejects_a_retained_raw_report_one_byte_over_its_limit_before_parsing() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let evidence_path = fixture.latest_evidence_path()?;
        let evidence = fs::read_to_string(&evidence_path)?;
        resize_retained_raw_report(&fixture, &evidence_path, &evidence, 8_388_609, false)?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "retained raw report exceeds 8388608 bytes")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_valid_large_retained_raw_report(target_bytes: usize) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let evidence_path = fixture.latest_evidence_path()?;
        let evidence = fs::read_to_string(&evidence_path)?;
        resize_retained_raw_report(&fixture, &evidence_path, &evidence, target_bytes, true)?;
        fixture.quality_profile("pr")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn resize_retained_raw_report(
    fixture: &Fixture,
    evidence_path: &Path,
    evidence: &str,
    target_bytes: usize,
    update_bound_length: bool,
) -> TestResult {
    let report_path = exact_raw_report_path(&fixture.root, evidence, "EG-00")?;
    let mut report = fs::read_to_string(&report_path)?;
    let padding = target_bytes
        .checked_sub(report.len())
        .ok_or_else(|| std::io::Error::other("raw report fixture already exceeds target size"))?;
    report.push_str(&" ".repeat(padding));
    fs::write(&report_path, &report)?;
    let digest = format!("sha256:{:x}", Sha256::digest(report.as_bytes()));
    rewrite_gate_field(evidence_path, evidence, "EG-00", "\"sha256\": \"", &digest)?;
    if update_bound_length {
        rewrite_gate_field(
            evidence_path,
            evidence,
            "EG-00",
            "\"bytes\": ",
            &target_bytes.to_string(),
        )?;
    }
    Ok(())
}

#[test]
fn quality_rejects_a_raw_report_command_digest_mismatch() -> TestResult {
    assert_invalid_retained_raw_report(
        |_, evidence_path, evidence| {
            rewrite_gate_field(
                evidence_path,
                evidence,
                "EG-00",
                "\"command_digest\": \"",
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
        },
        "command digest does not match its canonical structured invocation",
    )
}

#[test]
fn quality_rejects_coordinated_invocation_and_stored_digest_tampering() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let evidence_path = fixture.latest_evidence_path()?;
        let mut evidence = fs::read_to_string(&evidence_path)?;
        let report_path = exact_raw_report_path(&fixture.root, &evidence, "EG-00")?;
        let mut report = fs::read_to_string(&report_path)?;
        let original_gate = gate_record(&evidence, "EG-00")?;
        let original_report_digest =
            extract_json_string_after(original_gate, "\"sha256\": \"")?.to_owned();
        let original_command_digest =
            extract_json_string_after(original_gate, "\"command_digest\": \"")?.to_owned();

        evidence = replace_once_in_string(
            evidence,
            "\"--profile\"",
            "\"--profIle\"",
            "evidence invocation argument",
        )?;
        report = replace_once_in_string(
            report,
            "\"--profile\"",
            "\"--profIle\"",
            "raw report invocation argument",
        )?;
        let tampered_gate = gate_record(&evidence, "EG-00")?;
        let (_, invocation_tail) = tampered_gate
            .split_once("\"invocation\": ")
            .ok_or_else(|| std::io::Error::other("tampered gate omitted invocation"))?;
        let (canonical_invocation, _) = invocation_tail
            .split_once(",\n      \"command_digest\"")
            .ok_or_else(|| {
            std::io::Error::other("tampered gate invocation has no command digest boundary")
        })?;
        let mut command_hasher = Sha256::new();
        command_hasher.update(b"positron-quality-command-v2\0");
        command_hasher.update(canonical_invocation.as_bytes());
        let forged_command_digest = format!("sha256:{:x}", command_hasher.finalize());
        evidence = replace_once_in_string(
            evidence,
            &format!("\"command_digest\": \"{original_command_digest}\""),
            &format!("\"command_digest\": \"{forged_command_digest}\""),
            "evidence command digest",
        )?;
        report = replace_once_in_string(
            report,
            &format!("\"invocation_digest\": \"{original_command_digest}\""),
            &format!("\"invocation_digest\": \"{forged_command_digest}\""),
            "raw report invocation digest",
        )?;
        let forged_report_digest = format!("sha256:{:x}", Sha256::digest(report.as_bytes()));
        evidence = replace_once_in_string(
            evidence,
            &format!("\"sha256\": \"{original_report_digest}\""),
            &format!("\"sha256\": \"{forged_report_digest}\""),
            "evidence raw report digest",
        )?;
        fs::write(&report_path, report)?;
        fs::write(&evidence_path, evidence)?;

        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "does not match its canonical registered gate")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_external_gate_with_all_controlled_steps_deleted() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let evidence_path = fixture.latest_evidence_path()?;
        let mut evidence = fs::read_to_string(&evidence_path)?;
        let report_path = exact_raw_report_path(&fixture.root, &evidence, "EG-RUST")?;
        let mut report = fs::read_to_string(&report_path)?;
        let original_gate = gate_record(&evidence, "EG-RUST")?;
        let original_report_digest =
            extract_json_string_after(original_gate, "\"sha256\": \"")?.to_owned();
        let original_command_digest =
            extract_json_string_after(original_gate, "\"command_digest\": \"")?.to_owned();

        evidence = empty_json_arrays_after(
            evidence,
            "\"gate_id\": \"EG-RUST\"",
            "\"controlled_steps\"",
            1,
        )?;
        report = empty_json_arrays_after(
            report,
            "\"gate_id\": \"EG-RUST\"",
            "\"controlled_steps\"",
            2,
        )?;
        let tampered_gate = gate_record(&evidence, "EG-RUST")?;
        let (_, invocation_tail) = tampered_gate
            .split_once("\"invocation\": ")
            .ok_or_else(|| std::io::Error::other("tampered gate omitted invocation"))?;
        let (canonical_invocation, _) = invocation_tail
            .split_once(",\n      \"command_digest\"")
            .ok_or_else(|| {
            std::io::Error::other("tampered gate invocation has no command digest boundary")
        })?;
        let mut command_hasher = Sha256::new();
        command_hasher.update(b"positron-quality-command-v2\0");
        command_hasher.update(canonical_invocation.as_bytes());
        let forged_command_digest = format!("sha256:{:x}", command_hasher.finalize());
        evidence = replace_once_in_string(
            evidence,
            &format!("\"command_digest\": \"{original_command_digest}\""),
            &format!("\"command_digest\": \"{forged_command_digest}\""),
            "evidence command digest",
        )?;
        report = replace_once_in_string(
            report,
            &format!("\"invocation_digest\": \"{original_command_digest}\""),
            &format!("\"invocation_digest\": \"{forged_command_digest}\""),
            "raw report invocation digest",
        )?;
        let forged_report_bytes = report.len();
        let forged_report_digest = format!("sha256:{:x}", Sha256::digest(report.as_bytes()));
        evidence = replace_once_in_string(
            evidence,
            &format!("\"sha256\": \"{original_report_digest}\""),
            &format!("\"sha256\": \"{forged_report_digest}\""),
            "evidence raw report digest",
        )?;
        let current_gate = gate_record(&evidence, "EG-RUST")?.to_owned();
        let original_report_bytes =
            extract_unsigned_after(&current_gate, "\"bytes\": ")?.to_string();
        evidence = replace_once_in_string(
            evidence,
            &format!("\"bytes\": {original_report_bytes}"),
            &format!("\"bytes\": {forged_report_bytes}"),
            "evidence raw report byte length",
        )?;
        fs::write(&report_path, report)?;
        fs::write(&evidence_path, evidence)?;

        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "does not contain its exact canonical controlled steps",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_accepts_a_failed_external_gate_with_a_nonempty_canonical_prefix() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        inject_rust_gate_failure_after_format(&fixture.root)?;
        let failed = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&failed, "injected canonical prefix failure")?;

        let retained = fixture.latest_evidence()?;
        let rust = gate_record(&retained, "EG-RUST")?;
        if !rust.contains("\"result\": \"failed\"")
            || !rust.contains("\"arguments\":[\"fmt\",\"--all\",\"--\",\"--check\"]")
            || rust.contains("\"arguments\":[\"clippy\"")
        {
            return Err(std::io::Error::other(
                "failed EG-RUST evidence did not retain exactly its executed canonical prefix",
            )
            .into());
        }

        let next = fixture.quality_output_for("pr")?;
        if !next.status.success() {
            return Err(std::io::Error::other(format!(
                "EG-EVIDENCE rejected a legitimate failed canonical prefix: {}\n{}",
                String::from_utf8_lossy(&next.stdout),
                String::from_utf8_lossy(&next.stderr)
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
fn quality_accepts_failed_internal_evidence_with_one_controlled_runner_step() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let evidence_directory = fixture.root.join("target/quality/evidence");
        fs::create_dir_all(&evidence_directory)?;
        let malformed = evidence_directory.join("1700000000000-111111111111-1.json");
        fs::write(&malformed, "{")?;

        let failed = fixture.quality_output_for("pr")?;
        assert_rejected_output(&failed, "retained engineering evidence is invalid")?;
        let retained = fixture.latest_evidence()?;
        let evidence_gate = gate_record(&retained, "EG-EVIDENCE")?;
        if !evidence_gate.contains("\"result\": \"failed\"")
            || !evidence_gate.contains("\"controlled_steps\":[]")
        {
            return Err(std::io::Error::other(
                "failed internal EG-EVIDENCE did not retain its canonical zero-step sequence",
            )
            .into());
        }
        let concurrency_gate = gate_record(&retained, "EG-CONCURRENCY")?;
        if !concurrency_gate.contains("\"result\": \"passed\"")
            || !concurrency_gate.contains("\"timeout_ms\":900000")
            || concurrency_gate
                .matches("\"program\":\"cargo-xtask-quality/bounded-runner\"")
                .count()
                != 1
        {
            return Err(std::io::Error::other(
                "process-backed EG-CONCURRENCY did not retain exactly one controlled child step",
            )
            .into());
        }
        let concurrency_report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &retained,
            "EG-CONCURRENCY",
        )?)?;
        for required in [
            "\"verdict\":\"exit-status:exit status: 0\"",
            "process-lifecycle-v1;phase=completed",
            "termination-requested=false",
            "process-reaped=true",
            "live=0",
            "shutdown-ms=100",
        ] {
            if !concurrency_report.contains(required) {
                return Err(std::io::Error::other(format!(
                    "process-backed EG-CONCURRENCY report omitted `{required}`"
                ))
                .into());
            }
        }

        fs::remove_file(malformed)?;
        let next = fixture.quality_output_for("pr")?;
        if !next.status.success() {
            return Err(std::io::Error::other(format!(
                "EG-EVIDENCE rejected a legitimate process-backed controlled step: {}\n{}",
                String::from_utf8_lossy(&next.stdout),
                String::from_utf8_lossy(&next.stderr)
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
fn quality_accepts_a_registered_internal_gate_with_zero_controlled_steps() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let initial = fixture.quality_output_for("pr")?;
        if !initial.status.success() {
            return Err(std::io::Error::other(format!(
                "registered internal gates did not produce initial PR evidence: {}\n{}",
                String::from_utf8_lossy(&initial.stdout),
                String::from_utf8_lossy(&initial.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let policy = gate_record(&evidence, "EG-POLICY")?;
        if !policy.contains("\"controlled_steps\":[]") {
            return Err(std::io::Error::other(
                "registered internal policy gate did not retain its canonical zero-step sequence",
            )
            .into());
        }
        for (gate_id, timeout_ms) in [
            ("EG-CONCURRENCY", 900_000_u128),
            ("EG-RESOURCE", 1_800_000_u128),
        ] {
            let gate = gate_record(&evidence, gate_id)?;
            if gate
                .matches("\"program\":\"cargo-xtask-quality/bounded-runner\"")
                .count()
                != 1
                || !gate.contains(&format!("\"timeout_ms\":{timeout_ms}"))
            {
                return Err(std::io::Error::other(format!(
                    "{gate_id} did not retain exactly one stage-timeout-bound child"
                ))
                .into());
            }
        }
        let next = fixture.quality_output_for("pr")?;
        if !next.status.success() {
            return Err(std::io::Error::other(format!(
                "EG-EVIDENCE rejected a legitimate internal zero-step gate: {}\n{}",
                String::from_utf8_lossy(&next.stdout),
                String::from_utf8_lossy(&next.stderr)
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
fn quality_rejects_malformed_retained_engineering_evidence_json() -> TestResult {
    assert_invalid_retained_engineering_evidence(
        |evidence_path, evidence| {
            fs::write(
                evidence_path,
                format!("{evidence}\ntrailing-malformed-json"),
            )?;
            Ok(())
        },
        "retained engineering evidence",
    )
}

#[test]
fn quality_capture_is_attempt_owned_and_charges_resources_before_copying() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = fs::read_to_string(root.join("tools/xtask/src/quality.rs"))?;
    if source.contains("static ACTIVE_GATE_CAPTURE")
        || !source.contains("struct GateCapture")
        || !source.contains("MAXIMUM_CONTROLLED_REPORT_STEPS")
        || !source.contains("stdout: &str")
        || !source.contains("stderr: &str")
    {
        return Err(std::io::Error::other(
            "gate capture is not explicitly attempt-owned and borrowed-resource bounded",
        )
        .into());
    }
    let charge = source
        .find("if stdout.len()")
        .ok_or_else(|| std::io::Error::other("gate capture does not charge borrowed streams"))?;
    let copy = source.find("stdout: stdout.to_owned()").ok_or_else(|| {
        std::io::Error::other("gate capture does not retain a bounded stream copy")
    })?;
    if charge >= copy {
        return Err(std::io::Error::other(
            "gate capture copies report streams before enforcing resource bounds",
        )
        .into());
    }
    Ok(())
}

#[test]
fn quality_report_serializer_bounds_encoded_bytes_before_copying() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = fs::read_to_string(root.join("tools/xtask/src/quality.rs"))?;
    for required in [
        "struct BoundedJsonWriter",
        "fn encoded_json_string_bytes",
        "try_reserve_exact",
        "encoded raw report exceeds",
    ] {
        if !source.contains(required) {
            return Err(std::io::Error::other(format!(
                "raw-report serialization omitted bounded encoded-size contract `{required}`"
            ))
            .into());
        }
    }
    Ok(())
}

#[test]
fn quality_rejects_duplicate_top_level_retained_engineering_evidence_keys() -> TestResult {
    assert_invalid_retained_engineering_evidence(
        |evidence_path, evidence| {
            let duplicate = "{\n  \"schema_version\": 3,\n";
            let Some(suffix) = evidence.strip_prefix("{\n") else {
                return Err(std::io::Error::other(
                    "fixture evidence did not begin with a JSON object",
                )
                .into());
            };
            fs::write(evidence_path, format!("{duplicate}{suffix}"))?;
            Ok(())
        },
        "retained engineering evidence",
    )
}

#[test]
fn quality_rejects_retained_evidence_missing_a_canonical_gate() -> TestResult {
    assert_invalid_retained_engineering_evidence(
        |evidence_path, _| {
            replace_once(
                evidence_path,
                "\"gate_id\": \"EG-SUPPLY\"",
                "\"gate_id\": \"EG-SUPPLX\"",
            )
        },
        "retained engineering evidence",
    )
}

#[test]
fn quality_rejects_a_duplicate_canonical_gate_in_retained_evidence() -> TestResult {
    assert_invalid_retained_engineering_evidence(
        |evidence_path, _| {
            replace_once(
                evidence_path,
                "\"gate_id\": \"EG-SUPPLY\"",
                "\"gate_id\": \"EG-00\"",
            )
        },
        "retained engineering evidence",
    )
}

#[test]
fn quality_rejects_an_extra_gate_in_retained_evidence() -> TestResult {
    assert_invalid_retained_engineering_evidence(
        |evidence_path, _| {
            replace_once(
                evidence_path,
                "\"gate_id\": \"EG-SUPPLY\"",
                "\"gate_id\": \"EG-EXTRA\"",
            )
        },
        "retained engineering evidence",
    )
}

#[test]
fn quality_rejects_a_retained_evidence_aggregate_result_overwrite() -> TestResult {
    assert_invalid_retained_engineering_evidence(
        |evidence_path, _| {
            replace_once(
                evidence_path,
                "  \"result\": \"passed\",",
                "  \"result\": \"failed\",",
            )
        },
        "retained engineering evidence",
    )
}

#[test]
fn quality_rejects_retained_evidence_without_its_schema_version() -> TestResult {
    assert_invalid_retained_engineering_evidence(
        |evidence_path, _| {
            replace_once(
                evidence_path,
                "\"schema_version\": 3",
                "\"removed_schema_version\": 3",
            )
        },
        "retained engineering evidence",
    )
}

#[test]
fn quality_retains_a_failed_evidence_reservation_when_a_raw_report_path_is_occupied() -> TestResult
{
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        let report = fixture
            .root
            .join("target/quality/evidence-reports/1700000000000-111111111111-1/EG-00.json");
        let parent = report.parent().ok_or_else(|| {
            std::io::Error::other("fixture raw report path has no parent directory")
        })?;
        fs::create_dir_all(parent)?;
        let occupied = b"{\"preexisting\":true}\n";
        fs::write(&report, occupied)?;

        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "engineering evidence raw report")?;
        if fs::read(&report)? != occupied {
            return Err(std::io::Error::other(
                "raw report reservation changed the pre-existing report bytes",
            )
            .into());
        }

        assert_schema_valid_recovery(&fixture.root, "1700000000000-111111111111-1")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_retains_failed_attempt_without_final_reports_when_first_staged_write_fails() -> TestResult
{
    assert_staged_report_write_failure("EG-00", false)
}

#[test]
fn quality_retains_failed_attempt_without_final_reports_when_middle_staged_write_fails()
-> TestResult {
    assert_staged_report_write_failure("EG-POLICY", false)
}

#[test]
fn quality_retains_failed_attempt_without_final_reports_when_last_staged_write_fails() -> TestResult
{
    assert_staged_report_write_failure("EG-SECRETS", false)
}

#[test]
fn quality_retains_failed_attempt_without_final_reports_when_staging_cleanup_fails() -> TestResult {
    assert_staged_report_write_failure("EG-POLICY", true)
}

#[cfg(unix)]
#[test]
fn quality_preserves_injected_non_owned_content_in_the_staging_bundle() -> TestResult {
    assert_injected_non_owned_report_content_survives("staging")
}

#[cfg(unix)]
#[test]
fn quality_preserves_injected_non_owned_content_in_the_final_bundle() -> TestResult {
    assert_injected_non_owned_report_content_survives("final")
}

#[test]
fn quality_retains_recovery_evidence_when_the_primary_evidence_write_fails() -> TestResult {
    assert_primary_evidence_publication_failure(inject_primary_evidence_write_failure)
}

#[test]
fn quality_retains_recovery_evidence_when_the_primary_evidence_flush_fails() -> TestResult {
    assert_primary_evidence_publication_failure(inject_primary_evidence_flush_failure)
}

#[test]
fn quality_retains_recovery_evidence_when_recovery_reconciliation_fails() -> TestResult {
    assert_primary_evidence_publication_failure(inject_recovery_cleanup_failure)
}

#[test]
fn quality_validates_a_retained_recovery_on_the_next_evidence_pass() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject_primary_evidence_write_failure(&fixture.root)?;
        let failed = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&failed, "injected primary evidence publication failure")?;
        assert_schema_valid_recovery(&fixture.root, "1700000000000-111111111111-1")?;

        let next = fixture.quality_output_for("pr")?;
        if !next.status.success() {
            return Err(std::io::Error::other(format!(
                "the next EG-EVIDENCE pass rejected a schema-valid recovery record: {}\n{}",
                String::from_utf8_lossy(&next.stdout),
                String::from_utf8_lossy(&next.stderr)
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
fn quality_does_not_touch_primary_evidence_when_recovery_is_preexisting() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject_primary_evidence_write_failure(&fixture.root)?;
        let first = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&first, "injected primary evidence publication failure")?;

        let attempt_id = "1700000000000-111111111111-1";
        let evidence_directory = fixture.root.join("target/quality/evidence");
        let primary = evidence_directory.join(format!("{attempt_id}.json"));
        let recovery = evidence_directory.join(format!("{attempt_id}-recovery.json"));
        let recovery_bytes = fs::read(&recovery)?;
        if primary.exists() {
            return Err(std::io::Error::other(
                "first failed publication left its incomplete primary evidence",
            )
            .into());
        }

        let second = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&second, "injected primary evidence publication failure")?;
        if primary.exists() {
            return Err(std::io::Error::other(
                "pre-existing recovery reservation allowed the primary path to be touched",
            )
            .into());
        }
        if fs::read(&recovery)? != recovery_bytes {
            return Err(std::io::Error::other(
                "repeated recovery reservation changed the pre-existing recovery bytes",
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
fn quality_preserves_recovery_when_primary_reservation_collides_afterward() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject_primary_reservation_collision(&fixture.root)?;
        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "engineering evidence attempt collision")?;

        let attempt_id = "1700000000000-111111111111-1";
        let primary = fixture
            .root
            .join("target/quality/evidence")
            .join(format!("{attempt_id}.json"));
        let occupied = b"{\"injected\":\"primary-reservation-collision\"}\n";
        if fs::read(&primary)? != occupied {
            return Err(std::io::Error::other(
                "primary reservation collision changed the occupied primary bytes",
            )
            .into());
        }
        assert_schema_valid_recovery(&fixture.root, attempt_id)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_does_not_acknowledge_primary_when_evidence_directory_parent_sync_fails() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject_evidence_directory_parent_sync_failure(&fixture.root)?;
        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "injected evidence directory durability failure")?;

        let evidence_directory = fixture.root.join("target/quality/evidence");
        if evidence_directory.exists() {
            return Err(std::io::Error::other(
                "evidence parent-sync failure left an acknowledged evidence directory",
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
fn quality_retains_recovery_when_a_staged_report_file_sync_fails() -> TestResult {
    assert_report_durability_failure(inject_staged_report_file_sync_failure)
}

#[test]
fn quality_retains_recovery_when_the_staging_directory_sync_fails() -> TestResult {
    assert_report_durability_failure(inject_staging_directory_sync_failure)
}

#[test]
fn quality_retains_recovery_when_the_final_report_parent_sync_fails() -> TestResult {
    assert_report_durability_failure(inject_final_report_parent_sync_failure)
}

#[test]
fn quality_retains_recovery_when_the_report_parent_chain_sync_fails() -> TestResult {
    assert_report_durability_failure(inject_report_parent_chain_sync_failure)
}

#[test]
fn quality_retains_recovery_when_the_staging_child_parent_sync_fails() -> TestResult {
    assert_report_durability_failure(inject_staging_child_parent_sync_failure)
}

fn assert_report_durability_failure(inject: impl FnOnce(&Path) -> TestResult) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject(&fixture.root)?;
        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "injected report durability failure")?;
        assert_recovered_failed_attempt(&fixture.root, "1700000000000-111111111111-1")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_primary_evidence_publication_failure(
    inject: impl FnOnce(&Path) -> TestResult,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject(&fixture.root)?;
        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "injected primary evidence publication failure")?;
        assert_recovered_failed_attempt(&fixture.root, "1700000000000-111111111111-1")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_recovered_failed_attempt(root: &Path, attempt_id: &str) -> TestResult {
    for directory in [
        root.join("target/quality/evidence-reports")
            .join(attempt_id),
        root.join("target/quality/evidence-report-staging")
            .join(attempt_id),
    ] {
        if directory.exists() {
            return Err(std::io::Error::other(format!(
                "failed evidence publication left a successful report bundle {}",
                directory.display()
            ))
            .into());
        }
    }
    assert_schema_valid_recovery(root, attempt_id)
}

fn assert_schema_valid_recovery(root: &Path, attempt_id: &str) -> TestResult {
    let evidence_directory = root.join("target/quality/evidence");
    let mut retained_failure = false;
    for entry in fs::read_dir(&evidence_directory)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let Ok(retained) = fs::read_to_string(&path) else {
            continue;
        };
        if retained.contains(&format!("\"value\": \"{attempt_id}\""))
            && retained.contains("\"result\": \"failed\"")
            && retained.contains("\"reason\": \"report-retention-failed\"")
        {
            assert_complete_evidence_contract(&retained)?;
            retained_failure = true;
        }
    }
    if !retained_failure {
        return Err(std::io::Error::other(
            "failed evidence publication omitted a schema-valid recovery record",
        )
        .into());
    }
    Ok(())
}

fn assert_staged_report_write_failure(gate_id: &str, inject_cleanup_failure: bool) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject_report_write_failure(&fixture.root, gate_id)?;
        if inject_cleanup_failure {
            inject_report_cleanup_failure(&fixture.root)?;
        }
        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "injected report staging failure")?;

        let attempt_id = "1700000000000-111111111111-1";
        assert_recovered_failed_attempt(&fixture.root, attempt_id)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
fn assert_injected_non_owned_report_content_survives(phase: &str) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        pin_fixture_attempt_identity(&fixture.root)?;
        inject_non_owned_report_content(&fixture.root, phase)?;
        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(&output, "injected non-owned publication content")?;

        let attempt_id = "1700000000000-111111111111-1";
        let bundle = match phase {
            "staging" => fixture
                .root
                .join("target/quality/evidence-report-staging")
                .join(attempt_id),
            "final" => fixture
                .root
                .join("target/quality/evidence-reports")
                .join(attempt_id),
            _ => {
                return Err(std::io::Error::other(format!(
                    "unknown injected publication phase `{phase}`"
                ))
                .into());
            },
        };
        if !bundle.is_dir() {
            return Err(std::io::Error::other(format!(
                "publication cleanup removed the injected {phase} bundle {}\nstdout:\n{}\nstderr:\n{}",
                bundle.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let injected_file = bundle.join("injected-file");
        if fs::read(&injected_file).map_err(|source| {
            std::io::Error::other(format!(
                "read injected file {}: {source}",
                injected_file.display()
            ))
        })? != b"non-owned bytes\n"
        {
            return Err(std::io::Error::other(
                "publication cleanup changed the injected file bytes",
            )
            .into());
        }
        if !bundle.join("injected-directory").is_dir() {
            return Err(std::io::Error::other(
                "publication cleanup removed the injected directory",
            )
            .into());
        }
        let injected_symlink = bundle.join("injected-symlink");
        if !fs::symlink_metadata(&injected_symlink)
            .map_err(|source| {
                std::io::Error::other(format!(
                    "inspect injected symlink {}: {source}",
                    injected_symlink.display()
                ))
            })?
            .file_type()
            .is_symlink()
        {
            return Err(
                std::io::Error::other("publication cleanup removed the injected symlink").into(),
            );
        }
        let mut entries = fs::read_dir(&bundle)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();
        let mut expected = vec![
            std::ffi::OsString::from("injected-directory"),
            std::ffi::OsString::from("injected-file"),
            std::ffi::OsString::from("injected-symlink"),
        ];
        expected.sort();
        if entries != expected {
            return Err(std::io::Error::other(format!(
                "publication cleanup retained unexpected owned entries: {entries:?}"
            ))
            .into());
        }
        let primary = fixture
            .root
            .join("target/quality/evidence")
            .join(format!("{attempt_id}.json"));
        if primary.exists() {
            return Err(
                std::io::Error::other("failed publication acknowledged primary evidence").into(),
            );
        }
        assert_schema_valid_recovery(&fixture.root, attempt_id)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_incomplete_evidence_identity_schema() -> TestResult {
    assert_fixture_rejected_profile(
        "pr",
        |root| {
            replace_all(
                &root.join("qualification/engineering/evidence.schema.json"),
                "\"command_digest\"",
                "\"removed_command_digest\"",
            )
        },
        "evidence schema is missing `\"command_digest\"`",
    )
}

#[test]
fn quality_rejects_evidence_schema_constraint_drift() -> TestResult {
    assert_fixture_rejected_profile(
        "pr",
        |root| {
            replace_once(
                &root.join("qualification/engineering/evidence.schema.json"),
                "\"maxLength\": 4096",
                "\"maxLength\": 4097",
            )
        },
        "evidence schema differs from the canonical v3 constraint owner",
    )
}

#[test]
fn quality_rejects_schema_v3_uppercase_source_identity() -> TestResult {
    assert_invalid_retained_engineering_evidence(
        |evidence_path, _| {
            replace_once(
                evidence_path,
                "\"revision\": \"0000000000000000000000000000000000000000\"",
                "\"revision\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
            )
        },
        "source revision is not a complete hexadecimal identity",
    )
}

#[test]
fn quality_rejects_schema_v3_overlong_exact_identity_value() -> TestResult {
    assert_invalid_retained_engineering_evidence(
        |evidence_path, _| {
            replace_once(
                evidence_path,
                "\"target\": {\"applicability\": \"exact\", \"value\": \"engineering-workspace\", \"reason\": \"-\"}",
                &format!(
                    "\"target\": {{\"applicability\": \"exact\", \"value\": \"{}\", \"reason\": \"-\"}}",
                    "a".repeat(4_097)
                ),
            )
        },
        "identity binding is invalid",
    )
}

#[test]
fn quality_qual_profile_rejects_the_scaffold_before_claiming_qualification() -> TestResult {
    assert_fixture_rejected_profile(
        "qual",
        |_| Ok(()),
        "the scaffold has no candidate artifact and the target registry forbids qualification claims",
    )
}

#[test]
fn quality_rejects_a_snapshot_digest_that_is_not_an_object_identity() -> TestResult {
    assert_fixture_rejected(
        make_snapshot_digest_invalid,
        "snapshot digest tool returned an invalid object identity",
    )
}

#[test]
fn quality_pre_commit_evidence_keeps_every_deferred_gate_explicit() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let evidence = fixture.latest_evidence()?;
        for expected in [
            "\"profile\": \"pre-commit\"",
            "\"gate_id\": \"EG-COVERAGE\"",
            "\"result\": \"not-selected\"",
            "\"applicability\": \"not-applicable\"",
            "\"reason\": \"gate-not-selected\"",
            "Not in the bounded local-feedback profile; the complete PR profile in trusted CI remains authoritative.",
        ] {
            if !evidence.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "pre-commit evidence omitted its deferred-gate verdict `{expected}`"
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
fn quality_accepts_a_scaffold_only_workspace_with_pending_thresholds() -> TestResult {
    assert_fixture_accepted(configure_scaffold_only_policy)
}

#[test]
fn quality_pr_skips_the_scheduled_coverage_campaign() -> TestResult {
    let fixture = Fixture::create()?;
    fs::write(
        fixture
            .root
            .join("target/quality-tools/reject-coverage-execution"),
        "",
    )?;
    let result = fixture.quality_profile("pr");
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_global_local_incremental_disable() -> TestResult {
    assert_fixture_rejected(
        disable_incremental_compilation_globally,
        "local development configuration must not globally disable incremental compilation",
    )
}

#[test]
fn quality_rejects_a_pr_workflow_without_the_pinned_tool_cache() -> TestResult {
    assert_fixture_rejected(
        remove_pr_tool_cache,
        "required workflow safeguard `actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9` is missing",
    )
}

#[test]
fn quality_rejects_a_pr_workflow_without_cached_tool_verification() -> TestResult {
    assert_fixture_rejected(
        remove_cached_pr_tool_verification,
        "required workflow safeguard `\"$tool_root/cargo-audit\" --version` is missing",
    )
}

#[test]
fn quality_ext_executes_the_foundational_coverage_harness() -> TestResult {
    let fixture = Fixture::create()?;
    let result = fixture.quality_profile("ext");
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn extended_workflow_routes_opt_in_mutation_through_the_authoritative_runner() -> TestResult {
    let workflow = fs::read_to_string(repository_root()?.join(".github/workflows/extended.yml"))?;

    assert!(
        !workflow
            .lines()
            .any(|line| line.trim_start().starts_with("cargo mutants")),
        "CI must not invoke the mutation detector outside cargo xtask quality"
    );
    assert!(
        workflow.contains("cargo xtask quality --profile ext --retain-m0-02-mutation"),
        "the explicit mutation selection must enter through the authoritative runner"
    );

    Ok(())
}

#[test]
fn quality_ext_runs_the_focused_mutation_campaign_only_when_explicitly_selected() -> TestResult {
    let fixture = Fixture::create_m0_02_domain_types()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/require-m0-02-mutation"),
            "",
        )?;
        let output = fixture.quality_output_for_arguments([
            "quality",
            "--profile",
            "ext",
            "--retain-m0-02-mutation",
        ])?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "the explicit retained mutation campaign failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
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
fn quality_ext_executes_the_controlled_owner_verdict_suite_with_the_fixture_suite() -> TestResult {
    let fixture = Fixture::create()?;
    fs::write(
        fixture
            .root
            .join("target/quality-tools/require-owner-verdict-coverage"),
        "",
    )?;
    let result = fixture.quality_profile("ext");
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_coverage_campaign_without_both_owner_verdict_targets() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        remove_one_m0_01b_owner_coverage_target(&fixture.root)?;
        let output = fixture.quality_output_from_fixture_source("pre-commit")?;
        assert_rejected_output(
            &output,
            "M0-01B coverage target selection must run the controlled owner verdict suite in both total and changed-code campaigns",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_frozen_m0_01_coverage_baseline_change() -> TestResult {
    assert_fixture_rejected(
        lower_the_frozen_m0_01_line_baseline,
        "frozen baseline `coverage-line` drifted from its retained M0-01 value",
    )
}

#[test]
fn quality_ext_rejects_coverage_below_the_frozen_baseline() -> TestResult {
    assert_fixture_rejected_profile(
        "ext",
        reduce_line_coverage_measurement,
        "coverage line 70.00 is below frozen M0 baseline 70.52",
    )
}

#[test]
fn quality_ext_rejects_an_unpinned_coverage_detector() -> TestResult {
    assert_fixture_rejected_profile(
        "ext",
        make_coverage_detector_report_a_different_version,
        "coverage detector `cargo-llvm-cov`: expected version `0.8.7`",
    )
}

#[test]
fn quality_rejects_a_different_square_canary_in_generated_search_index() -> TestResult {
    assert_fixture_rejected_profile(
        "pr",
        add_square_shaped_search_index_canary,
        "fixture detected Square-shaped secret canary",
    )
}

#[test]
fn quality_rejects_a_non_square_generated_search_index_canary() -> TestResult {
    assert_fixture_rejected_profile(
        "pr",
        add_non_square_search_index_canary,
        "fixture detected generated search-index non-Square secret canary",
    )
}

#[test]
fn quality_rejects_an_activation_without_a_measured_baseline() -> TestResult {
    assert_fixture_rejected(
        remove_coverage_baseline,
        "baseline `coverage-line` is not measured",
    )
}

#[test]
fn quality_rejects_a_nonfinite_measured_baseline() -> TestResult {
    assert_fixture_rejected(
        make_coverage_baseline_nonfinite,
        "measured baselines must use a non-negative numeric value",
    )
}

#[test]
fn quality_rejects_an_unrecognized_m0_threshold_state() -> TestResult {
    assert_fixture_rejected(
        |root| set_threshold_field(root, "coverage-line", "state", "unmeasured"),
        "baseline `coverage-line` is not measured",
    )
}

#[test]
fn quality_rejects_each_nonempty_activation_ledger_field_on_a_scaffold_scope() -> TestResult {
    assert_scope_fields_rejected(
        "positron-query",
        &[
            ("activation_id", "M0-01"),
            ("activation_scope_set", "positron-domain"),
            ("allowed_edges", "positron-query->positron-domain"),
            ("risk_gates", "EG-COVERAGE"),
            (
                "test_commands",
                "cargo test --locked --package xtask --test foundational_scope_activation",
            ),
            ("coverage_baseline", "coverage-line"),
            ("mutation_baseline", "mutation-score"),
            ("dependency_review", "none"),
            ("contract_evidence", POLICY_CHANGE),
        ],
        "scaffold application scopes cannot advertise activation, edges, gates, tests, baselines, reviews, or evidence",
    )
}

#[test]
fn quality_rejects_each_missing_activation_ledger_field_on_an_active_scope() -> TestResult {
    assert_scope_fields_rejected(
        "positron-domain",
        &[
            ("activation_id", "-"),
            ("activation_scope_set", "-"),
            ("allowed_edges", "-"),
            ("risk_gates", "-"),
            ("test_commands", "-"),
            ("coverage_baseline", "-"),
            ("mutation_baseline", "-"),
            ("dependency_review", "-"),
            ("contract_evidence", "-"),
        ],
        "active application scopes require an atomic activation ledger",
    )
}

#[test]
fn quality_rejects_each_application_activation_field_on_a_tooling_scope() -> TestResult {
    assert_scope_fields_rejected(
        "xtask",
        &[
            ("activation_id", "M0-01"),
            ("activation_scope_set", "positron-domain"),
            ("allowed_edges", "xtask->positron-domain"),
            ("coverage_baseline", "coverage-line"),
            ("mutation_baseline", "mutation-score"),
            ("dependency_review", "none"),
            ("contract_evidence", POLICY_CHANGE),
        ],
        "tooling scopes cannot claim application activation ledger fields",
    )
}

#[test]
fn quality_rejects_a_scope_set_that_is_neither_dash_nor_a_nonempty_set() -> TestResult {
    assert_fixture_rejected(
        |root| set_scope_field(root, "positron-query", "activation_scope_set", "|"),
        "field `activation_scope_set` must be `-` or a non-empty pipe-delimited set",
    )
}

#[test]
fn quality_rejects_malformed_activation_edges() -> TestResult {
    for malformed in [
        "->positron-domain",
        "positron-query->",
        "positron-query->positron-query",
    ] {
        assert_fixture_rejected(
            |root| set_scope_field(root, "positron-query", "allowed_edges", malformed),
            "field `allowed_edges` has an invalid edge",
        )?;
    }
    Ok(())
}

#[test]
fn quality_rejects_invalid_measured_baseline_values() -> TestResult {
    for invalid in ["not-a-number", "-1"] {
        assert_fixture_rejected(
            |root| set_threshold_field(root, "coverage-line", "value", invalid),
            "measured baselines must use a non-negative numeric value",
        )?;
    }
    Ok(())
}

#[test]
fn quality_accepts_zero_as_a_valid_measured_baseline() -> TestResult {
    assert_fixture_accepted(|root| {
        configure_scaffold_only_policy(root)?;
        set_threshold_field(root, "coverage-line", "state", "measured-baseline")?;
        set_threshold_field(root, "coverage-line", "value", "0")?;
        set_threshold_field(root, "coverage-line", "scope", "m0-01-foundational-policy")?;
        set_threshold_field(root, "coverage-line", "evidence", POLICY_CHANGE)
    })
}

#[test]
fn quality_rejects_an_incomplete_m0_02_domain_types_ledger() -> TestResult {
    assert_scope_fields_rejected(
        "positron-domain",
        &[("activation_id", "M0-02")],
        "M0-02 Domain Types must declare only the exact `positron-domain` scope set",
    )
}

#[test]
fn quality_rejects_an_incomplete_foundational_scope_set() -> TestResult {
    assert_fixture_rejected(
        |root| {
            set_scope_field(
                root,
                "positron-domain",
                "activation_scope_set",
                "positron-api|positron-domain",
            )
        },
        "scope `positron-domain` does not declare the complete M0-01 set",
    )
}

#[test]
fn quality_rejects_a_missing_mutation_baseline_reference() -> TestResult {
    assert_fixture_rejected(
        |root| {
            set_scope_field(
                root,
                "positron-domain",
                "mutation_baseline",
                "different-score",
            )
        },
        "scope `positron-domain` is missing the complete M0 baseline set",
    )
}

#[test]
fn quality_rejects_an_unreviewed_activation_dependency() -> TestResult {
    assert_fixture_rejected(
        |root| {
            set_scope_field(
                root,
                "positron-domain",
                "dependency_review",
                "unreviewed-dependency",
            )
        },
        "scope `positron-domain` names unreviewed dependency `unreviewed-dependency`",
    )
}

#[test]
fn quality_retains_full_dependency_metadata_above_the_stream_capture_ceiling() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fs::write(
            fixture
                .root
                .join("target/quality-tools/emit-large-dependency-metadata"),
            b"enabled\n",
        )?;
        fixture.quality_profile("pr")?;
        let evidence = fixture.latest_evidence()?;
        let report =
            fs::read_to_string(exact_raw_report_path(&fixture.root, &evidence, "EG-DEPS")?)?;
        for expected in [
            "metadata-artifact=target/quality/dependency-metadata/",
            "identity=",
            "packages+workspace+resolve=validated",
            "digest=sha256:",
        ] {
            if !report.contains(expected) {
                return Err(std::io::Error::other(format!(
                    "dependency raw report omitted `{expected}`"
                ))
                .into());
            }
        }
        let metadata_directory = fixture.root.join("target/quality/dependency-metadata");
        let artifacts = fs::read_dir(&metadata_directory)?.collect::<Result<Vec<_>, _>>()?;
        let [attempt] = artifacts.as_slice() else {
            return Err(std::io::Error::other(
                "dependency metadata did not retain exactly one attempt-owned artifact",
            )
            .into());
        };
        let artifact = attempt.path().join("metadata.json");
        if fs::metadata(&artifact)?.len() <= 131_072 {
            return Err(std::io::Error::other(
                "dependency metadata regression did not exceed the stream capture ceiling",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_rejects_a_replaced_dependency_metadata_artifact_without_reading_the_forgery()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        inject_dependency_metadata_artifact_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        let tools = fixture.root.join("target/quality-tools");
        wait_for_path(
            &tools.join("dependency-metadata-artifact-ready"),
            Duration::from_secs(30),
        )?;
        let artifact = PathBuf::from(
            fs::read_to_string(tools.join("dependency-metadata-artifact-path"))?
                .trim()
                .to_owned(),
        );
        let owned = artifact.with_extension("owned");
        fs::rename(&artifact, &owned)?;
        let forged = b"{\"packages\":[],\"workspace_members\":[],\"workspace_root\":\"/forged\",\"target_directory\":\"/forged/target\",\"resolve\":{}}\n";
        fs::write(&artifact, forged)?;
        fs::write(
            tools.join("dependency-metadata-artifact-release"),
            b"release\n",
        )?;

        let output = child.wait_with_output()?;
        assert_rejected_output(
            &output,
            "dependency metadata artifact canonical name was replaced",
        )?;
        if fs::read(&artifact)? != forged {
            return Err(std::io::Error::other(
                "dependency metadata rejection changed the forged replacement",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_rejects_a_replaced_dependency_metadata_directory_without_touching_its_canary()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        inject_dependency_metadata_artifact_barrier(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let child = fixture.quality_child_from_built_fixture_for("pr")?;
        let tools = fixture.root.join("target/quality-tools");
        wait_for_path(
            &tools.join("dependency-metadata-artifact-ready"),
            Duration::from_secs(30),
        )?;
        let artifact = PathBuf::from(
            fs::read_to_string(tools.join("dependency-metadata-artifact-path"))?
                .trim()
                .to_owned(),
        );
        let directory = artifact
            .parent()
            .ok_or_else(|| std::io::Error::other("metadata artifact had no parent"))?;
        let owned = directory.with_extension("owned");
        fs::rename(directory, &owned)?;
        fs::create_dir(directory)?;
        let canary = directory.join("canary");
        fs::write(&canary, b"untouched\n")?;
        fs::write(
            directory.join(
                artifact
                    .file_name()
                    .ok_or_else(|| std::io::Error::other("metadata artifact had no file name"))?,
            ),
            b"{\"packages\":[],\"workspace_members\":[],\"workspace_root\":\"/forged\",\"target_directory\":\"/forged/target\",\"resolve\":{}}\n",
        )?;
        fs::write(
            tools.join("dependency-metadata-artifact-release"),
            b"release\n",
        )?;

        let output = child.wait_with_output()?;
        assert_rejected_output(
            &output,
            "dependency metadata directory canonical name was replaced",
        )?;
        if fs::read(&canary)? != b"untouched\n" {
            return Err(std::io::Error::other(
                "dependency metadata directory rejection changed its canary",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_rejects_a_parent_sync_failure_after_creating_dependency_metadata_directory() -> TestResult
{
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-DEPS|EG-EVIDENCE|EG-POLICY",
        )?;
        inject_dependency_metadata_parent_sync_failure(&fixture.root)?;
        fixture.build_fixture_xtask()?;
        let output = fixture
            .quality_child_from_built_fixture_for("pr")?
            .wait_with_output()?;
        assert_rejected_output(
            &output,
            "injected dependency metadata parent synchronization failure",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_activation_without_its_registered_owner() -> TestResult {
    assert_fixture_rejected(missing_domain_owner, "unknown semantic owner `-`")
}

#[test]
fn quality_rejects_an_absolute_scope_path() -> TestResult {
    assert_fixture_rejected(
        make_foundational_scope_path_absolute,
        "scope path must be repository-relative",
    )
}

#[test]
fn quality_rejects_a_forbidden_foundational_dependency_edge() -> TestResult {
    assert_fixture_rejected(
        add_forbidden_foundational_edge,
        "foundation edge `positron-domain->positron-api` is forbidden",
    )
}

#[test]
fn quality_rejects_a_missing_registered_foundational_edge() -> TestResult {
    assert_fixture_rejected(
        remove_registered_foundational_edge,
        "foundation edges for `positron-domain` do not match its activation ledger",
    )
}

#[test]
fn quality_rejects_a_cycle_in_the_registered_architecture_edges() -> TestResult {
    assert_fixture_rejected(
        add_architecture_cycle,
        "architecture edge registry: cycle reaches `positron`",
    )
}

#[test]
fn quality_rejects_a_deliberately_unregistered_source_file() -> TestResult {
    assert_fixture_rejected(
        add_unregistered_source_file,
        "code or executable source is outside every registered crate or artifact scope",
    )
}

#[test]
fn quality_rejects_behavior_in_a_remaining_scaffold_crate() -> TestResult {
    assert_fixture_rejected(
        add_behavior_to_scaffold_crate,
        "adds behavior to scaffold-only scope `positron-query`",
    )
}

#[test]
fn quality_rejects_a_pass_through_module_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_pass_through_reexport,
        "pass-through module surface is forbidden",
    )
}

#[test]
fn quality_rejects_a_deferred_runtime_symbol_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_deferred_metrics_symbol,
        "deferred runtime symbol `MetricsStore` is forbidden",
    )
}

#[test]
fn quality_rejects_a_hidden_feature_flag_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_hidden_feature_flag,
        "scope `positron-domain` declares `[features]` despite its `none` dependency review",
    )
}

#[test]
fn quality_rejects_a_placeholder_api_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_placeholder_api,
        "activation-only scope `positron-domain` contains behavior or a placeholder API",
    )
}

#[test]
fn quality_rejects_a_disabled_deferred_module_in_an_activated_scope() -> TestResult {
    assert_fixture_rejected(
        add_disabled_deferred_module,
        "activation-only scope `positron-domain` contains behavior or a placeholder API",
    )
}

#[test]
fn quality_rejects_an_extra_doc_only_source_in_an_activation_only_scope() -> TestResult {
    assert_fixture_rejected(
        add_extra_doc_only_activation_source,
        "activation-only scope `positron-domain` must retain exactly its crate root source",
    )
}

#[test]
fn quality_does_not_misclassify_a_symbol_with_a_deferred_prefix() -> TestResult {
    assert_fixture_rejected(
        add_non_deferred_symbol_with_a_deferred_prefix,
        "activation-only scope `positron-domain` contains behavior or a placeholder API",
    )
}

#[test]
fn quality_rejects_an_activated_coverage_gate_without_ci_tool_provisioning() -> TestResult {
    assert_fixture_rejected(
        remove_coverage_tool_provisioning,
        "coverage-selected workflow `.github/workflows/extended.yml` is missing",
    )
}

#[test]
fn quality_rejects_a_coverage_workflow_that_does_not_retain_raw_reports() -> TestResult {
    assert_fixture_rejected(
        remove_raw_coverage_report_retention,
        "coverage-selected workflow `.github/workflows/extended.yml` must retain `target/quality/`",
    )
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn create() -> TestResult<Self> {
        Self::create_with_identity(false)
    }

    fn create_with_real_git() -> TestResult<Self> {
        Self::create_with_identity(true)
    }

    fn create_m0_02_domain_types() -> TestResult<Self> {
        Self::create_with_policy(false, configure_m0_02_domain_types_ledger)
    }

    fn create_current_registry() -> TestResult<Self> {
        Self::create_with_policy(false, |_| Ok(()))
    }

    fn create_with_identity(real_git: bool) -> TestResult<Self> {
        Self::create_with_policy(real_git, configure_activation_ledger)
    }

    fn create_with_policy(real_git: bool, configure: fn(&Path) -> TestResult) -> TestResult<Self> {
        let root = temporary_root()?;
        let source = repository_root()?;
        copy_tree(&source, &root)?;
        configure(&root)?;
        install_fixture_tools(&root, real_git)?;
        if real_git {
            initialize_git_repository(&root)?;
        }
        Ok(Self { root })
    }

    fn quality(&self) -> TestResult {
        let output = self.quality_output()?;
        if output.status.success() {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(std::io::Error::other(format!(
            "the public quality runner rejected the complete activation fixture: {stdout}\n{stderr}"
        ))
        .into())
    }

    fn quality_profile(&self, profile: &str) -> TestResult {
        let output = self.quality_output_for(profile)?;
        if output.status.success() {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(std::io::Error::other(format!(
            "the public quality runner rejected the complete activation fixture: {stdout}\n{stderr}"
        ))
        .into())
    }

    fn quality_output(&self) -> TestResult<std::process::Output> {
        self.quality_output_for("pre-commit")
    }

    fn quality_output_for(&self, profile: &str) -> TestResult<std::process::Output> {
        self.quality_output_for_arguments(["quality", "--profile", profile])
    }

    fn quality_output_for_arguments<const N: usize>(
        &self,
        arguments: [&str; N],
    ) -> TestResult<std::process::Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_xtask"))
            .current_dir(&self.root)
            .args(arguments)
            .output()?)
    }

    fn quality_output_from_fixture_source(
        &self,
        profile: &str,
    ) -> TestResult<std::process::Output> {
        self.build_fixture_xtask()?;
        self.quality_output_from_built_fixture(profile)
    }

    fn quality_output_from_built_fixture(&self, profile: &str) -> TestResult<std::process::Output> {
        let output = Command::new(self.root.join("target/debug/xtask"))
            .current_dir(&self.root)
            .args(["quality", "--profile", profile])
            .output()?;
        Ok(output)
    }

    fn quality_output_for_with_environment<const N: usize>(
        &self,
        profile: &str,
        environment: [(&str, &str); N],
    ) -> TestResult<std::process::Output> {
        let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .current_dir(&self.root)
            .args(["quality", "--profile", profile])
            .envs(environment)
            .output()?;
        Ok(output)
    }

    fn latest_environment_digest(&self) -> TestResult<String> {
        let content = self.latest_evidence()?;
        let marker = "\"environment_digest\": \"";
        let (_, value) = content.split_once(marker).ok_or_else(|| {
            std::io::Error::other("engineering evidence omitted environment_digest")
        })?;
        let (digest, _) = value.split_once('"').ok_or_else(|| {
            std::io::Error::other("engineering evidence has a malformed environment_digest")
        })?;
        Ok(digest.to_owned())
    }

    fn latest_evidence(&self) -> TestResult<String> {
        Ok(fs::read_to_string(self.latest_evidence_path()?)?)
    }

    fn latest_evidence_path(&self) -> TestResult<PathBuf> {
        let evidence_directory = self.root.join("target/quality/evidence");
        let mut evidence = fs::read_dir(&evidence_directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        evidence.sort();
        let path = evidence.last().ok_or_else(|| {
            std::io::Error::other("quality did not retain an engineering evidence artifact")
        })?;
        Ok(path.clone())
    }

    #[cfg(unix)]
    fn quality_child(&self) -> TestResult<Child> {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .current_dir(&self.root)
            .args(["quality", "--profile", "pre-commit"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(Into::into)
    }

    fn build_fixture_xtask(&self) -> TestResult {
        let output = Command::new(env!("CARGO"))
            .current_dir(&self.root)
            .args(["build", "--locked", "--quiet", "--package", "xtask"])
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "fixture xtask build failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }

    #[cfg(unix)]
    fn quality_child_from_built_fixture(&self) -> TestResult<Child> {
        self.quality_child_from_built_fixture_for("pre-commit")
    }

    #[cfg(unix)]
    fn quality_child_from_built_fixture_for(&self, profile: &str) -> TestResult<Child> {
        Command::new(self.root.join("target/debug/xtask"))
            .current_dir(&self.root)
            .args(["quality", "--profile", profile])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(Into::into)
    }

    fn remove(self) -> TestResult {
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }
}

#[cfg(unix)]
struct ControlledDescriptorProtocol {
    ready: PathBuf,
    release: PathBuf,
    pid: PathBuf,
}

#[cfg(unix)]
impl ControlledDescriptorProtocol {
    fn create(root: &Path) -> TestResult<Self> {
        let directory = root.join("target/controlled-descriptor-protocol");
        fs::create_dir_all(&directory)?;
        let release = directory.join("release");
        let status = Command::new("mkfifo").arg(&release).status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "create controlled descriptor release FIFO failed with {status}"
            ))
            .into());
        }
        Ok(Self {
            ready: directory.join("ready"),
            release,
            pid: directory.join("descendant.pid"),
        })
    }

    fn wait_until_ready(&self, timeout: Duration) -> TestResult {
        let deadline = Instant::now() + timeout;
        while !self.ready.is_file() {
            if Instant::now() >= deadline {
                return Err(std::io::Error::other(
                    "controlled descendant did not complete its readiness handshake",
                )
                .into());
            }
            thread::yield_now();
        }
        Ok(())
    }

    fn descendant_is_running(&self) -> TestResult<bool> {
        let pid = fs::read_to_string(&self.pid)?.trim().to_owned();
        if pid.is_empty() {
            return Err(std::io::Error::other(
                "controlled descendant did not publish a process identity",
            )
            .into());
        }
        let status = Command::new("kill")
            .args(["-0", &pid])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(status.success())
    }

    fn cleanup(&self, quality: &mut Child) -> TestResult {
        if quality.try_wait()?.is_none() {
            quality.kill()?;
            let status = quality.wait()?;
            if status.success() {
                return Err(std::io::Error::other(
                    "controlled quality runner exited successfully after forced termination",
                )
                .into());
            }
        }
        self.terminate_descendant()
    }

    fn terminate_descendant(&self) -> TestResult {
        if !self.pid.is_file() || !self.descendant_is_running()? {
            return Ok(());
        }
        self.signal_descendant("-TERM")?;
        if self.wait_until_descendant_stops(Duration::from_secs(2))? {
            return Ok(());
        }
        self.signal_descendant("-KILL")?;
        if self.wait_until_descendant_stops(Duration::from_secs(2))? {
            return Ok(());
        }
        Err(std::io::Error::other(
            "controlled descendant remained alive after deterministic cleanup",
        )
        .into())
    }

    fn signal_descendant(&self, signal: &str) -> TestResult {
        let pid = fs::read_to_string(&self.pid)?.trim().to_owned();
        let status = Command::new("kill").args([signal, &pid]).status()?;
        if status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "signal {signal} to controlled descendant failed with {status}"
        ))
        .into())
    }

    fn wait_until_descendant_stops(&self, timeout: Duration) -> TestResult<bool> {
        let deadline = Instant::now() + timeout;
        while self.descendant_is_running()? {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            thread::yield_now();
        }
        Ok(true)
    }
}

#[cfg(unix)]
fn install_open_descriptor_git_fixture(
    root: &Path,
    protocol: &ControlledDescriptorProtocol,
) -> TestResult {
    let path = root.join("target/quality-tools/bin/git");
    let ready = shell_quote(&protocol.ready)?;
    let release = shell_quote(&protocol.release)?;
    let pid = shell_quote(&protocol.pid)?;
    let script = format!(
        r#"#!/bin/sh
set -eu
case "${{1:-}}" in
  rev-parse)
    (
      : > {ready}
      read -r _ < {release}
    ) &
    descendant="$!"
    printf '%s\n' "$descendant" > {pid}
    while [ ! -f {ready} ]; do
      :
    done
    printf '%s\n' '0000000000000000000000000000000000000000'
    ;;
  status)
    ;;
  hash-object)
    cat >/dev/null
    printf '%s\n' '1111111111111111111111111111111111111111'
    ;;
  *)
    printf 'unsupported fixture git command: %s\n' "${{1:-}}" >&2
    exit 2
    ;;
esac
"#,
    );
    write_tool(&path, &script)
}

#[cfg(unix)]
fn install_ambient_path_canary_git_fixture(root: &Path, canary: &Path) -> TestResult {
    let path = root.join("target/quality-tools/bin/git");
    if !canary.ends_with("ambient-path-canary") {
        return Err(std::io::Error::other(
            "ambient PATH fixture canary must retain its stable path marker",
        )
        .into());
    }
    let script = r#"#!/bin/sh
set -eu
case ":$PATH:" in
  *ambient-path-canary*)
    printf '%s\n' 'ambient PATH canary reached a controlled child' >&2
    exit 70
    ;;
esac
case "${1:-}" in
  merge-base)
    printf '%s\n' '542f3835dc67f819e566e017c04e165b15416861'
    ;;
  diff)
    printf '%s\n' 'qualification/engineering/README.md'
    printf '%s\n' 'qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json'
    printf '%s\n' 'qualification/engineering/scopes.tsv'
    printf '%s\n' 'qualification/engineering/security-canary-targets.tsv'
    printf '%s\n' 'qualification/engineering/security-crypto-targets.tsv'
    printf '%s\n' 'qualification/engineering/security-runners.tsv'
    printf '%s\n' 'qualification/engineering/security-threat-surfaces.tsv'
    printf '%s\n' 'qualification/engineering/security/TM-0010-m0-10-runner-crypto.json'
    printf '%s\n' 'qualification/engineering/security/TM-0011-m0-10-runner-artifacts.json'
    printf '%s\n' 'qualification/fixtures/adversarial/cryptography/m0-10-secret-canary-leak.tsv'
    printf '%s\n' 'qualification/fixtures/adversarial/cryptography/m0-10-security-canary-golden.tsv'
    printf '%s\n' 'tools/xtask/src/bounded_input.rs'
    printf '%s\n' 'tools/xtask/src/crypto_targets.rs'
    printf '%s\n' 'tools/xtask/src/main.rs'
    printf '%s\n' 'tools/xtask/src/quality.rs'
    printf '%s\n' 'tools/xtask/src/security_catalog.rs'
    printf '%s\n' 'tools/xtask/src/security_change_review.rs'
    printf '%s\n' 'tools/xtask/src/security_harness.rs'
    printf '%s\n' 'tools/xtask/src/security_harness/canary.rs'
    printf '%s\n' 'tools/xtask/src/security_harness/canary_budget.rs'
    printf '%s\n' 'tools/xtask/src/security_harness/canary_tests.rs'
    printf '%s\n' 'tools/xtask/src/security_harness/crypto.rs'
    printf '%s\n' 'tools/xtask/src/security_threat_surface.rs'
    printf '%s\n' 'tools/xtask/tests/foundational_scope_activation.rs'
    printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_10_final_blockers.rs'
    printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_10_security_crypto.rs'
    ;;
  rev-parse)
    printf '%s\n' '0000000000000000000000000000000000000000'
    ;;
  status)
    ;;
  hash-object)
    cat >/dev/null
    case "${SSL_CERT_FILE:-}" in
      *fixture-certificate-one.pem)
        printf '%s\n' '1111111111111111111111111111111111111111'
        ;;
      *fixture-certificate-two.pem)
        printf '%s\n' '2222222222222222222222222222222222222222'
        ;;
      *)
        printf '%s\n' '3333333333333333333333333333333333333333'
        ;;
    esac
    ;;
  *)
    printf 'unsupported fixture git command: %s\n' "${1:-}" >&2
    exit 2
    ;;
esac
"#
    .to_owned();
    write_tool(&path, &script)
}

#[cfg(unix)]
fn shell_quote(path: &Path) -> TestResult<String> {
    let value = path
        .as_os_str()
        .to_str()
        .ok_or_else(|| std::io::Error::other("fixture path is not valid UTF-8"))?;
    Ok(format!("'{}'", value.replace('\'', "'\"'\"'")))
}

#[cfg(unix)]
fn wait_for_child_exit(
    child: &mut Child,
    timeout: Duration,
) -> TestResult<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(
                "public quality runner did not return a closed controlled-harness verdict before its deadline",
            )
            .into());
        }
        thread::yield_now();
    }
}

#[cfg(unix)]
fn wait_for_path(path: &Path, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    loop {
        if path.try_exists()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(format!(
                "timed out waiting for fixture path {}",
                path.display()
            ))
            .into());
        }
        thread::yield_now();
    }
}

#[cfg(unix)]
fn read_child_output(child: &mut Child) -> TestResult<(String, String)> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("public quality runner stdout was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("public quality runner stderr was unavailable"))?;
    let mut captured_stdout = String::new();
    let mut captured_stderr = String::new();
    let mut stdout = stdout;
    let mut stderr = stderr;
    stdout.read_to_string(&mut captured_stdout)?;
    stderr.read_to_string(&mut captured_stderr)?;
    Ok((captured_stdout, captured_stderr))
}

fn assert_fixture_rejected(
    mutate: impl FnOnce(&Path) -> TestResult,
    expected_failure: &str,
) -> TestResult {
    assert_fixture_rejected_profile("pre-commit", mutate, expected_failure)
}

fn assert_fixture_rejected_profile(
    profile: &str,
    mutate: impl FnOnce(&Path) -> TestResult,
    expected_failure: &str,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        mutate(&fixture.root)?;
        assert_existing_fixture_rejected(&fixture, profile, expected_failure)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_existing_fixture_rejected(
    fixture: &Fixture,
    profile: &str,
    expected_failure: &str,
) -> TestResult {
    let output = fixture.quality_output_for(profile)?;
    assert_rejected_output(&output, expected_failure)
}

fn assert_rejected_output(output: &std::process::Output, expected_failure: &str) -> TestResult {
    if output.status.success() {
        return Err(std::io::Error::other(
            "the public quality runner accepted an invalid activation fixture",
        )
        .into());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    if !combined.contains(expected_failure) {
        return Err(std::io::Error::other(format!(
            "quality failed for the wrong reason; expected `{expected_failure}`, got `{combined}`"
        ))
        .into());
    }
    Ok(())
}

fn assert_no_fixture_trees(root: &Path) -> TestResult {
    let temporary_base = root.join("target/quality/tmp");
    if !temporary_base.try_exists()? {
        return Ok(());
    }
    for attempt in fs::read_dir(&temporary_base)? {
        let attempt = attempt?;
        if !attempt.file_type()?.is_dir() {
            continue;
        }
        for entry in fs::read_dir(attempt.path())? {
            let entry = entry?;
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("qualification-fixtures-")
            {
                return Err(std::io::Error::other(format!(
                    "attempt-owned fixture tree remained at {}",
                    entry.path().display()
                ))
                .into());
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn assert_external_canary_untouched(external: &Path, canary: &Path) -> TestResult {
    if fs::read(canary)? != b"untouched\n" {
        return Err(std::io::Error::other("fixture swap changed the external canary").into());
    }
    let mut entries = fs::read_dir(external)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    if entries != [std::ffi::OsString::from("canary")] {
        return Err(std::io::Error::other(
            "fixture swap created or removed content outside the owned root",
        )
        .into());
    }
    Ok(())
}

#[cfg(unix)]
fn run_parallel_reservation_racers(
    fixture: &Fixture,
    barrier_candidate: &str,
) -> TestResult<Vec<std::process::Output>> {
    pin_fixture_attempt_identity(&fixture.root)?;
    inject_reservation_barrier(&fixture.root)?;
    fs::write(
        fixture
            .root
            .join("target/quality-tools/reservation-barrier-candidate"),
        format!("{barrier_candidate}\n"),
    )?;
    fixture.build_fixture_xtask()?;
    let first = fixture.quality_child_from_built_fixture()?;
    let second = fixture.quality_child_from_built_fixture()?;
    Ok(vec![first.wait_with_output()?, second.wait_with_output()?])
}

#[cfg(unix)]
fn assert_exact_parallel_retained_verdicts(
    root: &Path,
    expected_invocation_files: &[String],
    preexisting_files: &[String],
) -> TestResult {
    let evidence_directory = root.join("target/quality/evidence");
    let mut actual = fs::read_dir(&evidence_directory)?
        .map(|entry| {
            entry.and_then(|entry| {
                entry.file_name().into_string().map_err(|_| {
                    std::io::Error::other("retained racer filename is not valid UTF-8")
                })
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort();
    let mut expected = expected_invocation_files
        .iter()
        .chain(preexisting_files)
        .cloned()
        .collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        return Err(std::io::Error::other(format!(
            "parallel racers retained unexpected verdict set: expected {expected:?}, got {actual:?}"
        ))
        .into());
    }
    for filename in expected_invocation_files {
        let retained = fs::read_to_string(evidence_directory.join(filename))?;
        assert_complete_evidence_contract(&retained)?;
    }
    Ok(())
}

fn assert_invalid_retained_raw_report(
    mutate: impl FnOnce(&Fixture, &Path, &str) -> TestResult,
    expected_failure: &str,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let evidence_path = fixture.latest_evidence_path()?;
        let evidence = fs::read_to_string(&evidence_path)?;
        mutate(&fixture, &evidence_path, &evidence)?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, expected_failure)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_invalid_retained_engineering_evidence(
    mutate: impl FnOnce(&Path, &str) -> TestResult,
    expected_failure: &str,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.quality()?;
        let evidence_path = fixture.latest_evidence_path()?;
        let evidence = fs::read_to_string(&evidence_path)?;
        mutate(&evidence_path, &evidence)?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, expected_failure)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn exact_raw_report_path(root: &Path, evidence: &str, gate: &str) -> TestResult<PathBuf> {
    let record = gate_record(evidence, gate)?;
    let marker = "\"raw_report\": {";
    let (_, raw_report) = record
        .split_once(marker)
        .ok_or_else(|| std::io::Error::other(format!("gate `{gate}` omitted raw_report")))?;
    let path_marker = "\"path\": \"";
    let (_, path) = raw_report.split_once(path_marker).ok_or_else(|| {
        std::io::Error::other(format!("gate `{gate}` raw_report omitted exact path"))
    })?;
    let (path, _) = path.split_once('"').ok_or_else(|| {
        std::io::Error::other(format!("gate `{gate}` raw_report path is malformed"))
    })?;
    Ok(root.join(path))
}

fn rewrite_gate_field(
    evidence_path: &Path,
    evidence: &str,
    gate: &str,
    marker: &str,
    replacement: &str,
) -> TestResult {
    let record = gate_record(evidence, gate)?;
    let (_, value_and_suffix) = record.split_once(marker).ok_or_else(|| {
        std::io::Error::other(format!("gate `{gate}` omitted field marker `{marker}`"))
    })?;
    let old_value = if marker.ends_with('"') {
        value_and_suffix.split_once('"').map(|(value, _)| value)
    } else {
        value_and_suffix
            .find(|character: char| !character.is_ascii_digit())
            .and_then(|end| value_and_suffix.get(..end))
    }
    .ok_or_else(|| std::io::Error::other(format!("gate `{gate}` field is malformed")))?;
    let old = format!("{marker}{old_value}");
    let new = format!("{marker}{replacement}");
    replace_once(evidence_path, &old, &new)
}

fn gate_record<'evidence>(evidence: &'evidence str, gate: &str) -> TestResult<&'evidence str> {
    let marker = format!("\"gate_id\": \"{gate}\"");
    let (_, tail) = evidence
        .split_once(&marker)
        .ok_or_else(|| std::io::Error::other(format!("evidence omitted gate `{gate}`")))?;
    Ok(tail
        .split_once("\"gate_id\":")
        .map_or(tail, |(record, _)| record))
}

fn assert_failed_aggregator_evidence(
    fixture: &Fixture,
    source_revision: &str,
    reason: &str,
) -> TestResult {
    let evidence = fixture.latest_evidence()?;
    assert_complete_evidence_contract(&evidence)?;
    for expected in [
        "\"result\": \"failed\"",
        "\"merge_eligible\": false",
        "\"gate_id\": \"EG-00\"",
        "\"result\": \"failed\"",
        "\"command_digest\": \"sha256:",
        "\"--aggregator-failure\"",
        "\"applicability\": \"exact\"",
        source_revision,
        reason,
    ] {
        if !evidence.contains(expected) {
            return Err(std::io::Error::other(format!(
                "failed aggregator evidence omitted `{expected}`"
            ))
            .into());
        }
    }
    Ok(())
}

fn assert_complete_evidence_contract(evidence: &str) -> TestResult {
    for required in [
        "\"schema_version\": 3",
        "\"collision_of\"",
        "\"collision_slots\"",
        "\"release_manifest\"",
        "\"artifact\"",
        "\"target\"",
        "\"environment_digest\"",
        "\"toolchain_digest\"",
        "\"effective_configuration\"",
        "\"fixture_registry_digest\"",
        "\"corpus\"",
        "\"seed\"",
        "\"fault_schedule\"",
        "\"verifier\"",
        "\"approval\"",
        "\"exception\"",
        "\"command_digest\"",
        "\"owner\"",
        "\"raw_report\"",
    ] {
        if !evidence.contains(required) {
            return Err(std::io::Error::other(format!(
                "evidence is missing required schema field `{required}`"
            ))
            .into());
        }
    }
    Ok(())
}

fn assert_gate_owner_binding(evidence: &str, gate: &str, owner: &str) -> TestResult {
    let marker = format!("\"gate_id\": \"{gate}\"");
    let (_, tail) = evidence
        .split_once(&marker)
        .ok_or_else(|| std::io::Error::other(format!("evidence omitted gate `{gate}`")))?;
    let gate_record = tail
        .split_once("\"gate_id\":")
        .map_or(tail, |(record, _)| record);
    let expected = format!("\"value\": \"{owner}\"");
    if !gate_record.contains(&expected) {
        return Err(std::io::Error::other(format!(
            "gate `{gate}` is not bound one-to-one to owner `{owner}`"
        ))
        .into());
    }
    Ok(())
}

fn assert_fixture_accepted(mutate: impl FnOnce(&Path) -> TestResult) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        mutate(&fixture.root)?;
        fixture.quality()
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_scope_fields_rejected(
    package: &str,
    fields: &[(&str, &str)],
    expected_failure: &str,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        for (field, value) in fields {
            configure_activation_ledger(&fixture.root)?;
            set_scope_field(&fixture.root, package, field, value)?;
            assert_existing_fixture_rejected(&fixture, "pre-commit", expected_failure)?;
        }
        configure_activation_ledger(&fixture.root)?;
        fixture.quality()
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn repository_root() -> TestResult<PathBuf> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_directory
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("xtask manifest has no workspace root"))?;
    Ok(root.to_path_buf())
}

fn temporary_root() -> TestResult<PathBuf> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = env::temp_dir().join(format!(
        "positron-foundational-activation-{}-{timestamp}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn copy_tree(source: &Path, destination: &Path) -> TestResult {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_str(), Some(".git" | "target" | "mutants.out")) {
            continue;
        }
        let target = destination.join(&name);
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(std::io::Error::other(format!(
                "fixture source contains an unsupported symlink: {}",
                entry.path().display()
            ))
            .into());
        }
        if file_type.is_dir() {
            fs::create_dir_all(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn configure_activation_ledger(root: &Path) -> TestResult {
    rewrite_scopes(root)?;
    rewrite_edges(root)?;
    rewrite_thresholds(root)?;
    write_policy_change(root)?;
    remove_scaffold_markers(root)?;
    restore_m0_01_domain_source_shape(root)?;
    restore_m0_01_api_source_shape(root)?;
    restore_m0_01_config_source_shape(root)?;
    Ok(())
}

fn restore_m0_01_domain_source_shape(root: &Path) -> TestResult {
    let source_root = root.join("crates/positron-domain/src");
    for name in [
        "identity.rs",
        "lifecycle.rs",
        "outcome.rs",
        "routing.rs",
        "time.rs",
        "value.rs",
    ] {
        let path = source_root.join(name);
        if path.is_file() {
            fs::remove_file(path)?;
        }
    }
    for contract_test in [
        "crates/positron-domain/tests/dynamic_domain_properties.rs",
        "crates/positron-domain/tests/foundational_domain_types.rs",
    ] {
        let contract_test = root.join(contract_test);
        if contract_test.is_file() {
            fs::remove_file(contract_test)?;
        }
    }
    fs::write(
        source_root.join("lib.rs"),
        "//! Historical M0-01 activation-only fixture.\n#![forbid(unsafe_code)]\n",
    )?;
    Ok(())
}

fn restore_m0_01_api_source_shape(root: &Path) -> TestResult {
    for path in [
        "crates/positron-api/src/generated.rs",
        "crates/positron-api/tests/canonical_public_interface.rs",
        "api/positron/v1/http.json",
        "api/positron/v1/openapi.json",
        "api/positron/v1/positron.proto",
        "api/positron/v1/schema.sha256",
        "api/positron/v1/validation-fixtures.json",
    ] {
        let path = root.join(path);
        if path.is_file() {
            fs::remove_file(path)?;
        }
    }
    fs::write(
        root.join("crates/positron-api/src/lib.rs"),
        "//! Historical M0-01 activation-only fixture.\n#![forbid(unsafe_code)]\n",
    )?;
    let artifact_scopes = root.join("qualification/engineering/artifact-scopes.tsv");
    let content = fs::read_to_string(&artifact_scopes)?;
    if content.contains("canonical-api\tapi/positron/v1\tPublic API and SDK\tactive\t-") {
        fs::write(
            artifact_scopes,
            content.replace(
                "canonical-api\tapi/positron/v1\tPublic API and SDK\tactive\t-",
                "canonical-api\tapi/positron/v1\tPublic API and SDK\tscaffold\tREADME.md",
            ),
        )?;
    }
    Ok(())
}

fn restore_m0_01_config_source_shape(root: &Path) -> TestResult {
    let rust_contract = root.join("crates/positron-config/src/contract.rs");
    if rust_contract.is_file() {
        fs::remove_file(rust_contract)?;
    }
    let contract_test = root.join("crates/positron-config/tests/configuration_foundation.rs");
    if contract_test.is_file() {
        fs::remove_file(contract_test)?;
    }
    fs::write(
        root.join("crates/positron-config/src/lib.rs"),
        "//! Historical M0-01 activation-only fixture.\n#![forbid(unsafe_code)]\n",
    )?;
    let manifest = root.join("crates/positron-config/Cargo.toml");
    let content = fs::read_to_string(&manifest)?;
    fs::write(
        manifest,
        content.replace(
            "\n[dependencies]\ntoml = { version = \"=1.1.4\", default-features = false, features = [\"parse\", \"serde\", \"std\"] }\n",
            "",
        ),
    )?;
    let lockfile = Command::new(env!("CARGO"))
        .current_dir(root)
        .args(["generate-lockfile", "--offline"])
        .output()?;
    if !lockfile.status.success() {
        return Err(std::io::Error::other(format!(
            "historical fixture lockfile generation failed: {}",
            String::from_utf8_lossy(&lockfile.stderr)
        ))
        .into());
    }
    let configuration = root.join("configuration");
    if configuration.is_dir() {
        fs::remove_dir_all(configuration)?;
    }
    for (field, value) in [
        ("activation_id", "M0-01"),
        ("activation_scope_set", ACTIVATION_SET),
        (
            "test_commands",
            "cargo test --locked --package xtask --test foundational_scope_activation",
        ),
        (
            "coverage_baseline",
            "coverage-branch|coverage-changed-code|coverage-line|coverage-region",
        ),
        ("mutation_baseline", "mutation-score"),
        ("contract_evidence", POLICY_CHANGE),
    ] {
        set_scope_field(root, "positron-config", field, value)?;
    }
    let artifacts = root.join("qualification/engineering/artifact-scopes.tsv");
    let content = fs::read_to_string(&artifacts)?;
    fs::write(
        artifacts,
        content.replace(
            "configuration-artifacts\tconfiguration\tRecovery and Lifecycle\tactive\t-\tEG-DOCS|EG-ERROR|EG-MATRIX|EG-SECRETS|EG-TEST\n",
            "",
        ),
    )?;
    Ok(())
}

fn configure_m0_02_domain_types_ledger(root: &Path) -> TestResult {
    set_scope_field(
        root,
        "positron-domain",
        "risk_gates",
        "EG-COVERAGE|EG-DYNAMIC",
    )?;
    set_scope_field(
        root,
        "positron-domain",
        "activation_id",
        M0_02_ACTIVATION_ID,
    )?;
    set_scope_field(
        root,
        "positron-domain",
        "activation_scope_set",
        M0_02_ACTIVATION_SET,
    )?;
    set_scope_field(
        root,
        "positron-domain",
        "test_commands",
        "cargo test --locked --package positron-domain",
    )?;
    set_scope_field(
        root,
        "positron-domain",
        "coverage_baseline",
        "domain-coverage-branch|domain-coverage-line|domain-coverage-region",
    )?;
    set_scope_field(
        root,
        "positron-domain",
        "mutation_baseline",
        "domain-mutation-score",
    )?;
    set_scope_field(
        root,
        "positron-domain",
        "contract_evidence",
        M0_02_POLICY_CHANGE,
    )?;

    let edges_path = root.join("qualification/engineering/architecture-edges.tsv");
    let edges = fs::read_to_string(&edges_path)?;
    fs::write(
        edges_path,
        edges.replace("\tpositron-domain\tM0-01\n", "\tpositron-domain\tM0-02\n"),
    )?;

    let thresholds_path = root.join("qualification/engineering/thresholds.tsv");
    let mut thresholds = fs::read_to_string(&thresholds_path)?;
    for threshold in [
        "domain-coverage-branch",
        "domain-coverage-line",
        "domain-coverage-region",
        "domain-mutation-score",
    ] {
        let registered = thresholds
            .lines()
            .any(|line| line.split('\t').next() == Some(threshold));
        if !registered {
            thresholds.push_str(&format!(
                "{threshold}\tmeasured-baseline\t100.00\tpercent\tm0-02-domain-types\tFixture M0-02 baseline\t{M0_02_POLICY_CHANGE}\n"
            ));
        }
    }
    fs::write(thresholds_path, thresholds)?;
    for threshold in [
        "domain-coverage-branch",
        "domain-coverage-line",
        "domain-coverage-region",
        "domain-mutation-score",
    ] {
        set_threshold_field(root, threshold, "value", "100.00")?;
    }
    write_m0_02_policy_change(root)
}

fn configure_scaffold_only_policy(root: &Path) -> TestResult {
    for package in ["positron-domain", "positron-api", "positron-config"] {
        set_scope_field(root, package, "state", "scaffold")?;
        for field in [
            "activation_id",
            "activation_scope_set",
            "allowed_edges",
            "risk_gates",
            "test_commands",
            "coverage_baseline",
            "mutation_baseline",
            "dependency_review",
            "contract_evidence",
        ] {
            set_scope_field(root, package, field, "-")?;
        }
        restore_scaffold_marker(root, package)?;
    }
    for threshold in [
        "coverage-line",
        "coverage-region",
        "coverage-branch",
        "coverage-changed-code",
        "mutation-score",
    ] {
        set_threshold_field(root, threshold, "state", "pending-measured-baseline")?;
        set_threshold_field(root, threshold, "value", "-")?;
        set_threshold_field(root, threshold, "scope", "active-application-code")?;
        set_threshold_field(root, threshold, "evidence", "-")?;
    }
    Ok(())
}

fn remove_coverage_baseline(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/thresholds.tsv"),
        &format!("coverage-line\tmeasured-baseline\t{FROZEN_COVERAGE_LINE}"),
        "coverage-line\tpending-measured-baseline\t-",
    )
}

fn make_coverage_baseline_nonfinite(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/thresholds.tsv"),
        &format!("coverage-line\tmeasured-baseline\t{FROZEN_COVERAGE_LINE}"),
        "coverage-line\tmeasured-baseline\tNaN",
    )
}

fn missing_domain_owner(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/scopes.tsv"),
        "positron-domain\tcrates/positron-domain\tArchitecture",
        "positron-domain\tcrates/positron-domain\t-",
    )
}

fn make_foundational_scope_path_absolute(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/scopes.tsv"),
        "positron-domain\tcrates/positron-domain",
        "positron-domain\t/activation-must-not-escape-the-repository",
    )
}

fn add_forbidden_foundational_edge(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/architecture-edges.tsv");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("positron-domain\tpositron-api\tM0-01\n");
    fs::write(path, content)?;
    Ok(())
}

fn remove_registered_foundational_edge(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/architecture-edges.tsv"),
        "positron-runtime\tpositron-domain\tM0-01\n",
        "",
    )
}

fn add_architecture_cycle(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/architecture-edges.tsv");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("positron-backup\tpositron\t-\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_unregistered_source_file(root: &Path) -> TestResult {
    fs::write(root.join("unregistered.rs"), "fn forbidden() {}\n")?;
    Ok(())
}

fn add_behavior_to_scaffold_crate(root: &Path) -> TestResult {
    let path = root.join("crates/positron-query/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub fn behavior_is_not_legal_here() {}\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_pass_through_reexport(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub use positron_api::GeneratedMessage;\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_deferred_metrics_symbol(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub struct MetricsStore;\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_hidden_feature_flag(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/Cargo.toml");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\n[features]\ndeferred-metrics = []\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_placeholder_api(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub struct PlaceholderApi;\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_disabled_deferred_module(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\n#[cfg(feature = \"deferred-metrics\")]\nmod metrics;\n");
    fs::write(path, content)?;
    Ok(())
}

fn add_extra_doc_only_activation_source(root: &Path) -> TestResult {
    fs::write(
        root.join("crates/positron-domain/src/extra.rs"),
        "//! This source file is deliberately documentation-only.\n",
    )?;
    Ok(())
}

fn add_non_deferred_symbol_with_a_deferred_prefix(root: &Path) -> TestResult {
    let path = root.join("crates/positron-domain/src/lib.rs");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\npub struct MetricsStorehouse;\n");
    fs::write(path, content)?;
    Ok(())
}

fn disable_incremental_compilation_globally(root: &Path) -> TestResult {
    let path = root.join(".cargo/config.toml");
    let mut content = fs::read_to_string(&path)?;
    content.push_str("\n[build]\nincremental = false\n");
    fs::write(path, content)?;
    Ok(())
}

fn remove_pr_tool_cache(root: &Path) -> TestResult {
    replace_once(
        &root.join(".github/workflows/quality.yml"),
        "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        "actions/cache/restore@0000000000000000000000000000000000000000",
    )
}

fn remove_cached_pr_tool_verification(root: &Path) -> TestResult {
    replace_once(
        &root.join(".github/workflows/quality.yml"),
        "          \"$tool_root/cargo-audit\" --version | grep --fixed-strings --line-regexp \"cargo-audit 0.22.2\"\n",
        "",
    )
}

fn remove_coverage_tool_provisioning(root: &Path) -> TestResult {
    let path = root.join(".github/workflows/extended.yml");
    let content = fs::read_to_string(&path)?;
    let content = content
        .replace(
            "      - name: Install pinned branch-coverage toolchain\n        run: rustup toolchain install nightly-2026-07-20 --profile minimal --component llvm-tools-preview\n\n",
            "",
        )
        .replace(
            "          cargo install --locked --version 0.8.7 cargo-llvm-cov\n",
            "",
        );
    fs::write(path, content)?;
    Ok(())
}

fn remove_raw_coverage_report_retention(root: &Path) -> TestResult {
    replace_once(
        &root.join(".github/workflows/extended.yml"),
        "path: target/quality/",
        "path: target/quality/coverage/",
    )?;
    Ok(())
}

fn reduce_line_coverage_measurement(root: &Path) -> TestResult {
    replace_once(
        &root.join("target/quality-tools/bin/cargo"),
        "\"lines\":{\"percent\":100.0}",
        "\"lines\":{\"percent\":70.0}",
    )
}

fn make_coverage_detector_report_a_different_version(root: &Path) -> TestResult {
    replace_once(
        &root.join("target/quality-tools/bin/cargo"),
        "cargo-llvm-cov 0.8.7",
        "cargo-llvm-cov 0.8.6",
    )
}

fn make_snapshot_digest_exceed_its_capture_bound(root: &Path) -> TestResult {
    replace_once(
        &root.join("target/quality-tools/bin/git"),
        "cat >/dev/null\n    printf '%s\\n' '1111111111111111111111111111111111111111'",
        "cat >/dev/null\n    /usr/bin/head -c 1025 /dev/zero | /usr/bin/tr '\\0' x",
    )
}

fn make_snapshot_digest_exit_nonzero(root: &Path) -> TestResult {
    replace_once(
        &root.join("target/quality-tools/bin/git"),
        "cat >/dev/null\n    printf '%s\\n' '1111111111111111111111111111111111111111'",
        "cat >/dev/null\n    printf '%s\\n' 'fixture digest failure' >&2\n    exit 79",
    )
}

fn make_snapshot_digest_invalid(root: &Path) -> TestResult {
    replace_once(
        &root.join("target/quality-tools/bin/git"),
        "cat >/dev/null\n    printf '%s\\n' '1111111111111111111111111111111111111111'",
        "cat >/dev/null\n    printf '%s\\n' 'not-an-object-identity'",
    )
}

fn make_fixture_git_report_dirty(root: &Path) -> TestResult {
    replace_once(
        &root.join("target/quality-tools/bin/git"),
        "  status)\n    ;;",
        "  status)\n    printf '%s\\n' ' M fixture-policy.tsv'\n    ;;",
    )
}

fn pin_fixture_attempt_identity(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "fn attempt_identity(revision: &str, started_unix_ms: u128) -> String {\n    let revision_prefix = revision.chars().take(12).collect::<String>();\n    format!(\"{started_unix_ms}-{revision_prefix}-{}\", std::process::id())\n}",
        "fn attempt_identity(_revision: &str, _started_unix_ms: u128) -> String {\n    \"1700000000000-111111111111-1\".to_owned()\n}",
    )
}

#[cfg(unix)]
fn inject_fixture_registry_capture_barrier(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/quality.rs");
    replace_once(
        &source,
        "    println!(\n        \"Positron engineering quality: profile={}, revision={}, dirty={}\",\n",
        "    fixture_registry_capture_barrier(&root)?;\n    println!(\n        \"Positron engineering quality: profile={}, revision={}, dirty={}\",\n",
    )?;
    replace_once(
        &source,
        "fn digest_relative_files(\n",
        r#"fn fixture_registry_capture_barrier(root: &Path) -> Result<(), XtaskError> {
    let tools = root.join("target/quality-tools");
    let ready = tools.join("fixture-registry-capture-ready");
    let release = tools.join("fixture-registry-capture-release");
    fs::write(&ready, b"ready\n")
        .map_err(|source| XtaskError::io("publish fixture registry capture barrier", source))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if release
            .try_exists()
            .map_err(|source| XtaskError::io("inspect fixture registry capture barrier", source))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                "fixture registry capture barrier",
                "registry mutator did not release the barrier",
            ));
        }
        std::thread::yield_now();
    }
}

fn digest_relative_files(
"#,
    )
}

fn remove_fault_adapter_invocation(root: &Path, variant: &str) -> TestResult {
    let source = root.join("tools/xtask/src/qualification_fixtures.rs");
    let original = "    let adapter = QualityFixtureAdapter::for_schedule(fault_schedule);\n    execute_fixture_adapter(&case_root, adapter, candidate, published, successor)?;\n";
    let replacement = format!(
        "    let adapter = QualityFixtureAdapter::for_schedule(fault_schedule);\n    if fault_schedule != CrashSchedule::{variant} {{\n        execute_fixture_adapter(&case_root, adapter, candidate, published, successor)?;\n    }}\n"
    );
    replace_once(&source, original, &replacement)
}

fn bypass_fault_operation(root: &Path, adapter: &str) -> TestResult {
    let source = root.join("tools/xtask/src/qualification_fixtures.rs");
    if !matches!(
        adapter,
        "BoundedStorage"
            | "ControlledClock"
            | "Cancellation"
            | "NetworkPublication"
            | "ProviderPublication"
    ) {
        return Err(std::io::Error::other(format!("unknown bypassed adapter `{adapter}`")).into());
    }
    let original = "            let receipt = exercise_deterministic_fault(case_root, adapter, candidate, successor)?;\n";
    let replacement = format!(
        "            let receipt = if adapter == QualityFixtureAdapter::{adapter} {{\n                FaultOperationReceipt {{\n                    observation: adapter.expected_observation(),\n                    error_identity: \"forged-operation-bypass\".to_owned(),\n                }}\n            }} else {{\n                exercise_deterministic_fault(case_root, adapter, candidate, successor)?\n            }};\n"
    );
    replace_once(&source, original, &replacement)
}

#[cfg(unix)]
fn inject_candidate_replacement_after_first_read(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/qualification_fixtures.rs");
    replace_once(
        &source,
        "    if let Err(error) = case_root.require_child_file_identity(\n",
        "    if let Err(error) = replace_candidate_after_first_read(case_root) {\n        return CandidateStateOutcome::ReadIoSecurityError(error);\n    }\n    if let Err(error) = case_root.require_child_file_identity(\n",
    )?;
    replace_once(
        &source,
        "fn read_adapter_observation(\n",
        r#"fn replace_candidate_after_first_read(
    case_root: &DirectoryCapability,
) -> Result<(), XtaskError> {
    case_root.remove_file("candidate.state")?;
    std::os::unix::fs::symlink(
        "missing-candidate-target",
        case_root.diagnostic_path.join("candidate.state"),
    )
    .map_err(|source| XtaskError::io("replace candidate after first bounded read", source))
}

fn read_adapter_observation(
"#,
    )
}

#[cfg(unix)]
fn inject_dependency_metadata_artifact_barrier(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/quality.rs");
    replace_once(
        &source,
        "    let summary = validate_dependency_metadata_artifact(root, &artifact)?;\n",
        "    dependency_metadata_artifact_barrier(root, artifact.diagnostic_path())?;\n    let summary = validate_dependency_metadata_artifact(root, &artifact)?;\n",
    )?;
    replace_once(
        &source,
        "fn bounded_stream_summary(stream: &str) -> String {\n",
        r#"fn dependency_metadata_artifact_barrier(
    root: &Path,
    artifact_path: &Path,
) -> Result<(), XtaskError> {
    let tools = root.join("target/quality-tools");
    fs::write(
        tools.join("dependency-metadata-artifact-path"),
        artifact_path.as_os_str().as_encoded_bytes(),
    )
    .map_err(|source| XtaskError::io("publish dependency metadata artifact path", source))?;
    fs::write(
        tools.join("dependency-metadata-artifact-ready"),
        b"ready\n",
    )
    .map_err(|source| XtaskError::io("publish dependency metadata barrier", source))?;
    let release = tools.join("dependency-metadata-artifact-release");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if release
            .try_exists()
            .map_err(|source| XtaskError::io("inspect dependency metadata barrier", source))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                "dependency metadata artifact barrier",
                "artifact swapper did not release the barrier",
            ));
        }
        std::thread::yield_now();
    }
}

fn bounded_stream_summary(stream: &str) -> String {
"#,
    )
}

#[cfg(unix)]
fn inject_dependency_metadata_parent_sync_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/qualification_fixtures.rs"),
        "            Ok(()) => {\n                self.sync()?;\n                self.open_child_directory(name, label)\n            },\n",
        "            Ok(()) => {\n                return Err(XtaskError::invalid(\n                    \"injected dependency metadata parent synchronization failure\",\n                    format!(\"created {} but could not synchronize its parent\", path.display()),\n                ));\n            },\n",
    )
}

#[cfg(unix)]
fn inject_fixture_root_claim_barrier(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/qualification_fixtures.rs");
    replace_once(
        &source,
        "        let parent = DirectoryCapability::open(temporary_root, \"attempt temporary root\")?;\n        let name = format!(\"qualification-fixtures-{name}\");\n",
        "        let parent = DirectoryCapability::open(temporary_root, \"attempt temporary root\")?;\n        fixture_root_claim_barrier(temporary_root)?;\n        let name = format!(\"qualification-fixtures-{name}\");\n",
    )?;
    replace_once(
        &source,
        "impl OwnedFixtureRoot {\n",
        r#"fn fixture_root_claim_barrier(temporary_root: &Path) -> Result<(), XtaskError> {
    let workspace = temporary_root
        .ancestors()
        .nth(4)
        .ok_or_else(|| XtaskError::invalid_path(temporary_root, "fixture TMPDIR has no workspace ancestor"))?;
    let tools = workspace.join("target/quality-tools");
    let path = tools.join("fixture-root-claim-path");
    let ready = tools.join("fixture-root-claim-ready");
    let release = tools.join("fixture-root-claim-release");
    fs::write(&path, temporary_root.as_os_str().as_encoded_bytes())
        .map_err(|source| XtaskError::io("publish fixture root claim path", source))?;
    fs::write(&ready, b"ready\n")
        .map_err(|source| XtaskError::io("publish fixture root claim readiness", source))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if release
            .try_exists()
            .map_err(|source| XtaskError::io("inspect fixture root claim barrier", source))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                "fixture root claim barrier",
                "symlink racer did not release the barrier",
            ));
        }
        std::thread::yield_now();
    }
}

impl OwnedFixtureRoot {
"#,
    )
}

#[cfg(unix)]
fn inject_fixture_writer_claim_barrier(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/qualification_fixtures.rs");
    replace_once(
        &source,
        "    let case_root = claim_process_root(claim)?;\n    validate_field(&case_root.diagnostic_path, 0, \"predecessor\", predecessor)?;\n",
        "    let case_root = claim_process_root(claim)?;\n    fixture_case_claim_barrier(&case_root.diagnostic_path, \"writer\")?;\n    validate_field(&case_root.diagnostic_path, 0, \"predecessor\", predecessor)?;\n",
    )?;
    inject_fixture_case_claim_barrier(&source)
}

#[cfg(unix)]
fn inject_fixture_integrity_claim_barrier(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/qualification_fixtures.rs");
    replace_once(
        &source,
        "    let case_root = fixture_root.create_case(&case.fixture_id)?;\n    let original = \"prior-attempt.evidence\";\n",
        "    let case_root = fixture_root.create_case(&case.fixture_id)?;\n    fixture_case_claim_barrier(&case_root.diagnostic_path, \"integrity\")?;\n    let original = \"prior-attempt.evidence\";\n",
    )?;
    inject_fixture_case_claim_barrier(&source)
}

#[cfg(unix)]
fn inject_fixture_case_claim_barrier(source: &Path) -> TestResult {
    replace_once(
        source,
        "fn execute_integrity_case(\n",
        r#"fn fixture_case_claim_barrier(case_root: &Path, kind: &str) -> Result<(), XtaskError> {
    let workspace = case_root
        .ancestors()
        .find(|candidate| candidate.join("project-positron.md").is_file())
        .ok_or_else(|| XtaskError::invalid_path(case_root, "fixture case has no workspace ancestor"))?;
    let tools = workspace.join("target/quality-tools");
    let path = tools.join(format!("fixture-{kind}-claim-path"));
    let ready = tools.join(format!("fixture-{kind}-claim-ready"));
    let release = tools.join(format!("fixture-{kind}-claim-release"));
    fs::write(&path, case_root.as_os_str().as_encoded_bytes())
        .map_err(|source| XtaskError::io("publish fixture case claim path", source))?;
    fs::write(&ready, b"ready\n")
        .map_err(|source| XtaskError::io("publish fixture case claim readiness", source))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if release
            .try_exists()
            .map_err(|source| XtaskError::io("inspect fixture case claim barrier", source))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                "fixture case claim barrier",
                "case swapper did not release the barrier",
            ));
        }
        std::thread::yield_now();
    }
}

fn execute_integrity_case(
"#,
    )
}

#[cfg(unix)]
fn inject_fixture_writer_timeout(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/qualification_fixtures.rs");
    replace_once(
        &source,
        "    let case_root = claim_process_root(claim)?;\n    validate_field(&case_root.diagnostic_path, 0, \"predecessor\", predecessor)?;\n",
        "    let case_root = claim_process_root(claim)?;\n    fixture_writer_timeout(&case_root.diagnostic_path)?;\n    validate_field(&case_root.diagnostic_path, 0, \"predecessor\", predecessor)?;\n",
    )?;
    replace_once(
        &source,
        "fn run_writer_process(\n",
        r#"fn fixture_writer_timeout(case_root: &Path) -> Result<(), XtaskError> {
    let workspace = case_root
        .ancestors()
        .nth(6)
        .ok_or_else(|| XtaskError::invalid_path(case_root, "fixture case has no workspace ancestor"))?;
    fs::write(
        workspace.join("target/quality-tools/fixture-writer-timeout-pid"),
        std::process::id().to_string(),
    )
    .map_err(|source| XtaskError::io("publish timed-out fixture writer PID", source))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    Err(XtaskError::invalid(
        "injected fixture writer timeout",
        "writer safety deadline elapsed",
    ))
}

fn run_writer_process(
"#,
    )
}

#[cfg(unix)]
fn inject_stalled_writer_reap_observation(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/qualification_fixtures.rs"),
        "    child\n        .try_wait()\n        .map_err(|source| XtaskError::io(format!(\"observe {label} reap\"), source))\n",
        "    fs::write(\n        \"target/quality-tools/fixture-writer-reap-stall-pid\",\n        child.id().to_string(),\n    )\n    .map_err(|source| XtaskError::io(\"publish stalled writer PID\", source))?;\n    fs::write(\n        \"target/quality-tools/fixture-writer-reap-observer-entered\",\n        b\"entered\\n\",\n    )\n    .map_err(|source| XtaskError::io(\"publish stalled reap observer entry\", source))?;\n    let _label = label;\n    Ok(None)\n",
    )
}

#[cfg(unix)]
fn inject_fixture_cleanup_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/qualification_fixtures.rs"),
        "    fn cleanup(&mut self) -> Result<(), XtaskError> {\n        if !self.active {\n",
        "    fn cleanup(&mut self) -> Result<(), XtaskError> {\n        if self.active {\n            return Err(XtaskError::invalid(\n                \"injected qualification fixture cleanup failure\",\n                \"owned tree could not be reconciled\",\n            ));\n        }\n        if !self.active {\n",
    )
}

#[cfg(unix)]
fn inject_fixture_cleanup_replacement_barrier(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/qualification_fixtures.rs");
    replace_once(
        &source,
        "        remove_child_directory_by_identity(&self.parent, identity)?;\n",
        "        remove_child_directory_by_identity(&self.parent, identity)?;\n        fixture_cleanup_replacement_barrier(&self.path)?;\n",
    )?;
    replace_once(
        &source,
        "impl OwnedFixtureRoot {\n",
        r#"fn fixture_cleanup_replacement_barrier(canonical: &Path) -> Result<(), XtaskError> {
    let workspace = canonical
        .ancestors()
        .find(|candidate| candidate.join("project-positron.md").is_file())
        .ok_or_else(|| XtaskError::invalid_path(canonical, "fixture root has no workspace ancestor"))?;
    let tools = workspace.join("target/quality-tools");
    fs::write(
        tools.join("fixture-cleanup-replacement-path"),
        canonical.as_os_str().as_encoded_bytes(),
    )
    .map_err(|source| XtaskError::io("publish cleanup replacement path", source))?;
    fs::write(
        tools.join("fixture-cleanup-replacement-ready"),
        b"ready\n",
    )
    .map_err(|source| XtaskError::io("publish cleanup replacement barrier", source))?;
    let release = tools.join("fixture-cleanup-replacement-release");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if release
            .try_exists()
            .map_err(|source| XtaskError::io("inspect cleanup replacement barrier", source))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                "fixture cleanup replacement barrier",
                "replacement racer did not release the barrier",
            ));
        }
        std::thread::yield_now();
    }
}

impl OwnedFixtureRoot {
"#,
    )
}

#[cfg(unix)]
fn inject_reservation_barrier(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/quality.rs");
    replace_once(
        &source,
        "        validate_serialized_evidence(&recovery, &recovery_bytes)?;\n        let mut recovery_file = match reserve_new_file(&recovery_path) {\n",
        "        validate_serialized_evidence(&recovery, &recovery_bytes)?;\n        reservation_fixture_barrier(root, &evidence.attempt_id)?;\n        let mut recovery_file = match reserve_new_file(&recovery_path) {\n",
    )?;
    replace_once(
        &source,
        "fn reserve_new_file(path: &Path) -> Result<fs::File, std::io::Error> {\n",
        r#"fn reservation_fixture_barrier(root: &Path, candidate: &str) -> Result<(), XtaskError> {
    let configured = fs::read_to_string(
        root.join("target/quality-tools/reservation-barrier-candidate"),
    )
    .map_err(|source| XtaskError::io("read reservation barrier candidate", source))?;
    if configured.trim() != candidate {
        return Ok(());
    }
    let directory = root
        .join("target/quality-tools/reservation-barrier")
        .join(candidate);
    fs::create_dir_all(&directory)
        .map_err(|source| XtaskError::io("create reservation barrier", source))?;
    fs::write(directory.join(std::process::id().to_string()), b"ready\n")
        .map_err(|source| XtaskError::io("publish reservation barrier participant", source))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let participants = fs::read_dir(&directory)
            .map_err(|source| XtaskError::io("read reservation barrier", source))?
            .count();
        if participants >= 2 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                "reservation fixture barrier",
                "parallel reservation participant did not arrive",
            ));
        }
        std::thread::yield_now();
    }
}

fn reserve_new_file(path: &Path) -> Result<fs::File, std::io::Error> {
"#,
    )
}

fn inject_report_write_failure(root: &Path, gate_id: &str) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "        validate_raw_report_binding(&evidence.attempt_id, gate)?;\n",
        &format!(
            "        validate_raw_report_binding(&evidence.attempt_id, gate)?;\n        if gate.gate_id == \"{gate_id}\" {{\n            return Err(XtaskError::invalid(\"injected report staging failure\", \"selected report write failed\"));\n        }}\n"
        ),
    )
}

fn inject_report_cleanup_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "        Ok(()) => {\n            let parent = path.parent().ok_or_else(|| {\n                XtaskError::invalid_path(path, \"incomplete primary evidence has no parent\")\n            })?;\n            sync_directory(parent).map_err(|error| {\n                XtaskError::invalid(\n                    \"incomplete primary evidence cleanup\",\n                    format!(\n                        \"removed {} but could not synchronize its parent: {error}\",\n                        path.display()\n                    ),\n                )\n            })\n        },",
        "        Ok(()) => {\n            let parent = path.parent().ok_or_else(|| {\n                XtaskError::invalid_path(path, \"incomplete primary evidence has no parent\")\n            })?;\n            sync_directory(parent)?;\n            Err(XtaskError::invalid(\n                \"injected report staging failure\",\n                \"cleanup reported failure after removing the incomplete primary\",\n            ))\n        },",
    )
}

#[cfg(unix)]
fn inject_final_report_claim_barrier(root: &Path) -> TestResult {
    let source = root.join("tools/xtask/src/quality.rs");
    replace_once(
        &source,
        "fn claim_final_report_directory(\n",
        r#"fn report_publication_fixture_barrier(final_path: &Path) -> Result<(), XtaskError> {
    let target = final_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| XtaskError::invalid_path(final_path, "fixture final path has no target ancestor"))?;
    let tools = target.join("quality-tools");
    let ready = tools.join("report-publication-barrier-ready");
    let release = tools.join("report-publication-barrier-release");
    fs::write(&ready, b"ready\n")
        .map_err(|source| XtaskError::io("publish report fixture barrier", source))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if release
            .try_exists()
            .map_err(|source| XtaskError::io("inspect report fixture barrier", source))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                "report fixture barrier",
                "publication racer did not release the barrier",
            ));
        }
        std::thread::yield_now();
    }
}

fn claim_final_report_directory(
"#,
    )?;
    replace_once(
        &source,
        ") -> Result<(), XtaskError> {\n    match fs::create_dir(final_path) {\n",
        ") -> Result<(), XtaskError> {\n    report_publication_fixture_barrier(final_path)?;\n    match fs::create_dir(final_path) {\n",
    )
}

fn inject_primary_cleanup_parent_sync_failure(root: &Path) -> TestResult {
    fs::write(
        root.join("target/quality-tools/fail-primary-cleanup-parent-sync"),
        b"1700000000000-111111111111-1\n",
    )?;
    let source = root.join("tools/xtask/src/quality.rs");
    replace_once(
        &source,
        "            .and_then(|()| Err(std::io::Error::other(\n                \"injected primary evidence publication failure: primary write failed\",\n            )))\n",
        "            .and_then(|()| {\n                fs::write(\n                    root.join(\"target/quality-tools/primary-cleanup-sync-armed\"),\n                    b\"armed\\n\",\n                )?;\n                Err(std::io::Error::other(\n                    \"injected primary evidence publication failure: primary write failed\",\n                ))\n            })\n",
    )?;
    replace_once(
        &source,
        "fn sync_directory(path: &Path) -> Result<(), XtaskError> {\n",
        r#"fn sync_directory(path: &Path) -> Result<(), XtaskError> {
    let tools = path
        .parent()
        .and_then(Path::parent)
        .map(|target| target.join("quality-tools"));
    if let Some(tools) = tools {
        let marker = tools.join("fail-primary-cleanup-parent-sync");
        if let Ok(attempt) = fs::read_to_string(marker) {
            let attempt = attempt.trim();
            if tools.join("primary-cleanup-sync-armed").exists()
                && path.ends_with("target/quality/evidence")
                && !path.join(format!("{attempt}.json")).exists()
                && path.join(format!("{attempt}-recovery.json")).exists()
            {
                return Err(XtaskError::invalid(
                    "injected primary cleanup parent sync failure",
                    "evidence parent synchronization failed after primary unlink",
                ));
            }
        }
    }
"#,
    )
}

#[cfg(unix)]
fn inject_non_owned_report_content(root: &Path, phase: &str) -> TestResult {
    let source = root.join("tools/xtask/src/quality.rs");
    replace_once(
        &source,
        "fn publish_staged_reports(\n",
        r#"fn inject_non_owned_publication_content(path: &Path) -> Result<(), XtaskError> {
    fs::write(path.join("injected-file"), b"non-owned bytes\n")
        .map_err(|source| XtaskError::io("inject non-owned publication file", source))?;
    fs::create_dir(path.join("injected-directory"))
        .map_err(|source| XtaskError::io("inject non-owned publication directory", source))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("injected-file", path.join("injected-symlink"))
        .map_err(|source| XtaskError::io("inject non-owned publication symlink", source))?;
    Err(XtaskError::invalid(
        "injected non-owned publication content",
        "publication stopped after non-owned content appeared",
    ))
}

fn publish_staged_reports(
"#,
    )?;
    match phase {
        "staging" => replace_once(
            &source,
            "        stage_raw_reports(\n            &self.report_staging_path,\n            &self.evidence,\n            &mut self.report_staging_files,\n        )?;\n        sync_directory(&self.report_staging_path)?;\n",
            "        stage_raw_reports(\n            &self.report_staging_path,\n            &self.evidence,\n            &mut self.report_staging_files,\n        )?;\n        inject_non_owned_publication_content(&self.report_staging_path)?;\n",
        ),
        "final" => replace_once(
            &source,
            "        publish_staged_reports(\n            &self.report_staging_files,\n            &self.report_final_path,\n            &mut self.report_final_files,\n        )?;\n        sync_directory(&self.report_final_path)?;\n",
            "        publish_staged_reports(\n            &self.report_staging_files,\n            &self.report_final_path,\n            &mut self.report_final_files,\n        )?;\n        inject_non_owned_publication_content(&self.report_final_path)?;\n",
        ),
        _ => Err(std::io::Error::other(format!(
            "unknown non-owned publication injection phase `{phase}`"
        ))
        .into()),
    }
}

fn inject_primary_evidence_write_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "            .write_all(serialized.as_bytes())\n",
        "            .write_all(serialized.as_bytes())\n            .and_then(|()| Err(std::io::Error::other(\n                \"injected primary evidence publication failure: primary write failed\",\n            )))\n",
    )
}

fn inject_primary_evidence_flush_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "            .and_then(|()| self.file.flush())\n",
        "            .and_then(|()| Err(std::io::Error::other(\n                \"injected primary evidence publication failure: primary flush failed\",\n            )))\n",
    )
}

fn inject_recovery_cleanup_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "fn cleanup_recovery_marker(path: &Path) -> Result<(), XtaskError> {\n    fs::remove_file(path).map_err(|source| {\n        XtaskError::io(\n            format!(\"reconcile recovery evidence {}\", path.display()),\n            source,\n        )\n    })\n}",
        "fn cleanup_recovery_marker(_path: &Path) -> Result<(), XtaskError> {\n    Err(XtaskError::invalid(\n        \"injected primary evidence publication failure\",\n        \"recovery cleanup failed\",\n    ))\n}",
    )
}

fn inject_primary_reservation_collision(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "        let file = match reserve_new_file(&path) {\n",
        "        fs::write(&path, b\"{\\\"injected\\\":\\\"primary-reservation-collision\\\"}\\n\")\n            .map_err(|source| XtaskError::io(\n                format!(\"inject primary reservation collision {}\", path.display()),\n                source,\n            ))?;\n        let file = match reserve_new_file(&path) {\n",
    )
}

fn inject_staged_report_file_sync_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "        file.write_all(content.as_bytes())\n            .and_then(|()| file.flush())\n            .and_then(|()| file.sync_all())\n",
        "        file.write_all(content.as_bytes())\n            .and_then(|()| file.flush())\n            .and_then(|()| Err(std::io::Error::other(\n                \"injected report durability failure: staged report file sync failed\",\n            )))\n",
    )
}

fn inject_staging_directory_sync_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "fn sync_directory(path: &Path) -> Result<(), XtaskError> {\n",
        "fn sync_directory(path: &Path) -> Result<(), XtaskError> {\n    if path.parent().and_then(Path::file_name).and_then(OsStr::to_str)\n        == Some(\"evidence-report-staging\")\n    {\n        return Err(XtaskError::invalid(\n            \"injected report durability failure\",\n            \"staging directory sync failed\",\n        ));\n    }\n",
    )
}

fn inject_final_report_parent_sync_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "fn sync_directory(path: &Path) -> Result<(), XtaskError> {\n",
        "fn sync_directory(path: &Path) -> Result<(), XtaskError> {\n    if path.file_name().and_then(OsStr::to_str) == Some(\"evidence-reports\") {\n        return Err(XtaskError::invalid(\n            \"injected report durability failure\",\n            \"final report parent sync failed\",\n        ));\n    }\n",
    )
}

fn inject_evidence_directory_parent_sync_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "    sync_directory(child)?;\n    sync_directory(parent)\n",
        "    sync_directory(child)?;\n    if child.file_name().and_then(OsStr::to_str) == Some(\"evidence\") {\n        return Err(XtaskError::invalid(\n            \"injected evidence directory durability failure\",\n            \"evidence directory parent sync failed\",\n        ));\n    }\n    sync_directory(parent)\n",
    )
}

fn inject_report_parent_chain_sync_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "    sync_directory(child)?;\n    sync_directory(parent)\n",
        "    sync_directory(child)?;\n    if child.file_name().and_then(OsStr::to_str) == Some(\"evidence-reports\") {\n        return Err(XtaskError::invalid(\n            \"injected report durability failure\",\n            \"report parent chain sync failed\",\n        ));\n    }\n    sync_directory(parent)\n",
    )
}

fn inject_staging_child_parent_sync_failure(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "    sync_directory(child)?;\n    sync_directory(parent)\n",
        "    sync_directory(child)?;\n    if parent.file_name().and_then(OsStr::to_str)\n        == Some(\"evidence-report-staging\")\n    {\n        return Err(XtaskError::invalid(\n            \"injected report durability failure\",\n            \"staging child parent sync failed\",\n        ));\n    }\n    sync_directory(parent)\n",
    )
}

fn inject_rust_gate_failure_after_format(root: &Path) -> TestResult {
    replace_once(
        &root.join("tools/xtask/src/quality.rs"),
        "    let clippy = run_status(\n",
        "    if root\n        .join(\"target/quality-tools/inject-rust-gate-failure\")\n        .is_file()\n    {\n        return Err(XtaskError::invalid(\n            \"injected canonical prefix failure\",\n            \"rust gate stopped after its first canonical step\",\n        ));\n    }\n    let clippy = run_status(\n",
    )?;
    fs::write(
        root.join("target/quality-tools/inject-rust-gate-failure"),
        "",
    )?;
    Ok(())
}

fn remove_one_m0_01b_owner_coverage_target(root: &Path) -> TestResult {
    let path = root.join("tools/xtask/src/quality.rs");
    replace_once(
        &path,
        "                CoverageTarget::Binary(\"xtask\"),\n",
        "",
    )?;
    let mut content = fs::read_to_string(&path)?;
    content.push_str(
        r#"
/*
                CoverageTarget::Test("foundational_scope_activation"),
                CoverageTarget::Binary("xtask"),
*/
"#,
    );
    fs::write(path, content)?;
    Ok(())
}

fn lower_the_frozen_m0_01_line_baseline(root: &Path) -> TestResult {
    replace_once(
        &root.join("qualification/engineering/thresholds.tsv"),
        &format!("coverage-line\tmeasured-baseline\t{FROZEN_COVERAGE_LINE}"),
        "coverage-line\tmeasured-baseline\t70.00",
    )
}

fn add_square_shaped_search_index_canary(root: &Path) -> TestResult {
    fs::write(
        root.join("target/quality-tools/emit-search-index-square-canary"),
        "",
    )?;
    Ok(())
}

fn add_non_square_search_index_canary(root: &Path) -> TestResult {
    fs::write(
        root.join("target/quality-tools/emit-search-index-projection-canary"),
        "",
    )?;
    Ok(())
}

fn replace_once(path: &Path, before: &str, after: &str) -> TestResult {
    let content = fs::read_to_string(path)?;
    let Some((prefix, suffix)) = content.split_once(before) else {
        return Err(std::io::Error::other(format!(
            "fixture source {} does not contain `{before}`",
            path.display()
        ))
        .into());
    };
    fs::write(path, format!("{prefix}{after}{suffix}"))?;
    Ok(())
}

fn replace_once_in_string(
    content: String,
    before: &str,
    after: &str,
    subject: &str,
) -> TestResult<String> {
    let Some((prefix, suffix)) = content.split_once(before) else {
        return Err(std::io::Error::other(format!(
            "{subject} fixture does not contain `{before}`"
        ))
        .into());
    };
    Ok(format!("{prefix}{after}{suffix}"))
}

fn extract_json_string_after<'content>(
    content: &'content str,
    marker: &str,
) -> TestResult<&'content str> {
    let (_, suffix) = content
        .split_once(marker)
        .ok_or_else(|| std::io::Error::other(format!("fixture omitted marker `{marker}`")))?;
    suffix
        .split_once('"')
        .map(|(value, _)| value)
        .ok_or_else(|| {
            std::io::Error::other(format!("fixture value after `{marker}` is malformed")).into()
        })
}

fn extract_unsigned_after<'content>(
    content: &'content str,
    marker: &str,
) -> TestResult<&'content str> {
    let (_, suffix) = content
        .split_once(marker)
        .ok_or_else(|| std::io::Error::other(format!("fixture omitted marker `{marker}`")))?;
    let length = suffix.bytes().take_while(u8::is_ascii_digit).count();
    suffix
        .get(..length)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            std::io::Error::other(format!("fixture value after `{marker}` is malformed")).into()
        })
}

fn empty_json_arrays_after(
    mut content: String,
    start_marker: &str,
    field: &str,
    count: usize,
) -> TestResult<String> {
    let mut search_from = content
        .find(start_marker)
        .map(|index| index + start_marker.len())
        .ok_or_else(|| std::io::Error::other(format!("fixture omitted `{start_marker}`")))?;
    for _ in 0..count {
        let field_start = content
            .get(search_from..)
            .and_then(|suffix| suffix.find(field))
            .map(|index| search_from + index)
            .ok_or_else(|| std::io::Error::other(format!("fixture omitted `{field}`")))?;
        let array_start = content
            .get(field_start + field.len()..)
            .and_then(|suffix| suffix.find('['))
            .map(|index| field_start + field.len() + index)
            .ok_or_else(|| std::io::Error::other(format!("fixture `{field}` is not an array")))?;
        let mut depth = 0_usize;
        let mut in_string = false;
        let mut escaped = false;
        let mut array_end = None;
        let array_bytes = content
            .as_bytes()
            .get(array_start..)
            .ok_or_else(|| std::io::Error::other(format!("fixture `{field}` array is invalid")))?;
        for (offset, byte) in array_bytes.iter().copied().enumerate() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
                continue;
            }
            match byte {
                b'"' => in_string = true,
                b'[' => depth += 1,
                b']' => {
                    depth = depth.checked_sub(1).ok_or_else(|| {
                        std::io::Error::other(format!("fixture `{field}` array is unbalanced"))
                    })?;
                    if depth == 0 {
                        array_end = Some(array_start + offset);
                        break;
                    }
                },
                _ => {},
            }
        }
        let array_end = array_end
            .ok_or_else(|| std::io::Error::other(format!("fixture `{field}` array is unclosed")))?;
        content.replace_range(array_start..=array_end, "[]");
        search_from = array_start + 2;
    }
    Ok(content)
}

fn replace_all(path: &Path, before: &str, after: &str) -> TestResult {
    let content = fs::read_to_string(path)?;
    if !content.contains(before) {
        return Err(std::io::Error::other(format!(
            "fixture source {} does not contain `{before}`",
            path.display()
        ))
        .into());
    }
    fs::write(path, content.replace(before, after))?;
    Ok(())
}

fn set_scope_field(root: &Path, package: &str, field: &str, value: &str) -> TestResult {
    set_tsv_field(
        &root.join("qualification/engineering/scopes.tsv"),
        "package",
        package,
        field,
        value,
    )
}

fn set_threshold_field(root: &Path, threshold_id: &str, field: &str, value: &str) -> TestResult {
    set_tsv_field(
        &root.join("qualification/engineering/thresholds.tsv"),
        "threshold_id",
        threshold_id,
        field,
        value,
    )
}

fn set_tsv_field(
    path: &Path,
    identity_field: &str,
    identity: &str,
    field: &str,
    value: &str,
) -> TestResult {
    let content = fs::read_to_string(path)?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| std::io::Error::other(format!("{} has no header", path.display())))?;
    let headers = header.split('\t').collect::<Vec<_>>();
    let identity_index = headers
        .iter()
        .position(|header| *header == identity_field)
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "{} has no `{identity_field}` column",
                path.display()
            ))
        })?;
    let field_index = headers
        .iter()
        .position(|header| *header == field)
        .ok_or_else(|| {
            std::io::Error::other(format!("{} has no `{field}` column", path.display()))
        })?;
    let mut rewritten = vec![header.to_owned()];
    let mut replaced = false;
    for line in lines {
        let mut fields = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
        if fields.len() != headers.len() {
            return Err(std::io::Error::other(format!(
                "{} has an unexpected field count",
                path.display()
            ))
            .into());
        }
        let current_value = fields.get(identity_index).ok_or_else(|| {
            std::io::Error::other(format!(
                "{} has no `{identity_field}` column value",
                path.display()
            ))
        })?;
        if current_value == identity {
            let selected_field = fields.get_mut(field_index).ok_or_else(|| {
                std::io::Error::other(format!("{} has no `{field}` column value", path.display()))
            })?;
            *selected_field = value.to_owned();
            replaced = true;
        }
        rewritten.push(fields.join("\t"));
    }
    if !replaced {
        return Err(std::io::Error::other(format!(
            "{} has no `{identity_field}` value `{identity}`",
            path.display()
        ))
        .into());
    }
    fs::write(path, format!("{}\n", rewritten.join("\n")))?;
    Ok(())
}

fn rewrite_scopes(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/scopes.tsv");
    let existing = fs::read_to_string(&path)?;
    let mut rewritten = String::from(
        "package\tpath\tsemantic_owner\tkind\tstate\tactivation_id\tactivation_scope_set\tallowed_edges\trisk_gates\ttest_commands\tcoverage_baseline\tmutation_baseline\tdependency_review\tcontract_evidence\n",
    );
    for (line_number, line) in existing.lines().enumerate() {
        if line_number == 0 {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        let (
            package,
            scope_path,
            semantic_owner,
            kind,
            existing_state,
            existing_risk_gates,
            existing_test_commands,
        ) = match fields.as_slice() {
            [
                package,
                scope_path,
                semantic_owner,
                kind,
                state,
                risk_gates,
                test_commands,
            ] => (
                *package,
                *scope_path,
                *semantic_owner,
                *kind,
                *state,
                *risk_gates,
                *test_commands,
            ),
            [
                package,
                scope_path,
                semantic_owner,
                kind,
                state,
                _,
                _,
                _,
                risk_gates,
                test_commands,
                _,
                _,
                _,
                _,
            ] => (
                *package,
                *scope_path,
                *semantic_owner,
                *kind,
                *state,
                *risk_gates,
                *test_commands,
            ),
            _ => {
                return Err(std::io::Error::other(format!(
                    "unexpected source scope field count on line {}",
                    line_number + 1
                ))
                .into());
            },
        };
        let (
            state,
            activation_id,
            scope_set,
            edges,
            risk_gates,
            test_commands,
            coverage,
            mutation,
            review,
            trace,
        ) = match package {
            "positron-domain" => (
                "active",
                ACTIVATION_ID,
                ACTIVATION_SET,
                "positron-backup->positron-domain|positron-governance->positron-domain|positron-ingest->positron-domain|positron-kernel->positron-domain|positron-query->positron-domain|positron-runtime->positron-domain|positron-signals->positron-domain",
                "EG-COVERAGE",
                "cargo test --locked --package xtask --test foundational_scope_activation",
                "coverage-branch|coverage-changed-code|coverage-line|coverage-region",
                "mutation-score",
                "none",
                POLICY_CHANGE,
            ),
            "positron-api" => (
                "active",
                ACTIVATION_ID,
                ACTIVATION_SET,
                "positron-operator->positron-api|positron-runtime->positron-api",
                "EG-COVERAGE",
                "cargo test --locked --package xtask --test foundational_scope_activation",
                "coverage-branch|coverage-changed-code|coverage-line|coverage-region",
                "mutation-score",
                "none",
                POLICY_CHANGE,
            ),
            "positron-config" => (
                "active",
                ACTIVATION_ID,
                ACTIVATION_SET,
                "positron-runtime->positron-config",
                "EG-COVERAGE",
                "cargo test --locked --package xtask --test foundational_scope_activation",
                "coverage-branch|coverage-changed-code|coverage-line|coverage-region",
                "mutation-score",
                "none",
                POLICY_CHANGE,
            ),
            _ if kind == "application" => ("scaffold", "-", "-", "-", "-", "-", "-", "-", "-", "-"),
            _ => (
                existing_state,
                "-",
                "-",
                "-",
                existing_risk_gates,
                existing_test_commands,
                "-",
                "-",
                "-",
                "-",
            ),
        };
        rewritten.push_str(&format!(
            "{}\t{}\t{}\t{}\t{state}\t{activation_id}\t{scope_set}\t{edges}\t{risk_gates}\t{test_commands}\t{coverage}\t{mutation}\t{review}\t{trace}\n",
            package, scope_path, semantic_owner, kind
        ));
    }
    fs::write(path, rewritten)?;
    Ok(())
}

fn rewrite_edges(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/architecture-edges.tsv");
    let existing = fs::read_to_string(&path)?;
    let mut rewritten = String::from("caller\tdependency\tactivation_id\n");
    for (line_number, line) in existing.lines().enumerate() {
        if line_number == 0 {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        let (caller, dependency) = match fields.as_slice() {
            [caller, dependency] | [caller, dependency, _] => (*caller, *dependency),
            _ => {
                return Err(std::io::Error::other(format!(
                    "unexpected source edge field count on line {}",
                    line_number + 1
                ))
                .into());
            },
        };
        let activation_id = if matches!(
            dependency,
            "positron-domain" | "positron-api" | "positron-config"
        ) {
            ACTIVATION_ID
        } else {
            "-"
        };
        rewritten.push_str(&format!("{caller}\t{dependency}\t{activation_id}\n"));
    }
    fs::write(path, rewritten)?;
    Ok(())
}

fn rewrite_thresholds(root: &Path) -> TestResult {
    let path = root.join("qualification/engineering/thresholds.tsv");
    let existing = fs::read_to_string(&path)?;
    let mut rewritten =
        String::from("threshold_id\tstate\tvalue\tunit\tscope\trationale\tevidence\n");
    for (line_number, line) in existing.lines().enumerate() {
        if line_number == 0 {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        let (
            threshold_id,
            existing_state,
            existing_value,
            unit,
            existing_scope,
            existing_rationale,
        ) = match fields.as_slice() {
            [threshold_id, state, value, unit, scope, rationale]
            | [threshold_id, state, value, unit, scope, rationale, _] => {
                (*threshold_id, *state, *value, *unit, *scope, *rationale)
            },
            _ => {
                return Err(std::io::Error::other(format!(
                    "unexpected source threshold field count on line {}",
                    line_number + 1
                ))
                .into());
            },
        };
        let (state, value, scope, rationale, evidence) = match threshold_id {
            "coverage-line" => (
                "measured-baseline",
                FROZEN_COVERAGE_LINE,
                "m0-01-foundational-policy",
                "Fixture measurement for the public activation-policy seam",
                POLICY_CHANGE,
            ),
            "coverage-region" => (
                "measured-baseline",
                FROZEN_COVERAGE_REGION,
                "m0-01-foundational-policy",
                "Fixture measurement for the public activation-policy seam",
                POLICY_CHANGE,
            ),
            "coverage-branch" => (
                "measured-baseline",
                FROZEN_COVERAGE_BRANCH,
                "m0-01-foundational-policy",
                "Fixture measurement for the public activation-policy seam",
                POLICY_CHANGE,
            ),
            "coverage-changed-code" => (
                "measured-baseline",
                FROZEN_COVERAGE_CHANGED_CODE,
                "m0-01-foundational-policy",
                "Fixture measurement for the public activation-policy seam",
                POLICY_CHANGE,
            ),
            "mutation-score" => (
                "measured-baseline",
                "100.00",
                "m0-01-foundational-policy",
                "Fixture mutation measurement for the public activation-policy seam",
                POLICY_CHANGE,
            ),
            _ => (
                existing_state,
                existing_value,
                existing_scope,
                existing_rationale,
                "-",
            ),
        };
        rewritten.push_str(&format!(
            "{}\t{state}\t{value}\t{}\t{scope}\t{rationale}\t{evidence}\n",
            threshold_id, unit
        ));
    }
    fs::write(path, rewritten)?;
    Ok(())
}

fn write_policy_change(root: &Path) -> TestResult {
    let content = r#"{
  "schema_version": 1,
  "id": "PC-0002-m0-01-foundational-scope-activation",
  "status": "proposed-for-independent-review",
  "activation_id": "M0-01",
  "scope_set": ["positron-domain", "positron-api", "positron-config"],
  "baseline_evidence": "measured",
  "dependency_review": "none",
  "approvals_required": ["Architecture", "Quality Engineering"]
}
"#;
    fs::write(root.join(POLICY_CHANGE), content)?;
    Ok(())
}

fn write_m0_02_policy_change(root: &Path) -> TestResult {
    let content = r#"{
  "schema_version": 1,
  "id": "PC-0007-m0-02-domain-types",
  "status": "proposed-for-independent-review",
  "activation_id": "M0-02",
  "scope_set": ["positron-domain"],
  "baseline_evidence": "measured",
  "dependency_review": "none",
  "approvals_required": ["Architecture", "Quality Engineering"]
}
"#;
    fs::write(root.join(M0_02_POLICY_CHANGE), content)?;
    Ok(())
}

fn remove_scaffold_markers(root: &Path) -> TestResult {
    for package in ["positron-domain", "positron-api", "positron-config"] {
        let path = root.join("crates").join(package).join("src/lib.rs");
        let content = fs::read_to_string(&path)?;
        fs::write(
            path,
            content.replacen("//! @positron-scaffold-only\n", "", 1),
        )?;
    }
    Ok(())
}

fn restore_scaffold_marker(root: &Path, package: &str) -> TestResult {
    if package == "positron-config" {
        let rust_contract = root.join("crates/positron-config/src/contract.rs");
        if rust_contract.is_file() {
            fs::remove_file(rust_contract)?;
        }
    }
    let path = root.join("crates").join(package).join("src/lib.rs");
    let content = fs::read_to_string(&path)?;
    if content.starts_with("//! @positron-scaffold-only\n") {
        return Ok(());
    }
    fs::write(path, format!("//! @positron-scaffold-only\n{content}"))?;
    Ok(())
}

fn install_fixture_tools(root: &Path, real_git: bool) -> TestResult {
    let directory = root.join("target/quality-tools/bin");
    fs::create_dir_all(&directory)?;
    write_tool(
        &directory.join("rustfmt"),
        "#!/bin/sh\nprintf 'rustfmt 1.9.0-stable\\n'\n",
    )?;
    write_tool(
        &directory.join("rustc"),
        "#!/bin/sh\nprintf 'rustc 1.96.0\\n'\n",
    )?;
    write_tool(
        &directory.join("cargo-machete"),
        "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then\n  printf 'cargo-machete 0.9.2\\n'\nfi\n",
    )?;
    write_tool(
        &directory.join("cargo"),
        r#"#!/bin/sh
set -eu
command="${1:-}"
if [ "$command" = "+nightly-2026-07-20" ]; then
  shift
  command="${1:-}"
fi
if [ "$command" = "--config" ]; then
  case "${2:-}" in
    env.POSITRON_MATRIX_BINDING_DIGEST=\"sha256:????????????????????????????????????????????????????????????????\") ;;
    *)
      printf '%s\n' 'fixture received a malformed matrix binding transport' >&2
      exit 78
      ;;
  esac
  shift 2
  command="${1:-}"
fi
case "$command" in
  --version)
    printf 'cargo 1.96.0\n'
    ;;
  clippy)
    if [ "${2:-}" = "--version" ]; then
      printf 'clippy 0.1.96\n'
    fi
    ;;
  nextest)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-nextest 0.9.138\n'
    elif [ "$*" = "nextest run --locked --workspace --all-targets --all-features --profile ci --status-level fail --final-status-level fail" ]; then
      printf '     Summary [   0.001s] 1 tests run: 1 passed, 0 skipped\n' >&2
    else
      printf '%s\n' 'fixture received a noncanonical Nextest invocation' >&2
      exit 78
    fi
    ;;
  deny)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-deny 0.19.9\n'
    fi
    ;;
  audit)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-audit 0.22.2\n'
    fi
    ;;
  metadata)
    if [ -f target/quality-tools/emit-large-dependency-metadata ]; then
      printf '%s' '{"packages":['
      index=0
      padding='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
      while [ "$index" -lt 440 ]; do
        if [ "$index" -ne 0 ]; then
          printf ','
        fi
        printf '{"name":"fixture-%s","description":"%s"}' "$index" "$padding"
        index=$((index + 1))
      done
      printf '%s\n' '],"workspace_members":[],"workspace_root":"/fixture","target_directory":"/fixture/target","resolve":{}}'
    else
      printf '%s\n' '{"packages":[],"workspace_members":[],"workspace_root":"/fixture","target_directory":"/fixture/target","resolve":{}}'
    fi
    ;;
  vet)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-vet 0.10.2\n'
    fi
    ;;
  llvm-cov)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-llvm-cov 0.8.7\n'
      exit 0
    fi
    if [ -f target/quality-tools/require-owner-verdict-coverage ]; then
      owner_verdict_suite=false
      previous=
      for argument in "$@"; do
        if [ "$previous" = "--bin" ] && [ "$argument" = "xtask" ]; then
          owner_verdict_suite=true
          break
        fi
        previous="$argument"
      done
      if [ "$owner_verdict_suite" != true ]; then
        printf '%s\n' 'fixture requires controlled owner verdict coverage' >&2
        exit 76
      fi
    fi
    if [ -f target/quality-tools/reject-coverage-execution ]; then
      printf '%s\n' 'fixture rejects routine coverage execution' >&2
      exit 75
    fi
    output=
    previous=
    for argument in "$@"; do
      if [ "$previous" = "--output-path" ]; then
        output="$argument"
        break
      fi
      previous="$argument"
    done
    if [ -n "$output" ]; then
      mkdir -p "$(dirname "$output")"
      printf '%s\n' '{"data":[{"totals":{"branches":{"percent":100.0},"lines":{"percent":100.0},"regions":{"percent":100.0}}}]}' > "$output"
    fi
    ;;
  mutants)
    if [ "${2:-}" = "--version" ]; then
      printf 'cargo-mutants 27.1.0\n'
      exit 0
    fi
    if [ ! -f target/quality-tools/require-m0-02-mutation ]; then
      printf '%s\n' 'fixture rejects unselected M0-02 mutation execution' >&2
      exit 80
    fi
    output=
    previous=
    for argument in "$@"; do
      if [ "$previous" = "--output" ]; then
        output="$argument"
        break
      fi
      previous="$argument"
    done
    if [ -z "$output" ]; then
      printf '%s\n' 'fixture requires a retained mutation output path' >&2
      exit 81
    fi
    mkdir -p "$output/mutants.out"
    printf '%s\n' '{"outcomes":[]}' > "$output/mutants.out/outcomes.json"
    ;;
  doc)
    target="${CARGO_TARGET_DIR:?CARGO_TARGET_DIR is required}"
    document_root="$target/doc"
    search_index="$document_root/search.index/7ee4fc406f.js"
    mkdir -p "$(dirname "$search_index")"
    token_prefix=$(printf '\163\161\060\141\164\160\055')
    : > "$search_index"
    if [ -f target/quality-tools/emit-search-index-square-canary ]; then
      printf '%s%s\n' "$token_prefix" '1111111111111111111111' > "$search_index"
    fi
    if [ -f target/quality-tools/emit-search-index-projection-canary ]; then
      printf '%s\n' 'GENERATED_DOC_NON_SQUARE_SECRET_CANARY' >> "$search_index"
    fi
    ;;
  run)
    case " $* " in
      *" quality-security-probe "*)
        printf '%s\n' 'security-probe-result-v1=authn:unauthenticated|authz:forbidden|tenant:tenant-mismatch|allow:allowed'
        ;;
      *" quality-secret-canary "*)
        golden=qualification/fixtures/adversarial/cryptography/m0-10-security-canary-golden.tsv
        leak=qualification/fixtures/adversarial/cryptography/m0-10-secret-canary-leak.tsv
        if [ "$(wc -l < "$golden")" -ne 10 ] || ! grep -qx 'logs	REDACTED:logs' "$golden"; then
          printf '%s\n' 'committed canary golden drifted' >&2
          exit 79
        fi
        if [ "$(wc -l < "$leak")" -ne 2 ] || ! grep -qx 'support-artifacts	leak' "$leak"; then
          printf '%s\n' 'intentional leak fixture drifted' >&2
          exit 79
        fi
        artifact_root=
        selector=
        previous=
        for argument in "$@"; do
          if [ "$previous" = "quality-secret-canary" ]; then
            artifact_root="$argument"
          elif [ -n "$artifact_root" ]; then
            selector="$argument"
          fi
          previous="$argument"
        done
        if [ -z "$artifact_root" ] || [ "$selector" != "registered-synthetic-v1-r001" ]; then
          printf '%s\n' 'candidate artifact invocation drifted' >&2
          exit 79
        fi
        mkdir -p "$artifact_root/written" "$artifact_root/packaged" "$artifact_root/collected"
        for sink in logs errors metrics traces diagnostics evidence binaries packages support-artifacts; do
          printf 'REDACTED:%s' "$sink" > "$artifact_root/written/$sink.artifact"
          printf 'REDACTED:%s' "$sink" > "$artifact_root/packaged/$sink.artifact"
          printf 'REDACTED:%s' "$sink" > "$artifact_root/collected/$sink.artifact"
        done
        if [ -f target/quality-tools/emit-m0-10-intentional-leak ]; then
          canary_prefix=POSITRON
          canary_kind=SYNTHETIC
          canary_label=CANARY
          canary_version=V1
          printf '%s_%s_%s_%s:%s' "$canary_prefix" "$canary_kind" "$canary_label" "$canary_version" support-artifacts \
            > "$artifact_root/collected/support-artifacts.artifact"
        fi
        ;;
      *)
        printf '%s\n' 'fixture received an unregistered xtask child command' >&2
        exit 77
        ;;
    esac
    ;;
  test)
    package=
    previous=
    for argument in "$@"; do
      if [ "$previous" = "--package" ]; then
        package="$argument"
        break
      fi
      previous="$argument"
    done
    if [ "$package" = "positron-domain" ] && [ -f target/quality-tools/reject-m0-02-dynamic-execution ]; then
      printf '%s\n' 'fixture rejects M0-02 dynamic execution' >&2
      exit 75
    fi
    if [ "$package" = "xtask" ]; then
      case " $* " in
        *" security_harness::tests::crypto_self_test_covers_the_registered_harness_obligations "*)
          ;;
        *)
          printf '%s\n' 'private runner self-tests are not qualification fixtures' >&2
          exit 77
          ;;
      esac
    fi
    ;;
  tree)
    package=unknown
    previous=
    for argument in "$@"; do
      if [ "$previous" = "--package" ]; then
        package=$argument
        break
      fi
      previous=$argument
    done
    printf '%s v0.0.0\n' "$package"
    ;;
esac
"#,
    )?;
    write_tool(
        &directory.join("gitleaks"),
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "version" ]; then
  printf '8.30.1\n'
  exit 0
fi
if [ "${1:-}" != "dir" ]; then
  exit 0
fi
target=
for argument in "$@"; do
  case "$argument" in
    --*)
      ;;
    dir)
      ;;
    *)
      target=$argument
      ;;
  esac
done
if [ -z "$target" ]; then
  target=.
fi
search_index="$target/search.index/7ee4fc406f.js"
if [ -f "$search_index" ]; then
  square_prefix=$(printf '\163\161\060\141\164\160\055')
  if grep -E "${square_prefix}[0-9]{22}" "$search_index" >/dev/null; then
    printf '%s\n' 'fixture detected Square-shaped secret canary' >&2
    exit 78
  fi
  if grep -F 'GENERATED_DOC_NON_SQUARE_SECRET_CANARY' "$search_index" >/dev/null; then
    printf '%s\n' 'fixture detected generated search-index non-Square secret canary' >&2
    exit 79
  fi
fi
exit 0
"#,
    )?;
    if !real_git {
        write_tool(
            &directory.join("git"),
            r#"#!/bin/sh
set -eu
case "${1:-}" in
  merge-base)
    if [ ! -f target/quality-tools/m0-10-missing-merge-base ]; then
      if [ -f target/quality-tools/m0-11-current-origin-main ]; then
        printf '%s\n' '9879d5924cb9af75e95ec2634469973e09f681e5'
      else
        printf '%s\n' '542f3835dc67f819e566e017c04e165b15416861'
      fi
    fi
    ;;
  diff)
    if [ -f target/quality-tools/m0-11-current-origin-main ]; then
      printf '%s\n' 'qualification/engineering/exact-targets-golden.tsv'
      printf '%s\n' 'qualification/engineering/exact-targets-invalid.tsv'
      printf '%s\n' 'qualification/engineering/exact-targets.tsv'
      printf '%s\n' 'qualification/engineering/policy-changes/PC-0016-m0-11-compatibility-exact-target-matrix.json'
      printf '%s\n' 'qualification/engineering/security-canary-targets.tsv'
      printf '%s\n' 'qualification/engineering/scopes.tsv'
      printf '%s\n' 'tools/xtask/src/bounded_input.rs'
      printf '%s\n' 'tools/xtask/src/crypto_targets.rs'
      printf '%s\n' 'tools/xtask/src/main.rs'
      printf '%s\n' 'tools/xtask/src/matrix_execution_plan.rs'
      printf '%s\n' 'tools/xtask/src/matrix_product_target.rs'
      printf '%s\n' 'tools/xtask/src/matrix_targets.rs'
      printf '%s\n' 'tools/xtask/src/matrix_verifier.rs'
      printf '%s\n' 'tools/xtask/src/quality.rs'
      printf '%s\n' 'tools/xtask/src/registry.rs'
      printf '%s\n' 'tools/xtask/src/security_catalog.rs'
      printf '%s\n' 'tools/xtask/src/security_change_review.rs'
      printf '%s\n' 'tools/xtask/src/security_harness.rs'
      printf '%s\n' 'tools/xtask/src/security_harness/canary.rs'
      printf '%s\n' 'tools/xtask/src/security_harness/canary_tests.rs'
      printf '%s\n' 'tools/xtask/src/security_threat_surface.rs'
      printf '%s\n' 'tools/xtask/tests/fixtures/m0_11_exact_targets_golden.tsv'
      printf '%s\n' 'tools/xtask/tests/fixtures/m0_11_exact_targets_invalid.tsv'
      printf '%s\n' 'tools/xtask/tests/foundational_scope_activation.rs'
      printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_11_matrix.rs'
      printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_11_matrix_binding.rs'
      printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_11_matrix_execution.rs'
      printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_11_matrix_lifecycle.rs'
      printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_11_matrix_policy.rs'
      exit 0
    fi
    if [ -f target/quality-tools/m0-10-current-origin-main ]; then
      printf '%s\n' 'qualification/engineering/README.md'
      printf '%s\n' 'qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json'
      printf '%s\n' 'qualification/engineering/scopes.tsv'
      printf '%s\n' 'qualification/engineering/security-canary-targets.tsv'
      printf '%s\n' 'qualification/engineering/security-crypto-targets.tsv'
      printf '%s\n' 'qualification/engineering/security-runners.tsv'
      printf '%s\n' 'qualification/engineering/security-threat-surfaces.tsv'
      printf '%s\n' 'qualification/engineering/security/TM-0010-m0-10-runner-crypto.json'
      printf '%s\n' 'qualification/engineering/security/TM-0011-m0-10-runner-artifacts.json'
      printf '%s\n' 'qualification/fixtures/adversarial/cryptography/m0-10-secret-canary-leak.tsv'
      printf '%s\n' 'qualification/fixtures/adversarial/cryptography/m0-10-security-canary-golden.tsv'
      printf '%s\n' 'tools/xtask/src/bounded_input.rs'
      printf '%s\n' 'tools/xtask/src/crypto_targets.rs'
      printf '%s\n' 'tools/xtask/src/main.rs'
      printf '%s\n' 'tools/xtask/src/quality.rs'
      printf '%s\n' 'tools/xtask/src/security_catalog.rs'
      printf '%s\n' 'tools/xtask/src/security_change_review.rs'
      printf '%s\n' 'tools/xtask/src/security_harness.rs'
      printf '%s\n' 'tools/xtask/src/security_harness/canary.rs'
      printf '%s\n' 'tools/xtask/src/security_harness/canary_budget.rs'
      printf '%s\n' 'tools/xtask/src/security_harness/canary_tests.rs'
      printf '%s\n' 'tools/xtask/src/security_harness/crypto.rs'
      printf '%s\n' 'tools/xtask/src/security_threat_surface.rs'
      printf '%s\n' 'tools/xtask/tests/foundational_scope_activation.rs'
      printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_10_final_blockers.rs'
      printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_10_security_crypto.rs'
      exit 0
    fi
    if [ -f target/quality-tools/m0-10-unclassified-changed-path ]; then
      printf '%s\n' 'tools/xtask/src/security_catalog.rs'
      exit 0
    fi
    if [ -f target/quality-tools/m0-10-uncovered-security-path ]; then
      printf '%s\n' 'tools/xtask/src/security_harness/uncovered.rs'
      exit 0
    fi
    printf '%s\n' 'qualification/engineering/README.md'
    printf '%s\n' 'qualification/engineering/policy-changes/PC-0015-m0-10-security-crypto-runners.json'
    printf '%s\n' 'qualification/engineering/scopes.tsv'
    printf '%s\n' 'qualification/engineering/security-canary-targets.tsv'
    printf '%s\n' 'qualification/engineering/security-crypto-targets.tsv'
    printf '%s\n' 'qualification/engineering/security-runners.tsv'
    printf '%s\n' 'qualification/engineering/security-threat-surfaces.tsv'
    printf '%s\n' 'qualification/engineering/security/TM-0010-m0-10-runner-crypto.json'
    printf '%s\n' 'qualification/engineering/security/TM-0011-m0-10-runner-artifacts.json'
    printf '%s\n' 'qualification/fixtures/adversarial/cryptography/m0-10-secret-canary-leak.tsv'
    printf '%s\n' 'qualification/fixtures/adversarial/cryptography/m0-10-security-canary-golden.tsv'
    printf '%s\n' 'tools/xtask/src/bounded_input.rs'
    printf '%s\n' 'tools/xtask/src/crypto_targets.rs'
    printf '%s\n' 'tools/xtask/src/main.rs'
    printf '%s\n' 'tools/xtask/src/quality.rs'
    printf '%s\n' 'tools/xtask/src/security_catalog.rs'
    printf '%s\n' 'tools/xtask/src/security_change_review.rs'
    printf '%s\n' 'tools/xtask/src/security_harness.rs'
    printf '%s\n' 'tools/xtask/src/security_harness/canary.rs'
    printf '%s\n' 'tools/xtask/src/security_harness/canary_budget.rs'
    printf '%s\n' 'tools/xtask/src/security_harness/canary_tests.rs'
    printf '%s\n' 'tools/xtask/src/security_harness/crypto.rs'
    printf '%s\n' 'tools/xtask/src/security_threat_surface.rs'
    printf '%s\n' 'tools/xtask/tests/foundational_scope_activation.rs'
    printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_10_final_blockers.rs'
    printf '%s\n' 'tools/xtask/tests/foundational_scope_activation/m0_10_security_crypto.rs'
    ;;
  rev-parse)
    printf '%s\n' '0000000000000000000000000000000000000000'
    ;;
  status)
    ;;
  hash-object)
    cat >/dev/null
    printf '%s\n' '1111111111111111111111111111111111111111'
    ;;
  *)
    printf 'unsupported fixture git command: %s\n' "${1:-}" >&2
    exit 2
    ;;
esac
"#,
        )?;
    }
    Ok(())
}

fn write_tool(path: &Path, content: &str) -> TestResult {
    fs::write(path, content)?;
    make_executable(path)?;
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> TestResult {
    Ok(())
}

fn initialize_git_repository(root: &Path) -> TestResult {
    run_git(root, ["init", "--quiet"])?;
    run_git(root, ["config", "user.email", "fixtures@example.invalid"])?;
    run_git(root, ["config", "user.name", "Positron fixture"])?;
    run_git(root, ["add", "."])?;
    run_git(root, ["commit", "--quiet", "-m", "fixture"])?;
    Ok(())
}

fn run_git<const N: usize>(root: &Path, arguments: [&str; N]) -> TestResult {
    let status = Command::new("git")
        .current_dir(root)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(arguments)
        .status()?;
    if status.success() {
        return Ok(());
    }
    Err(std::io::Error::other("fixture Git setup failed").into())
}
