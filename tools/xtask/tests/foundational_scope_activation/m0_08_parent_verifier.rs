use super::m0_08_support::*;
use super::*;

#[test]
fn quality_rejects_a_post_verification_forged_worker_slot_through_the_public_seam() -> TestResult {
    assert_post_verification_record_rejected(
        "EG-CONCURRENCY",
        "Ok(record.replace(\"workers=0:0:cancelled\", \"workers=0:1:cancelled\"))",
        "worker schedule slots do not exactly match the frozen scenario",
    )
}

#[test]
fn quality_rejects_a_post_verification_malformed_measurement_through_the_public_seam() -> TestResult
{
    assert_post_verification_record_rejected(
        "EG-CONCURRENCY",
        "Ok(\"measurement-v1;workers\".to_owned())",
        "child measurement contains a malformed field",
    )
}

#[test]
fn quality_rejects_a_post_verification_missing_field_through_the_public_seam() -> TestResult {
    assert_post_verification_record_rejected(
        "EG-CONCURRENCY",
        "Ok(record.replace(\";joined-ids=0,1,2\", \"\"))",
        "child measurement omits a required field",
    )
}

#[test]
fn quality_rejects_a_post_verification_duplicate_field_through_the_public_seam() -> TestResult {
    assert_post_verification_record_rejected(
        "EG-CONCURRENCY",
        "Ok(format!(\"{record};retries=0\"))",
        "child measurement contains a duplicate field",
    )
}

#[test]
fn quality_rejects_a_post_verification_extra_field_through_the_public_seam() -> TestResult {
    assert_post_verification_record_rejected(
        "EG-CONCURRENCY",
        "Ok(format!(\"{record};fabricated=true\"))",
        "child measurement contains an extra or stale field",
    )
}

#[test]
fn quality_rejects_a_post_verification_stale_schema_through_the_public_seam() -> TestResult {
    assert_post_verification_record_rejected(
        "EG-CONCURRENCY",
        "Ok(record.replacen(\"measurement-v1\", \"measurement-v0\", 1))",
        "child measurement schema identity is missing or stale",
    )
}

#[test]
fn quality_rejects_a_post_verification_mismatched_identity_through_the_public_seam() -> TestResult {
    assert_post_verification_record_rejected(
        "EG-CONCURRENCY",
        "Ok(record.replace(\"seed=seed-concurrency-v1\", \"seed=stale-seed-v1\"))",
        "child measurement identity mismatches the frozen scenario",
    )
}

#[test]
fn quality_rejects_a_post_verification_resource_count_through_the_public_seam() -> TestResult {
    assert_post_verification_record_rejected(
        "EG-RESOURCE",
        "Ok(record.replace(\"registered=3\", \"registered=2\"))",
        "worker count does not exactly match the frozen scenario",
    )
}

#[test]
fn quality_rejects_a_post_verification_resource_retry_ceiling_through_the_public_seam() -> TestResult
{
    assert_post_verification_record_rejected(
        "EG-RESOURCE",
        "Ok(record.replace(\"retries=2\", \"retries=1\"))",
        "resource retry ceiling, reservation release, or queue outcome is false",
    )
}

#[test]
fn quality_rejects_a_post_verification_resource_fairness_through_the_public_seam() -> TestResult {
    assert_post_verification_record_rejected(
        "EG-RESOURCE",
        "Ok(record.replace(\"workers=0:0:executed,1:1:executed,2:2:executed\", \"workers=1:0:executed,0:1:executed,2:2:executed\"))",
        "worker order does not prove the frozen fair resource schedule",
    )
}

#[test]
fn quality_rejects_a_post_verification_missing_join_through_the_public_seam() -> TestResult {
    assert_post_verification_record_rejected(
        "EG-RESOURCE",
        "Ok(record.replace(\"joined-ids=0,1,2\", \"joined-ids=0,1\"))",
        "joined worker IDs do not exactly match the frozen lifecycle",
    )
}

#[test]
fn quality_rejects_a_post_verification_wrong_shutdown_bound_through_the_public_seam() -> TestResult
{
    assert_post_verification_record_rejected(
        "EG-RESOURCE",
        "Ok(record.replace(\"shutdown-ms=100\", \"shutdown-ms=99\"))",
        "worker shutdown bound does not match the frozen lifecycle",
    )
}

#[test]
fn quality_rejects_a_post_capture_registry_swap_that_attempts_to_authorize_child_tamper()
-> TestResult {
    assert_post_verification_record_rejected(
        "EG-CONCURRENCY",
        r#"fs::write(
        REGISTRY_PATH,
        b"scenario_id\tgate_id\tspawn_site\tschedule\tseed\tmax_tasks\tqueue_capacity\treservation_capacity\tretry_limit\tshutdown_ms\texpected\nconcurrency-cancel-join\tEG-CONCURRENCY\tquality-bounded-worker-v1\tforged-schedule-v1\tseed-concurrency-v1\t3\t1\t1\t1\t100\tcancelled-then-joined-v1\nresource-fair-pressure\tEG-RESOURCE\tquality-bounded-worker-v1\tround-robin-pressure-v1\tseed-resource-v1\t3\t3\t2\t2\t100\tfair-pressure-retry-leak-free-v1\n",
    )
    .map_err(|source| XtaskError::io("test post-capture scenario registry swap", source))?;
    Ok(record.replace("schedule=cancel-then-join-v1", "schedule=forged-schedule-v1"))"#,
        "child measurement identity mismatches the frozen scenario",
    )
}

#[test]
fn quality_rejects_parent_gate_descriptor_drift_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture.root.join("qualification/engineering/gates.tsv"),
            "EG-CONCURRENCY\tPR|EXT|QUAL\tApplication Runtime\t900\t4096\tnon-waivable\trisk\tconcurrency",
            "EG-CONCURRENCY\tPR|EXT|QUAL\tApplication Runtime\t901\t4096\tnon-waivable\trisk\tconcurrency",
        )?;
        let output = fixture.quality_output_for("pr")?;
        assert_parent_verifier_failure(
            &fixture,
            &output,
            "EG-CONCURRENCY",
            "parent-captured gate descriptor does not match the frozen gate contract",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_parent_captured_capacity_drift_when_child_checks_are_removed() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RESOURCE|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture
                .root
                .join("qualification/engineering/concurrency-fixtures.tsv"),
            "resource-fair-pressure\tEG-RESOURCE\tquality-bounded-worker-v1\tround-robin-pressure-v1\tseed-resource-v1\t3\t3\t2\t2\t100\tfair-pressure-retry-leak-free-v1",
            "resource-fair-pressure\tEG-RESOURCE\tquality-bounded-worker-v1\tround-robin-pressure-v1\tseed-resource-v1\t3\t3\t3\t2\t100\tfair-pressure-retry-leak-free-v1",
        )?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        replace_once(
            &source,
            "    validate_resource_scenario(scenario)?;\n",
            "    let _child_scenario_check_is_diagnostic_only = validate_resource_scenario;\n",
        )?;
        replace_once(
            &source,
            "    verify_child_measurement_record(scenario, &record, ScenarioGate::Resource)?;\n    Ok(record)",
            "    Ok(record)",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_parent_verifier_failure(
            &fixture,
            &output,
            "EG-RESOURCE",
            "parent-captured scenario identity or capacity bounds drifted from the contract",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_parent_captured_spawn_owner_drift_when_source_policy_is_removed() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture
                .root
                .join("qualification/engineering/concurrency-spawn-sites.tsv"),
            "tools/xtask/src/registered_task_lifecycle.rs\tRegisteredTasks::spawn\tthread\tquality-bounded-worker-v1",
            "tools/xtask/src/registered_task_lifecycle.rs\tRegisteredTasks::forged\tthread\tquality-bounded-worker-v1",
        )?;
        replace_once(
            &fixture.root.join("tools/xtask/src/quality.rs"),
            "    crate::bounded_runners::validate_source_policy(registry, root)?;\n",
            "    let _child_source_policy_is_diagnostic_only = crate::bounded_runners::validate_source_policy;\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_parent_verifier_failure(
            &fixture,
            &output,
            "EG-CONCURRENCY",
            "parent-captured spawn registry omitted an exact lifecycle owner",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_extra_parent_captured_spawn_owner_when_source_policy_is_removed() -> TestResult
{
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let registry = fixture
            .root
            .join("qualification/engineering/concurrency-spawn-sites.tsv");
        let mut content = fs::read_to_string(&registry)?;
        content.push_str(
            "tools/xtask/src/controlled_execution.rs\tforged_owner\tprocess\tforged-owner-v1\n",
        );
        fs::write(&registry, content)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/quality.rs"),
            "    crate::bounded_runners::validate_source_policy(registry, root)?;\n",
            "    let _child_source_policy_is_diagnostic_only = crate::bounded_runners::validate_source_policy;\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_parent_verifier_failure(
            &fixture,
            &output,
            "EG-CONCURRENCY",
            "parent-captured spawn registry contains a missing, extra, or stale lifecycle owner",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_post_verification_record_rejected(
    gate: &str,
    tampered_return: &str,
    expected_detail: &str,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        let gate_kind = match gate {
            "EG-CONCURRENCY" => {
                enable_concurrency_gate(&fixture)?;
                "Concurrency"
            },
            "EG-RESOURCE" => {
                set_scope_field(
                    &fixture.root,
                    "xtask",
                    "risk_gates",
                    "EG-00|EG-ARCH|EG-BUILD|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RESOURCE|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
                )?;
                "Resource"
            },
            _ => {
                return Err(
                    std::io::Error::other("parent verifier test selected an unknown gate").into(),
                );
            },
        };
        let verified_return = format!(
            "    verify_child_measurement_record(scenario, &record, ScenarioGate::{gate_kind})?;\n    Ok(record)"
        );
        let tampered_return = format!(
            "    verify_child_measurement_record(scenario, &record, ScenarioGate::{gate_kind})?;\n    {tampered_return}"
        );
        replace_once(
            &fixture.root.join("tools/xtask/src/bounded_runners.rs"),
            &verified_return,
            &tampered_return,
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_parent_verifier_failure(&fixture, &output, gate, expected_detail)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_parent_verifier_failure(
    fixture: &Fixture,
    output: &std::process::Output,
    gate: &str,
    expected_detail: &str,
) -> TestResult {
    let expected = format!("parent bounded measurement verifier: {expected_detail}");
    assert_rejected_output(output, &expected)?;
    let evidence = fixture.latest_evidence()?;
    if !gate_record(&evidence, gate)?.contains("\"result\": \"failed\"") {
        return Err(std::io::Error::other(format!(
            "{gate} parent-verifier tamper did not retain a failed gate outcome"
        ))
        .into());
    }
    let report = fs::read_to_string(exact_raw_report_path(&fixture.root, &evidence, gate)?)?;
    if !report.contains(&expected) {
        return Err(std::io::Error::other(format!(
            "{gate} retained report omitted parent-verifier failure `{expected}`"
        ))
        .into());
    }
    Ok(())
}
