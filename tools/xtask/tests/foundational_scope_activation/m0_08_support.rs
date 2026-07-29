use super::*;

pub(super) fn enable_concurrency_gate(fixture: &Fixture) -> TestResult {
    set_scope_field(
        &fixture.root,
        "xtask",
        "risk_gates",
        "EG-00|EG-ARCH|EG-BUILD|EG-CONCURRENCY|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
    )
}

pub(super) fn assert_imported_concurrency_alias_rejected(source_append: &str) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(source_append);
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "unregistered imported concurrency primitive alias")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

pub(super) fn assert_unbounded_concurrency_primitive_rejected(source_append: &str) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(source_append);
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "unbounded concurrency primitive")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

pub(super) fn assert_tampered_resource_slots_rejected(
    original: &str,
    tampered: &str,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RESOURCE|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture.root.join("tools/xtask/src/bounded_runners.rs"),
            "    verify_measurement_record(scenario, &record, ScenarioGate::Resource)?;\n",
            &format!(
                "    let record = record.replace(\"{original}\", \"{tampered}\");\n    verify_measurement_record(scenario, &record, ScenarioGate::Resource)?;\n"
            ),
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "schedule slots are not unique and contiguous")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

pub(super) fn assert_concurrency_lifecycle_failure(
    fixture: &Fixture,
    spawned_ids: &str,
) -> TestResult {
    assert_lifecycle_observations(fixture, spawned_ids, spawned_ids, spawned_ids)
}

pub(super) fn assert_lifecycle_observations(
    fixture: &Fixture,
    spawned_ids: &str,
    completed_ids: &str,
    joined_ids: &str,
) -> TestResult {
    let evidence = fixture.latest_evidence()?;
    if !gate_record(&evidence, "EG-CONCURRENCY")?.contains("\"result\": \"failed\"") {
        return Err(std::io::Error::other(
            "lifecycle fault did not retain a failed concurrency gate outcome",
        )
        .into());
    }
    let report = fs::read_to_string(exact_raw_report_path(
        &fixture.root,
        &evidence,
        "EG-CONCURRENCY",
    )?)?;
    let required = format!("lifecycle-v1;spawned-ids={spawned_ids};cancelled-ids=");
    if !report.contains(&required)
        || !report.contains(&format!("completed-ids={completed_ids};"))
        || !report.contains(&format!("joined-ids={joined_ids};"))
        || !report.contains(";live=0")
    {
        return Err(std::io::Error::other(format!(
            "lifecycle failure did not retain reconciliation evidence `{required}`: {report}"
        ))
        .into());
    }
    Ok(())
}

pub(super) fn assert_lifecycle_state(fixture: &Fixture, state: &str) -> TestResult {
    let evidence = fixture.latest_evidence()?;
    let report = fs::read_to_string(exact_raw_report_path(
        &fixture.root,
        &evidence,
        "EG-CONCURRENCY",
    )?)?;
    if !report.contains(state)
        || !report.contains("joined-ids=0,1,2;")
        || !report.contains(";live=0")
    {
        return Err(
            std::io::Error::other(format!("missing truthful lifecycle state `{state}`")).into(),
        );
    }
    Ok(())
}

pub(super) fn assert_controlled_process_deadline_failure(
    fixture: &Fixture,
    output: &std::process::Output,
) -> TestResult {
    assert_rejected_output(output, "controlled runner failed during deadline")?;
    let evidence = fixture.latest_evidence()?;
    let gate = gate_record(&evidence, "EG-CONCURRENCY")?;
    if !gate.contains("\"result\": \"failed\"")
        || gate
            .matches("\"program\":\"cargo-xtask-quality/bounded-runner\"")
            .count()
            != 1
    {
        return Err(std::io::Error::other(
            "deadline failure did not retain exactly one controlled runner invocation",
        )
        .into());
    }
    let report = fs::read_to_string(exact_raw_report_path(
        &fixture.root,
        &evidence,
        "EG-CONCURRENCY",
    )?)?;
    for required in [
        "\"verdict\":\"controlled-failure:deadline\"",
        "process-lifecycle-v1;phase=deadline",
        "termination-requested=true",
        "process-reaped=true",
        "live=0",
        "deadline-ms=100",
    ] {
        if !report.contains(required) {
            return Err(std::io::Error::other(format!(
                "controlled deadline report omitted `{required}`"
            ))
            .into());
        }
    }
    Ok(())
}

pub(super) fn assert_cancellation_state(
    original_dispatch: &str,
    expected_error: &str,
    state: &str,
    replacement_dispatch: &str,
) -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        if !original_dispatch.is_empty() {
            replace_once(&source, original_dispatch, replacement_dispatch)?;
        }
        replace_once(
            &source,
            "            tasks.dispatch(1, WorkerCommand::Execute { schedule_slot: 1 })?;\n            tasks.dispatch(2, WorkerCommand::Execute { schedule_slot: 2 })?;\n            Ok(())",
            "            Err(XtaskError::invalid(\"test cancellation state\", \"injected mid-dispatch failure\"))",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, expected_error)?;
        assert_lifecycle_state(&fixture, state)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}
