use super::m0_08_support::*;
use super::*;

#[test]
fn quality_runs_concurrency_and_resource_through_the_registered_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CONCURRENCY|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RESOURCE|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let output = fixture.quality_output_for("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "registered concurrency/resource runners did not complete successfully: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        for (gate, required) in [
            (
                "EG-CONCURRENCY",
                "measurement-v1;scenario=concurrency-cancel-join;schedule=cancel-then-join-v1;seed=seed-concurrency-v1;registered=3;workers=0:0:cancelled,1:1:executed,2:2:executed;retries=0;reservations=0;queue-empty=true;joined-ids=0,1,2;shutdown-ms=100",
            ),
            (
                "EG-RESOURCE",
                "measurement-v1;scenario=resource-fair-pressure;schedule=round-robin-pressure-v1;seed=seed-resource-v1;registered=3;workers=0:0:executed,1:1:executed,2:2:executed;retries=2;reservations=0;queue-empty=true;joined-ids=0,1,2;shutdown-ms=100",
            ),
        ] {
            let record = gate_record(&evidence, gate)?;
            if !record.contains("\"result\": \"passed\"") {
                return Err(std::io::Error::other(format!(
                    "{gate} did not retain a passing public outcome"
                ))
                .into());
            }
            let report =
                fs::read_to_string(exact_raw_report_path(&fixture.root, &evidence, gate)?)?;
            if !report.contains(required) {
                return Err(std::io::Error::other(format!(
                    "{gate} immutable raw report omitted lifecycle evidence `{required}`"
                ))
                .into());
            }
            for parent_binding in [
                "parent-measurement-verification-v1",
                "identity=parent-bounded-measurement-verifier-v1",
                "version=1",
                "verifier-sha256=sha256:20a2dc38a14b0fdf864234b574144df77cfadf33b79335fe7124f68832d20be3",
                "verdict=passed",
                &format!("gate={gate}"),
                "gate-descriptor-sha256=sha256:",
                "scenario-registry-sha256=sha256:",
                "spawn-registry-sha256=sha256:",
                "measurement-sha256=sha256:",
                "child-self-verification=diagnostic-only",
                "process-reaped=true;live=0",
            ] {
                if !report.contains(parent_binding) {
                    return Err(std::io::Error::other(format!(
                        "{gate} immutable raw report omitted parent verification binding `{parent_binding}`"
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
fn quality_reconciles_after_a_partial_registered_spawn_failure_through_the_public_seam()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture
                .root
                .join("tools/xtask/src/registered_task_lifecycle.rs"),
            "            let worker_results = results_sender.clone();\n",
            "            if id == 1 { return owner.reconcile_failure(XtaskError::invalid(\"test lifecycle spawn\", \"injected partial spawn failure\")); }\n            let worker_results = results_sender.clone();\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "injected partial spawn failure")?;
        assert_concurrency_lifecycle_failure(&fixture, "0")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_reconciles_after_a_mid_dispatch_failure_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/bounded_runners.rs"),
            "            tasks.dispatch(1, WorkerCommand::Execute { schedule_slot: 1 })?;\n            tasks.dispatch(2, WorkerCommand::Execute { schedule_slot: 2 })?;\n            Ok(())",
            "            Err(XtaskError::invalid(\"test lifecycle dispatch\", \"injected mid-dispatch failure\"))",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "injected mid-dispatch failure")?;
        assert_concurrency_lifecycle_failure(&fixture, "0,1,2")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_reconciles_after_a_result_timeout_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture.root.join("qualification/engineering/gates.tsv"),
            "EG-CONCURRENCY\tPR|EXT|QUAL\tApplication Runtime\t900\t4096\tnon-waivable\trisk\tconcurrency",
            "EG-CONCURRENCY\tPR|EXT|QUAL\tApplication Runtime\t1\t4096\tnon-waivable\trisk\tconcurrency",
        )?;
        replace_once(
            &fixture
                .root
                .join("tools/xtask/src/registered_task_lifecycle.rs"),
            "    let (completion, schedule_slot) = match command {",
            "    cooperative_pause(&cancel, Duration::from_millis(1250))?;\n    let (completion, schedule_slot) = match command {",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_controlled_process_deadline_failure(&fixture, &output)
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_bounds_cooperative_worker_join_by_the_registered_shutdown_deadline() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture
                .root
                .join("tools/xtask/src/registered_task_lifecycle.rs"),
            "    let (completion, schedule_slot) = match command {",
            "    cooperative_pause(&cancel, Duration::from_millis(250))?;\n    let (completion, schedule_slot) = match command {",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "ordinary 250ms worker execution was incorrectly charged to the 100ms shutdown clock: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-CONCURRENCY",
        )?)?;
        let (_, duration) = report.split_once(";shutdown-elapsed-ms=").ok_or_else(|| {
            std::io::Error::other("lifecycle evidence omitted shutdown elapsed time")
        })?;
        let duration = duration
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .unwrap_or_default()
            .parse::<u128>()?;
        if duration > 100 {
            return Err(std::io::Error::other(format!(
                "successful worker reconciliation reported an invalid shutdown duration: {duration}ms"
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
fn quality_reaps_a_noncooperative_worker_process_inside_the_registered_bound() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/bounded_runners.rs"),
            "    let result = (|| {\n        let registry =",
            "    if gate == CONCURRENCY_GATE {\n        readiness.signal()?;\n        loop { std::thread::park(); }\n    }\n    let result = (|| {\n        let registry =",
        )?;
        fixture.build_fixture_xtask()?;
        let mut quality = fixture.quality_child_from_built_fixture_for("pr")?;
        wait_for_bounded_runner_readiness_and_cancel(
            &fixture,
            "eg-concurrency",
            Duration::from_secs(30),
        )?;
        // This outer test-infrastructure watchdog includes fixture startup and broad
        // nextest contention; the product lifecycle bound asserted below remains 100ms.
        let status = match wait_for_child_exit(&mut quality, Duration::from_secs(30)) {
            Ok(status) => status,
            Err(error) => {
                drop(quality.kill());
                drop(quality.wait());
                return Err(error);
            },
        };
        let (stdout, stderr) = read_child_output(&mut quality)?;
        if status.success() || !stderr.contains("controlled runner failed during cancellation") {
            return Err(std::io::Error::other(format!(
                "the public quality seam did not return a typed noncooperative-worker cancellation: {stdout}\n{stderr}"
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-CONCURRENCY",
        )?)?;
        for required in [
            "process-lifecycle-v1;phase=cancellation",
            "termination-requested=true",
            "process-reaped=true",
            "live=0",
            "shutdown-ms=100",
        ] {
            if !report.contains(required) {
                return Err(std::io::Error::other(format!(
                    "noncooperative lifecycle evidence omitted `{required}`"
                ))
                .into());
            }
        }
        let (_, elapsed) = report
            .split_once(";shutdown-elapsed-ms=")
            .ok_or_else(|| std::io::Error::other("process lifecycle omitted elapsed time"))?;
        let elapsed = elapsed
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .unwrap_or_default()
            .parse::<u128>()?;
        if elapsed > 100 {
            return Err(std::io::Error::other(format!(
                "noncooperative worker kill and reap exceeded the registered 100ms bound: {elapsed}ms"
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
fn quality_uses_one_registered_deadline_for_work_cancellation_join_and_evidence() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/bounded_runners.rs"),
            "            tasks.dispatch(2, WorkerCommand::Execute { schedule_slot: 2 })?;\n            Ok(())",
            "            tasks.dispatch(2, WorkerCommand::Execute { schedule_slot: 2 })?;\n            std::thread::sleep(Duration::from_millis(60));\n            Err(XtaskError::invalid(\"test lifecycle deadline\", \"injected single-deadline failure\"))",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "injected single-deadline failure")?;
        let evidence = fixture.latest_evidence()?;
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-CONCURRENCY",
        )?)?;
        let (_, elapsed) = report.split_once(";shutdown-elapsed-ms=").ok_or_else(|| {
            std::io::Error::other("lifecycle evidence omitted shutdown elapsed time")
        })?;
        let elapsed = elapsed
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .unwrap_or_default()
            .parse::<u128>()?;
        if elapsed > 100 {
            return Err(std::io::Error::other(format!(
                "cancellation and join exceeded the distinct registered 100ms shutdown deadline: {elapsed}ms"
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
fn quality_reconciles_after_worker_error_and_panic_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture
                .root
                .join("tools/xtask/src/registered_task_lifecycle.rs"),
            ") -> Result<(), XtaskError> {\n    let command = loop {",
            ") -> Result<(), XtaskError> {\n    if id == 1 { return Err(XtaskError::invalid(\"test lifecycle worker\", \"injected worker error\")); }\n    if id == 2 { panic!(\"injected worker panic\"); }\n    let command = loop {",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "injected worker error")?;
        assert_lifecycle_observations(&fixture, "0,1,2", "0,1,2", "0,1")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_records_cancel_delivered_reconciliation_through_the_public_seam() -> TestResult {
    assert_cancellation_state("", "injected mid-dispatch failure", "cancelled-ids=", "")
}

#[test]
fn quality_records_already_queued_reconciliation_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let lifecycle_source = fixture
            .root
            .join("tools/xtask/src/registered_task_lifecycle.rs");
        let runner_source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        replace_once(
            &lifecycle_source,
            "const CANCELLATION_JOIN_RESERVE: Duration = Duration::from_millis(25);\n",
            "const CANCELLATION_JOIN_RESERVE: Duration = Duration::from_millis(25);\nstatic TEST_FULL_SLOT_BARRIER: std::sync::OnceLock<std::sync::Barrier> = std::sync::OnceLock::new();\n",
        )?;
        replace_once(
            &lifecycle_source,
            ") -> Result<(), XtaskError> {\n    let command = loop {",
            ") -> Result<(), XtaskError> {\n    if id == 0 { TEST_FULL_SLOT_BARRIER.get_or_init(|| std::sync::Barrier::new(2)).wait(); }\n    let command = loop {",
        )?;
        replace_once(
            &runner_source,
            "            tasks.dispatch(0, WorkerCommand::Cancel { schedule_slot: 0 })?;\n            tasks.dispatch(1, WorkerCommand::Execute { schedule_slot: 1 })?;\n            tasks.dispatch(2, WorkerCommand::Execute { schedule_slot: 2 })?;\n            Ok(())",
            "            tasks.dispatch(0, WorkerCommand::Execute { schedule_slot: 9 })?;\n            Err(XtaskError::invalid(\"test cancellation state\", \"injected full-slot failure\"))",
        )?;
        replace_once(
            &lifecycle_source,
            "        let mut cleanup_errors = Vec::new();\n",
            "        TEST_FULL_SLOT_BARRIER.get_or_init(|| std::sync::Barrier::new(2)).wait();\n        let mut cleanup_errors = Vec::new();\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "injected full-slot failure")?;
        assert_lifecycle_state(&fixture, "already-queued-ids=0")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_records_disconnected_reconciliation_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture
                .root
                .join("tools/xtask/src/registered_task_lifecycle.rs"),
            "        let value = match operation(&mut owner) {",
            "        thread::sleep(Duration::from_millis(30));\n        let value = match operation(&mut owner) {",
        )?;
        replace_once(
            &fixture
                .root
                .join("tools/xtask/src/registered_task_lifecycle.rs"),
            ") -> Result<(), XtaskError> {\n    let command = loop {",
            ") -> Result<(), XtaskError> {\n    if id == 0 { return Ok(()); }\n    let command = loop {",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(
            &output,
            "registered task exited before its command was delivered",
        )?;
        assert_lifecycle_state(&fixture, "disconnected-ids=0")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_omitted_serialized_worker_measurement_through_the_public_seam() -> TestResult
{
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CONCURRENCY|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture.root.join("tools/xtask/src/bounded_runners.rs"),
            "    verify_child_measurement_record(scenario, &record, ScenarioGate::Concurrency)?;\n",
            "    let record = record.replacen(\"workers=\", \"workers=;omitted-\", 1);\n    verify_child_measurement_record(scenario, &record, ScenarioGate::Concurrency)?;\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(
            &output,
            "measurement record contains a duplicate or empty field",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_tampered_serialized_join_observations_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/bounded_runners.rs"),
            "    let record = measurement_record(scenario, &measurements, &joined_ids, 0, 0, true);\n",
            "    let record = measurement_record(scenario, &measurements, &joined_ids, 0, 0, true);\n    let record = record.replace(\"joined-ids=0,1,2\", \"joined-ids=0,1,1\");\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(
            &output,
            "observed join records do not match the registered workers",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_tampered_serialized_resource_schedule_through_the_public_seam() -> TestResult {
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
            "    verify_child_measurement_record(scenario, &record, ScenarioGate::Resource)?;\n",
            "    let record = record.replacen(\"workers=\", \"workers=2:0:executed,1:1:executed,0:2:executed;tampered-\", 1);\n    verify_child_measurement_record(scenario, &record, ScenarioGate::Resource)?;\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "measurement record contains a malformed field")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_duplicate_and_missing_resource_schedule_slots_through_the_public_seam()
-> TestResult {
    assert_tampered_resource_slots_rejected(
        "workers=0:0:executed,1:1:executed,2:2:executed",
        "workers=0:0:executed,1:0:executed,2:2:executed",
    )
}

#[test]
fn quality_rejects_non_contiguous_resource_schedule_slots_through_the_public_seam() -> TestResult {
    assert_tampered_resource_slots_rejected(
        "workers=0:0:executed,1:1:executed,2:2:executed",
        "workers=0:0:executed,1:2:executed,2:3:executed",
    )
}

#[test]
fn quality_rejects_tampered_serialized_resource_pressure_and_leak_state() -> TestResult {
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
            "    verify_child_measurement_record(scenario, &record, ScenarioGate::Resource)?;\n",
            "    let record = record.replace(\"retries=2;reservations=0;queue-empty=true\", \"retries=3;reservations=1;queue-empty=false\");\n    verify_child_measurement_record(scenario, &record, ScenarioGate::Resource)?;\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(
            &output,
            "retained schedule and measurements do not prove fair bounded leak-free recovery",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}
