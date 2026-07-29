use super::m0_08_support::*;
use super::*;

#[test]
fn quality_rejects_an_unregistered_tooling_spawn_site_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CONCURRENCY|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n#[allow(dead_code)]\nfn unregistered_spawn_regression() -> std::io::Result<()> {\n    let _child = std::process::Command::new(\"true\").spawn()?;\n    Ok(())\n}\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "unregistered process or task spawn")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-CONCURRENCY")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "unregistered tooling spawn did not retain a failed concurrency gate outcome",
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
fn quality_rejects_a_multiline_direct_thread_spawn_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CONCURRENCY|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str("\n#[allow(dead_code)]\nfn multiline_spawn_regression() {\n    let _handle = std::thread::\n        spawn(|| {});\n}\n");
        fs::write(&source, content)?;
        fixture.build_fixture_xtask()?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "direct unregistered thread spawn")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_aliased_thread_spawn_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CONCURRENCY|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str("\nuse std::thread as SpawnAlias;\n#[allow(dead_code)]\nfn aliased_spawn_regression() { let _handle = SpawnAlias::spawn(|| {}); }\n");
        fs::write(&source, content)?;
        fixture.build_fixture_xtask()?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "unregistered imported concurrency primitive alias")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-CONCURRENCY")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "aliased thread spawn did not retain a failed concurrency gate outcome",
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
fn quality_rejects_a_braced_thread_spawn_alias_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::thread::{spawn as launch};\n#[allow(dead_code)] fn braced_spawn_alias() { let _worker = launch(|| {}); }\n",
    )
}

#[test]
fn quality_rejects_a_rebound_imported_spawn_alias_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::thread::spawn as entry;\n#[allow(dead_code)] fn rebound_spawn_alias() { let invoke = entry; let _worker = invoke(|| {}); }\n",
    )
}

#[test]
fn quality_rejects_a_rebound_thread_module_alias_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::thread as entry;\n#[allow(dead_code)] fn rebound_thread_module_alias() { let invoke = entry::spawn; let _worker = invoke(|| {}); }\n",
    )
}

#[test]
fn quality_rejects_a_rebound_grouped_thread_module_alias_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::{thread as entry};\n#[allow(dead_code)] fn rebound_grouped_thread_module_alias() { let invoke = entry::spawn; let _worker = invoke(|| {}); }\n",
    )
}

#[test]
fn quality_rejects_a_braced_channel_alias_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::sync::mpsc::{channel as unbounded};\n#[allow(dead_code)] fn braced_channel_alias() { let _queue = unbounded::<()>(); }\n",
    )
}

#[test]
fn quality_rejects_a_rebound_imported_channel_factory_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::sync::mpsc::channel as entry;\n#[allow(dead_code)] fn rebound_channel_factory() { let invoke = entry; let (sender, _receiver) = invoke(); let _ = sender.send(()); }\n",
    )
}

#[test]
fn quality_rejects_a_direct_generic_channel_through_the_public_seam() -> TestResult {
    assert_unbounded_concurrency_primitive_rejected(
        "use std::sync::mpsc;\n#[allow(dead_code)] fn direct_generic_channel() { let _queue = mpsc::channel::<()>(); }\n",
    )
}

#[test]
fn quality_rejects_a_module_aliased_generic_channel_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::sync::mpsc as m;\n#[allow(dead_code)] fn module_alias_channel() { let _queue = m::channel::<()>(); }\n",
    )
}

#[test]
fn quality_rejects_a_grouped_module_aliased_generic_channel_through_the_public_seam() -> TestResult
{
    assert_imported_concurrency_alias_rejected(
        "use std::sync::{mpsc as m};\n#[allow(dead_code)] fn grouped_module_alias_channel() { let _queue = m::channel::<()>(); }\n",
    )
}

#[test]
fn quality_rejects_a_nested_grouped_module_aliased_channel_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::{sync::{mpsc as m}};\n#[allow(dead_code)] fn nested_grouped_module_alias_channel() { let _queue = m::channel::<()>(); }\n",
    )
}

#[test]
fn quality_rejects_a_nested_grouped_spawn_alias_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::{thread::spawn as launch};\n#[allow(dead_code)] fn nested_grouped_spawn() { let _worker = launch(|| {}); }\n",
    )
}

#[test]
fn quality_rejects_a_multiline_grouped_spawn_alias_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::thread::{\n    spawn as launch,\n};\n#[allow(dead_code)] fn multiline_grouped_alias() { let _worker = launch(|| {}); }\n",
    )
}

#[test]
fn quality_accepts_a_nested_grouped_bounded_channel_alias_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "use std::{sync::{mpsc::{sync_channel as bounded}}};\n#[allow(dead_code)] fn bounded_channel_alias() { let (_sender, _receiver) = bounded::<()>(1); }\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "the public quality seam falsely rejected a bounded channel alias: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ))
        .into())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_accepts_a_rebound_bounded_channel_factory_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "use std::sync::mpsc::sync_channel as entry;\n#[allow(dead_code)] fn rebound_bounded_channel_factory() { let invoke = entry; let (sender, _receiver) = invoke(1); let _ = sender.send(()); }\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "the public quality seam falsely rejected a rebound bounded channel factory: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ))
        .into())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_scans_production_after_a_cfg_test_module_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n#[cfg(test)]\nmod scanner_only_tests {\n    #[test]\n    fn test_only_spawn_is_excluded() { let _worker = std::thread::spawn(|| {}); }\n}\n\n#[allow(dead_code)]\nfn production_after_cfg_test_module() { let _worker = std::thread::spawn(|| {}); }\n",
        );
        fs::write(&source, content)?;
        fixture.build_fixture_xtask()?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "direct unregistered thread spawn")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_skips_only_nested_cfg_test_items_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n#[cfg(test)]\n#[allow(dead_code)]\nmod scanner_only_tests {\n    #[cfg(test)]\n    mod nested {\n        fn test_only_spawn_is_excluded() { let _worker = std::thread::spawn(|| {}); }\n    }\n}\n\n#[allow(dead_code)]\nfn production_after_nested_cfg_test_module() { let _queue = std::sync::mpsc::sync_channel::<()>(1); }\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "the public quality seam did not isolate nested cfg(test) item boundaries: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ))
        .into())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_function_pointer_spawn_binding_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "#[allow(dead_code)] fn function_pointer_spawn() { let launch = std::thread::spawn; let _worker = launch(|| {}); }\n",
    )
}

#[test]
fn quality_rejects_a_stale_semantic_spawn_site_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CONCURRENCY|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        replace_once(
            &fixture
                .root
                .join("qualification/engineering/concurrency-spawn-sites.tsv"),
            "RegisteredTasks::spawn\tthread\tquality-bounded-worker-v1",
            "RegisteredTasks::spawn\tthread\tstale-bounded-worker-v1",
        )?;
        fixture.build_fixture_xtask()?;
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(&output, "unregistered semantic spawn site")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-CONCURRENCY")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "stale semantic spawn site did not retain a failed concurrency gate outcome",
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
fn quality_rejects_a_duplicate_observed_semantic_spawn_site_through_the_public_seam() -> TestResult
{
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture
            .root
            .join("tools/xtask/src/registered_task_lifecycle.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n// positron-concurrency-spawn: RegisteredTasks::spawn\\tquality-bounded-worker-v1\n#[allow(dead_code)]\nfn duplicate_registered_spawn_regression() { let _worker = thread::Builder::new().spawn(|| {}); }\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "duplicate observed semantic spawn site")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_a_new_unobserved_semantic_spawn_site_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let registry = fixture
            .root
            .join("qualification/engineering/concurrency-spawn-sites.tsv");
        let mut content = fs::read_to_string(&registry)?;
        content.push_str(
            "tools/xtask/src/bounded_runners.rs\tnew_registered_spawn\tthread\tnew-bounded-worker-v1\n",
        );
        fs::write(&registry, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(
            &output,
            "registered spawn-site set does not exactly match active tooling source",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_unregistered_spawn_in_a_resource_only_profile_through_the_public_seam()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RESOURCE|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        let source = fixture
            .root
            .join("tools/xtask/src/registered_task_lifecycle.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n#[allow(dead_code)]\nfn resource_only_unregistered_spawn_regression() { let _worker = thread::Builder::new().spawn(|| {}); }\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "unregistered process or task spawn")?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-RESOURCE")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "resource-only scan bypass did not retain a failed resource gate outcome",
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
fn quality_rejects_resource_capacity_drift_through_the_public_seam() -> TestResult {
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
        let output = fixture.quality_output_for("pr")?;
        assert_rejected_output(
            &output,
            "registered resource bounds or deterministic schedule drifted",
        )?;
        let evidence = fixture.latest_evidence()?;
        if !gate_record(&evidence, "EG-RESOURCE")?.contains("\"result\": \"failed\"") {
            return Err(std::io::Error::other(
                "resource capacity drift did not retain a failed resource gate outcome",
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
fn quality_rejects_an_oversized_frozen_concurrency_registry_through_the_public_seam() -> TestResult
{
    let fixture = Fixture::create()?;
    let result = (|| {
        set_scope_field(
            &fixture.root,
            "xtask",
            "risk_gates",
            "EG-00|EG-ARCH|EG-BUILD|EG-CONCURRENCY|EG-DEPS|EG-DOCS|EG-ERROR|EG-EVIDENCE|EG-POLICY|EG-RUST|EG-SAFETY|EG-SECRETS|EG-SUPPLY|EG-TEST",
        )?;
        fs::write(
            fixture
                .root
                .join("qualification/engineering/concurrency-fixtures.tsv"),
            vec![b'x'; 16_385],
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "fixture identity input exceeds 16384 bytes")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_rejects_an_oversized_frozen_concurrency_spawn_registry_through_the_public_seam()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        fs::write(
            fixture
                .root
                .join("qualification/engineering/concurrency-spawn-sites.tsv"),
            vec![b'x'; 16_385],
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "fixture identity input exceeds 16384 bytes")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[cfg(unix)]
#[test]
fn quality_rejects_a_symbolic_link_frozen_concurrency_spawn_registry_through_the_public_seam()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let registry = fixture
            .root
            .join("qualification/engineering/concurrency-spawn-sites.tsv");
        let external = fixture
            .root
            .join("target/quality-tools/external-spawn-sites.tsv");
        fs::write(&external, fs::read(&registry)?)?;
        fs::remove_file(&registry)?;
        std::os::unix::fs::symlink(&external, &registry)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "registry symlinks are forbidden")
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_uses_the_frozen_spawn_registry_after_a_post_capture_swap_through_the_public_seam()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/bounded_runners.rs"),
            "pub(crate) fn validate_source_policy(\n    registry: &FrozenBoundedRunnerRegistry,\n    root: &Path,\n) -> Result<(), XtaskError> {\n",
            "pub(crate) fn validate_source_policy(\n    registry: &FrozenBoundedRunnerRegistry,\n    root: &Path,\n) -> Result<(), XtaskError> {\n    std::fs::write(root.join(SPAWN_SITE_REGISTRY_PATH), b\"swapped after frozen capture\").map_err(|error| XtaskError::io(\"test post-capture spawn registry swap\", error))?;\n",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "post-capture registry swap changed frozen runner behavior: {}\\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}
