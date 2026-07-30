use super::m0_08_support::*;
use super::*;

#[test]
fn quality_rejects_raw_direct_thread_spawn_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn raw_direct_spawn() {\n    let _worker = std::thread::r#spawn(|| {});\n}\n",
        "direct unregistered thread spawn",
    )
}

#[test]
fn quality_rejects_raw_spawn_methods_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn raw_spawn_methods(builder: std::thread::Builder, scope: &std::thread::Scope<'_, '_>) {\n    let _worker = builder.r#spawn(|| {});\n    let _scoped = builder.r#spawn_scoped(scope, || {});\n}\n",
        "unregistered process or task spawn",
    )
}

#[test]
fn quality_rejects_raw_unbounded_channel_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn raw_channel() {\n    let _channel = std::sync::mpsc::r#channel::<usize>();\n}\n",
        "unbounded concurrency primitive",
    )
}

#[test]
fn quality_rejects_raw_module_and_import_aliases_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod raw_aliases {\n    use std::thread as r#worker;\n    use r#worker::r#spawn as r#launch;\n    const SPAWN: usize = r#launch;\n}\n",
        "unregistered imported concurrency primitive alias",
    )
}

#[test]
fn quality_rejects_thread_spawn_through_an_extern_crate_alias() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod extern_thread_alias {\n    extern crate std as runtime;\n    fn invoke() {\n        let _worker = runtime::thread::spawn(|| {});\n    }\n}\n",
        "unregistered imported concurrency primitive alias",
    )
}

#[test]
fn quality_rejects_unbounded_channel_through_an_extern_crate_alias() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod extern_channel_alias {\n    extern crate std as runtime;\n    fn invoke() {\n        let _channel = runtime::sync::mpsc::channel::<()>;\n    }\n}\n",
        "unregistered imported concurrency primitive alias",
    )
}

#[test]
fn quality_accepts_an_unrelated_extern_crate_alias() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n#[cfg(any())]\nmod safe_extern_alias {\n    extern crate std as runtime;\n    fn invoke() {\n        let _map = runtime::collections::BTreeMap::<usize, usize>::new();\n    }\n}\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "safe unrelated extern crate alias was rejected: {}\n{}",
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
fn quality_rejects_bare_spawn_from_a_transitively_aliased_thread_glob_through_the_public_seam()
-> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod transitive_thread_glob {\n    use std as platform;\n    use platform::thread as workers;\n    use workers::*;\n    fn invoke() {\n        let _worker = spawn(|| {});\n    }\n}\n",
        "forbidden concurrency primitive glob import",
    )
}

#[test]
fn quality_rejects_bare_channel_from_a_transitively_aliased_mpsc_glob_through_the_public_seam()
-> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod transitive_mpsc_glob {\n    use std::sync as synchronization;\n    use synchronization::mpsc as mailbox;\n    use mailbox::*;\n    fn invoke() {\n        let _channel = channel::<()>();\n    }\n}\n",
        "forbidden concurrency primitive glob import",
    )
}

#[test]
fn quality_rejects_a_rebound_grouped_tokio_spawn_alias_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod external_tokio_spawn {\n    use tokio as runtime;\n    use runtime::{spawn as entry};\n    fn invoke() {\n        let rebound = entry;\n        let _worker = rebound(async {});\n    }\n}\n",
        "unregistered imported concurrency primitive alias",
    )?;
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod external_tokio_spawn_glob {\n    use tokio as runtime;\n    use runtime::*;\n    fn invoke() {\n        let _worker = spawn(async {});\n    }\n}\n",
        "forbidden concurrency primitive glob import",
    )
}

#[test]
fn quality_rejects_a_transitively_aliased_async_std_task_glob_through_the_public_seam() -> TestResult
{
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod external_async_std_spawn {\n    use async_std as runtime;\n    use runtime::task as tasks;\n    use tasks::*;\n    fn invoke() {\n        let _worker = spawn(async {});\n    }\n}\n",
        "forbidden concurrency primitive glob import",
    )?;
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod external_async_std_spawn_alias {\n    use async_std::task::{spawn as entry};\n    const SPAWN: usize = entry;\n}\n",
        "unregistered imported concurrency primitive alias",
    )
}

#[test]
fn quality_rejects_a_tokio_unbounded_channel_function_item_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn external_tokio_unbounded_channel() {\n    let factory = tokio::sync::mpsc::unbounded_channel::<()>;\n    let _channel = factory();\n}\n",
        "unregistered imported concurrency primitive alias",
    )?;
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod external_tokio_unbounded_channel_glob {\n    use tokio::sync as synchronization;\n    use synchronization::mpsc as mailbox;\n    use mailbox::*;\n    fn invoke() {\n        let _channel = unbounded_channel::<()>();\n    }\n}\n",
        "forbidden concurrency primitive glob import",
    )
}

#[test]
fn quality_accepts_an_unrelated_glob_import_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n#[cfg(any())]\nmod unrelated_glob {\n    use std::cmp::*;\n    fn invoke() {\n        let _minimum = min(1_usize, 2_usize);\n    }\n}\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "safe unrelated glob import was rejected: {}\n{}",
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
fn quality_accepts_unrelated_external_imports_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n#[cfg(any())]\nmod safe_external_imports {\n    use async_std::task::block_on as async_spawn;\n    use tokio::sync::mpsc::channel as unbounded_channel;\n    use tokio::task::yield_now as spawn;\n    use tokio::time::*;\n    fn invoke() {\n        let _async_std_item = async_spawn;\n        let _channel_item = unbounded_channel;\n        let _tokio_item = spawn;\n        let _time_item = sleep;\n        let local_spawn = || {};\n        local_spawn();\n    }\n}\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "safe unrelated external imports were rejected: {}\n{}",
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
fn quality_accepts_unrelated_raw_identifiers_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n#[allow(dead_code)]\nfn r#future() {\n    let r#spawnling = 1_usize;\n    let r#channel_capacity = r#spawnling;\n    let _ = r#channel_capacity;\n}\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "safe unrelated raw identifiers were rejected: {}\n{}",
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
fn quality_rejects_chained_thread_module_aliases_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod chained_thread_alias {\n    use std::thread as a;\n    use a as b;\n    const SPAWN: usize = (b::spawn);\n}\n",
        "unregistered imported concurrency primitive alias",
    )
}

#[test]
fn quality_rejects_chained_mpsc_module_aliases_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod chained_mpsc_alias {\n    use std::sync::mpsc as a;\n    use a as b;\n    static CHANNEL: usize = ((b::channel));\n}\n",
        "unregistered imported concurrency primitive alias",
    )
}

#[test]
fn quality_rejects_builder_and_scope_function_items_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn forbidden_thread_function_items() {\n    let _builder = (((std::thread::Builder::spawn)));\n    let _scope = std::thread::Scope::spawn;\n}\n",
        "unregistered imported concurrency primitive alias",
    )
}

#[test]
fn quality_rejects_aliased_builder_function_items_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod aliased_builder_function_item {\n    use std::thread::Builder as a;\n    use a as b;\n    const SPAWN: usize = ((b::spawn));\n}\n",
        "unregistered imported concurrency primitive alias",
    )
}

#[test]
fn quality_rejects_vec_deque_turbofish_new_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn unbounded_queue_function_item() {\n    let _queue = std::collections::VecDeque::<usize>::new;\n}\n",
        "unbounded concurrency primitive",
    )
}

#[test]
fn quality_rejects_every_resolved_vec_deque_reference_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn unbounded_queue_with_capacity() {\n    let _factory = std::collections::VecDeque::<usize>::with_capacity;\n}\n",
        "unbounded concurrency primitive",
    )?;
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn unbounded_queue_default() {\n    let _factory = std::collections::VecDeque::<usize>::default;\n}\n",
        "unbounded concurrency primitive",
    )?;
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn unbounded_queue_type_reference() {\n    let _queue: Option<std::collections::VecDeque<usize>> = None;\n}\n",
        "unbounded concurrency primitive",
    )
}

#[test]
fn quality_rejects_aliased_globbed_and_extern_aliased_vec_deque_references() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod aliased_unbounded_queue {\n    use std::collections::VecDeque as Queue;\n    const FACTORY: usize = Queue::<usize>::default;\n}\n",
        "concurrency primitive",
    )?;
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod globbed_unbounded_queue {\n    use std::collections::*;\n    const FACTORY: usize = VecDeque::<usize>::with_capacity;\n}\n",
        "forbidden concurrency primitive glob import",
    )?;
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nmod extern_unbounded_queue {\n    extern crate std as runtime;\n    const FACTORY: usize = runtime::collections::VecDeque::<usize>::default;\n}\n",
        "concurrency primitive",
    )
}

#[test]
fn quality_accepts_an_unrelated_collection_type_through_the_public_seam() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "\n#[cfg(any())]\nmod safe_collection {\n    extern crate std as runtime;\n    fn invoke() {\n        let _map = runtime::collections::BTreeMap::<usize, usize>::new();\n        let _vector = std::vec::Vec::<usize>::with_capacity(4);\n    }\n}\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "safe unrelated collection type was rejected: {}\n{}",
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
fn quality_rejects_multiline_spawn_scoped_turbofish_through_the_public_seam() -> TestResult {
    assert_concurrency_source_rejected(
        "\n#[cfg(any())]\nfn multiline_scoped_spawn(builder: std::thread::Builder, scope: &std::thread::Scope<'_, '_>) {\n    let _worker = builder\n        .spawn_scoped\n        :: <_, ()>\n        (scope, || Ok(()));\n}\n",
        "unregistered process or task spawn",
    )
}

#[test]
fn quality_rejects_a_marker_not_immediately_bound_to_its_exact_spawn() -> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        replace_once(
            &fixture.root.join("tools/xtask/src/controlled_execution.rs"),
            "// positron-concurrency-spawn: InputBroker::start\\tcontrolled-input-broker-v1\n            .spawn()",
            "// positron-concurrency-spawn: InputBroker::start\\tcontrolled-input-broker-v1\n\n            .spawn()",
        )?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        assert_rejected_output(&output, "spawn marker at tooling line")?;
        assert_rejected_output(
            &output,
            "is not immediately bound to its exact method spawn",
        )
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

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
fn quality_rejects_a_typed_rebound_spawn_alias_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::thread::spawn as entry;\n#[allow(dead_code)] fn typed_rebound_spawn_alias() { let invoke: _ = entry; let _worker = invoke(|| {}); }\n",
    )
}

#[test]
fn quality_rejects_a_transitively_typed_rebound_spawn_alias_through_the_public_seam() -> TestResult
{
    assert_imported_concurrency_alias_rejected(
        "use std::thread::spawn as entry;\n#[allow(dead_code)] fn transitively_typed_rebound_spawn_alias() { let first: _ = entry; let invoke: _ = first; let _worker = invoke(|| {}); }\n",
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
fn quality_rejects_an_explicitly_typed_rebound_channel_factory_through_the_public_seam()
-> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::sync::mpsc::{channel as entry, Receiver, Sender};\n#[allow(dead_code)] fn typed_rebound_channel_factory() { let invoke: fn() -> (Sender<()>, Receiver<()>) = entry; let (sender, _receiver) = invoke(); let _ = sender.send(()); }\n",
    )
}

#[test]
fn quality_rejects_a_parenthesized_rebound_channel_factory_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "use std::sync::mpsc::channel as entry;\n#[allow(dead_code, unused_parens)] fn parenthesized_rebound_channel_factory() { let invoke = ( ( entry ) ); let (sender, _receiver) = invoke(); let _ = sender.send(()); }\n",
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
fn quality_accepts_a_parenthesized_rebound_bounded_channel_factory_through_the_public_seam()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "use std::sync::mpsc::sync_channel as entry;\n#[allow(dead_code, unused_parens)] fn parenthesized_rebound_bounded_channel_factory() { let invoke: _ = ((entry)); let (sender, _receiver) = invoke(1); let _ = sender.send(()); }\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "the public quality seam falsely rejected a typed parenthesized bounded channel factory: {}\n{}",
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
fn quality_rejects_a_parenthesized_direct_spawn_binding_through_the_public_seam() -> TestResult {
    assert_imported_concurrency_alias_rejected(
        "#[allow(dead_code, unused_parens)] fn parenthesized_direct_spawn() { let launch = (((std::thread::spawn))); let _worker = launch(|| {}); }\n",
    )
}

#[test]
fn quality_rejects_const_and_static_forbidden_value_bindings_through_the_public_seam() -> TestResult
{
    assert_imported_concurrency_alias_rejected(
        "#[allow(unused_imports)] use std::thread::spawn as launch_value;\n#[allow(unused_imports)] use std::sync::mpsc::channel as channel_value;\n#[cfg(any())] const SPAWN_VALUE: [usize; 1] = [(launch_value)];\n#[cfg(any())] static CHANNEL_VALUE: (usize,) = (channel_value,);\n",
    )
}

#[test]
fn quality_rejects_builder_spawn_scoped_and_turbofish_sites_through_the_public_seam() -> TestResult
{
    assert_concurrency_source_rejected(
        "#[cfg(any())] fn builder_spawn_shapes() { let _ = std::thread::Builder::new().spawn::<_, ()>(|| ()); let _ = std::thread::Builder::new().spawn_scoped::<_, ()>(scope, || ()); }\n",
        "unregistered process or task spawn",
    )
}

#[test]
fn quality_accepts_spawn_like_identifiers_comments_and_literals_through_the_public_seam()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        enable_concurrency_gate(&fixture)?;
        let source = fixture.root.join("tools/xtask/src/bounded_runners.rs");
        let mut content = fs::read_to_string(&source)?;
        content.push_str(
            "#[allow(dead_code)] fn safe_spawn_words() { let spawn_factory = \"std::thread::spawn\"; let channel_name = \"mpsc::channel\"; let _ = (spawn_factory, channel_name); /* .spawn_scoped::<T>(...) */ }\n",
        );
        fs::write(&source, content)?;
        let output = fixture.quality_output_from_fixture_source("pr")?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "token-aware source policy rejected safe spawn-like text: {}\n{}",
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
            "\n#[allow(dead_code)]\nfn duplicate_registered_spawn_regression() {\n    let _worker = thread::Builder::new()\n        // positron-concurrency-spawn: RegisteredTasks::spawn\\tquality-bounded-worker-v1\n        .spawn(|| {});\n}\n",
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
            "pub(crate) fn validate_source_policy(\n    registry: &FrozenBoundedRunnerRegistry,\n    root: &Path,\n) -> Result<(), XtaskError> {\n    std::fs::write(root.join(registry::SPAWN_SITE_REGISTRY_PATH), b\"swapped after frozen capture\").map_err(|error| XtaskError::io(\"test post-capture spawn registry swap\", error))?;\n",
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
