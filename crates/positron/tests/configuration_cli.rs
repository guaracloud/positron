use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn operator_commands_are_deterministic_and_never_start_the_runtime()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let current = root.join("current.toml");
    let candidate = root.join("candidate.toml");
    std::fs::write(
        &current,
        "schema_version = 1\n[diagnostics]\nlog_level = \"info\"\n",
    )?;
    std::fs::write(
        &candidate,
        "schema_version = 1\n[diagnostics]\nlog_level = \"debug\"\n[runtime]\nshutdown_grace_seconds = 60\n",
    )?;

    let validate = run(["config", "validate", "--config", path(&candidate)?]);
    assert!(validate.status.success(), "{validate:?}");
    assert_eq!(
        stdout(&validate)?,
        "status=valid schema_version=1 warning_count=0\n"
    );
    assert!(stderr(&validate)?.is_empty());

    let explain = run(["config", "explain", "--setting", "diagnostics.log_level"]);
    assert!(explain.status.success(), "{explain:?}");
    assert_eq!(
        stdout(&explain)?,
        "setting=diagnostics.log_level type=string default=info domain=enum:error,warn,info,debug secrecy=public provenance=non_secret_overrides mutability=live_reloadable\n"
    );

    let effective = run([
        "config",
        "effective",
        "--redacted",
        "--config",
        path(&candidate)?,
    ]);
    assert!(effective.status.success(), "{effective:?}");
    let effective = stdout(&effective)?;
    assert!(effective.contains("log_level = \"debug\""));
    assert!(effective.contains("\"diagnostics.log_level\" = \"configuration_file\""));
    assert!(effective.contains("local_key_file = \"<redacted>\""));

    let diff = run([
        "config",
        "diff",
        "--current",
        path(&current)?,
        "--candidate",
        path(&candidate)?,
    ]);
    assert!(diff.status.success(), "{diff:?}");
    assert_eq!(
        stdout(&diff)?,
        "plan=restart_required change_count=2\nsetting=diagnostics.log_level before=info before_source=configuration_file after=debug after_source=configuration_file mutability=live_reloadable\nsetting=runtime.shutdown_grace_seconds before=30 before_source=compiled_default after=60 after_source=configuration_file mutability=restart_required\n"
    );

    let migrate = run(["config", "migrate", "--config", path(&candidate)?]);
    assert!(migrate.status.success(), "{migrate:?}");
    assert_eq!(
        stdout(&migrate)?,
        "status=compatible from_schema_version=1 to_schema_version=1 changed=false\n"
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn effective_and_failure_outputs_redact_protected_reference_canaries()
-> Result<(), Box<dyn std::error::Error>> {
    const CANARY: &str = "/private/positron-config-canary";
    let root = temporary_root()?;
    let first = root.join("first.toml");
    let second = root.join("second.toml");
    std::fs::write(
        &first,
        format!("schema_version = 1\n[security]\nlocal_key_file = \"{CANARY}-first\"\n"),
    )?;
    std::fs::write(
        &second,
        format!("schema_version = 1\n[security]\nlocal_key_file = \"{CANARY}-second\"\n"),
    )?;

    let effective = run([
        "config",
        "effective",
        "--redacted",
        "--config",
        path(&first)?,
    ]);
    assert!(effective.status.success(), "{effective:?}");
    assert_redacted(&effective, CANARY)?;

    let diff = run([
        "config",
        "diff",
        "--current",
        path(&first)?,
        "--candidate",
        path(&second)?,
    ]);
    assert!(diff.status.success(), "{diff:?}");
    assert_redacted(&diff, CANARY)?;
    assert!(stdout(&diff)?.contains("before=<redacted>"));
    assert!(stdout(&diff)?.contains("after=<redacted>"));

    let rejected = run([
        "config",
        "validate",
        "--set",
        format!("security.local_key_file={CANARY}").as_str(),
    ]);
    assert!(!rejected.status.success());
    assert_redacted(&rejected, CANARY)?;
    assert_eq!(
        stderr(&rejected)?,
        "positron: configuration_rejected code=secret_override_not_allowed retry=after_input_correction completion=rejected source=security.local_key_file\n"
    );

    let missing_redacted = run(["config", "effective"]);
    assert!(!missing_redacted.status.success());
    assert_eq!(
        stderr(&missing_redacted)?,
        "positron: effective configuration requires --redacted\n"
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn migration_rejects_an_unsupported_schema_without_coercion()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let unsupported = root.join("unsupported.toml");
    std::fs::write(&unsupported, "schema_version = 2\n")?;

    let output = run(["config", "migrate", "--config", path(&unsupported)?]);
    assert!(!output.status.success());
    assert_eq!(
        stderr(&output)?,
        "positron: configuration_rejected code=unsupported_value retry=after_input_correction completion=rejected source=schema_version\n"
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn diff_reports_immutable_changes_as_a_non_mutating_migration_requirement()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let current = root.join("current.toml");
    let candidate = root.join("candidate.toml");
    std::fs::write(&current, "schema_version = 1\n")?;
    std::fs::write(
        &candidate,
        "schema_version = 1\n[storage]\ndata_directory = \"/srv/positron\"\n",
    )?;

    let output = run([
        "config",
        "diff",
        "--current",
        path(&current)?,
        "--candidate",
        path(&candidate)?,
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        stdout(&output)?,
        "plan=requires_migration change_count=1\nsetting=storage.data_directory before=/var/lib/positron before_source=compiled_default after=/srv/positron after_source=configuration_file mutability=immutable_after_initialization\n"
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn run(arguments: impl IntoIterator<Item = impl AsRef<str>>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(
            arguments
                .into_iter()
                .map(|argument| argument.as_ref().to_owned()),
        )
        .env_clear()
        .output()
        .expect("Positron configuration command should run")
}

fn assert_redacted(output: &Output, canary: &str) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        !stdout(output)?.contains(canary),
        "stdout leaked canary: {output:?}"
    );
    assert!(
        !stderr(output)?.contains(canary),
        "stderr leaked canary: {output:?}"
    );
    assert!(
        !format!("{output:?}").contains(canary),
        "debug output leaked canary"
    );
    Ok(())
}

fn stdout(output: &Output) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(output.stdout.clone())
}

fn stderr(output: &Output) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(output.stderr.clone())
}

fn temporary_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "positron-configuration-cli-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root)?;
    Ok(root)
}

fn path(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str()
        .ok_or_else(|| "test path was not UTF-8".into())
}
