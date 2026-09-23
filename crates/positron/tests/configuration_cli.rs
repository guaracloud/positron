use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const MAX_ROOT_COLLISION_RETRIES: u64 = 64;

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
        "plan = \"restart_required\"\nchange_count = 2\n\n[[change]]\nsetting = \"diagnostics.log_level\"\nbefore = \"info\"\nbefore_source = \"configuration_file\"\nafter = \"debug\"\nafter_source = \"configuration_file\"\nmutability = \"live_reloadable\"\n\n[[change]]\nsetting = \"runtime.shutdown_grace_seconds\"\nbefore = \"30\"\nbefore_source = \"compiled_default\"\nafter = \"60\"\nafter_source = \"configuration_file\"\nmutability = \"restart_required\"\n"
    );

    let migrate = run(["config", "migrate", "--config", path(&candidate)?]);
    assert!(migrate.status.success(), "{migrate:?}");
    assert_eq!(
        stdout(&migrate)?,
        "status=compatible from_schema_version=1 to_schema_version=1 changed=false\n"
    );
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
    assert!(stdout(&diff)?.contains("before = \"<redacted>\""));
    assert!(stdout(&diff)?.contains("after = \"<redacted>\""));

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
        "plan = \"requires_migration\"\nchange_count = 1\n\n[[change]]\nsetting = \"storage.data_directory\"\nbefore = \"/var/lib/positron\"\nbefore_source = \"compiled_default\"\nafter = \"/srv/positron\"\nafter_source = \"configuration_file\"\nmutability = \"immutable_after_initialization\"\n"
    );
    Ok(())
}

#[test]
fn public_operator_output_escapes_field_looking_path_values()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let current = root.join("current.toml");
    let candidate = root.join("candidate.toml");
    std::fs::write(&current, "schema_version = 1\n")?;
    std::fs::write(
        &candidate,
        "schema_version = 1\n\
         [storage]\n\
         data_directory = \"/srv/space \\\"quote\\\" \\\\branch before_source=forged\"\n",
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
    let report = stdout(&output)?;
    assert_eq!(
        report,
        r##"plan = "requires_migration"
change_count = 1

[[change]]
setting = "storage.data_directory"
before = "/var/lib/positron"
before_source = "compiled_default"
after = "/srv/space \"quote\" \\branch before_source=forged"
after_source = "configuration_file"
mutability = "immutable_after_initialization"
"##
    );
    Ok(())
}

#[test]
fn public_cli_rejects_a_configuration_file_just_over_the_canonical_input_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let oversized = root.join("oversized.toml");
    std::fs::write(&oversized, "x".repeat(16 * 1024 + 1))?;

    let output = run(["config", "validate", "--config", path(&oversized)?]);
    assert!(!output.status.success());
    assert_eq!(
        stderr(&output)?,
        "positron: configuration_rejected code=resource_limit retry=after_input_correction completion=rejected source=configuration_document\n"
    );
    Ok(())
}

#[test]
fn export_destination_diff_is_complete_and_uses_canonical_membership_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let current = root.join("current.toml");
    let membership_changed = root.join("membership-changed.toml");
    let reordered = root.join("reordered.toml");
    std::fs::write(
        &current,
        "schema_version = 1\n\
         [[export.destination]]\n\
         name = \"archive\"\n\
         identity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\n\
         allowed_tenants = [\"11111111-1111-1111-1111-111111111111\", \"22222222-2222-2222-2222-222222222222\"]\n\
         [[export.destination]]\n\
         name = \"warehouse\"\n\
         identity = \"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\"\n\
         allowed_tenants = [\"33333333-3333-3333-3333-333333333333\"]\n",
    )?;
    std::fs::write(
        &membership_changed,
        "schema_version = 1\n\
         [[export.destination]]\n\
         name = \"archive\"\n\
         identity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\n\
         allowed_tenants = [\"11111111-1111-1111-1111-111111111111\", \"33333333-3333-3333-3333-333333333333\"]\n\
         [[export.destination]]\n\
         name = \"warehouse\"\n\
         identity = \"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\"\n\
         allowed_tenants = [\"33333333-3333-3333-3333-333333333333\"]\n",
    )?;
    std::fs::write(
        &reordered,
        "schema_version = 1\n\
         [[export.destination]]\n\
         name = \"warehouse\"\n\
         identity = \"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\"\n\
         allowed_tenants = [\"33333333-3333-3333-3333-333333333333\"]\n\
         [[export.destination]]\n\
         name = \"archive\"\n\
         identity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\n\
         allowed_tenants = [\"22222222-2222-2222-2222-222222222222\", \"11111111-1111-1111-1111-111111111111\"]\n",
    )?;

    let membership_diff = run([
        "config",
        "diff",
        "--current",
        path(&current)?,
        "--candidate",
        path(&membership_changed)?,
    ]);
    assert!(membership_diff.status.success(), "{membership_diff:?}");
    let membership_report = stdout(&membership_diff)?;
    assert!(membership_report.contains("plan = \"requires_migration\""));
    assert!(membership_report.contains("change_count = 1"));
    assert!(membership_report.contains(
        "allowed_tenants=[11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222]"
    ));
    assert!(membership_report.contains(
        "allowed_tenants=[11111111-1111-1111-1111-111111111111,33333333-3333-3333-3333-333333333333]"
    ));

    let reordered_diff = run([
        "config",
        "diff",
        "--current",
        path(&current)?,
        "--candidate",
        path(&reordered)?,
    ]);
    assert!(reordered_diff.status.success(), "{reordered_diff:?}");
    assert_eq!(
        stdout(&reordered_diff)?,
        "plan = \"no_change\"\nchange_count = 0\n"
    );

    let reverse_reordered_diff = run([
        "config",
        "diff",
        "--current",
        path(&reordered)?,
        "--candidate",
        path(&current)?,
    ]);
    assert!(
        reverse_reordered_diff.status.success(),
        "{reverse_reordered_diff:?}"
    );
    assert_eq!(stdout(&reverse_reordered_diff)?, stdout(&reordered_diff)?);
    Ok(())
}

#[test]
fn invalid_utf8_is_malformed_while_missing_configuration_is_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let invalid_utf8 = root.join("invalid-utf8.toml");
    let missing = root.join("missing.toml");
    std::fs::write(&invalid_utf8, b"schema_version = 1\n\xff")?;

    let malformed = run(["config", "validate", "--config", path(&invalid_utf8)?]);
    assert!(!malformed.status.success());
    assert_eq!(
        stderr(&malformed)?,
        "positron: configuration_rejected code=malformed retry=after_input_correction completion=rejected source=configuration_document\n"
    );

    let unavailable = run(["config", "validate", "--config", path(&missing)?]);
    assert!(!unavailable.status.success());
    assert_eq!(
        stderr(&unavailable)?,
        "positron: configuration_rejected code=configuration_document_unavailable retry=after_input_correction completion=rejected source=configuration_document\n"
    );
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

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        Self::new_from_sequence(NEXT_ROOT.fetch_add(1, Ordering::Relaxed))
    }

    fn new_from_sequence(sequence: u64) -> Result<Self, std::io::Error> {
        for offset in 0..MAX_ROOT_COLLISION_RETRIES {
            let path = Self::path_for(sequence.saturating_add(offset));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
    }

    fn path_for(sequence: u64) -> PathBuf {
        std::env::temp_dir().join(format!(
            "positron-configuration-cli-{}-{sequence}",
            std::process::id()
        ))
    }

    fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.0.join(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temporary_root() -> Result<TemporaryRoot, std::io::Error> {
    TemporaryRoot::new()
}

#[test]
fn temporary_root_skips_a_stale_process_sequence() -> Result<(), std::io::Error> {
    let sequence = (0..MAX_ROOT_COLLISION_RETRIES)
        .map(|offset| u64::MAX - MAX_ROOT_COLLISION_RETRIES + offset)
        .find(|candidate| !TemporaryRoot::path_for(*candidate).exists())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::AlreadyExists))?;
    let stale = TemporaryRoot::path_for(sequence);
    std::fs::create_dir(&stale)?;

    let result = (|| {
        let root = TemporaryRoot::new_from_sequence(sequence)?;
        assert_ne!(root.path(), stale);
        Ok(())
    })();
    std::fs::remove_dir(&stale)?;
    result
}

fn path(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str()
        .ok_or_else(|| "test path was not UTF-8".into())
}
