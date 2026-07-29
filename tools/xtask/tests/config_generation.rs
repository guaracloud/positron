#![forbid(unsafe_code)]

//! Black-box tests for the bounded canonical configuration generator.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn generation_publishes_positive_boundary_negative_and_adversarial_validation_fixtures()
-> TestResult {
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    let result = (|| {
        fixture.assert_success()?;
        let validation = fixture.read("configuration/validation-fixtures.json")?;
        for class in ["positive", "boundary", "negative", "adversarial"] {
            assert!(validation.contains(&format!("\"class\": \"{class}\"")));
        }
        assert!(validation.contains("schema_version = 1"));
        assert!(validation.contains("shutdown_grace_seconds = 3600"));
        assert!(validation.contains("unknown_setting"));
        assert!(validation.contains("maximum_document_bytes"));
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn canonical_setting_changes_propagate_to_schema_and_reference() -> TestResult {
    let source = canonical_source()?.replace(
        "RuntimeShutdownGraceSeconds | \"runtime.shutdown_grace_seconds\" | Integer | \"30\" | UnsignedIntegerRange(1, 3600)",
        "RuntimeShutdownGraceSeconds | \"runtime.shutdown_grace_seconds\" | Integer | \"45\" | UnsignedIntegerRange(1, 7200)",
    );
    let fixture = GeneratorFixture::create(&source)?;
    let result = (|| {
        fixture.assert_success()?;
        let schema = fixture.read("configuration/schema.json")?;
        let reference = fixture.read("configuration/reference.md")?;
        let validation = fixture.read("configuration/validation-fixtures.json")?;
        assert!(schema.contains("\"maximum\": 7200"));
        assert!(reference.contains("`45`"));
        assert!(validation.contains("shutdown_grace_seconds = 7200"));
        assert!(!schema.contains("\"maximum\": 3600"));
        assert!(!reference.contains("`30`"));
        assert!(!validation.contains("shutdown_grace_seconds = 3600"));
        fixture.assert_mutated_runtime_uses_default_and_range(45, 7200)?;
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn duplicate_or_missing_setting_declarations_fail_closed() -> TestResult {
    let source = canonical_source()?.replace(
        "SchemaVersion | \"schema_version\" | Integer | \"1\" | ExactUnsignedInteger(1)",
        "SchemaVersion | \"diagnostics.log_level\" | Integer | \"1\" | ExactUnsignedInteger(1)",
    );
    let fixture = GeneratorFixture::create(&source)?;
    let result = fixture.assert_failure_containing("missing or ambiguous");
    fixture.remove()?;
    result
}

#[test]
fn unsupported_specification_grammar_fails_closed() -> TestResult {
    let source = canonical_source()?.replace(
        "pub(crate) const SETTING_DEFINITIONS: [SettingDefinition; 7] = define_settings! {",
        "pub(crate) const SETTING_DEFINITIONS = define_settings! {",
    );
    let fixture = GeneratorFixture::create(&source)?;
    let result = fixture.assert_failure_containing("header is not exact");
    fixture.remove()?;
    result
}

#[test]
fn generation_is_byte_identical_when_repeated() -> TestResult {
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    let result = (|| {
        fixture.assert_success()?;
        let first = fixture.generated_artifacts()?;
        fixture.assert_success()?;
        let second = fixture.generated_artifacts()?;
        assert_eq!(first, second);
        Ok(())
    })();
    fixture.remove()?;
    result
}

fn canonical_source() -> TestResult<String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Ok(fs::read_to_string(
        manifest.join("../../crates/positron-config/src/contract.rs"),
    )?)
}

struct GeneratorFixture {
    root: PathBuf,
}

impl GeneratorFixture {
    fn create(source: &str) -> TestResult<Self> {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "positron-config-generation-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("configuration"))?;
        fs::create_dir_all(root.join("crates/positron-config/src"))?;
        fs::write(root.join("crates/positron-config/src/contract.rs"), source)?;
        Ok(Self { root })
    }

    fn run(&self) -> TestResult<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_xtask"))
            .current_dir(&self.root)
            .arg("generate-config")
            .output()?)
    }

    fn assert_success(&self) -> TestResult {
        let output = self.run()?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "generator failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }

    fn assert_failure_containing(&self, expected: &str) -> TestResult {
        let output = self.run()?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !output.status.success() && combined.contains(expected) {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "generator did not fail with `{expected}`: {combined}"
        ))
        .into())
    }

    fn generated_artifacts(&self) -> TestResult<Vec<Vec<u8>>> {
        [
            "configuration/schema.json",
            "configuration/reference.md",
            "configuration/validation-fixtures.json",
        ]
        .iter()
        .map(|path| Ok(fs::read(self.root.join(path))?))
        .collect()
    }

    fn assert_mutated_runtime_uses_default_and_range(
        &self,
        expected_default: u16,
        expected_maximum: u16,
    ) -> TestResult {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        fs::copy(
            repository.join("crates/positron-config/src/lib.rs"),
            self.root.join("crates/positron-config/src/lib.rs"),
        )?;
        fs::copy(
            repository.join("crates/positron-config/Cargo.toml"),
            self.root.join("crates/positron-config/Cargo.toml"),
        )?;
        fs::copy(repository.join("Cargo.lock"), self.root.join("Cargo.lock"))?;
        fs::create_dir_all(self.root.join("crates/positron-config/tests"))?;
        fs::write(
            self.root.join("Cargo.toml"),
            "[workspace]\n\
             members = [\"crates/positron-config\"]\n\
             resolver = \"3\"\n\n\
             [workspace.package]\n\
             version = \"0.0.0\"\n\
             edition = \"2024\"\n\
             rust-version = \"1.96.0\"\n\
             authors = [\"Guara Cloud\"]\n\
             license = \"MIT\"\n\
             repository = \"https://github.com/guaracloud/positron\"\n\
             homepage = \"https://github.com/guaracloud/positron\"\n\n\
             [workspace.lints.rust]\n\
             warnings = \"deny\"\n\
             unsafe_code = \"forbid\"\n\n\
             [workspace.lints.clippy]\n\
             all = \"deny\"\n",
        )?;
        fs::write(
            self.root
                .join("crates/positron-config/tests/mutated_contract.rs"),
            format!(
                "use positron_config::{{ConfigurationFailureCode, ConfigurationInputs, EnvironmentOverrides, CommandLineOverrides, resolve}};\n\
                 fn inputs(file: Option<&str>) -> ConfigurationInputs {{\n\
                     ConfigurationInputs::try_new(\n\
                         file,\n\
                         EnvironmentOverrides::try_from_pairs::<&str, &str>([]).expect(\"bounded empty environment\"),\n\
                         CommandLineOverrides::try_from_pairs::<&str, &str>([]).expect(\"bounded empty command line\"),\n\
                     ).expect(\"bounded input\")\n\
                 }}\n\
                 #[test]\n\
                 fn runtime_consumes_mutated_rust_contract() {{\n\
                     assert_eq!(resolve(inputs(None)).expect(\"valid defaults\").shutdown_grace_seconds(), {expected_default});\n\
                     let accepted = format!(\"schema_version = 1\\n[runtime]\\nshutdown_grace_seconds = {expected_maximum}\\n\");\n\
                     assert!(resolve(inputs(Some(&accepted))).is_ok());\n\
                     let rejected_value = {expected_maximum} + 1;\n\
                     let rejected = format!(\"schema_version = 1\\n[runtime]\\nshutdown_grace_seconds = {{rejected_value}}\\n\");\n\
                     assert!(matches!(resolve(inputs(Some(&rejected))), Err(error) if error.code() == ConfigurationFailureCode::UnsupportedValue));\n\
                 }}\n"
            ),
        )?;
        let lock = Command::new("cargo")
            .current_dir(&self.root)
            .args(["generate-lockfile", "--offline"])
            .output()?;
        if !lock.status.success() {
            return Err(std::io::Error::other(format!(
                "mutated Rust contract fixture lock failed: {}\n{}",
                String::from_utf8_lossy(&lock.stdout),
                String::from_utf8_lossy(&lock.stderr)
            ))
            .into());
        }
        let output = Command::new("cargo")
            .current_dir(&self.root)
            .args([
                "test",
                "--locked",
                "--offline",
                "--package",
                "positron-config",
                "--test",
                "mutated_contract",
            ])
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "mutated Rust contract did not change runtime behavior: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }

    fn read(&self, path: &str) -> TestResult<String> {
        Ok(fs::read_to_string(self.root.join(path))?)
    }

    fn remove(&self) -> TestResult {
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }
}
