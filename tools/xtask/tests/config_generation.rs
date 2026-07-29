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
fn canonical_setting_changes_propagate_to_schema_and_reference() -> TestResult {
    let source = canonical_source()?.replace(
        "30 seconds\tpublic\trestart-required\trange:1:3600",
        "45 seconds\tpublic\trestart-required\trange:1:7200",
    );
    let fixture = GeneratorFixture::create(&source)?;
    let result = (|| {
        fixture.assert_success()?;
        let schema = fixture.read("configuration/schema.json")?;
        let reference = fixture.read("configuration/reference.md")?;
        assert!(schema.contains("\"maximum\": 7200"));
        assert!(reference.contains("`45 seconds`"));
        assert!(!schema.contains("\"maximum\": 3600"));
        assert!(!reference.contains("`30 seconds`"));
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn duplicate_or_missing_setting_declarations_fail_closed() -> TestResult {
    let source = canonical_source()?.replace(
        "schema_version\tinteger\t1\tpublic\timmutable after initialization\tconst:1",
        "diagnostics.log_level\tinteger\t1\tpublic\timmutable after initialization\tconst:1",
    );
    let fixture = GeneratorFixture::create(&source)?;
    let result = fixture.assert_failure_containing("missing or ambiguous");
    fixture.remove()?;
    result
}

#[test]
fn unsupported_specification_grammar_fails_closed() -> TestResult {
    let source = canonical_source()?.replace(
        "path\tkind\tdefault\tsecrecy\tmutability\tconstraint",
        "path\tkind\tdefault\tconstraint",
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
        manifest.join("../../configuration/spec.tsv"),
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
        fs::write(root.join("configuration/spec.tsv"), source)?;
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
        ["configuration/schema.json", "configuration/reference.md"]
            .iter()
            .map(|path| Ok(fs::read(self.root.join(path))?))
            .collect()
    }

    fn read(&self, path: &str) -> TestResult<String> {
        Ok(fs::read_to_string(self.root.join(path))?)
    }

    fn remove(&self) -> TestResult {
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }
}
