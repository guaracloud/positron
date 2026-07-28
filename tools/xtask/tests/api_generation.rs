#![forbid(unsafe_code)]

//! Black-box tests for the bounded canonical API generator.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn semantic_rpc_changes_propagate_to_every_generated_transport_artifact() -> TestResult {
    let source = canonical_source()?
        .replace("rpc Negotiate(", "rpc Inspect(")
        .replace("uint32 api_major = 1;", "uint32 requested_major = 3;");
    let fixture = GeneratorFixture::create(&source)?;
    let result = (|| {
        fixture.assert_success()?;
        let rust = fixture.read("crates/positron-api/src/generated.rs")?;
        let openapi = fixture.read("api/positron/v1/openapi.json")?;
        let http = fixture.read("api/positron/v1/http.json")?;

        assert!(rust.contains("CapabilityService/Inspect"));
        assert!(rust.contains("const GRPC_API_MAJOR_TAG: u8 = 24;"));
        assert!(rust.contains("\"requested_major\""));
        assert!(openapi.contains("/v1/capabilities:inspect"));
        assert!(openapi.contains("\"operationId\": \"InspectCapabilityResponse\""));
        assert!(openapi.contains("\"requested_major\""));
        assert!(http.contains("\"rpc\": \"positron.v1.CapabilityService/Inspect\""));
        assert!(http.contains("\"path\": \"/v1/capabilities:inspect\""));
        assert!(http.contains("\"proto\": \"requested_major\""));
        assert!(http.contains("\"number\": 3"));
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn ambiguous_semantic_declarations_fail_closed() -> TestResult {
    let source = canonical_source()?.replace(
        "package positron.v1;",
        "package positron.v1;\npackage positron.shadow;",
    );
    let fixture = GeneratorFixture::create(&source)?;
    let result = fixture.assert_failure_containing("missing or ambiguous");
    fixture.remove()?;
    result
}

#[test]
fn ambiguous_request_field_numbers_fail_closed() -> TestResult {
    let source =
        canonical_source()?.replace("Capability capability = 2;", "Capability capability = 1;");
    let fixture = GeneratorFixture::create(&source)?;
    let result = fixture.assert_failure_containing("request fields are missing or ambiguous");
    fixture.remove()?;
    result
}

#[test]
fn oversized_canonical_sources_fail_closed() -> TestResult {
    let source = "x".repeat(65_537);
    let fixture = GeneratorFixture::create(&source)?;
    let result = fixture.assert_failure_containing("exceeds 65536 bytes");
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
        manifest.join("../../api/positron/v1/positron.proto"),
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
            "positron-api-generation-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("api/positron/v1"))?;
        fs::create_dir_all(root.join("crates/positron-api/src"))?;
        fs::write(root.join("api/positron/v1/positron.proto"), source)?;
        Ok(Self { root })
    }

    fn run(&self) -> TestResult<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_xtask"))
            .current_dir(&self.root)
            .arg("generate-api")
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
            "crates/positron-api/src/generated.rs",
            "api/positron/v1/schema.sha256",
            "api/positron/v1/openapi.json",
            "api/positron/v1/http.json",
        ]
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
