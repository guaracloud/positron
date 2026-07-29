#![forbid(unsafe_code)]

//! Black-box tests for the bounded canonical API generator.

use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn generation_publishes_cross_transport_validation_fixtures_for_each_required_class() -> TestResult
{
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    let result = (|| {
        fixture.assert_success()?;
        let validation = fixture.read("api/positron/v1/validation-fixtures.json")?;
        for class in ["positive", "boundary", "negative", "adversarial"] {
            assert!(validation.contains(&format!("\"class\": \"{class}\"")));
        }
        assert!(validation.contains("grpc_hex"));
        assert!(validation.contains("http_json"));
        assert!(validation.contains("CAPABILITY_AVAILABILITY_IMPLEMENTED"));
        assert!(validation.contains("PUBLIC_ERROR_CODE_UNKNOWN_FIELD"));
        assert!(validation.contains("PUBLIC_ERROR_CODE_MALFORMED_REQUEST"));
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn combined_generation_emits_every_public_api_and_configuration_artifact_twice() -> TestResult {
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    fixture.copy_configuration_source()?;
    let result = (|| {
        fixture.assert_combined_success()?;
        let first = fixture.all_generated_artifacts()?;
        fixture.assert_combined_success()?;
        let second = fixture.all_generated_artifacts()?;
        assert_eq!(first, second);
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn generation_verification_rejects_a_hand_edited_checked_artifact() -> TestResult {
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    fixture.copy_configuration_source()?;
    let result = (|| {
        fixture.assert_combined_success()?;
        fs::write(
            fixture.root.join("api/positron/v1/openapi.json"),
            b"hand edit\n",
        )?;
        fixture.assert_verification_failure_containing("not clean and deterministic")
    })();
    fixture.remove()?;
    result
}

#[test]
fn generation_verification_preserves_every_simultaneously_drifted_artifact() -> TestResult {
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    fixture.copy_configuration_source()?;
    let result = (|| {
        fixture.assert_combined_success()?;
        let api_drift = b"hand-edited OpenAPI\n";
        let configuration_drift = b"hand-edited configuration schema\n";
        fs::write(fixture.root.join("api/positron/v1/openapi.json"), api_drift)?;
        fs::write(
            fixture.root.join("configuration/schema.json"),
            configuration_drift,
        )?;
        fixture.assert_verification_failure_containing("not clean and deterministic")?;
        assert_eq!(
            fs::read(fixture.root.join("api/positron/v1/openapi.json"))?,
            api_drift
        );
        assert_eq!(
            fs::read(fixture.root.join("configuration/schema.json"))?,
            configuration_drift
        );
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn generation_verification_restores_outputs_when_a_later_generator_fails() -> TestResult {
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    fixture.copy_configuration_source()?;
    let result = (|| {
        fixture.assert_combined_success()?;
        let api_drift = b"hand-edited OpenAPI before configuration failure\n";
        fs::write(fixture.root.join("api/positron/v1/openapi.json"), api_drift)?;
        let configuration_path = fixture.root.join("crates/positron-config/src/contract.rs");
        let invalid_configuration = fs::read_to_string(&configuration_path)?.replace(
            "pub(crate) const SETTING_DEFINITIONS: [SettingDefinition; 7] = define_settings! {",
            "pub(crate) const SETTING_DEFINITIONS = define_settings! {",
        );
        fs::write(configuration_path, invalid_configuration)?;
        fixture.assert_verification_failure_containing("header is not exact")?;
        assert_eq!(
            fs::read(fixture.root.join("api/positron/v1/openapi.json"))?,
            api_drift
        );
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn generation_verification_detects_read_only_drift_without_mutating_checked_output() -> TestResult {
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    fixture.copy_configuration_source()?;
    let result = (|| {
        fixture.assert_combined_success()?;
        let path = fixture.root.join("api/positron/v1/openapi.json");
        let drift = b"read-only hand-edited OpenAPI\n";
        fs::write(&path, drift)?;
        let mut permissions = fs::metadata(&path)?.permissions();
        permissions.set_mode(0o444);
        fs::set_permissions(&path, permissions)?;
        fixture.assert_verification_failure_containing("not clean and deterministic")?;
        assert_eq!(fs::read(&path)?, drift);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o444);
        assert!(
            fs::read_dir(fixture.root.join("target/quality/tmp"))?
                .collect::<Result<Vec<_>, _>>()?
                .is_empty()
        );
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn parallel_generation_verifications_claim_distinct_bounded_staging() -> TestResult {
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    fixture.copy_configuration_source()?;
    let result = (|| {
        fixture.assert_combined_success()?;
        let outputs = thread::scope(|scope| {
            let first = scope.spawn(|| fixture.verification_output());
            let second = scope.spawn(|| fixture.verification_output());
            [first.join(), second.join()]
        });
        for joined in outputs {
            let output =
                joined.map_err(|_| io::Error::other("parallel verification thread panicked"))??;
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "parallel verification failed: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ))
                .into());
            }
        }
        assert!(
            fs::read_dir(fixture.root.join("target/quality/tmp"))?
                .collect::<Result<Vec<_>, _>>()?
                .is_empty()
        );
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn two_clean_generations_ignore_preexisting_staging_contamination_and_report_parity() -> TestResult
{
    let fixture = GeneratorFixture::create(&canonical_source()?)?;
    fixture.copy_configuration_source()?;
    let result = (|| {
        fixture.assert_combined_success()?;
        let contaminated = fixture
            .root
            .join("target/quality/tmp/verify-generation-0/api/positron/v1/openapi.json");
        let parent = contaminated
            .parent()
            .ok_or_else(|| io::Error::other("contaminated fixture has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(&contaminated, b"preexisting staging contamination\n")?;

        let output = fixture.verification_output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "two-clean verification failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        let stdout = String::from_utf8(output.stdout)?;
        let (_, digests) = stdout
            .split_once("clean generation A sha256:")
            .ok_or_else(|| io::Error::other("first clean generation digest is missing"))?;
        let (first, second_with_verdict) = digests
            .split_once("; clean generation B sha256:")
            .ok_or_else(|| io::Error::other("second clean generation digest is missing"))?;
        let (second, verdict) = second_with_verdict
            .split_once("; parity=")
            .ok_or_else(|| io::Error::other("clean generation parity verdict is missing"))?;
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(first, second);
        assert_eq!(verdict.trim(), "byte-identical");
        assert_eq!(
            fs::read(&contaminated)?,
            b"preexisting staging contamination\n"
        );
        let remaining = fs::read_dir(fixture.root.join("target/quality/tmp"))?
            .collect::<Result<Vec<_>, _>>()?;
        let [remaining] = remaining.as_slice() else {
            return Err(io::Error::other("owned staging roots were not both removed").into());
        };
        assert_eq!(remaining.file_name(), "verify-generation-0");
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn semantic_rpc_changes_propagate_to_every_generated_transport_artifact() -> TestResult {
    let source = canonical_source()?
        .replace("rpc Negotiate(", "rpc Inspect(")
        .replacen("uint32 api_major = 1;", "uint32 requested_major = 3;", 1);
    let fixture = GeneratorFixture::create(&source)?;
    let result = (|| {
        fixture.assert_success()?;
        let rust = fixture.read("crates/positron-api/src/generated.rs")?;
        let openapi = fixture.read("api/positron/v1/openapi.json")?;
        let http = fixture.read("api/positron/v1/http.json")?;
        let validation = fixture.read("api/positron/v1/validation-fixtures.json")?;

        assert!(rust.contains("CapabilityService/Inspect"));
        assert!(rust.contains("const GRPC_API_MAJOR_TAG: u8 = 24;"));
        assert!(rust.contains("requested_major: u32"));
        assert!(openapi.contains("/v1/capabilities:inspect"));
        assert!(openapi.contains("\"operationId\": \"InspectCapabilityResponse\""));
        assert!(openapi.contains("\"requested_major\""));
        assert!(http.contains("\"rpc\": \"positron.v1.CapabilityService/Inspect\""));
        assert!(http.contains("\"path\": \"/v1/capabilities:inspect\""));
        assert!(http.contains("\"proto\": \"requested_major\""));
        assert!(http.contains("\"number\": 3"));
        assert!(validation.contains("\\\"requested_major\\\":1"));
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn response_field_changes_propagate_to_generated_schema_surfaces() -> TestResult {
    let source =
        canonical_source()?.replace("string schema_digest = 2;", "string source_digest = 7;");
    let fixture = GeneratorFixture::create(&source)?;
    let result = (|| {
        fixture.assert_success()?;
        let rust = fixture.read("crates/positron-api/src/generated.rs")?;
        let openapi = fixture.read("api/positron/v1/openapi.json")?;
        let http = fixture.read("api/positron/v1/http.json")?;

        assert!(rust.contains("source_digest: SchemaDigest"));
        assert!(openapi.contains("\"source_digest\""));
        assert!(http.contains("\"proto\": \"source_digest\""));
        assert!(http.contains("\"number\": 7"));
        assert!(!rust.contains("schema_digest: SchemaDigest"));
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn public_error_field_changes_propagate_to_generated_schema_surfaces() -> TestResult {
    let source = canonical_source()?.replace(
        "SafeDetail safe_detail = 5;",
        "SafeDetail redacted_detail = 9 [deprecated = true];",
    );
    let fixture = GeneratorFixture::create(&source)?;
    let result = (|| {
        fixture.assert_success()?;
        let rust = fixture.read("crates/positron-api/src/generated.rs")?;
        let openapi = fixture.read("api/positron/v1/openapi.json")?;
        let http = fixture.read("api/positron/v1/http.json")?;

        assert!(rust.contains("redacted_detail: SafeDetail"));
        assert!(rust.contains("pub const fn redacted_detail"));
        assert!(openapi.contains("\"redacted_detail\""));
        assert!(openapi.contains("\"x-protobuf-field-number\": 9"));
        assert!(openapi.contains("\"deprecated\": true"));
        assert!(http.contains("\"proto\": \"redacted_detail\""));
        Ok(())
    })();
    fixture.remove()?;
    result
}

#[test]
fn capability_and_enum_value_changes_propagate_to_generated_schema_surfaces() -> TestResult {
    let source = canonical_source()?
        .replace(
            "CAPABILITY_METRICS = 3;",
            "CAPABILITY_METRICS = 9 [deprecated = true];",
        )
        .replace(
            "CAPABILITY_AVAILABILITY_UNAVAILABLE = 2;",
            "CAPABILITY_AVAILABILITY_UNAVAILABLE = 7;",
        );
    let fixture = GeneratorFixture::create(&source)?;
    let result = (|| {
        fixture.assert_success()?;
        let rust = fixture.read("crates/positron-api/src/generated.rs")?;
        let openapi = fixture.read("api/positron/v1/openapi.json")?;
        let http = fixture.read("api/positron/v1/http.json")?;

        assert!(rust.contains("Metrics = 9"));
        assert!(rust.contains("Unavailable = 7"));
        assert!(rust.contains("Self::Metrics => true"));
        assert!(openapi.contains("\"enum\": [0, 1, 2, 9]"));
        assert!(openapi.contains("\"enum\": [0, 1, 7, 3, 4]"));
        assert!(http.contains("\"CAPABILITY_METRICS\", \"number\": 9, \"deprecated\": true"));
        assert!(http.contains("\"CAPABILITY_AVAILABILITY_UNAVAILABLE\", \"number\": 7"));
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
    let result = fixture
        .assert_failure_containing("message `CapabilityRequest` fields are missing or ambiguous");
    fixture.remove()?;
    result
}

#[test]
fn ambiguous_enum_numbers_fail_closed() -> TestResult {
    let source = canonical_source()?.replace("CAPABILITY_METRICS = 3;", "CAPABILITY_METRICS = 2;");
    let fixture = GeneratorFixture::create(&source)?;
    let result = fixture.assert_failure_containing("values are missing, ambiguous, or unsupported");
    fixture.remove()?;
    result
}

#[test]
fn unsupported_proto_constructs_fail_closed() -> TestResult {
    let source = canonical_source()?.replace(
        "string schema_digest = 2;",
        "oneof digest_value {\n    string schema_digest = 2;\n  }",
    );
    let fixture = GeneratorFixture::create(&source)?;
    let result = fixture.assert_failure_containing("request field");
    fixture.remove()?;
    result
}

#[test]
fn unsupported_top_level_proto_constructs_fail_closed() -> TestResult {
    let source = canonical_source()?.replace(
        "package positron.v1;",
        "package positron.v1;\nimport \"google/protobuf/empty.proto\";",
    );
    let fixture = GeneratorFixture::create(&source)?;
    let result = fixture.assert_failure_containing("unsupported protobuf statement");
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

    fn assert_combined_success(&self) -> TestResult {
        let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .current_dir(&self.root)
            .arg("generate")
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "combined generator failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }

    fn assert_verification_failure_containing(&self, expected: &str) -> TestResult {
        let output = self.verification_output()?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !output.status.success() && combined.contains(expected) {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "generation verification did not fail with `{expected}`: {combined}"
        ))
        .into())
    }

    fn verification_output(&self) -> io::Result<Output> {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .current_dir(&self.root)
            .arg("verify-generation")
            .output()
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
            "api/positron/v1/validation-fixtures.json",
        ]
        .iter()
        .map(|path| Ok(fs::read(self.root.join(path))?))
        .collect()
    }

    fn all_generated_artifacts(&self) -> TestResult<Vec<Vec<u8>>> {
        [
            "crates/positron-api/src/generated.rs",
            "api/positron/v1/schema.sha256",
            "api/positron/v1/openapi.json",
            "api/positron/v1/http.json",
            "api/positron/v1/validation-fixtures.json",
            "configuration/schema.json",
            "configuration/reference.md",
            "configuration/validation-fixtures.json",
        ]
        .iter()
        .map(|path| Ok(fs::read(self.root.join(path))?))
        .collect()
    }

    fn copy_configuration_source(&self) -> TestResult {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let source = manifest.join("../../crates/positron-config/src/contract.rs");
        let destination = self.root.join("crates/positron-config/src/contract.rs");
        let parent = destination.parent().ok_or_else(|| {
            std::io::Error::other("configuration contract destination has no parent")
        })?;
        fs::create_dir_all(parent)?;
        fs::create_dir_all(self.root.join("configuration"))?;
        fs::copy(source, destination)?;
        Ok(())
    }

    fn read(&self, path: &str) -> TestResult<String> {
        Ok(fs::read_to_string(self.root.join(path))?)
    }

    fn remove(&self) -> TestResult {
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }
}
