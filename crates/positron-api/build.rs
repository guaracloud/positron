use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::Write;
use std::path::PathBuf;

mod build_support;

fn main() -> Result<(), Box<dyn Error>> {
    let schema = "../../api/positron/v1/positron.proto";
    let mapping = "../../api/positron/v1/http.json";
    println!("cargo:rerun-if-changed={schema}");
    println!("cargo:rerun-if-changed={mapping}");
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(std::fs::read(schema)?) {
        write!(&mut digest, "{byte:02x}")?;
    }
    println!("cargo:rustc-env=POSITRON_API_SCHEMA_DIGEST={digest}");
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    for message in [
        "ApiKeyRequest",
        "ApiKeyResponse",
        "KeyDescriptor",
        "TenantQuotaUpdateRequest",
        "TenantQuotaUpdateResponse",
    ] {
        config.type_attribute(
            format!(".positron.v1.{message}"),
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(deny_unknown_fields)]",
        );
    }
    for enumeration in ["KeyAction", "KeyScope"] {
        config.type_attribute(
            format!(".positron.v1.{enumeration}"),
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"snake_case\")]",
        );
    }
    config.field_attribute(
        ".positron.v1.ApiKeyRequest.action",
        "#[serde(with = \"super::action_json\")]",
    );
    config.field_attribute(".positron.v1.ApiKeyRequest.scope", "#[serde(default, skip_serializing_if = \"Option::is_none\", with = \"super::optional_scope_json\")]");
    for field in [
        "principal",
        "expires_at_unix_seconds",
        "expected_generation",
        "idempotency_key",
        "target_tenant",
    ] {
        config.field_attribute(
            format!(".positron.v1.ApiKeyRequest.{field}"),
            "#[serde(default, skip_serializing_if = \"Option::is_none\")]",
        );
    }
    config.field_attribute(
        ".positron.v1.KeyDescriptor.scope",
        "#[serde(with = \"super::scope_json\")]",
    );
    config.skip_debug([".positron.v1.ApiKeyResponse"]);
    let descriptor = PathBuf::from(std::env::var("OUT_DIR")?).join("positron-v1.bin");
    config.file_descriptor_set_path(&descriptor);
    config.compile_protos(&[schema], &["../../api"])?;
    build_support::generate_clients(&descriptor, mapping)?;
    Ok(())
}
