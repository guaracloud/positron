mod api_key;
mod policy_activate;
mod policy_diff;
mod policy_explain;
mod policy_preview;
mod policy_test;
mod tenant_alias;
mod tenant_lifecycle;
mod tenant_quota;
mod tenant_retention;
mod tenant_service;

use super::validation::ValidatedOperations;
use std::error::Error;
use std::path::PathBuf;

pub(super) fn generate_all(operations: &ValidatedOperations) -> Result<(), Box<dyn Error>> {
    api_key::generate_api_key_client(operations)?;
    tenant_quota::generate_tenant_quota_client(operations)?;
    tenant_lifecycle::generate_tenant_lifecycle_client(operations)?;
    tenant_retention::generate_tenant_retention_client(operations)?;
    tenant_service::generate_tenant_service_client(operations)?;
    tenant_alias::generate_tenant_alias_client(operations)?;
    policy_preview::generate_policy_preview_client(operations)?;
    policy_test::generate_policy_test_client(operations)?;
    policy_diff::generate_policy_diff_client(operations)?;
    policy_explain::generate_policy_explain_client(operations)?;
    policy_activate::generate_policy_activate_client(operations)?;
    Ok(())
}

fn write_generated(filename: &str, source: String) -> Result<(), Box<dyn Error>> {
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join(filename),
        source,
    )?;
    Ok(())
}
