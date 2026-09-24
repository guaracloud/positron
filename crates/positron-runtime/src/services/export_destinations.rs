use std::sync::Arc;

use positron_domain::identity::TenantId;
use positron_query::ExportDestinationResolver;

use crate::RuntimeConfiguration;

/// Runtime composition adapter from the canonical configuration to Query's
/// narrow destination-resolution seam.
pub struct ConfiguredExportDestinationResolver {
    configuration: Arc<RuntimeConfiguration>,
}

impl ConfiguredExportDestinationResolver {
    #[must_use]
    pub fn from_runtime(configuration: Arc<RuntimeConfiguration>) -> Self {
        Self { configuration }
    }
}

impl ExportDestinationResolver for ConfiguredExportDestinationResolver {
    fn resolve(&self, tenant: TenantId, name: &str) -> Option<[u8; 16]> {
        let configuration = self
            .configuration
            .observed()
            .map(|observation| Arc::clone(observation.effective()))
            .ok()?;
        configuration
            .export_destination(tenant, name)
            .map(|destination| destination.identity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use positron_config::{
        CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve,
    };

    #[test]
    fn resolves_only_the_configured_destination_for_an_allowed_tenant()
    -> Result<(), Box<dyn std::error::Error>> {
        let inputs = ConfigurationInputs::try_new(
            Some(
                "schema_version = 1\n[[export.destination]]\nname = \"regulated-archive\"\nidentity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\nallowed_tenants = [\"11111111-1111-1111-1111-111111111111\"]\n",
            ),
            EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        )?;
        let runtime = Arc::new(RuntimeConfiguration::new(Arc::new(resolve(inputs)?)));
        let resolver = ConfiguredExportDestinationResolver::from_runtime(runtime);
        let allowed = TenantId::parse_canonical("11111111-1111-1111-1111-111111111111")?;
        let denied = TenantId::parse_canonical("22222222-2222-2222-2222-222222222222")?;

        assert_eq!(
            resolver.resolve(allowed, "regulated-archive"),
            Some([0xa1; 16])
        );
        assert_eq!(resolver.resolve(denied, "regulated-archive"), None);
        assert_eq!(resolver.resolve(allowed, "unknown"), None);
        Ok(())
    }
}
