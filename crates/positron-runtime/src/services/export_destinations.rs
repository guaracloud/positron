use std::sync::Arc;

use positron_config::EffectiveConfiguration;
use positron_domain::identity::TenantId;
use positron_query::ExportDestinationResolver;

/// Runtime composition adapter from the canonical configuration to Query's
/// narrow destination-resolution seam.
pub struct ConfiguredExportDestinationResolver {
    configuration: Arc<EffectiveConfiguration>,
}

impl ConfiguredExportDestinationResolver {
    #[must_use]
    pub fn new(configuration: Arc<EffectiveConfiguration>) -> Self {
        Self { configuration }
    }
}

impl ExportDestinationResolver for ConfiguredExportDestinationResolver {
    fn resolve(&self, tenant: TenantId, name: &str) -> Option<[u8; 16]> {
        self.configuration
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
        let resolver = ConfiguredExportDestinationResolver::new(Arc::new(resolve(inputs)?));
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
