use positron_governance::{
    AdministrativeIdempotencyKey, AuthorizedContext, IngestPolicyActivation,
    PolicyAdministrationFailureCode, ResourceGeneration,
};
use positron_ingest::IngestPolicy;
use positron_kernel::Catalog;

use super::{ServiceFailure, ServiceHandle, failure::classify_catalog_failure_code};

impl ServiceHandle {
    pub fn activate_ingest_policy(
        &self,
        context: AuthorizedContext,
        expected: ResourceGeneration,
        key: AdministrativeIdempotencyKey,
        candidate: IngestPolicy,
    ) -> Result<IngestPolicyActivation, ServiceFailure> {
        let instance = &self.instance;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| ServiceFailure::KeyUnavailable)?,
        )
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
        let identity = positron_governance::Identity::open(
            &catalog
                .pin()
                .map_err(|failure| classify_catalog_failure_code(failure.code()))?,
        )
        .map_err(|_| ServiceFailure::CorruptState)?;
        instance
            .ingest_policy
            .activate(&catalog, &identity, context, expected, key, candidate)
            .map_err(|failure| match failure.code() {
                PolicyAdministrationFailureCode::Unauthorized => ServiceFailure::Unauthorized,
                PolicyAdministrationFailureCode::PersistenceUnavailable
                | PolicyAdministrationFailureCode::CorruptState => {
                    ServiceFailure::StorageUnavailable
                },
                _ => ServiceFailure::InvalidRequest,
            })
    }
}
