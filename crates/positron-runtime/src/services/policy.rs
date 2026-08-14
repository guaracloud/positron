use positron_governance::{
    AdministrativeIdempotencyKey, AuthorizedContext, IngestPolicyActivation,
    PolicyAdministrationFailureCode, ResourceGeneration,
};
use positron_ingest::IngestPolicy;
use positron_kernel::Catalog;

use super::{ServiceFailure, ServiceHandle};

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
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
        instance
            .ingest_policy
            .activate(
                &catalog,
                &instance.identity,
                context,
                expected,
                key,
                candidate,
            )
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
