use std::sync::Arc;

use positron_config::{ConfigurationDiff, EffectiveConfiguration};
use positron_governance::{ConfigurationAuditOutcome, ConfigurationAuditRequest};
use positron_kernel::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, FormatEpoch, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::{
    BootstrapFailure, BootstrapFailureCode, ConfigurationPublication,
    ConfigurationPublicationDisposition, ConfigurationRuntimeFailure, InitializedInstance,
};

const CONFIGURATION_OBJECT_MAGIC: [u8; 8] = *b"POSCFGV1";

/// The runtime's adapter to the sole Catalog Writer for configuration
/// publication. It persists only redacted effective configuration bytes.
#[derive(Clone)]
pub struct CatalogConfigurationPublication {
    instance: Arc<InitializedInstance>,
}

impl CatalogConfigurationPublication {
    #[must_use]
    pub fn new(instance: Arc<InitializedInstance>) -> Self {
        Self { instance }
    }

    /// Ensures the resolved startup configuration has one durable active
    /// generation before any runtime consumer receives it.
    pub fn establish(
        &self,
        active: &EffectiveConfiguration,
    ) -> Result<u64, ConfigurationRuntimeFailure> {
        self.instance
            .establish_configuration_generation(active)
            .map_err(|_| ConfigurationRuntimeFailure::PublicationUnavailable)
    }

    /// Records a rejected source candidate without publishing any new
    /// configuration object. The active generation remains authoritative.
    pub fn record_invalid(
        &self,
        active: &EffectiveConfiguration,
    ) -> Result<(), ConfigurationRuntimeFailure> {
        self.instance
            .record_invalid_configuration_change(active)
            .map_err(|_| ConfigurationRuntimeFailure::PublicationUnavailable)
    }
}

impl ConfigurationPublication for CatalogConfigurationPublication {
    fn publish(
        &self,
        active: &EffectiveConfiguration,
        candidate: &EffectiveConfiguration,
        diff: &ConfigurationDiff,
        disposition: ConfigurationPublicationDisposition,
    ) -> Result<u64, ConfigurationRuntimeFailure> {
        self.instance
            .publish_configuration_change(active, candidate, diff, disposition)
            .map_err(|_| ConfigurationRuntimeFailure::PublicationUnavailable)
    }
}

impl InitializedInstance {
    fn record_invalid_configuration_change(
        &self,
        active: &EffectiveConfiguration,
    ) -> Result<(), BootstrapFailure> {
        self.commit_configuration_audit_only(active, ConfigurationAuditOutcome::RejectedInvalid)
            .map(|_| ())
    }

    pub(crate) fn establish_configuration_generation(
        &self,
        active: &EffectiveConfiguration,
    ) -> Result<u64, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let basis = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(generation) = configuration_generation_if_matches(&basis, active)? {
            return Ok(generation);
        }
        let catalog_generation = basis
            .number()
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let digest = configuration_digest(active);
        let request = ConfigurationAuditRequest::new(
            ConfigurationAuditOutcome::PublishedLive,
            catalog_generation,
            1,
            digest,
            digest,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let transaction = TransactionId::new(request.transaction_id())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let objects = successor_objects(&basis, transaction, active, Some(catalog_generation))?;
        let proposal = CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let audit = AuditIntent::new(request.encode())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let committed_generation = catalog
            .commit(basis.identity(), proposal, Some(audit))
            .map(|commit| commit.number())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        exact_catalog_generation(committed_generation, catalog_generation)
    }

    pub(crate) fn publish_configuration_change(
        &self,
        active: &EffectiveConfiguration,
        candidate: &EffectiveConfiguration,
        diff: &ConfigurationDiff,
        disposition: ConfigurationPublicationDisposition,
    ) -> Result<u64, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let basis = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let catalog_generation = basis
            .number()
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let request = ConfigurationAuditRequest::new(
            audit_outcome(disposition),
            catalog_generation,
            u8::try_from(diff.changes().len())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
            configuration_digest(active),
            configuration_digest(candidate),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let transaction = TransactionId::new(request.transaction_id())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let replaces_active_configuration = matches!(
            disposition,
            ConfigurationPublicationDisposition::PublishedLive
                | ConfigurationPublicationDisposition::PendingRestart
        );
        let persisted_active = if disposition == ConfigurationPublicationDisposition::PublishedLive
        {
            candidate
        } else {
            active
        };
        let objects = successor_objects(
            &basis,
            transaction,
            persisted_active,
            replaces_active_configuration.then_some(catalog_generation),
        )?;
        let proposal = CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let audit = AuditIntent::new(request.encode())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let committed_generation = catalog
            .commit(basis.identity(), proposal, Some(audit))
            .map(|commit| commit.number())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        exact_catalog_generation(committed_generation, catalog_generation)
    }

    fn commit_configuration_audit_only(
        &self,
        active: &EffectiveConfiguration,
        outcome: ConfigurationAuditOutcome,
    ) -> Result<u64, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let basis = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let catalog_generation = basis
            .number()
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let digest = configuration_digest(active);
        let request =
            ConfigurationAuditRequest::new(outcome, catalog_generation, 1, digest, digest)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let transaction = TransactionId::new(request.transaction_id())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let objects = successor_objects(&basis, transaction, active, None)?;
        let proposal = CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let audit = AuditIntent::new(request.encode())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        catalog
            .commit(basis.identity(), proposal, Some(audit))
            .map(|commit| commit.number())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }
}

fn successor_objects(
    basis: &positron_kernel::CatalogSnapshot,
    transaction: TransactionId,
    active: &EffectiveConfiguration,
    replacement_generation: Option<u64>,
) -> Result<Vec<CatalogObject>, BootstrapFailure> {
    let replace_configuration = replacement_generation.is_some();
    let capacity = basis
        .object_count()
        .checked_add(usize::from(replace_configuration))
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(capacity)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    let mut configuration_count = 0_u8;
    for identity in basis.object_identities() {
        let bytes = basis
            .object(identity)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if bytes.starts_with(&CONFIGURATION_OBJECT_MAGIC) {
            configuration_count = configuration_count
                .checked_add(1)
                .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            if replace_configuration {
                continue;
            }
        }
        objects.push(
            CatalogObject::new(bytes.to_vec())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
        );
    }
    if configuration_count > 1 || (!replace_configuration && configuration_count == 0) {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::CatalogUnavailable,
        ));
    }
    if let Some(generation) = replacement_generation {
        objects.push(
            CatalogObject::new(configuration_object(transaction, generation, active))
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
        );
    }
    Ok(objects)
}

fn configuration_generation_if_matches(
    basis: &positron_kernel::CatalogSnapshot,
    active: &EffectiveConfiguration,
) -> Result<Option<u64>, BootstrapFailure> {
    let expected = active.redacted_effective();
    let mut found = None;
    for identity in basis.object_identities() {
        let bytes = basis
            .object(identity)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if !bytes.starts_with(&CONFIGURATION_OBJECT_MAGIC) {
            continue;
        }
        if found.replace(bytes).is_some() {
            return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
        }
    }
    let Some(bytes) = found else {
        return Ok(None);
    };
    let generation_start = CONFIGURATION_OBJECT_MAGIC.len().saturating_add(16);
    let generation_end = generation_start.saturating_add(8);
    let generation_bytes = bytes
        .get(generation_start..generation_end)
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let generation = u64::from_be_bytes(
        generation_bytes
            .try_into()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
    );
    if generation == 0 {
        return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
    }
    let rendered = bytes
        .get(generation_end..)
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    Ok((rendered == expected.as_bytes()).then_some(generation))
}

fn configuration_object(
    transaction: TransactionId,
    generation: u64,
    active: &EffectiveConfiguration,
) -> Vec<u8> {
    let rendered = active.redacted_effective();
    let mut object = Vec::with_capacity(
        CONFIGURATION_OBJECT_MAGIC
            .len()
            .saturating_add(16)
            .saturating_add(8)
            .saturating_add(rendered.len()),
    );
    object.extend_from_slice(&CONFIGURATION_OBJECT_MAGIC);
    object.extend_from_slice(&transaction.to_bytes());
    object.extend_from_slice(&generation.to_be_bytes());
    object.extend_from_slice(rendered.as_bytes());
    object
}

fn exact_catalog_generation(
    committed_generation: u64,
    expected_generation: u64,
) -> Result<u64, BootstrapFailure> {
    (committed_generation == expected_generation)
        .then_some(committed_generation)
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
}

fn configuration_digest(configuration: &EffectiveConfiguration) -> [u8; 32] {
    let digest = Sha256::digest(configuration.redacted_effective().as_bytes());
    let mut result = [0; 32];
    result.copy_from_slice(&digest);
    result
}

const fn audit_outcome(
    disposition: ConfigurationPublicationDisposition,
) -> ConfigurationAuditOutcome {
    match disposition {
        ConfigurationPublicationDisposition::PublishedLive => {
            ConfigurationAuditOutcome::PublishedLive
        },
        ConfigurationPublicationDisposition::PendingRestart => {
            ConfigurationAuditOutcome::PendingRestart
        },
        ConfigurationPublicationDisposition::RejectedImmutable => {
            ConfigurationAuditOutcome::RejectedImmutable
        },
        ConfigurationPublicationDisposition::RequiresDrain => {
            ConfigurationAuditOutcome::RequiresDrain
        },
        ConfigurationPublicationDisposition::FencedDrift => ConfigurationAuditOutcome::FencedDrift,
    }
}
