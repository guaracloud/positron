use std::sync::Arc;

use positron_config::{ConfigurationDiff, EffectiveConfiguration};
use positron_domain::routing::SignalKind;
use positron_governance::{
    ConfigurationAuditContext, ConfigurationAuditOutcome, ConfigurationAuditRequest,
};
use positron_kernel::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::{
    BootstrapFailure, BootstrapFailureCode, ConfigurationPublication,
    ConfigurationPublicationDisposition, ConfigurationRuntimeFailure, InitializedInstance,
};

const CONFIGURATION_OBJECT_MAGIC: [u8; 8] = *b"POSCFGV1";
const CONFIGURATION_OBJECT_HEADER_BYTES: usize =
    CONFIGURATION_OBJECT_MAGIC.len() + 16 + 8 + 32 + 32;
const CONFIGURATION_BINDING_DOMAIN: &[u8] = b"positron.configuration.binding.v1\0";

#[derive(Debug)]
pub(crate) enum ConfigurationEstablishFailure {
    ImmutableConfiguration,
    Unavailable,
}

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
            .map_err(|failure| match failure {
                ConfigurationEstablishFailure::ImmutableConfiguration => {
                    ConfigurationRuntimeFailure::ImmutableConfiguration
                },
                ConfigurationEstablishFailure::Unavailable => {
                    ConfigurationRuntimeFailure::PublicationUnavailable
                },
            })
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
    ) -> Result<u64, ConfigurationEstablishFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        let expected_audit_binding = ConfigurationAuditBinding::from_configuration(&secret, active)
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        let basis = catalog
            .pin()
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        let expected_digest = expected_audit_binding.redacted_digest;
        if let Some(existing) = configuration_catalog_state(&basis)
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?
        {
            if existing.effective_digest == expected_digest
                && existing.audit_binding_digest == expected_audit_binding.private_digest
            {
                return Ok(existing.generation);
            }
            if existing.immutable_digest != active.immutable_configuration_digest() {
                let catalog_generation = basis
                    .number()
                    .checked_add(1)
                    .ok_or(ConfigurationEstablishFailure::Unavailable)?;
                let request = self
                    .configuration_audit_request(
                        ConfigurationAuditOutcome::RejectedImmutable,
                        catalog_generation,
                        1,
                        ConfigurationAuditBinding::stored(
                            existing.effective_digest,
                            existing.audit_binding_digest,
                        ),
                        expected_audit_binding,
                    )
                    .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
                let transaction = TransactionId::new(request.transaction_id())
                    .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
                let objects = successor_objects(&basis, transaction, None)
                    .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
                let proposal = CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)
                    .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
                let audit = AuditIntent::new(request.encode())
                    .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
                let committed_generation = catalog
                    .commit(basis.identity(), proposal, Some(audit))
                    .map(|commit| commit.number())
                    .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
                exact_catalog_generation(committed_generation, catalog_generation)
                    .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
                return Err(ConfigurationEstablishFailure::ImmutableConfiguration);
            }
        }
        let catalog_generation = basis
            .number()
            .checked_add(1)
            .ok_or(ConfigurationEstablishFailure::Unavailable)?;
        let request = self
            .configuration_audit_request(
                ConfigurationAuditOutcome::PublishedLive,
                catalog_generation,
                1,
                expected_audit_binding,
                expected_audit_binding,
            )
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        let transaction = TransactionId::new(request.transaction_id())
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        let objects = successor_objects(
            &basis,
            transaction,
            Some((
                catalog_generation,
                active,
                expected_audit_binding.private_digest,
            )),
        )
        .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        let proposal = CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        let audit = AuditIntent::new(request.encode())
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        let committed_generation = catalog
            .commit(basis.identity(), proposal, Some(audit))
            .map(|commit| commit.number())
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)?;
        exact_catalog_generation(committed_generation, catalog_generation)
            .map_err(|_| ConfigurationEstablishFailure::Unavailable)
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
        let active_binding = ConfigurationAuditBinding::from_configuration(&secret, active)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let candidate_binding =
            ConfigurationAuditBinding::from_configuration(&secret, candidate)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let basis = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let catalog_generation = basis
            .number()
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let request = self
            .configuration_audit_request(
                audit_outcome(disposition),
                catalog_generation,
                u8::try_from(diff.changes().len())
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
                active_binding,
                candidate_binding,
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let transaction = TransactionId::new(request.transaction_id())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let replaces_active_configuration = matches!(
            disposition,
            ConfigurationPublicationDisposition::PublishedLive
                | ConfigurationPublicationDisposition::PendingRestart
        );
        let (persisted_active, persisted_binding) =
            if disposition == ConfigurationPublicationDisposition::PublishedLive {
                (candidate, candidate_binding.private_digest)
            } else {
                (active, active_binding.private_digest)
            };
        let replacement = replaces_active_configuration.then_some((
            catalog_generation,
            persisted_active,
            persisted_binding,
        ));
        let objects = successor_objects(&basis, transaction, replacement)?;
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
        let binding = ConfigurationAuditBinding::from_configuration(&secret, active)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let basis = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let catalog_generation = basis
            .number()
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let request =
            self.configuration_audit_request(outcome, catalog_generation, 1, binding, binding)?;
        let transaction = TransactionId::new(request.transaction_id())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let objects = successor_objects(&basis, transaction, None)?;
        let proposal = CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let audit = AuditIntent::new(request.encode())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        catalog
            .commit(basis.identity(), proposal, Some(audit))
            .map(|commit| commit.number())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }

    fn configuration_audit_request(
        &self,
        outcome: ConfigurationAuditOutcome,
        catalog_generation: u64,
        changed_setting_count: u8,
        active: ConfigurationAuditBinding,
        candidate: ConfigurationAuditBinding,
    ) -> Result<ConfigurationAuditRequest, BootstrapFailure> {
        let audit_scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        let ingest_time_unix_seconds = self
            .retention_time
            .governance_time_seconds(audit_scope)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let request_id = configuration_request_id(
            self.instance.to_bytes(),
            outcome,
            active.private_digest,
            candidate.private_digest,
        );
        let context = ConfigurationAuditContext::new(
            outcome,
            ingest_time_unix_seconds,
            self.administrator(),
            None,
            self.instance.to_bytes(),
            request_id,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        ConfigurationAuditRequest::new(
            context,
            catalog_generation,
            changed_setting_count,
            active.redacted_digest,
            candidate.redacted_digest,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }
}

fn successor_objects(
    basis: &positron_kernel::CatalogSnapshot,
    transaction: TransactionId,
    replacement: Option<(u64, &EffectiveConfiguration, [u8; 32])>,
) -> Result<Vec<CatalogObject>, BootstrapFailure> {
    let replace_configuration = replacement.is_some();
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
    if let Some((generation, active, audit_binding_digest)) = replacement {
        objects.push(
            CatalogObject::new(configuration_object(
                transaction,
                generation,
                active,
                audit_binding_digest,
            ))
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
        );
    }
    Ok(objects)
}

struct ConfigurationCatalogState {
    generation: u64,
    immutable_digest: [u8; 32],
    effective_digest: [u8; 32],
    audit_binding_digest: [u8; 32],
}

/// Couples the redacted audit summary with the complete configuration intent.
///
/// Governance Audit persists the redacted digest defined by its public
/// contract. The Catalog-held opaque digest binds the complete intent and
/// only influences the opaque audit request ID.
/// That gives the Catalog proposal and its audit intent one exact binding
/// without placing protected references in an audit record.
#[derive(Clone, Copy)]
struct ConfigurationAuditBinding {
    redacted_digest: [u8; 32],
    private_digest: [u8; 32],
}

impl ConfigurationAuditBinding {
    fn from_configuration(
        secret: &CatalogSecret,
        configuration: &EffectiveConfiguration,
    ) -> Result<Self, positron_kernel::CatalogFailure> {
        Ok(Self {
            redacted_digest: configuration_digest(configuration),
            private_digest: secret.opaque_digest(
                CONFIGURATION_BINDING_DOMAIN,
                &configuration.audit_binding_digest(),
            )?,
        })
    }

    const fn stored(redacted_digest: [u8; 32], private_digest: [u8; 32]) -> Self {
        Self {
            redacted_digest,
            private_digest,
        }
    }
}

fn configuration_catalog_state(
    basis: &positron_kernel::CatalogSnapshot,
) -> Result<Option<ConfigurationCatalogState>, BootstrapFailure> {
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
    if bytes.len() < CONFIGURATION_OBJECT_HEADER_BYTES {
        return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
    }
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
    let immutable_digest_end = generation_end.saturating_add(32);
    let immutable_digest = bytes
        .get(generation_end..immutable_digest_end)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let audit_binding_digest = bytes
        .get(immutable_digest_end..CONFIGURATION_OBJECT_HEADER_BYTES)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let rendered = bytes
        .get(CONFIGURATION_OBJECT_HEADER_BYTES..)
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    if rendered.is_empty() {
        return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
    }
    let digest = Sha256::digest(rendered);
    let mut effective_digest = [0; 32];
    effective_digest.copy_from_slice(&digest);
    Ok(Some(ConfigurationCatalogState {
        generation,
        immutable_digest,
        effective_digest,
        audit_binding_digest,
    }))
}

fn configuration_object(
    transaction: TransactionId,
    generation: u64,
    active: &EffectiveConfiguration,
    audit_binding_digest: [u8; 32],
) -> Vec<u8> {
    let rendered = active.redacted_effective();
    let mut object = Vec::with_capacity(
        CONFIGURATION_OBJECT_MAGIC
            .len()
            .saturating_add(16)
            .saturating_add(8)
            .saturating_add(32)
            .saturating_add(32)
            .saturating_add(rendered.len()),
    );
    object.extend_from_slice(&CONFIGURATION_OBJECT_MAGIC);
    object.extend_from_slice(&transaction.to_bytes());
    object.extend_from_slice(&generation.to_be_bytes());
    object.extend_from_slice(&active.immutable_configuration_digest());
    object.extend_from_slice(&audit_binding_digest);
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

/// Returns the one redacted effective-configuration digest bound to Catalog
/// and Governance Audit publication.
#[must_use]
pub(crate) fn configuration_digest(configuration: &EffectiveConfiguration) -> [u8; 32] {
    let digest = Sha256::digest(configuration.redacted_effective().as_bytes());
    let mut result = [0; 32];
    result.copy_from_slice(&digest);
    result
}

fn configuration_request_id(
    instance: [u8; 16],
    outcome: ConfigurationAuditOutcome,
    active_binding_digest: [u8; 32],
    candidate_binding_digest: [u8; 32],
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"positron.configuration.request.v1\0");
    hasher.update(instance);
    hasher.update([configuration_outcome_code(outcome)]);
    hasher.update(active_binding_digest);
    hasher.update(candidate_binding_digest);
    let digest = hasher.finalize();
    let mut request_id = [0; 16];
    for (destination, source) in request_id.iter_mut().zip(digest.iter()) {
        *destination = *source;
    }
    if request_id.iter().all(|byte| *byte == 0) {
        request_id[0] = 1;
    }
    request_id
}

const fn configuration_outcome_code(outcome: ConfigurationAuditOutcome) -> u8 {
    match outcome {
        ConfigurationAuditOutcome::PublishedLive => 1,
        ConfigurationAuditOutcome::PendingRestart => 2,
        ConfigurationAuditOutcome::RejectedImmutable => 3,
        ConfigurationAuditOutcome::RequiresDrain => 4,
        ConfigurationAuditOutcome::RejectedInvalid => 5,
        ConfigurationAuditOutcome::FencedDrift => 6,
    }
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
