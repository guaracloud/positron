use super::{
    AuditIntent, Catalog, CatalogFailure, CatalogFailureCode, CatalogObject, CatalogProposal,
    CatalogRotation, CatalogWrappingKey, TransactionId,
};
use crate::data_protection::DataProtection;
use crate::{RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts};

const ROTATION_AUDIT_DOMAIN: &[u8] = b"catalog-root-rotation-v1\0";
const ROTATION_TRANSACTION_DOMAIN: &[u8] = b"positron-catalog-root-rotation-transaction-v1";

impl Catalog<'_> {
    /// Rewraps every reachable encrypted artifact under a successor root key.
    ///
    /// Marker authentication is a separate stable authority and is never changed. An
    /// interrupted pass can be reopened with [`super::CatalogSecret::with_predecessor`] and retried.
    /// Started, successor-verified, and completed states are deterministic audited Catalog
    /// transactions. The predecessor route remains installed until completion is published.
    pub fn rewrap(
        &self,
        transaction: TransactionId,
        replacement: CatalogWrappingKey,
        intent: AuditIntent,
    ) -> Result<CatalogRotation, CatalogFailure> {
        let transactions = rotation_transactions(transaction)?;
        let audits = rotation_audits(&replacement, &intent)?;
        let replacement_route = (replacement.provider_key_reference, replacement.key_epoch);
        let claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            rewrap_resource_claim(),
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
        let _reservation = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;

        self.refresh_state()?;
        let started_exists = self.has_transaction(transactions[0])?;
        {
            let secret = self
                .secret
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            let valid_route = match secret.predecessor.as_ref() {
                Some(_) => replacement.same_route(&secret.wrapping),
                None => {
                    (started_exists && replacement.same_route(&secret.wrapping))
                        || (replacement.key_epoch > secret.wrapping.key_epoch
                            && !replacement.same_route(&secret.wrapping))
                },
            };
            if !valid_route {
                return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
            }
        }

        let expected = self.pin()?.identity();
        let started = self.commit_unreserved(
            expected,
            self.rotation_proposal(transactions[0])?,
            Some(audits[0].clone()),
        )?;

        if !self.has_transaction(transactions[1])? {
            let state = self
                .state
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            let mut secret = self
                .secret
                .lock()
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
            let current = match secret.predecessor.as_ref() {
                Some(predecessor) => predecessor,
                None => &secret.wrapping,
            };
            for outcome in state.transactions.values() {
                for identity in &outcome.record.objects {
                    self.storage.rewrap_object(
                        current,
                        &replacement,
                        self.instance,
                        *identity,
                        outcome.record.format_epoch,
                    )?;
                }
                if let Some(audit) = outcome.audit.as_ref() {
                    self.storage.rewrap_audit(
                        current,
                        &replacement,
                        self.instance,
                        audit.position,
                        audit.hash,
                    )?;
                }
                self.storage.rewrap_commit(
                    current,
                    &replacement,
                    self.instance,
                    outcome.record.generation,
                )?;
            }
            if secret.predecessor.is_none() {
                let predecessor = std::mem::replace(&mut secret.wrapping, replacement);
                secret.predecessor = Some(predecessor);
            }
        }

        let verified = self.commit_unreserved(
            self.pin()?.identity(),
            self.rotation_proposal(transactions[1])?,
            Some(audits[1].clone()),
        )?;
        let completed = self.commit_unreserved(
            self.pin()?.identity(),
            self.rotation_proposal(transactions[2])?,
            Some(audits[2].clone()),
        )?;
        let mut secret = self
            .secret
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        if secret.wrapping.provider_key_reference != replacement_route.0
            || secret.wrapping.key_epoch != replacement_route.1
        {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        secret.predecessor = None;
        Ok(CatalogRotation {
            started,
            verified,
            completed,
        })
    }

    fn has_transaction(&self, transaction: TransactionId) -> Result<bool, CatalogFailure> {
        self.state
            .lock()
            .map(|state| state.transactions.contains_key(&transaction))
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))
    }

    fn rotation_proposal(
        &self,
        transaction: TransactionId,
    ) -> Result<CatalogProposal, CatalogFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::ConcurrentWriter))?;
        let epoch = state
            .current
            .format_epoch()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        let objects = state
            .current
            .0
            .objects
            .values()
            .map(|plaintext| CatalogObject::new(plaintext.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        CatalogProposal::new(transaction, epoch, objects)
    }
}

fn rotation_transactions(base: TransactionId) -> Result<[TransactionId; 3], CatalogFailure> {
    fn derive(base: TransactionId, stage: u8) -> Result<TransactionId, CatalogFailure> {
        let mut encoded = Vec::with_capacity(ROTATION_TRANSACTION_DOMAIN.len() + 17);
        encoded.extend_from_slice(ROTATION_TRANSACTION_DOMAIN);
        encoded.extend_from_slice(&base.0);
        encoded.push(stage);
        let digest = DataProtection::hash(&encoded)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        let mut identifier = [0_u8; 16];
        identifier.copy_from_slice(&digest[..16]);
        TransactionId::new(identifier)
    }
    Ok([derive(base, 0)?, derive(base, 1)?, derive(base, 2)?])
}

fn rotation_audits(
    replacement: &CatalogWrappingKey,
    intent: &AuditIntent,
) -> Result<[AuditIntent; 3], CatalogFailure> {
    fn prepare(
        replacement: &CatalogWrappingKey,
        intent: &AuditIntent,
        stage: &[u8],
    ) -> Result<AuditIntent, CatalogFailure> {
        let mut encoded = Vec::with_capacity(
            ROTATION_AUDIT_DOMAIN.len() + stage.len() + 1 + 16 + 8 + intent.0.len(),
        );
        encoded.extend_from_slice(ROTATION_AUDIT_DOMAIN);
        encoded.extend_from_slice(stage);
        encoded.push(0);
        encoded.extend_from_slice(&replacement.provider_key_reference);
        encoded.extend_from_slice(&replacement.key_epoch.to_be_bytes());
        encoded.extend_from_slice(&intent.0);
        AuditIntent::new(encoded)
    }
    Ok([
        prepare(replacement, intent, b"started")?,
        prepare(replacement, intent, b"verified")?,
        prepare(replacement, intent, b"completed")?,
    ])
}

fn rewrap_resource_claim() -> ResourceAmounts {
    super::recovery_resource_claim().maximum(ResourceAmounts::new([
        super::MAX_RECOVERY_MEMORY_BYTES,
        1,
        1,
        super::MAX_RECOVERY_MEMORY_BYTES,
        super::MAX_RECOVERY_ITEMS,
        0,
        1,
        1,
        1,
        8,
        super::MAX_RETAINED_HISTORY_BYTES as u64,
    ]))
}
