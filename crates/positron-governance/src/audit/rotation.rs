use crate::identity::IdentityFailure;

use super::ROOT_ROTATION_MAGIC;

/// Closed stages durably published by one Catalog root rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogRootRotationStage {
    Started,
    Verified,
    Completed,
}

impl CatalogRootRotationStage {
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Started => "catalog.root-rotation.started",
            Self::Verified => "catalog.root-rotation.verified",
            Self::Completed => "catalog.root-rotation.completed",
        }
    }
}

/// Typed, redacted meaning of one committed Catalog root-rotation position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogRootRotationAuditEntry {
    position: u64,
    stage: CatalogRootRotationStage,
    provider_key_reference: [u8; 16],
    key_epoch: u64,
    transaction_id: [u8; 16],
}

impl CatalogRootRotationAuditEntry {
    pub(super) fn decode_intent(
        position: u64,
        transaction_id: [u8; 16],
        intent: &[u8],
    ) -> Result<Self, IdentityFailure> {
        let remaining = intent
            .strip_prefix(ROOT_ROTATION_MAGIC)
            .ok_or(IdentityFailure)?;
        let stage_end = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(IdentityFailure)?;
        let stage = match remaining.get(..stage_end).ok_or(IdentityFailure)? {
            b"started" => CatalogRootRotationStage::Started,
            b"verified" => CatalogRootRotationStage::Verified,
            b"completed" => CatalogRootRotationStage::Completed,
            _ => return Err(IdentityFailure),
        };
        let body = remaining
            .get(stage_end.checked_add(1).ok_or(IdentityFailure)?..)
            .ok_or(IdentityFailure)?;
        let provider_key_reference: [u8; 16] = body
            .get(..16)
            .ok_or(IdentityFailure)?
            .try_into()
            .map_err(|_| IdentityFailure)?;
        let key_epoch = body
            .get(16..24)
            .ok_or(IdentityFailure)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| IdentityFailure)?;
        let administration_intent = body.get(24..).ok_or(IdentityFailure)?;
        if provider_key_reference.iter().all(|byte| *byte == 0)
            || key_epoch == 0
            || administration_intent.is_empty()
        {
            return Err(IdentityFailure);
        }
        Ok(Self {
            position,
            stage,
            provider_key_reference,
            key_epoch,
            transaction_id,
        })
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn stage(&self) -> CatalogRootRotationStage {
        self.stage
    }

    #[must_use]
    pub const fn action(&self) -> &'static str {
        self.stage.action()
    }

    #[must_use]
    pub const fn provider_key_reference(&self) -> [u8; 16] {
        self.provider_key_reference
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        self.transaction_id
    }

    #[must_use]
    pub const fn outcome(&self) -> &'static str {
        "committed"
    }
}
