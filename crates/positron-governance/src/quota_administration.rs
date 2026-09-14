use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::TenantId;
use positron_kernel::CatalogFailureCode;

use crate::tenant_quota_record::TenantQuotaState;
use crate::{
    AdministrativeIdempotencyKey, AuthorizedContext, ResourceGeneration,
    TenantAdministrationFailure,
};

#[path = "quota_administration_flow.rs"]
mod quota_administration_flow;
#[path = "quota_administration_publication.rs"]
mod quota_administration_publication;
#[path = "quota_administration_receipt.rs"]
mod quota_administration_receipt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantQuotaUpdate {
    pub(super) generation: ResourceGeneration,
    pub(super) audit_position: u64,
}

impl TenantQuotaUpdate {
    #[must_use]
    pub const fn resource_generation(self) -> ResourceGeneration {
        self.generation
    }

    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

pub struct TenantQuotaAdministration;

/// One bounded tenant-quota mutation request at the Administration boundary.
#[derive(Clone, Copy)]
pub struct TenantQuotaUpdateRequest {
    pub(super) actor: AuthorizedContext,
    pub(super) tenant: TenantId,
    pub(super) expected: ResourceGeneration,
    pub(super) key: AdministrativeIdempotencyKey,
    pub(super) weight: u32,
    pub(super) resources: [u64; 11],
}

impl TenantQuotaUpdateRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        tenant: TenantId,
        expected: ResourceGeneration,
        key: AdministrativeIdempotencyKey,
        weight: u32,
        resources: [u64; 11],
    ) -> Self {
        Self {
            actor,
            tenant,
            expected,
            key,
            weight,
            resources,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantQuotaAdministrationFailureCode {
    InvalidInput,
    Unauthorized,
    StaleResourceGeneration,
    IdempotencyConflict,
    PersistenceUnavailable,
    CorruptState,
}

#[derive(Debug)]
pub struct TenantQuotaAdministrationFailure {
    code: TenantQuotaAdministrationFailureCode,
    conflict: Option<TenantQuotaGenerationConflict>,
}

impl TenantQuotaAdministrationFailure {
    pub(super) const fn new(code: TenantQuotaAdministrationFailureCode) -> Self {
        Self {
            code,
            conflict: None,
        }
    }

    pub(super) fn stale(current: TenantQuotaState, request: TenantQuotaUpdateRequest) -> Self {
        Self {
            code: TenantQuotaAdministrationFailureCode::StaleResourceGeneration,
            conflict: Some(TenantQuotaGenerationConflict::between(current, request)),
        }
    }

    pub(super) const fn stale_generation(current: ResourceGeneration) -> Self {
        Self {
            code: TenantQuotaAdministrationFailureCode::StaleResourceGeneration,
            conflict: Some(TenantQuotaGenerationConflict::generation_only(current)),
        }
    }

    #[must_use]
    pub const fn code(&self) -> TenantQuotaAdministrationFailureCode {
        self.code
    }

    #[must_use]
    pub fn current_generation(&self) -> Option<ResourceGeneration> {
        self.conflict
            .map(TenantQuotaGenerationConflict::current_generation)
    }

    #[must_use]
    pub const fn generation_conflict(&self) -> Option<TenantQuotaGenerationConflict> {
        self.conflict
    }
}

/// A stale quota precondition's current generation and redacted field-level
/// difference. It deliberately never includes quota values or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantQuotaGenerationConflict {
    current: ResourceGeneration,
    changed_fields: u16,
}

impl TenantQuotaGenerationConflict {
    const WEIGHT_BIT: u16 = 1;
    const RESOURCE_START_BIT: u16 = 1 << 1;
    const GENERATION_ONLY_BIT: u16 = 1 << 12;
    const RESOURCE_NAMES: [&str; 11] = [
        "memory_bytes",
        "queue_slots",
        "task_slots",
        "buffer_cache_bytes",
        "batch_items",
        "lease_slots",
        "retry_slots",
        "io_permits",
        "cpu_work_units",
        "file_descriptors",
        "disk_headroom_bytes",
    ];

    fn between(current: TenantQuotaState, request: TenantQuotaUpdateRequest) -> Self {
        Self::from_parts(current, request.weight, request.resources)
    }

    fn from_parts(
        current: TenantQuotaState,
        requested_weight: u32,
        requested_resources: [u64; 11],
    ) -> Self {
        let mut changed_fields = if current.weight == requested_weight {
            0
        } else {
            Self::WEIGHT_BIT
        };
        for (index, (current, requested)) in current
            .resources
            .into_iter()
            .zip(requested_resources)
            .enumerate()
        {
            if current != requested {
                changed_fields |= Self::RESOURCE_START_BIT << index;
            }
        }
        if changed_fields == 0 {
            changed_fields = Self::GENERATION_ONLY_BIT;
        }
        Self {
            current: current.generation,
            changed_fields,
        }
    }

    const fn generation_only(current: ResourceGeneration) -> Self {
        Self {
            current,
            changed_fields: Self::GENERATION_ONLY_BIT,
        }
    }

    #[must_use]
    pub const fn current_generation(self) -> ResourceGeneration {
        self.current
    }

    /// Renders only stable field names in canonical order; values stay
    /// inside the authorized administration boundary.
    #[must_use]
    pub fn semantic_diff(self) -> String {
        let mut rendered = String::with_capacity(192);
        if self.changed_fields & Self::WEIGHT_BIT != 0 {
            rendered.push_str("weight");
        }
        for (index, name) in Self::RESOURCE_NAMES.iter().enumerate() {
            if self.changed_fields & (Self::RESOURCE_START_BIT << index) == 0 {
                continue;
            }
            if !rendered.is_empty() {
                rendered.push(',');
            }
            rendered.push_str(name);
        }
        if rendered.is_empty() {
            rendered.push_str("resource_generation");
        }
        rendered
    }
}

impl Display for TenantQuotaAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tenant quota administration failed")
    }
}

impl Error for TenantQuotaAdministrationFailure {}
pub(super) fn map_tenant_quota_record_failure(
    failure: TenantAdministrationFailure,
) -> TenantQuotaAdministrationFailure {
    let code = match failure {
        TenantAdministrationFailure::Unauthorized => {
            TenantQuotaAdministrationFailureCode::Unauthorized
        },
        TenantAdministrationFailure::InvalidInput
        | TenantAdministrationFailure::DuplicateTenant
        | TenantAdministrationFailure::StaleGeneration
        | TenantAdministrationFailure::IdempotencyConflict
        | TenantAdministrationFailure::PersistenceUnavailable => {
            TenantQuotaAdministrationFailureCode::CorruptState
        },
    };
    TenantQuotaAdministrationFailure::new(code)
}

pub(super) fn corrupt() -> TenantQuotaAdministrationFailure {
    TenantQuotaAdministrationFailure::new(TenantQuotaAdministrationFailureCode::CorruptState)
}

pub(super) fn map_catalog(
    failure: positron_kernel::CatalogFailure,
) -> TenantQuotaAdministrationFailure {
    let code = match failure.code() {
        CatalogFailureCode::IdempotencyConflict => {
            TenantQuotaAdministrationFailureCode::IdempotencyConflict
        },
        CatalogFailureCode::IntegrityCorruption => {
            TenantQuotaAdministrationFailureCode::CorruptState
        },
        _ => TenantQuotaAdministrationFailureCode::PersistenceUnavailable,
    };
    TenantQuotaAdministrationFailure::new(code)
}

#[cfg(test)]
mod tests {
    use positron_domain::identity::{PrincipalId, TenantId};

    use super::quota_administration_receipt::{QuotaSemantics, RECEIPT_MAGIC, decode, encode};
    use super::*;

    #[test]
    fn quota_receipt_rejects_every_truncated_persisted_encoding() {
        let semantics = QuotaSemantics {
            key: AdministrativeIdempotencyKey::new([1; 16]).expect("key"),
            principal: PrincipalId::from_bytes([2; 16]).expect("principal"),
            tenant: TenantId::from_bytes([3; 16]).expect("tenant"),
            expected: ResourceGeneration::new(1).expect("expected generation"),
            generation: ResourceGeneration::new(2).expect("generation"),
            weight: 1,
            resources: [1; 11],
            request_digest: [4; 32],
        };
        let encoded = encode(RECEIPT_MAGIC, semantics);
        assert_eq!(encoded.len(), 196);
        assert!(decode(&encoded).is_ok());
        for length in 0..encoded.len() {
            assert!(
                decode(&encoded[..length]).is_err(),
                "truncation at {length}"
            );
        }
    }

    #[test]
    fn stale_quota_diff_names_only_changed_fields_in_canonical_order() {
        let current = TenantQuotaState {
            generation: ResourceGeneration::new(7).expect("generation"),
            weight: 2,
            resources: [11; 11],
        };
        let mut requested = [11; 11];
        requested[0] = 12;
        requested[10] = 13;
        let conflict = TenantQuotaGenerationConflict::from_parts(current, 3, requested);
        assert_eq!(conflict.current_generation().get(), 7);
        assert_eq!(
            conflict.semantic_diff(),
            "weight,memory_bytes,disk_headroom_bytes"
        );
        assert!(!conflict.semantic_diff().contains("11"));
        assert!(!conflict.semantic_diff().contains("12"));
        assert!(!conflict.semantic_diff().contains("13"));
    }
}
