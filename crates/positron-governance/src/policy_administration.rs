use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};

use crate::{AuthorizedContext, Identity};
use positron_domain::identity::TenantId;
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    FormatEpoch, TransactionId,
};
use positron_policy::IngestPolicy;

mod codec;
use codec::{ActivationSemantics, encode_audit, encode_receipt, find_receipt, request_digest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceGeneration(u64);

impl ResourceGeneration {
    pub fn new(value: u64) -> Result<Self, PolicyAdministrationFailure> {
        (value != 0).then_some(Self(value)).ok_or_else(|| {
            PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::InvalidInput)
        })
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdministrativeIdempotencyKey([u8; 16]);

impl AdministrativeIdempotencyKey {
    pub fn new(bytes: [u8; 16]) -> Result<Self, PolicyAdministrationFailure> {
        (!bytes.iter().all(|byte| *byte == 0))
            .then_some(Self(bytes))
            .ok_or_else(|| {
                PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::InvalidInput)
            })
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngestPolicyActivation {
    generation: ResourceGeneration,
    digest: [u8; 32],
    audit_position: u64,
}

/// Read-only serving view of the latest durably activated tenant policy.
///
/// A serving cache cannot be constructed independently from its bound
/// Administration.
///
/// ```compile_fail
/// use positron_domain::identity::TenantId;
/// use positron_governance::IngestPolicyAdministration;
/// use positron_kernel::CatalogSnapshot;
/// fn detached(snapshot: &CatalogSnapshot, tenant: TenantId) {
///     let _ = IngestPolicyAdministration::serving_snapshot(snapshot, tenant);
/// }
/// ```
#[derive(Clone)]
pub struct IngestPolicyServingSnapshot {
    current: Arc<RwLock<Arc<IngestPolicy>>>,
}

impl IngestPolicyServingSnapshot {
    pub fn pin(&self) -> Result<Arc<IngestPolicy>, PolicyAdministrationFailure> {
        self.current
            .read()
            .map(|current| Arc::clone(&current))
            .map_err(|_| {
                PolicyAdministrationFailure::new(
                    PolicyAdministrationFailureCode::PersistenceUnavailable,
                )
            })
    }

    fn advance(&self, policy: IngestPolicy) -> Result<(), PolicyAdministrationFailure> {
        let mut current = self.current.write().map_err(|_| {
            PolicyAdministrationFailure::new(
                PolicyAdministrationFailureCode::PersistenceUnavailable,
            )
        })?;
        if current.generation() == policy.generation() && current.digest() != policy.digest() {
            return Err(PolicyAdministrationFailure::new(
                PolicyAdministrationFailureCode::CorruptState,
            ));
        }
        if current.generation() < policy.generation() {
            *current = Arc::new(policy);
        }
        Ok(())
    }
}

impl IngestPolicyActivation {
    #[must_use]
    pub const fn resource_generation(self) -> ResourceGeneration {
        self.generation
    }
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

pub struct IngestPolicyAdministration {
    tenant: TenantId,
    serving: IngestPolicyServingSnapshot,
}

impl IngestPolicyAdministration {
    pub fn open(
        catalog: &Catalog<'_>,
        tenant: TenantId,
    ) -> Result<Self, PolicyAdministrationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        Ok(Self {
            tenant,
            serving: IngestPolicyServingSnapshot {
                current: Arc::new(RwLock::new(Arc::new(Self::activated(&snapshot, tenant)?))),
            },
        })
    }

    #[must_use]
    pub fn serving(&self) -> IngestPolicyServingSnapshot {
        self.serving.clone()
    }

    pub fn activate(
        &self,
        catalog: &Catalog<'_>,
        identity: &Identity,
        context: AuthorizedContext,
        expected: ResourceGeneration,
        key: AdministrativeIdempotencyKey,
        candidate: IngestPolicy,
    ) -> Result<IngestPolicyActivation, PolicyAdministrationFailure> {
        let tenant = self.tenant;
        let principal = identity
            .authorize_policy_activation(context, tenant)
            .map_err(|_| {
                PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::Unauthorized)
            })?;
        let requested = ResourceGeneration::new(candidate.generation())?;
        if expected.0.checked_add(1) != Some(requested.0) {
            return Err(PolicyAdministrationFailure::new(
                PolicyAdministrationFailureCode::InvalidResourceGeneration,
            ));
        }
        let request_digest = request_digest(tenant, expected, requested, candidate.digest());
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(receipt) = find_receipt(&snapshot, key)? {
            if receipt.principal != principal
                || receipt.tenant != tenant
                || receipt.expected != expected
                || receipt.generation != requested
                || receipt.digest != candidate.digest()
                || receipt.request_digest != request_digest
            {
                return Err(PolicyAdministrationFailure::new(
                    PolicyAdministrationFailureCode::IdempotencyConflict,
                ));
            }
            self.serving.advance(candidate.clone())?;
            return Ok(IngestPolicyActivation {
                generation: requested,
                digest: candidate.digest(),
                audit_position: audit_position(catalog, key)?,
            });
        }
        let current = Self::activated(&snapshot, tenant)?;
        if current.generation() != expected.0 {
            return Err(PolicyAdministrationFailure::stale(current.generation()));
        }
        let mut objects = retained_objects(&snapshot, tenant)?;
        let activation = candidate.activated_object(tenant).map_err(|_| {
            PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::InvalidInput)
        })?;
        objects.push(CatalogObject::new(activation.into_bytes()).map_err(map_catalog)?);
        let semantics = ActivationSemantics {
            key,
            principal,
            tenant,
            expected,
            generation: requested,
            digest: candidate.digest(),
            request_digest,
        };
        objects.push(CatalogObject::new(encode_receipt(semantics)).map_err(map_catalog)?);
        let audit = encode_audit(semantics);
        let commit = catalog
            .commit(
                snapshot.identity(),
                CatalogProposal::new(
                    TransactionId::new(key.0).map_err(map_catalog)?,
                    FormatEpoch::CATALOG_V1,
                    objects,
                )
                .map_err(map_catalog)?,
                Some(AuditIntent::new(audit).map_err(map_catalog)?),
            )
            .map_err(|failure| self.map_commit_failure(catalog, failure))?;
        self.serving.advance(candidate.clone())?;
        let audit_position = commit
            .governance_audit_record()
            .ok_or_else(|| {
                PolicyAdministrationFailure::new(
                    PolicyAdministrationFailureCode::PersistenceUnavailable,
                )
            })?
            .position();
        Ok(IngestPolicyActivation {
            generation: requested,
            digest: candidate.digest(),
            audit_position,
        })
    }

    fn activated(
        snapshot: &CatalogSnapshot,
        tenant: TenantId,
    ) -> Result<IngestPolicy, PolicyAdministrationFailure> {
        let mut activated = None;
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or_else(|| {
                    PolicyAdministrationFailure::new(
                        PolicyAdministrationFailureCode::PersistenceUnavailable,
                    )
                })?;
            let Some(policy) =
                IngestPolicy::decode_activated_object(tenant, bytes).map_err(|_| {
                    PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::CorruptState)
                })?
            else {
                continue;
            };
            if activated.replace(policy).is_some() {
                return Err(PolicyAdministrationFailure::new(
                    PolicyAdministrationFailureCode::CorruptState,
                ));
            }
        }
        activated.map_or_else(
            || {
                IngestPolicy::preserving(1).map_err(|_| {
                    PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::CorruptState)
                })
            },
            Ok,
        )
    }

    fn map_commit_failure(
        &self,
        catalog: &Catalog<'_>,
        failure: positron_kernel::CatalogFailure,
    ) -> PolicyAdministrationFailure {
        if failure.code() != CatalogFailureCode::StaleGeneration {
            return map_catalog(failure);
        }
        let snapshot = match catalog.pin() {
            Ok(snapshot) => snapshot,
            Err(pin_failure) => return map_catalog(pin_failure),
        };
        match Self::activated(&snapshot, self.tenant) {
            Ok(current) => PolicyAdministrationFailure::stale(current.generation()),
            Err(decode_failure) => decode_failure,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyAdministrationFailureCode {
    InvalidInput,
    Unauthorized,
    InvalidResourceGeneration,
    StaleResourceGeneration,
    IdempotencyConflict,
    PersistenceUnavailable,
    CorruptState,
}

#[derive(Debug)]
pub struct PolicyAdministrationFailure {
    code: PolicyAdministrationFailureCode,
    current: Option<ResourceGeneration>,
}

impl PolicyAdministrationFailure {
    const fn new(code: PolicyAdministrationFailureCode) -> Self {
        Self {
            code,
            current: None,
        }
    }
    const fn stale(current: u64) -> Self {
        Self {
            code: PolicyAdministrationFailureCode::StaleResourceGeneration,
            current: Some(ResourceGeneration(current)),
        }
    }
    #[must_use]
    pub const fn code(&self) -> PolicyAdministrationFailureCode {
        self.code
    }
    #[must_use]
    pub const fn current_generation(&self) -> Option<ResourceGeneration> {
        self.current
    }
}

impl Display for PolicyAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ingest policy administration failed")
    }
}
impl Error for PolicyAdministrationFailure {}

fn retained_objects(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Vec<CatalogObject>, PolicyAdministrationFailure> {
    let mut objects = Vec::new();
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or_else(|| {
                PolicyAdministrationFailure::new(
                    PolicyAdministrationFailureCode::PersistenceUnavailable,
                )
            })?;
        if IngestPolicy::decode_activated_object(tenant, bytes)
            .map_err(|_| {
                PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::CorruptState)
            })?
            .is_none()
        {
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
        }
    }
    Ok(objects)
}

fn audit_position(
    catalog: &Catalog<'_>,
    key: AdministrativeIdempotencyKey,
) -> Result<u64, PolicyAdministrationFailure> {
    let transaction = TransactionId::new(key.0).map_err(map_catalog)?;
    catalog
        .governance_audit_records()
        .map_err(map_catalog)?
        .into_iter()
        .find(|record| record.transaction() == transaction)
        .map(|record| record.position())
        .ok_or_else(|| {
            PolicyAdministrationFailure::new(PolicyAdministrationFailureCode::CorruptState)
        })
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> PolicyAdministrationFailure {
    let code = match failure.code() {
        CatalogFailureCode::IdempotencyConflict => {
            PolicyAdministrationFailureCode::IdempotencyConflict
        },
        CatalogFailureCode::StaleGeneration => {
            PolicyAdministrationFailureCode::PersistenceUnavailable
        },
        CatalogFailureCode::IntegrityCorruption => PolicyAdministrationFailureCode::CorruptState,
        _ => PolicyAdministrationFailureCode::PersistenceUnavailable,
    };
    PolicyAdministrationFailure::new(code)
}
