use std::collections::{BTreeMap, BTreeSet};

use positron_domain::identity::{TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::{CatalogObject, CatalogSnapshot};

use super::tenant_administration_registry_codec::{
    TenantRegistry, decode_registry, is_registry, registry, registry_object,
};
use super::{TenantAdministration, TenantAdministrationFailure, map_catalog};
use crate::ResourceGeneration;
use crate::tenant_quota_record::{is_tenant_record, tenant_record_metadata};

/// Opaque position in one immutable tenant-registry generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantListContinuation {
    catalog_identity: [u8; 32],
    catalog_generation: u64,
    next_index: u16,
}

impl TenantListContinuation {
    #[must_use]
    pub fn to_bytes(self) -> [u8; 42] {
        let mut bytes = [0; 42];
        bytes[..32].copy_from_slice(&self.catalog_identity);
        bytes[32..40].copy_from_slice(&self.catalog_generation.to_be_bytes());
        bytes[40..].copy_from_slice(&self.next_index.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: [u8; 42]) -> Result<Self, TenantAdministrationFailure> {
        let catalog_generation = u64::from_be_bytes(
            bytes[32..40]
                .try_into()
                .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
        );
        let next_index = u16::from_be_bytes(
            bytes[40..]
                .try_into()
                .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
        );
        if catalog_generation == 0 || next_index == 0 {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        Ok(Self {
            catalog_identity: bytes[..32]
                .try_into()
                .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
            catalog_generation,
            next_index,
        })
    }
}

/// One bounded page of authenticated tenant-registry descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantInspectionPage {
    inspections: Vec<TenantInspection>,
    continuation: Option<TenantListContinuation>,
}

impl TenantInspectionPage {
    #[must_use]
    pub fn inspections(&self) -> &[TenantInspection] {
        &self.inspections
    }

    #[must_use]
    pub const fn continuation(&self) -> Option<TenantListContinuation> {
        self.continuation
    }
}

/// One redacted, authenticated tenant-administration view. It contains no
/// credential material or opaque key-envelope bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantInspection {
    tenant: TenantId,
    slug: TenantSlug,
    display_name: String,
    retention_seconds: u64,
    display_generation: ResourceGeneration,
    retention_generation: ResourceGeneration,
    lifecycle: TenantLifecycleState,
}

impl TenantInspection {
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn slug(&self) -> &str {
        self.slug.as_str()
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub const fn retention_seconds(&self) -> u64 {
        self.retention_seconds
    }

    #[must_use]
    pub const fn display_generation(&self) -> ResourceGeneration {
        self.display_generation
    }

    #[must_use]
    pub const fn retention_generation(&self) -> ResourceGeneration {
        self.retention_generation
    }

    #[must_use]
    pub const fn lifecycle(&self) -> TenantLifecycleState {
        self.lifecycle
    }
}

impl TenantAdministration {
    /// Lists redacted tenant state from one authenticated Catalog snapshot.
    /// The runtime authorizes enumeration before calling this pure decoder.
    pub fn list(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<TenantInspection>, TenantAdministrationFailure> {
        Ok(tenant_inspections(snapshot)?.1)
    }

    /// Enumerates one fixed-size page from an immutable Catalog snapshot.
    /// A continuation from a different snapshot is explicit rather than
    /// risking a skipped, duplicated, or mixed descriptor page.
    pub fn list_page(
        snapshot: &CatalogSnapshot,
        continuation: Option<TenantListContinuation>,
        limit: usize,
    ) -> Result<TenantInspectionPage, TenantAdministrationFailure> {
        if limit == 0 || limit > 128 {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let (_, inspections) = tenant_inspections(snapshot)?;
        let start = match continuation {
            None => 0,
            Some(continuation) => {
                if continuation.catalog_identity != snapshot.identity().to_bytes()
                    || continuation.catalog_generation != snapshot.number()
                {
                    return Err(TenantAdministrationFailure::StaleGeneration);
                }
                usize::from(continuation.next_index)
            },
        };
        if start > inspections.len() {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let end = start
            .checked_add(limit)
            .map(|end| end.min(inspections.len()))
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let mut page = Vec::new();
        page.try_reserve(end - start)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        page.extend_from_slice(
            inspections
                .get(start..end)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        );
        let continuation = if end < inspections.len() {
            Some(TenantListContinuation {
                catalog_identity: snapshot.identity().to_bytes(),
                catalog_generation: snapshot.number(),
                next_index: u16::try_from(end)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            })
        } else {
            None
        };
        Ok(TenantInspectionPage {
            inspections: page,
            continuation,
        })
    }

    /// Resolves one registered tenant from one authenticated Catalog snapshot.
    pub fn inspect(
        snapshot: &CatalogSnapshot,
        tenant: TenantId,
    ) -> Result<TenantInspection, TenantAdministrationFailure> {
        tenant_inspections(snapshot)?
            .1
            .into_iter()
            .find(|inspection| inspection.tenant == tenant)
            .ok_or(TenantAdministrationFailure::Unauthorized)
    }

    /// Reconstructs only the bounded admission limits from authenticated
    /// tenant registry records during instance reopen. The caller keeps the
    /// resulting live registration in the governor authority.
    pub fn registered_tenant_quotas(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<(TenantId, u32, [u64; 11])>, TenantAdministrationFailure> {
        let mut quotas = Vec::new();
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if is_tenant_record(bytes) {
                let record = tenant_record_metadata(bytes)?;
                quotas.push((record.tenant, record.weight, record.resources));
            }
        }
        Ok(quotas)
    }

    /// The initial Catalog publication establishes the independent tenant
    /// registry generation at one.  It is deliberately not coupled to any
    /// individual tenant's quota or policy generation.
    pub fn initial_registry(
        instance: positron_kernel::InstanceId,
        default_tenant: TenantId,
    ) -> Result<CatalogObject, TenantAdministrationFailure> {
        registry_object(
            instance,
            ResourceGeneration::new(1).map_err(|_| TenantAdministrationFailure::InvalidInput)?,
            &[default_tenant],
        )
    }

    /// Rewrites a V1 registry representation into the Epoch-2 immutable
    /// membership directory. Mutable default-tenant authority remains in the
    /// one authenticated governance object; this directory owns only tenant
    /// membership and never duplicates its mutable fields.
    pub fn epoch_two_registry(
        snapshot: &CatalogSnapshot,
    ) -> Result<CatalogObject, TenantAdministrationFailure> {
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let mut registry = registry(snapshot)?.unwrap_or(TenantRegistry {
            generation: ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
            tenants: Vec::new(),
        });
        if !registry.tenants.contains(&governance.tenant()) {
            registry.tenants.push(governance.tenant());
        }
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if is_tenant_record(bytes) {
                let record = tenant_record_metadata(bytes)?;
                if !registry.tenants.contains(&record.tenant) {
                    registry.tenants.push(record.tenant);
                }
            }
        }
        registry_object(
            positron_kernel::InstanceId::new(governance.instance()).map_err(map_catalog)?,
            registry.generation,
            &registry.tenants,
        )
    }

    /// Returns the authenticated immutable tenant membership directory. V1
    /// remains a singleton reader path; V2 requires the explicit directory.
    pub fn registered_tenant_ids(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<TenantId>, TenantAdministrationFailure> {
        Ok(tenant_inspections(snapshot)?
            .1
            .into_iter()
            .map(|inspection| inspection.tenant)
            .collect())
    }

    /// Reconstructs each registered tenant's durable lifecycle. The default
    /// lifecycle lives in POSGOV; every secondary lifecycle lives in its
    /// canonical POSTNR record.
    pub(crate) fn registered_tenant_lifecycles(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<(TenantId, TenantLifecycleState)>, TenantAdministrationFailure> {
        let registered = Self::registered_tenant_ids(snapshot)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let mut lifecycles = vec![(governance.tenant(), governance.lifecycle())];
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if !is_tenant_record(bytes) {
                continue;
            }
            let record = tenant_record_metadata(bytes)?;
            if record.tenant == governance.tenant()
                || !registered.contains(&record.tenant)
                || lifecycles
                    .iter()
                    .any(|(tenant, _)| *tenant == record.tenant)
            {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
            lifecycles.push((record.tenant, record.lifecycle));
        }
        if lifecycles.len() != registered.len() {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        Ok(lifecycles)
    }

    /// Reconstructs only the non-default tenant envelopes whose immutable
    /// membership and durable tenant records agree in this Catalog generation.
    pub fn registered_tenant_key_envelopes(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<(TenantId, Vec<u8>)>, TenantAdministrationFailure> {
        let tenants = Self::registered_tenant_ids(snapshot)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let mut envelopes = Vec::new();
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if !is_tenant_record(bytes) {
                continue;
            }
            let record = tenant_record_metadata(bytes)?;
            if record.tenant == governance.tenant()
                || !tenants.contains(&record.tenant)
                || envelopes.iter().any(|(tenant, _)| *tenant == record.tenant)
            {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
            envelopes.push((record.tenant, record.envelope));
        }
        if envelopes.len().checked_add(1) != Some(tenants.len()) {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        Ok(envelopes)
    }
}

fn tenant_inspections(
    snapshot: &CatalogSnapshot,
) -> Result<(TenantRegistry, Vec<TenantInspection>), TenantAdministrationFailure> {
    let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
    let default = TenantInspection {
        tenant: governance.tenant(),
        slug: governance.tenant_slug(),
        display_name: governance.display_name().to_owned(),
        retention_seconds: governance.retention_seconds(),
        display_generation: ResourceGeneration::new(governance.display_generation())
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        retention_generation: ResourceGeneration::new(governance.retention_generation())
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        lifecycle: governance.lifecycle(),
    };
    if snapshot.format_epoch() == Some(positron_kernel::FormatEpoch::CATALOG_V1) {
        return Ok((
            TenantRegistry {
                generation: ResourceGeneration::new(1)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
                tenants: vec![default.tenant],
            },
            vec![default],
        ));
    }

    let mut registry = None;
    let mut records = BTreeMap::new();
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if is_registry(bytes) {
            if registry.is_some() {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
            registry = Some(decode_registry(bytes)?);
        } else if is_tenant_record(bytes) {
            let record = tenant_record_metadata(bytes)?;
            if record.tenant == default.tenant || records.insert(record.tenant, record).is_some() {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
        }
    }
    let registry = registry.ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let registered = registry.tenants.iter().copied().collect::<BTreeSet<_>>();
    if registered.len() != registry.tenants.len()
        || !registered.contains(&default.tenant)
        || records.len().checked_add(1) != Some(registered.len())
        || records.keys().any(|tenant| !registered.contains(tenant))
    {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let mut inspections = Vec::new();
    inspections
        .try_reserve(registry.tenants.len())
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    for tenant in &registry.tenants {
        if *tenant == default.tenant {
            inspections.push(default.clone());
            continue;
        }
        let record = records
            .remove(tenant)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        inspections.push(TenantInspection {
            tenant: record.tenant,
            slug: TenantSlug::parse_canonical(&record.slug)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            display_name: record.display_name,
            retention_seconds: record.retention_seconds,
            display_generation: record.display_generation,
            retention_generation: record.retention_generation,
            lifecycle: record.lifecycle,
        });
    }
    if !records.is_empty() {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    Ok((registry, inspections))
}
