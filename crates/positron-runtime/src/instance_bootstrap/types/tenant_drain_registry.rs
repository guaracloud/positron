use super::tenant_drain_gates::{
    IngestDrainGate, LifecycleDrainPermit, LifecycleMutationGate, LifecycleMutationPermit,
    QueryDrainGate, QueryLifecycleDrainPermit,
};
use super::*;

/// Bounded, tenant-keyed lifecycle drain gates for the tenants that are
/// actually registered in the Catalog. The Catalog remains the lifecycle
/// authority; this registry only prevents one tenant's transition from
/// draining another tenant's data-plane work.
pub(in crate::instance_bootstrap) struct TenantDrainRegistry {
    maximum: usize,
    entries: Mutex<Vec<TenantDrainEntry>>,
}

struct TenantDrainEntry {
    tenant: TenantId,
    ingest: Arc<IngestDrainGate>,
    query: Arc<QueryDrainGate>,
    mutation: Arc<LifecycleMutationGate>,
    active: bool,
}

pub(in crate::instance_bootstrap) struct TenantDrainEnrollment<'registry> {
    registry: &'registry TenantDrainRegistry,
    tenant: TenantId,
    activated: bool,
}

impl TenantDrainRegistry {
    pub(in crate::instance_bootstrap) fn establish(
        registered: &[TenantId],
        maximum: u16,
    ) -> Result<Self, BootstrapFailure> {
        let maximum = usize::from(maximum);
        if maximum == 0 || registered.is_empty() || registered.len() > maximum {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::ResourceUnavailable,
            ));
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(registered.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        for tenant in registered {
            if entries
                .iter()
                .any(|entry: &TenantDrainEntry| entry.tenant == *tenant)
            {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            entries.push(TenantDrainEntry {
                tenant: *tenant,
                ingest: IngestDrainGate::new(),
                query: QueryDrainGate::new(),
                mutation: LifecycleMutationGate::new(),
                active: true,
            });
        }
        Ok(Self {
            maximum,
            entries: Mutex::new(entries),
        })
    }

    fn active_entry(
        &self,
        tenant: TenantId,
    ) -> Result<(Arc<IngestDrainGate>, Arc<QueryDrainGate>), BootstrapFailure> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let entry = entries
            .iter()
            .find(|entry| entry.tenant == tenant && entry.active)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        Ok((Arc::clone(&entry.ingest), Arc::clone(&entry.query)))
    }

    pub(in crate::instance_bootstrap) fn enter_ingest(
        &self,
        tenant: TenantId,
    ) -> Result<IngestDrainPermit, BootstrapFailure> {
        self.active_entry(tenant)?.0.enter()
    }

    pub(in crate::instance_bootstrap) fn enter_query(
        &self,
        tenant: TenantId,
        cancellation: QueryCancellation,
    ) -> Result<QueryDrainPermit, BootstrapFailure> {
        self.active_entry(tenant)?.1.enter(cancellation)
    }

    pub(super) fn close_and_drain(
        &self,
        tenant: TenantId,
    ) -> Result<LifecycleDrainPermit, BootstrapFailure> {
        self.active_entry(tenant)?.0.close_and_drain()
    }

    pub(super) fn cancel_and_drain(
        &self,
        tenant: TenantId,
    ) -> Result<QueryLifecycleDrainPermit, BootstrapFailure> {
        self.active_entry(tenant)?.1.cancel_and_drain()
    }

    pub(super) fn begin_lifecycle_mutation(
        &self,
        tenant: TenantId,
    ) -> Result<LifecycleMutationPermit, BootstrapFailure> {
        let mutation = {
            let entries = self
                .entries
                .lock()
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
            let entry = entries
                .iter()
                .find(|entry| entry.tenant == tenant && entry.active)
                .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
            Arc::clone(&entry.mutation)
        };
        mutation.acquire()
    }

    pub(super) fn close_all_and_drain(
        &self,
    ) -> Result<Vec<LifecycleDrainPermit>, BootstrapFailure> {
        let gates = self.active_gates()?;
        let mut permits = Vec::new();
        permits
            .try_reserve_exact(gates.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        for (ingest, _) in gates {
            permits.push(ingest.close_and_drain()?);
        }
        Ok(permits)
    }

    pub(super) fn cancel_all_and_drain(
        &self,
    ) -> Result<Vec<QueryLifecycleDrainPermit>, BootstrapFailure> {
        let gates = self.active_gates()?;
        let mut permits = Vec::new();
        permits
            .try_reserve_exact(gates.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        for (_, query) in gates {
            permits.push(query.cancel_and_drain()?);
        }
        Ok(permits)
    }

    fn active_gates(&self) -> Result<Vec<TenantDrainGates>, BootstrapFailure> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let mut gates = Vec::new();
        gates
            .try_reserve_exact(entries.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        for entry in entries.iter().filter(|entry| entry.active) {
            gates.push((Arc::clone(&entry.ingest), Arc::clone(&entry.query)));
        }
        Ok(gates)
    }

    pub(in crate::instance_bootstrap) fn prepare_tenant(
        &self,
        tenant: TenantId,
    ) -> Result<TenantDrainEnrollment<'_>, BootstrapFailure> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        if entries.len() >= self.maximum || entries.iter().any(|entry| entry.tenant == tenant) {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::ResourceUnavailable,
            ));
        }
        entries
            .try_reserve(1)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        entries.push(TenantDrainEntry {
            tenant,
            ingest: IngestDrainGate::new(),
            query: QueryDrainGate::new(),
            mutation: LifecycleMutationGate::new(),
            active: false,
        });
        Ok(TenantDrainEnrollment {
            registry: self,
            tenant,
            activated: false,
        })
    }

    #[cfg(test)]
    pub(super) fn install_ingest_transition_observer(
        &self,
        tenant: TenantId,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.active_entry(tenant)?
            .0
            .install_transition_observer(observer)
    }

    #[cfg(test)]
    pub(super) fn install_query_transition_observer(
        &self,
        tenant: TenantId,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.active_entry(tenant)?
            .1
            .install_transition_observer(observer)
    }
}

type TenantDrainGates = (Arc<IngestDrainGate>, Arc<QueryDrainGate>);

impl TenantDrainEnrollment<'_> {
    pub(super) fn activate(&mut self) {
        let mut entries = match self.registry.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.tenant == self.tenant && !entry.active)
        {
            entry.active = true;
            self.activated = true;
        }
    }
}

impl Drop for TenantDrainEnrollment<'_> {
    fn drop(&mut self) {
        if self.activated {
            return;
        }
        let mut entries = match self.registry.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(index) = entries
            .iter()
            .position(|entry| entry.tenant == self.tenant && !entry.active)
        {
            entries.remove(index);
        }
    }
}
