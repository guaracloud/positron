use super::tenant_drain_gates::{
    IngestDrainGate, LIFECYCLE_DRAIN_TIMEOUT, LifecycleDrainPermit, LifecycleMutationGate,
    LifecycleMutationPermit, QueryDrainGate, QueryLifecycleDrainPermit,
};
use super::*;

/// Bounded, tenant-keyed lifecycle drain gates for the tenants that are
/// actually registered in the Catalog. The Catalog remains the lifecycle
/// authority; this registry only prevents one tenant's transition from
/// draining another tenant's data-plane work.
pub(in crate::instance_bootstrap) struct TenantDrainRegistry {
    maximum: usize,
    entries: Mutex<Vec<TenantDrainEntry>>,
    topology: TopologyBarrier,
}

struct TopologyBarrier {
    state: Mutex<TopologyBarrierState>,
    changed: Condvar,
}

struct TopologyBarrierState {
    migration: bool,
    creations: u16,
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

pub(super) struct MigrationTopologyPermit<'registry> {
    registry: &'registry TenantDrainRegistry,
}

pub(super) struct TenantCreationTopologyPermit<'registry> {
    registry: &'registry TenantDrainRegistry,
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
            topology: TopologyBarrier {
                state: Mutex::new(TopologyBarrierState {
                    migration: false,
                    creations: 0,
                }),
                changed: Condvar::new(),
            },
        })
    }

    pub(super) fn lifecycle_deadline() -> Result<Instant, BootstrapFailure> {
        Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
    }

    pub(super) fn begin_migration_before(
        &self,
        deadline: Instant,
    ) -> Result<MigrationTopologyPermit<'_>, BootstrapFailure> {
        let mut state = self
            .topology
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        while state.migration || state.creations != 0 {
            let (next, timed_out) = wait_for_topology(&self.topology.changed, state, deadline)?;
            if timed_out {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            state = next;
        }
        state.migration = true;
        Ok(MigrationTopologyPermit { registry: self })
    }

    pub(super) fn begin_tenant_creation_before(
        &self,
        deadline: Instant,
    ) -> Result<TenantCreationTopologyPermit<'_>, BootstrapFailure> {
        let mut state = self
            .topology
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        while state.migration {
            let (next, timed_out) = wait_for_topology(&self.topology.changed, state, deadline)?;
            if timed_out {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            state = next;
        }
        state.creations = state
            .creations
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        Ok(TenantCreationTopologyPermit { registry: self })
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

    /// Closes all native data admission from one fixed membership snapshot,
    /// then waits for the already admitted work with one absolute deadline.
    #[cfg(test)]
    fn close_all_and_drain(&self) -> Result<TenantDrainPermit, BootstrapFailure> {
        self.close_all_and_drain_before(Self::lifecycle_deadline()?)
    }

    pub(super) fn close_all_and_drain_before(
        &self,
        deadline: Instant,
    ) -> Result<TenantDrainPermit, BootstrapFailure> {
        let gates = self.active_gates()?;
        let mut ingest = Vec::new();
        ingest
            .try_reserve_exact(gates.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let mut query = Vec::new();
        query
            .try_reserve_exact(gates.len())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        for (gate, _) in &gates {
            ingest.push(gate.close_before(deadline)?);
        }
        for (_, gate) in &gates {
            query.push(gate.cancel_before(deadline)?);
        }
        for permit in &ingest {
            permit.wait_for_drain_before(deadline)?;
        }
        for permit in &query {
            permit.wait_for_drain_before(deadline)?;
        }
        Ok(TenantDrainPermit {
            _ingest: ingest,
            _query: query,
        })
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

fn wait_for_topology<'registry>(
    changed: &'registry Condvar,
    state: std::sync::MutexGuard<'registry, TopologyBarrierState>,
    deadline: Instant,
) -> Result<(std::sync::MutexGuard<'registry, TopologyBarrierState>, bool), BootstrapFailure> {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Ok((state, true));
    };
    let (state, timed_out) = changed
        .wait_timeout(state, remaining)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    Ok((state, timed_out.timed_out()))
}

impl Drop for MigrationTopologyPermit<'_> {
    fn drop(&mut self) {
        let mut state = match self.registry.topology.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.migration = false;
        self.registry.topology.changed.notify_all();
    }
}

impl Drop for TenantCreationTopologyPermit<'_> {
    fn drop(&mut self) {
        let mut state = match self.registry.topology.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.creations = state.creations.saturating_sub(1);
        self.registry.topology.changed.notify_all();
    }
}

type TenantDrainGates = (Arc<IngestDrainGate>, Arc<QueryDrainGate>);

/// Keeps all global migration admission closures active until publication
/// completes or the attempt fails.
pub(super) struct TenantDrainPermit {
    _ingest: Vec<LifecycleDrainPermit>,
    _query: Vec<QueryLifecycleDrainPermit>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_drain_closes_late_tenant_admission_before_waiting_for_early_work() {
        let tenants = (0_u16..1024)
            .map(|number| {
                let mut bytes = [0_u8; 16];
                bytes[..2].copy_from_slice(&number.to_be_bytes());
                bytes[15] = 1;
                TenantId::from_bytes(bytes).expect("fixed tenant identifier")
            })
            .collect::<Vec<_>>();
        let registry =
            Arc::new(TenantDrainRegistry::establish(&tenants, 1024).expect("maximum registry"));
        let held_early = registry.enter_ingest(tenants[0]).expect("early work");
        let held_middle = registry.enter_ingest(tenants[512]).expect("middle work");
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        registry
            .install_query_transition_observer(tenants[1023], closed_tx)
            .expect("final query closure observer");
        let (completed_tx, completed_rx) = std::sync::mpsc::channel();
        let draining = Arc::clone(&registry);
        let drain = std::thread::spawn(move || {
            let _ = completed_tx.send(draining.close_all_and_drain());
        });

        closed_rx.recv().expect("all admission closes");
        let late_ingest = registry.enter_ingest(tenants[1023]);
        let late_query = registry.enter_query(tenants[1023], QueryCancellation::new());
        let late_ingest_refused = late_ingest.is_err();
        let late_query_refused = late_query.is_err();
        drop(late_ingest);
        drop(late_query);
        drop(held_early);
        assert!(
            completed_rx.try_recv().is_err(),
            "global drain waits for every admitted tenant work item"
        );
        drop(held_middle);
        let permit = completed_rx
            .recv()
            .expect("global drain completion")
            .expect("global drain completes after held work");
        drop(permit);
        drain.join().expect("global drain thread");

        assert!(late_ingest_refused, "the final tenant cannot admit ingest");
        assert!(late_query_refused, "the final tenant cannot admit queries");
    }

    #[test]
    fn expired_global_drain_deadline_reopens_every_closed_gate() {
        let tenants = [
            TenantId::from_bytes([1; 16]).expect("first tenant"),
            TenantId::from_bytes([2; 16]).expect("second tenant"),
        ];
        let registry = TenantDrainRegistry::establish(&tenants, 2).expect("registry");
        let held = registry.enter_ingest(tenants[0]).expect("held work");

        let failure = match registry.close_all_and_drain_before(Instant::now()) {
            Ok(_) => panic!("elapsed migration deadline must fail"),
            Err(failure) => failure,
        };
        let _ = failure;
        drop(held);

        for tenant in tenants {
            drop(registry.enter_ingest(tenant).expect("ingest reopens"));
            drop(
                registry
                    .enter_query(tenant, QueryCancellation::new())
                    .expect("query reopens"),
            );
        }
    }

    #[test]
    fn migration_topology_barrier_refuses_creation_until_publication_permit_drops() {
        let tenant = TenantId::from_bytes([3; 16]).expect("tenant");
        let registry = TenantDrainRegistry::establish(&[tenant], 2).expect("registry");
        let deadline = Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .expect("deadline");
        let migration = registry
            .begin_migration_before(deadline)
            .expect("migration barrier");

        assert!(
            registry
                .begin_tenant_creation_before(Instant::now())
                .is_err(),
            "creation cannot enter a migration topology interval"
        );
        drop(migration);
        drop(
            registry
                .begin_tenant_creation_before(deadline)
                .expect("creation proceeds after migration publication"),
        );
    }

    #[test]
    fn creation_topology_barrier_is_included_before_migration_snapshot() {
        let tenant = TenantId::from_bytes([4; 16]).expect("tenant");
        let registry = TenantDrainRegistry::establish(&[tenant], 2).expect("registry");
        let deadline = Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .expect("deadline");
        let creation = registry
            .begin_tenant_creation_before(deadline)
            .expect("creation barrier");

        assert!(
            registry.begin_migration_before(Instant::now()).is_err(),
            "migration cannot snapshot while a tenant enrollment is pending"
        );
        drop(creation);
        drop(
            registry
                .begin_migration_before(deadline)
                .expect("migration proceeds after enrollment completes"),
        );
    }
}
