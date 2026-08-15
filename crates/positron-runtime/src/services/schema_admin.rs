use positron_governance::AuthorizedContext;
use positron_ingest::{SchemaBudget, SchemaDiscovery, SchemaDiscoveryRequest};
use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim, WorkKind};

use super::{ServiceFailure, ServiceHandle};

/// Cursor bound to one immutable schema-discovery snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaDiscoveryCursor {
    snapshot: [u8; 32],
    next_offset: u16,
}

impl SchemaDiscoveryCursor {
    #[must_use]
    pub const fn snapshot(self) -> [u8; 32] {
        self.snapshot
    }

    #[must_use]
    pub const fn next_offset(self) -> u16 {
        self.next_offset
    }
}

/// One completed, bounded tenant schema-discovery operation page.
pub struct SchemaDiscoveryOperation {
    operation_id: [u8; 32],
    discovery: SchemaDiscovery,
    next_cursor: Option<SchemaDiscoveryCursor>,
}

impl SchemaDiscoveryOperation {
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 32] {
        self.operation_id
    }

    #[must_use]
    pub const fn discovery(&self) -> &SchemaDiscovery {
        &self.discovery
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<SchemaDiscoveryCursor> {
        self.next_cursor
    }
}

impl ServiceHandle {
    pub fn discover_log_schema(
        &self,
        context: AuthorizedContext,
        request: SchemaDiscoveryRequest,
        cursor: Option<SchemaDiscoveryCursor>,
    ) -> Result<SchemaDiscoveryOperation, ServiceFailure> {
        self.instance
            .identity
            .inspect(context, &[])
            .map_err(|_| ServiceFailure::Unauthorized)?;
        let memory = u64::try_from(SchemaBudget::system_max_memory_bytes())
            .map_err(|_| ServiceFailure::InvalidRequest)?;
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, memory)
            .map_err(|_| ServiceFailure::InvalidRequest)?;
        let claim = WorkClaim::tenant(
            self.instance.tenant,
            WorkKind::InteractiveQueryTail,
            amounts,
        )
        .map_err(|_| ServiceFailure::InvalidRequest)?;
        let capacity = self
            .instance
            .resource_governor()
            .reserve(claim)
            .map_err(|_| ServiceFailure::CapacityUnavailable)?;
        let discovery = self
            .schema_sessions
            .session(self.instance.tenant, self.instance.resource_governor())
            .map_err(|_| ServiceFailure::CapacityUnavailable)?
            .discover(self.instance.tenant, request)
            .map_err(|_| ServiceFailure::InvalidRequest)?;
        if cursor.is_some_and(|known| {
            known.snapshot != discovery.snapshot_digest()
                || usize::from(known.next_offset) != discovery.path_offset()
        }) {
            return Err(ServiceFailure::InvalidRequest);
        }
        let next_offset = discovery
            .path_offset()
            .checked_add(discovery.top_paths().len())
            .ok_or(ServiceFailure::InvalidRequest)?;
        let next_cursor = (next_offset < discovery.total_paths())
            .then(|| {
                u16::try_from(next_offset).map(|next_offset| SchemaDiscoveryCursor {
                    snapshot: discovery.snapshot_digest(),
                    next_offset,
                })
            })
            .transpose()
            .map_err(|_| ServiceFailure::InvalidRequest)?;
        drop(capacity);
        Ok(SchemaDiscoveryOperation {
            operation_id: discovery.snapshot_digest(),
            discovery,
            next_cursor,
        })
    }
}
