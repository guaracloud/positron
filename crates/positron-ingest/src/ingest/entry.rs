use positron_domain::identity::TenantId;
use positron_domain::routing::VirtualShardId;
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, StorageKernelResourceAuthority, StoreBlockIdentity,
};

use super::{IngestOutcome, LogIngest};
use crate::{IngestPolicy, NativeLogBatch, TenantSchemaSession};

impl<'service, 'kernel, 'catalog> LogIngest<'service, 'kernel, 'catalog> {
    #[must_use]
    pub fn new(
        authority: &'kernel StorageKernelResourceAuthority,
        ledger: &'service ActiveSegmentLedger<'kernel, 'catalog>,
        policy: &'service IngestPolicy,
        tenant: TenantId,
        shard: VirtualShardId,
        schema: TenantSchemaSession,
    ) -> Self {
        Self {
            authority,
            ledger,
            policy,
            tenant,
            shard,
            schema,
        }
    }

    /// Validates, reserves, prepares, and durably commits one Admission Group.
    #[must_use]
    pub fn accept(
        &self,
        batch: NativeLogBatch<'kernel>,
        identity: StoreBlockIdentity,
    ) -> IngestOutcome {
        self.accept_inner(batch, identity, None)
    }

    /// Observes cancellation before durability admission without fabricating a
    /// failed outcome after a commit boundary.
    #[must_use]
    pub fn accept_cancellable(
        &self,
        batch: NativeLogBatch<'kernel>,
        identity: StoreBlockIdentity,
        cancellation: &AppendCancellation,
    ) -> IngestOutcome {
        self.accept_inner(batch, identity, Some(cancellation))
    }
}
