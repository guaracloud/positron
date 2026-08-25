use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{CommittedLedgerReader, ControlTokenProtector};

use crate::{QueryFailure, QueryFailureCode};

const MAX_SOURCES: usize = 64;

/// The bounded, ordered set of durable sources observed by one tail session.
/// Every source must describe the same tenant and signal; the shard vector is
/// part of the authenticated cursor binding.
pub struct TailSourceSet<'kernel, 'catalog> {
    readers: Vec<CommittedLedgerReader<'kernel, 'catalog>>,
    tenant: TenantId,
    signal: SignalKind,
}

impl<'kernel, 'catalog> TailSourceSet<'kernel, 'catalog> {
    pub fn new(
        mut readers: Vec<CommittedLedgerReader<'kernel, 'catalog>>,
    ) -> Result<Self, QueryFailure> {
        if readers.is_empty() || readers.len() > MAX_SOURCES {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        readers.sort_by_key(|reader| reader.scope().shard_id());
        let first = readers
            .first()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?
            .scope();
        if readers.windows(2).any(|pair| {
            let left = pair[0].scope();
            let right = pair[1].scope();
            left.shard_id() == right.shard_id()
                || left.tenant_id() != first.tenant_id()
                || left.signal_kind() != first.signal_kind()
                || right.tenant_id() != first.tenant_id()
                || right.signal_kind() != first.signal_kind()
        }) {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        Ok(Self {
            readers,
            tenant: first.tenant_id(),
            signal: first.signal_kind(),
        })
    }

    pub(crate) fn single(
        reader: CommittedLedgerReader<'kernel, 'catalog>,
    ) -> Result<Self, QueryFailure> {
        Self::new(vec![reader])
    }

    pub(crate) fn readers(&self) -> &[CommittedLedgerReader<'kernel, 'catalog>] {
        &self.readers
    }

    pub(crate) const fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub(crate) fn digest(
        &self,
        protector: &ControlTokenProtector<'_>,
    ) -> Result<[u8; 32], QueryFailure> {
        let bytes = 1_usize
            .checked_add(std::mem::size_of::<[u8; 16]>())
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(self.readers.len().checked_mul(4)?))
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(bytes)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        canonical.extend_from_slice(b"T");
        canonical.extend_from_slice(&self.tenant.to_bytes());
        canonical.push(match self.signal {
            SignalKind::Logs => 1,
            SignalKind::Traces => 2,
        });
        canonical.extend_from_slice(
            &u8::try_from(self.readers.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?
                .to_be_bytes(),
        );
        for reader in &self.readers {
            canonical.extend_from_slice(&reader.scope().shard_id().value().to_be_bytes());
        }
        protector
            .digest(b"tail-source-set-v1", &canonical)
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
    }

    pub(crate) fn contains(&self, shard: VirtualShardId) -> bool {
        self.readers
            .iter()
            .any(|reader| reader.scope().shard_id() == shard)
    }
}
