use std::num::NonZeroU64;

use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_kernel::StoreBlockIdentity;

use super::codec::{Input, put_len, put_u64};
use super::{SchemaBudget, SchemaCatalog, SchemaFailure};

const TRAILER_MAGIC: &[u8; 8] = b"REPLAY1\0";
const MAX_FRONTIERS: usize = 4_096;
const FRONTIER_BYTES: usize = 4 + 8 + 16 + 32;

/// Canonical authenticated replay boundary for one tenant shard.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SchemaCheckpointFrontier {
    shard: VirtualShardId,
    position: CommitPosition,
    identity: StoreBlockIdentity,
    digest: [u8; 32],
}

impl SchemaCheckpointFrontier {
    pub fn new(
        shard: VirtualShardId,
        position: CommitPosition,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<Self, SchemaFailure> {
        if position == CommitPosition::origin() || digest.iter().all(|byte| *byte == 0) {
            return Err(SchemaFailure::InvalidValue);
        }
        Ok(Self {
            shard,
            position,
            identity,
            digest,
        })
    }

    #[must_use]
    pub const fn shard(self) -> VirtualShardId {
        self.shard
    }

    #[must_use]
    pub const fn position(self) -> CommitPosition {
        self.position
    }

    #[must_use]
    pub const fn identity(self) -> StoreBlockIdentity {
        self.identity
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

pub(super) fn encode(
    catalog: &SchemaCatalog,
    frontiers: &[SchemaCheckpointFrontier],
) -> Result<Vec<u8>, SchemaFailure> {
    if frontiers.len() > MAX_FRONTIERS {
        return Err(SchemaFailure::LimitExceeded);
    }
    let mut canonical = Vec::new();
    canonical
        .try_reserve_exact(frontiers.len())
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    canonical.extend_from_slice(frontiers);
    canonical.sort_by_key(|frontier| frontier.shard);
    if canonical.windows(2).any(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(a, b)| a.shard == b.shard)
    }) {
        return Err(SchemaFailure::InvalidValue);
    }
    let trailer = trailer_length(canonical.len());
    let mut bytes = catalog.encode_catalog_object()?;
    bytes
        .len()
        .checked_add(trailer)
        .filter(|total| *total <= catalog.budget().max_persistent_bytes())
        .ok_or(SchemaFailure::LimitExceeded)?;
    bytes
        .try_reserve_exact(trailer)
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    bytes.extend_from_slice(TRAILER_MAGIC);
    put_len(&mut bytes, canonical.len())?;
    for frontier in canonical {
        bytes.extend_from_slice(&frontier.shard.value().to_be_bytes());
        put_u64(&mut bytes, frontier.position.value());
        bytes.extend_from_slice(&frontier.identity.to_bytes());
        bytes.extend_from_slice(&frontier.digest);
    }
    Ok(bytes)
}

pub(super) fn preflight(bytes: &[u8]) -> Result<usize, SchemaFailure> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut input = Input::new(bytes);
    if input.take(TRAILER_MAGIC.len())? != TRAILER_MAGIC {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let count = input.usize()?;
    if count > MAX_FRONTIERS
        || input.remaining_len()
            != count
                .checked_mul(FRONTIER_BYTES)
                .ok_or(SchemaFailure::MalformedCatalog)?
    {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let mut previous = None;
    for _ in 0..count {
        let shard = u32::from_be_bytes(input.array()?);
        let position = input.u64()?;
        let identity: [u8; 16] = input.array()?;
        let digest: [u8; 32] = input.array()?;
        if shard == 0
            || position == 0
            || identity.iter().all(|byte| *byte == 0)
            || digest.iter().all(|byte| *byte == 0)
            || previous.is_some_and(|known| known >= shard)
        {
            return Err(SchemaFailure::MalformedCatalog);
        }
        previous = Some(shard);
    }
    Ok(count)
}

pub(super) fn decode(
    bytes: &[u8],
    budget: SchemaBudget,
    catalog_memory: usize,
) -> Result<Vec<SchemaCheckpointFrontier>, SchemaFailure> {
    let count = preflight(bytes)?;
    let frontier_memory = count
        .checked_mul(std::mem::size_of::<SchemaCheckpointFrontier>())
        .and_then(|memory| memory.checked_add(catalog_memory))
        .filter(|memory| *memory <= budget.max_memory_bytes())
        .ok_or(SchemaFailure::MalformedCatalog)?;
    let _ = frontier_memory;
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut input = Input::new(bytes);
    input.take(TRAILER_MAGIC.len())?;
    input.usize()?;
    let mut frontiers = Vec::new();
    frontiers
        .try_reserve_exact(count)
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    for _ in 0..count {
        let shard = VirtualShardId::new(u32::from_be_bytes(input.array()?))
            .map_err(|_| SchemaFailure::MalformedCatalog)?;
        let position = CommitPosition::origin()
            .advance_by(NonZeroU64::new(input.u64()?).ok_or(SchemaFailure::MalformedCatalog)?)
            .map_err(|_| SchemaFailure::MalformedCatalog)?;
        let identity =
            StoreBlockIdentity::new(input.array()?).map_err(|_| SchemaFailure::MalformedCatalog)?;
        let digest = input.array()?;
        frontiers.push(
            SchemaCheckpointFrontier::new(shard, position, identity, digest)
                .map_err(|_| SchemaFailure::MalformedCatalog)?,
        );
    }
    Ok(frontiers)
}

fn trailer_length(count: usize) -> usize {
    // `encode` rejects counts above `MAX_FRONTIERS` before this calculation.
    TRAILER_MAGIC.len() + 8 + count * FRONTIER_BYTES
}
