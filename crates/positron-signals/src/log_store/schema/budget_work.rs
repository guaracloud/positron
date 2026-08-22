use super::index::{SchemaBlockIndex, SchemaIndexPath};
use super::text_index::TextBlockSummary;
use super::{SchemaBudget, SchemaEntry};

impl SchemaBudget {
    /// Conservative retained-memory cost of one physical block-index owner.
    #[must_use]
    pub const fn block_index_memory_bytes() -> usize {
        std::mem::size_of::<SchemaBlockIndex>() + std::mem::size_of::<Vec<SchemaIndexPath>>()
    }

    /// Conservative retained-memory bound for a physical text summary and
    /// its block-index owner.
    #[must_use]
    pub fn text_index_block_memory_bound(body_bytes: usize) -> Option<usize> {
        Self::block_index_memory_bytes().checked_add(TextBlockSummary::memory_bound(body_bytes)?)
    }

    /// Conservative bounded work units for constructing one text summary.
    #[must_use]
    pub fn text_index_work_units(body_bytes: usize) -> Option<u64> {
        super::text_builder::work_units(body_bytes)
    }

    /// Conservative replay work bound for one authenticated payload.
    #[must_use]
    pub fn replay_schema_work_units(payload_bytes: usize) -> Option<u64> {
        Self::replay_decode_work_units(payload_bytes)?
            .checked_add(Self::text_index_work_units(payload_bytes)?)
    }

    /// Conservative structural decode and schema-discovery work bound before
    /// decoded bodies reveal the text-summary size. A replay admission may
    /// use this bound as a reduced-pruning fallback when the complete bound
    /// cannot fit the protected recovery pool.
    #[must_use]
    pub fn replay_decode_work_units(payload_bytes: usize) -> Option<u64> {
        // The replay codec observes structural components in fixed 64-byte
        // component quanta; raw bytes remain separately accounted as scanned
        // storage. A 64-byte quantum is conservative because each observed
        // component consumes at least one authenticated payload byte.
        let decode = u64::try_from(payload_bytes)
            .ok()?
            .checked_add(63)?
            .checked_div(64)?;
        let discovery_nodes = payload_bytes.min(Self::system_max_discovery_nodes());
        let discovery = discovery_nodes
            .checked_add(63)?
            .checked_div(64)
            .and_then(|value| u64::try_from(value).ok())?;
        decode.checked_add(discovery)
    }

    /// Conservative retained-memory cost of one indexed path copy.
    pub fn index_path_memory_bytes(path_bytes: usize, depth: usize) -> Option<usize> {
        let overhead = 2_usize.checked_mul(std::mem::size_of::<usize>())?;
        overhead
            .checked_add(depth.checked_mul(std::mem::size_of::<String>())?)?
            .checked_add(depth.checked_mul(overhead)?)?
            .checked_add(path_bytes)?
            .checked_add(std::mem::size_of::<SchemaIndexPath>())
    }

    /// Conservative peak for decoding one authenticated v2 block and staging its schema delta.
    pub fn replay_working_memory_bytes(payload_bytes: usize) -> Option<usize> {
        payload_bytes
            .checked_mul(4)?
            .checked_add(Self::system_max_memory_bytes())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<SchemaEntry>>()))
    }
}
