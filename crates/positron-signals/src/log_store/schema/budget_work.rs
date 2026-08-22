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
        // The codec observer accounts structural components in bounded
        // payload quanta; raw bytes remain separately accounted as scanned
        // storage. A 64 KiB quantum is the fixed replay work unit.
        let decode = u64::try_from(payload_bytes)
            .ok()?
            .checked_add(65_535)?
            .checked_div(65_536)?;
        let discovery = Self::system_max_discovery_nodes()
            .checked_add(63)?
            .checked_div(64)
            .and_then(|value| u64::try_from(value).ok())?;
        decode
            .checked_add(discovery)?
            .checked_add(Self::text_index_work_units(payload_bytes)?)
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
