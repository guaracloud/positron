use positron_domain::identity::TenantId;
use positron_domain::value::{AttributeNamespace, AttributeValueKind};

use super::catalog::SchemaCatalog;
use super::failure::SchemaFailure;
use super::model::{
    SchemaBudget, SchemaEntry, SchemaPath, entry_memory_bytes, entry_persistent_bytes,
};

const MAGIC: &[u8; 8] = b"PSCHEMA1";
const LEGACY_VERSION: u16 = 1;
pub(super) const PREVIOUS_VERSION: u16 = 2;
pub(super) const VERSION: u16 = 3;
const MAX_SEGMENTS_ON_WIRE: usize = 128;
mod encode;
mod index;
mod preflight;
mod value;

pub(super) const fn legacy_version(version: u16) -> bool {
    version == LEGACY_VERSION
}

pub(super) const fn text_version(version: u16) -> bool {
    version == VERSION
}

impl SchemaCatalog {
    /// Decodes one bounded schema Catalog Object through the production reader.
    pub fn decode_catalog_object(bytes: &[u8]) -> Result<Self, SchemaFailure> {
        decode_checkpoint(bytes).map(|(catalog, _)| catalog)
    }

    /// Recognizes this representation without interpreting unrelated Catalog Objects.
    pub fn decode_catalog_object_if_recognized(
        bytes: &[u8],
    ) -> Result<Option<Self>, SchemaFailure> {
        if bytes.starts_with(MAGIC) {
            Self::decode_catalog_object(bytes).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Returns the allocation bound validated before a catalog object decode.
    pub fn catalog_memory_bound(bytes: &[u8]) -> Result<usize, SchemaFailure> {
        let prefix = preflight::catalog_prefix(bytes)?;
        let frontier_count = super::checkpoint::preflight(
            bytes
                .get(prefix.offset..)
                .ok_or(SchemaFailure::MalformedCatalog)?,
        )?;
        prefix
            .memory_bound
            .checked_add(
                frontier_count
                    .checked_mul(std::mem::size_of::<
                        super::checkpoint::SchemaCheckpointFrontier,
                    >())
                    .ok_or(SchemaFailure::MalformedCatalog)?,
            )
            .filter(|memory| *memory <= prefix.budget.max_memory_bytes())
            .ok_or(SchemaFailure::MalformedCatalog)
    }

    /// Returns the heap bytes attributable to rebuildable physical sidecars.
    #[doc(hidden)]
    pub fn catalog_sidecar_memory_bound(bytes: &[u8]) -> Result<usize, SchemaFailure> {
        Ok(preflight::catalog_prefix(bytes)?.sidecar_memory_bound)
    }

    /// Encodes this immutable tenant schema representation for Catalog publication.
    pub fn encode_catalog_object(&self) -> Result<Vec<u8>, SchemaFailure> {
        encode::catalog(self)
    }

    /// Encodes the schema plus canonical bounded replay state in PSCHEMA1.
    pub fn encode_checkpoint_object(
        &self,
        frontiers: &[super::checkpoint::SchemaCheckpointFrontier],
    ) -> Result<Vec<u8>, SchemaFailure> {
        super::checkpoint::encode(self, frontiers)
    }

    /// Decodes one PSCHEMA1 checkpoint and its authenticated replay boundaries.
    pub fn decode_checkpoint_object(
        bytes: &[u8],
    ) -> Result<(Self, Vec<super::checkpoint::SchemaCheckpointFrontier>), SchemaFailure> {
        decode_checkpoint(bytes)
    }
}

fn decode_checkpoint(
    bytes: &[u8],
) -> Result<
    (
        SchemaCatalog,
        Vec<super::checkpoint::SchemaCheckpointFrontier>,
    ),
    SchemaFailure,
> {
    let prefix = preflight::catalog_prefix(bytes)?;
    super::checkpoint::preflight(
        bytes
            .get(prefix.offset..)
            .ok_or(SchemaFailure::MalformedCatalog)?,
    )?;
    let mut input = Input::new(
        bytes
            .get(..prefix.offset)
            .ok_or(SchemaFailure::MalformedCatalog)?,
    );
    input.take(MAGIC.len())?;
    if input.u16()? != prefix.version {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let tenant =
        TenantId::from_bytes(input.array()?).map_err(|_| SchemaFailure::MalformedCatalog)?;
    let max_entries = input.usize()?;
    let max_memory = input.usize()?;
    let max_persistent = input.usize()?;
    let max_index = input.usize()?;
    let budget = SchemaBudget::new(max_entries, max_memory, max_persistent, max_index)
        .map_err(|_| SchemaFailure::MalformedCatalog)?;
    let count = input.usize()?;
    let overflow_records = input.u64()?;
    let overflow_bytes = input.u64()?;
    let mut catalog = SchemaCatalog::new(tenant, budget).map_err(|failure| match failure {
        SchemaFailure::AllocationUnavailable => SchemaFailure::AllocationUnavailable,
        _ => SchemaFailure::MalformedCatalog,
    })?;
    for _ in 0..count {
        let namespace = decode_namespace(input.u8()?)?;
        let segment_count = usize::from(input.u16()?);
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(segment_count)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for _ in 0..segment_count {
            segments.push(input.string()?);
        }
        let path = SchemaPath::from_segments(namespace, segments)
            .map_err(|_| SchemaFailure::MalformedCatalog)?;
        if catalog
            .entries
            .last()
            .is_some_and(|entry| entry.path >= path)
        {
            return Err(SchemaFailure::MalformedCatalog);
        }
        let variant_count = input.usize()?;
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(super::model::MAX_VARIANTS)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for _ in 0..variant_count {
            let kind = decode_value_kind(input.u8()?)?;
            variants.push(kind);
        }
        let entry = SchemaEntry {
            path,
            variants,
            observations: input.u64()?,
            conflicts: input.u64()?,
            query_uses: input.u64()?,
            promoted: input.u8()? == 1,
            index_bytes: input.usize()?,
        };
        catalog.memory_bytes = catalog
            .memory_bytes
            .checked_add(entry_memory_cost(&entry))
            .ok_or(SchemaFailure::MalformedCatalog)?;
        catalog.persistent_bytes = catalog
            .persistent_bytes
            .checked_add(entry_persistent_cost(&entry))
            .ok_or(SchemaFailure::MalformedCatalog)?;
        catalog.index_bytes = catalog
            .index_bytes
            .checked_add(entry.index_bytes)
            .ok_or(SchemaFailure::MalformedCatalog)?;
        catalog.entries.push(entry);
    }
    let (block_indexes, physical_bytes, physical_memory) = index::decode(
        &mut input,
        budget,
        legacy_version(prefix.version),
        text_version(prefix.version),
    )?;
    if block_indexes
        .iter()
        .any(|index| !index.semantically_valid(&catalog.entries))
    {
        return Err(SchemaFailure::MalformedCatalog);
    }
    catalog.block_indexes = block_indexes;
    catalog.persistent_bytes = catalog
        .persistent_bytes
        .checked_add(physical_bytes)
        .ok_or(SchemaFailure::MalformedCatalog)?;
    catalog.index_bytes = catalog
        .index_bytes
        .checked_add(physical_bytes)
        .ok_or(SchemaFailure::MalformedCatalog)?;
    catalog.memory_bytes = catalog
        .memory_bytes
        .checked_add(physical_memory)
        .ok_or(SchemaFailure::MalformedCatalog)?;
    catalog.overflow_records = overflow_records;
    catalog.overflow_bytes = overflow_bytes;
    if catalog.memory_bytes > budget.max_memory_bytes()
        || catalog.persistent_bytes > budget.max_persistent_bytes()
        || catalog.index_bytes > budget.max_index_bytes()
    {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let frontiers = super::checkpoint::decode(
        bytes
            .get(prefix.offset..)
            .ok_or(SchemaFailure::MalformedCatalog)?,
        budget,
        catalog.memory_bytes,
    )?;
    Ok((catalog, frontiers))
}

fn entry_memory_cost(entry: &SchemaEntry) -> usize {
    entry_memory_bytes(&entry.path, entry.variants.capacity()).unwrap_or(usize::MAX)
}

fn entry_persistent_cost(entry: &SchemaEntry) -> usize {
    entry_persistent_bytes(&entry.path, entry.variants.len()).unwrap_or(usize::MAX)
}

fn namespace_tag(namespace: AttributeNamespace) -> u8 {
    match namespace {
        AttributeNamespace::Stream => 1,
        AttributeNamespace::Resource => 2,
        AttributeNamespace::InstrumentationScope => 3,
        AttributeNamespace::Record => 4,
    }
}

fn decode_namespace(tag: u8) -> Result<AttributeNamespace, SchemaFailure> {
    match tag {
        1 => Ok(AttributeNamespace::Stream),
        2 => Ok(AttributeNamespace::Resource),
        3 => Ok(AttributeNamespace::InstrumentationScope),
        4 => Ok(AttributeNamespace::Record),
        _ => Err(SchemaFailure::MalformedCatalog),
    }
}

fn value_tag(kind: AttributeValueKind) -> u8 {
    match kind {
        AttributeValueKind::Null => 0,
        AttributeValueKind::Boolean => 1,
        AttributeValueKind::SignedInteger => 2,
        AttributeValueKind::FloatingPoint => 3,
        AttributeValueKind::String => 4,
        AttributeValueKind::Bytes => 5,
        AttributeValueKind::Array => 6,
        AttributeValueKind::KeyValueList => 7,
    }
}

fn decode_value_kind(tag: u8) -> Result<AttributeValueKind, SchemaFailure> {
    match tag {
        0 => Ok(AttributeValueKind::Null),
        1 => Ok(AttributeValueKind::Boolean),
        2 => Ok(AttributeValueKind::SignedInteger),
        3 => Ok(AttributeValueKind::FloatingPoint),
        4 => Ok(AttributeValueKind::String),
        5 => Ok(AttributeValueKind::Bytes),
        6 => Ok(AttributeValueKind::Array),
        7 => Ok(AttributeValueKind::KeyValueList),
        _ => Err(SchemaFailure::MalformedCatalog),
    }
}

fn put_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn put_u16(bytes: &mut Vec<u8>, value: usize) -> Result<(), SchemaFailure> {
    bytes.extend_from_slice(
        &u16::try_from(value)
            .map_err(|_| SchemaFailure::LimitExceeded)?
            .to_be_bytes(),
    );
    Ok(())
}

pub(super) fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn put_len(bytes: &mut Vec<u8>, value: usize) -> Result<(), SchemaFailure> {
    put_u64(
        bytes,
        u64::try_from(value).map_err(|_| SchemaFailure::LimitExceeded)?,
    );
    Ok(())
}

fn put_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), SchemaFailure> {
    put_len(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

pub(super) struct Input<'a> {
    bytes: &'a [u8],
}

impl<'a> Input<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], SchemaFailure> {
        let (value, rest) = self
            .bytes
            .split_at_checked(length)
            .ok_or(SchemaFailure::MalformedCatalog)?;
        self.bytes = rest;
        Ok(value)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], SchemaFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| SchemaFailure::MalformedCatalog)
    }

    fn u8(&mut self) -> Result<u8, SchemaFailure> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(SchemaFailure::MalformedCatalog)?)
    }

    pub(super) fn starts_with(&self, prefix: &[u8]) -> bool {
        self.bytes.starts_with(prefix)
    }

    pub(super) const fn remaining_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    fn u16(&mut self) -> Result<u16, SchemaFailure> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, SchemaFailure> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn usize(&mut self) -> Result<usize, SchemaFailure> {
        usize::try_from(self.u64()?).map_err(|_| SchemaFailure::MalformedCatalog)
    }

    fn string(&mut self) -> Result<String, SchemaFailure> {
        let length = self.usize()?;
        let value = self.take(length)?;
        let value = std::str::from_utf8(value).map_err(|_| SchemaFailure::MalformedCatalog)?;
        let mut decoded = String::new();
        decoded
            .try_reserve_exact(length)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        decoded.push_str(value);
        Ok(decoded)
    }

    pub(super) const fn remaining_len(&self) -> usize {
        self.bytes.len()
    }
}
