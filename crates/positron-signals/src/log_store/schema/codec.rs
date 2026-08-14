use positron_domain::identity::TenantId;
use positron_domain::value::{AttributeNamespace, AttributeValueKind};
use positron_kernel::{CatalogObject, CatalogSnapshot};

use super::catalog::SchemaCatalog;
use super::failure::SchemaFailure;
use super::model::{
    ENTRY_MEMORY_OVERHEAD, ENTRY_PERSISTENT_OVERHEAD, SchemaBudget, SchemaEntry, SchemaPath,
};

const MAGIC: &[u8; 8] = b"PSCHEMA1";
const VERSION: u16 = 1;
const MAX_ENTRIES_ON_WIRE: usize = 4_096;
const MAX_SEGMENTS_ON_WIRE: usize = 128;

impl SchemaCatalog {
    /// Decodes one bounded schema Catalog Object through the production reader.
    pub fn decode_catalog_object(bytes: &[u8]) -> Result<(TenantId, Self), SchemaFailure> {
        decode(bytes)
    }

    /// Encodes this immutable tenant schema as a content-addressed Catalog Object.
    pub fn catalog_object(&self, tenant: TenantId) -> Result<CatalogObject, SchemaFailure> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&tenant.to_bytes());
        for value in [
            self.budget.max_entries(),
            self.budget.max_memory_bytes(),
            self.budget.max_persistent_bytes(),
            self.budget.max_index_bytes(),
        ] {
            bytes.extend_from_slice(
                &u64::try_from(value)
                    .map_err(|_| SchemaFailure::LimitExceeded)?
                    .to_be_bytes(),
            );
        }
        put_len(&mut bytes, self.entries.len())?;
        put_u64(&mut bytes, self.overflow_records);
        put_u64(&mut bytes, self.overflow_bytes);
        for entry in self.entries.values() {
            put_u8(&mut bytes, namespace_tag(entry.path.namespace()));
            put_u16(&mut bytes, entry.path.segments().len())?;
            for segment in entry.path.segments() {
                put_bytes(&mut bytes, segment.as_bytes())?;
            }
            put_len(&mut bytes, entry.variants.len())?;
            for variant in &entry.variants {
                put_u8(&mut bytes, value_tag(*variant));
            }
            put_u64(&mut bytes, entry.observations);
            put_u64(&mut bytes, entry.conflicts);
            put_u64(&mut bytes, entry.query_uses);
            put_u8(&mut bytes, u8::from(entry.promoted));
            put_u64(
                &mut bytes,
                u64::try_from(entry.index_bytes).map_err(|_| SchemaFailure::LimitExceeded)?,
            );
        }
        if bytes.len() > self.budget.max_persistent_bytes() {
            return Err(SchemaFailure::LimitExceeded);
        }
        CatalogObject::new(bytes).map_err(|_| SchemaFailure::CatalogUnavailable)
    }

    /// Rebuilds one tenant's schema from a pinned immutable Catalog snapshot.
    pub fn from_catalog_snapshot(
        snapshot: &CatalogSnapshot,
        tenant: TenantId,
    ) -> Result<Option<Self>, SchemaFailure> {
        let mut found = None;
        for identity in snapshot.object_identities() {
            let Some(bytes) = snapshot
                .object(identity)
                .map_err(|_| SchemaFailure::CatalogUnavailable)?
            else {
                return Err(SchemaFailure::CatalogUnavailable);
            };
            if !bytes.starts_with(MAGIC) {
                continue;
            }
            let (encoded_tenant, catalog) = decode(bytes)?;
            if encoded_tenant == tenant && found.replace(catalog).is_some() {
                return Err(SchemaFailure::MalformedCatalog);
            }
        }
        Ok(found)
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<(TenantId, SchemaCatalog), SchemaFailure> {
    let mut input = Input::new(bytes);
    if input.take(MAGIC.len())? != MAGIC || input.u16()? != VERSION {
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
    if count > MAX_ENTRIES_ON_WIRE || count > budget.max_entries() {
        return Err(SchemaFailure::MalformedCatalog);
    }
    let overflow_records = input.u64()?;
    let overflow_bytes = input.u64()?;
    let mut catalog = SchemaCatalog::new(budget).map_err(|_| SchemaFailure::MalformedCatalog)?;
    for _ in 0..count {
        let namespace = decode_namespace(input.u8()?)?;
        let segment_count = usize::from(input.u16()?);
        if segment_count == 0 || segment_count > MAX_SEGMENTS_ON_WIRE {
            return Err(SchemaFailure::MalformedCatalog);
        }
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(segment_count)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for _ in 0..segment_count {
            segments.push(input.string()?);
        }
        let path = SchemaPath::from_segments(namespace, segments)
            .map_err(|_| SchemaFailure::MalformedCatalog)?;
        if catalog.entries.contains_key(&path) {
            return Err(SchemaFailure::MalformedCatalog);
        }
        let variant_count = input.usize()?;
        if variant_count == 0 || variant_count > super::model::MAX_VARIANTS {
            return Err(SchemaFailure::MalformedCatalog);
        }
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(variant_count)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for _ in 0..variant_count {
            let kind = decode_value_kind(input.u8()?)?;
            if variants.contains(&kind) {
                return Err(SchemaFailure::MalformedCatalog);
            }
            variants.push(kind);
        }
        let entry = SchemaEntry {
            path: path.clone(),
            variants,
            observations: input.u64()?,
            conflicts: input.u64()?,
            query_uses: input.u64()?,
            promoted: match input.u8()? {
                0 => false,
                1 => true,
                _ => return Err(SchemaFailure::MalformedCatalog),
            },
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
        catalog.entries.insert(path, entry);
    }
    catalog.overflow_records = overflow_records;
    catalog.overflow_bytes = overflow_bytes;
    if catalog.memory_bytes > budget.max_memory_bytes()
        || catalog.persistent_bytes > budget.max_persistent_bytes()
        || catalog.index_bytes > budget.max_index_bytes()
        || !input.is_empty()
    {
        return Err(SchemaFailure::MalformedCatalog);
    }
    Ok((tenant, catalog))
}

fn entry_memory_cost(entry: &SchemaEntry) -> usize {
    ENTRY_MEMORY_OVERHEAD
        .saturating_add(entry.path.as_string().len())
        .saturating_add(std::mem::size_of::<AttributeValueKind>())
        .saturating_add(
            entry
                .variants
                .len()
                .saturating_sub(1)
                .saturating_mul(entry.path.as_string().len().saturating_add(8)),
        )
}

fn entry_persistent_cost(entry: &SchemaEntry) -> usize {
    ENTRY_PERSISTENT_OVERHEAD
        .saturating_add(entry.path.as_string().len())
        .saturating_add(entry.variants.len())
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

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_len(bytes: &mut Vec<u8>, value: usize) -> Result<(), SchemaFailure> {
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

struct Input<'a> {
    bytes: &'a [u8],
}

impl<'a> Input<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SchemaFailure> {
        let (value, rest) = self
            .bytes
            .split_at_checked(length)
            .ok_or(SchemaFailure::MalformedCatalog)?;
        self.bytes = rest;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SchemaFailure> {
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

    fn u16(&mut self) -> Result<u16, SchemaFailure> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, SchemaFailure> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn usize(&mut self) -> Result<usize, SchemaFailure> {
        usize::try_from(self.u64()?).map_err(|_| SchemaFailure::MalformedCatalog)
    }

    fn string(&mut self) -> Result<String, SchemaFailure> {
        let length = self.usize()?;
        let value = self.take(length)?;
        String::from_utf8(value.to_vec()).map_err(|_| SchemaFailure::MalformedCatalog)
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
