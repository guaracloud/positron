use positron_kernel::ResourceAmounts;
use positron_policy::{NativeLogCandidate, PolicyBudget};
use positron_signals::{SchemaBudget, SchemaEntry};

// Resource Governor CPU units are coarse concurrent-work reservations; policy
// steps remain byte-exact and are rounded up to one 64 Ki-step work quantum.
const POLICY_EVALUATION_STEPS_PER_CPU_WORK_UNIT: u64 = 65_536;
const SCHEMA_DISCOVERY_NODES_PER_CPU_WORK_UNIT: u64 = 64;
// A text sidecar is optional physical evidence. Requests whose conservative
// construction bound exceeds this admission slice intentionally fall back to
// authenticated body scans instead of making ordinary ingest unavailable.
const MAX_ADMITTED_TEXT_WORK_UNITS: u64 = 31;

#[derive(Clone, Copy)]
pub(super) struct SchemaAdmissionEstimate {
    staging_memory_bytes: u64,
    retained_memory_bytes: u64,
    #[allow(dead_code)]
    discovery_nodes: u64,
    #[allow(dead_code)]
    text_work_units: u64,
    schema_work_units: u64,
}

impl SchemaAdmissionEstimate {
    pub(super) const fn staging_memory_bytes(self) -> u64 {
        self.staging_memory_bytes
    }

    pub(super) const fn retained_memory_bytes(self) -> u64 {
        self.retained_memory_bytes
    }

    #[allow(dead_code)]
    pub(super) const fn discovery_nodes(self) -> u64 {
        self.discovery_nodes
    }

    #[allow(dead_code)]
    pub(super) const fn text_work_units(self) -> u64 {
        self.text_work_units
    }

    pub(super) const fn schema_work_units(self) -> u64 {
        self.schema_work_units
    }
}

pub(super) fn schema_admission_estimate(
    records: &[NativeLogCandidate],
) -> Option<SchemaAdmissionEstimate> {
    let mut clone_bytes = 0_u64;
    let mut schema_bytes = u64::try_from(std::mem::size_of::<Vec<SchemaEntry>>()).ok()?;
    let mut discovery_nodes = 0_u64;
    let mut text_body_bytes = 0_usize;
    let mut text_work_units = 0_u64;
    let mut has_text_body = false;
    let discovery_limit = u64::try_from(SchemaBudget::system_max_discovery_nodes()).ok()?;
    for record in records {
        if let Some(positron_domain::value::CandidateAttributeValue::String(body)) = record.body() {
            has_text_body = true;
            text_body_bytes = text_body_bytes.checked_add(body.len())?;
        }
        for attribute in record.attributes() {
            clone_bytes = clone_bytes
                .checked_add(u64::try_from(attribute.key().len()).ok()?)?
                .checked_add(u64::try_from(std::mem::size_of_val(attribute)).ok()?)?;
            for value in attribute.occurrences() {
                accumulate_clone_bytes(value, &mut clone_bytes)?;
                accumulate_schema_bytes(value, attribute.key().len(), 1, &mut schema_bytes)?;
                accumulate_discovery_nodes(value, &mut discovery_nodes, discovery_limit)?;
            }
        }
    }
    if has_text_body {
        let estimated_work = SchemaBudget::text_index_work_units(text_body_bytes)?;
        if estimated_work <= MAX_ADMITTED_TEXT_WORK_UNITS {
            schema_bytes = schema_bytes.checked_add(
                u64::try_from(SchemaBudget::text_index_block_memory_bound(
                    text_body_bytes,
                )?)
                .ok()?,
            )?;
            text_work_units = estimated_work;
        }
    }
    if discovery_nodes > 0 {
        schema_bytes = schema_bytes
            .checked_add(u64::try_from(SchemaBudget::block_index_memory_bytes()).ok()?)?;
    }
    let retained_memory_bytes =
        schema_bytes.min(u64::try_from(SchemaBudget::system_max_memory_bytes()).ok()?);
    let staging_memory_bytes = clone_bytes
        .checked_mul(2)?
        .checked_add(schema_bytes.min(schema_stage_ceiling_bytes()?))?
        .max(1);
    Some(SchemaAdmissionEstimate {
        staging_memory_bytes,
        retained_memory_bytes,
        discovery_nodes,
        text_work_units,
        schema_work_units: schema_discovery_cpu_work_units(discovery_nodes)?
            .checked_add(text_work_units)?,
    })
}

pub(super) fn group_work_amounts(
    record_count: u64,
    policy: PolicyBudget,
    schema: SchemaAdmissionEstimate,
) -> Option<ResourceAmounts> {
    let evaluation_work = policy
        .evaluation_steps()
        .checked_add(POLICY_EVALUATION_STEPS_PER_CPU_WORK_UNIT - 1)?
        / POLICY_EVALUATION_STEPS_PER_CPU_WORK_UNIT;
    let policy_and_store_work = evaluation_work.checked_mul(record_count)?.checked_add(1)?;
    // Policy and discovery execute sequentially within the admission group;
    // reserve their conservative peak rather than fabricating concurrency.
    let cpu_work = policy_and_store_work.max(schema.schema_work_units());
    let per_record = policy.reserved_memory_bytes()?;
    let policy_memory = per_record.checked_mul(record_count)?;
    let memory = 1_048_576_u64
        .checked_add(policy_memory)?
        .checked_add(schema.staging_memory_bytes)?;
    Some(ResourceAmounts::new([
        memory,
        1,
        1,
        1_048_576,
        record_count,
        0,
        1,
        1,
        cpu_work,
        4,
        1_048_576,
    ]))
}

fn schema_discovery_cpu_work_units(nodes: u64) -> Option<u64> {
    let bounded = nodes.min(u64::try_from(SchemaBudget::system_max_discovery_nodes()).ok()?);
    if bounded == 0 {
        return Some(0);
    }
    bounded
        .checked_add(SCHEMA_DISCOVERY_NODES_PER_CPU_WORK_UNIT - 1)?
        .checked_div(SCHEMA_DISCOVERY_NODES_PER_CPU_WORK_UNIT)
}

fn schema_stage_ceiling_bytes() -> Option<u64> {
    let catalog = SchemaBudget::system_max_memory_bytes();
    let delta_slots =
        SchemaBudget::system_max_entries().checked_mul(std::mem::size_of::<SchemaEntry>())?;
    u64::try_from(
        catalog
            .checked_add(delta_slots)?
            .checked_add(std::mem::size_of::<Vec<SchemaEntry>>())?,
    )
    .ok()
}

fn accumulate_clone_bytes(
    value: &positron_domain::value::CandidateAttributeValue,
    bytes: &mut u64,
) -> Option<()> {
    use positron_domain::value::CandidateAttributeValue as Value;
    let allocation_overhead =
        u64::try_from(2_usize.checked_mul(std::mem::size_of::<usize>())?).ok()?;
    *bytes = bytes.checked_add(u64::try_from(std::mem::size_of_val(value)).ok()?)?;
    *bytes = bytes.checked_add(match value {
        Value::Null | Value::Boolean(_) | Value::SignedInteger(_) | Value::FloatingPointBits(_) => {
            0
        },
        Value::String(value) => u64::try_from(value.len())
            .ok()?
            .checked_add(allocation_overhead)?,
        Value::Bytes(value) => u64::try_from(value.len())
            .ok()?
            .checked_add(allocation_overhead)?,
        Value::Array(values) => {
            for value in values {
                accumulate_clone_bytes(value, bytes)?;
            }
            allocation_overhead
        },
        Value::KeyValueList(entries) => {
            for entry in entries {
                *bytes = bytes
                    .checked_add(u64::try_from(std::mem::size_of::<String>()).ok()?)?
                    .checked_add(u64::try_from(entry.key().len()).ok()?)?;
                accumulate_clone_bytes(entry.value(), bytes)?;
            }
            allocation_overhead
        },
    })?;
    Some(())
}

fn accumulate_discovery_nodes(
    value: &positron_domain::value::CandidateAttributeValue,
    nodes: &mut u64,
    limit: u64,
) -> Option<()> {
    use positron_domain::value::CandidateAttributeValue as Value;
    if *nodes >= limit {
        return Some(());
    }
    *nodes = (*nodes).checked_add(1)?.min(limit);
    if let Value::KeyValueList(entries) = value {
        for entry in entries {
            accumulate_discovery_nodes(entry.value(), nodes, limit)?;
            if *nodes == limit {
                break;
            }
        }
    }
    Some(())
}

fn accumulate_schema_bytes(
    value: &positron_domain::value::CandidateAttributeValue,
    path_bytes: usize,
    depth: usize,
    bytes: &mut u64,
) -> Option<()> {
    use positron_domain::value::CandidateAttributeValue as Value;
    *bytes = bytes.checked_add(schema_entry_copy_bytes(path_bytes, depth)?)?;
    *bytes = bytes.checked_add(
        u64::try_from(SchemaBudget::index_path_memory_bytes(path_bytes, depth)?).ok()?,
    )?;
    if let Value::KeyValueList(entries) = value {
        for entry in entries {
            accumulate_schema_bytes(
                entry.value(),
                path_bytes.checked_add(entry.key().len())?,
                depth.checked_add(1)?,
                bytes,
            )?;
        }
    }
    Some(())
}

fn schema_entry_copy_bytes(path_bytes: usize, depth: usize) -> Option<u64> {
    if depth > positron_signals::SchemaPath::system_max_segments() {
        return schema_stage_ceiling_bytes();
    }
    let allocation_overhead = 2_usize.checked_mul(std::mem::size_of::<usize>())?;
    let path = allocation_overhead
        .checked_add(depth.checked_mul(std::mem::size_of::<String>())?)?
        .checked_add(depth.checked_mul(allocation_overhead)?)?
        .checked_add(path_bytes)?;
    let variants = allocation_overhead.checked_add(8_usize.checked_mul(std::mem::size_of::<
        positron_domain::value::AttributeValueKind,
    >())?)?;
    let one_copy = std::mem::size_of::<SchemaEntry>()
        .checked_add(path)?
        .checked_add(variants)?;
    u64::try_from(one_copy).ok()
}

#[cfg(test)]
#[path = "tests/capacity.rs"]
mod tests;
