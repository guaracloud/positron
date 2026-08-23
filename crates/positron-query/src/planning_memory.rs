use crate::plan::{FilterPredicate, LogicalPlan, ProjectionColumn};
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};

// The parser frontends borrow the bounded source but retain token/stage
// vectors, native-value candidates, and validation output simultaneously.
// This is deliberately conservative and is admitted before either frontend
// runs, so no parser allocation can bypass the query memory authority.
const BASE_BYTES: u64 = 2;
const PIPE_SLOT_BYTES: u64 = 16;
const SQL_TOKEN_BYTES: u64 = 2_048;
const NATIVE_VALUE_BYTES_PER_SOURCE_BYTE: u64 = 64;
const PATH_SCRATCH_BYTES_PER_SOURCE_BYTE: u64 = 512;
const MAX_PLAN_COLUMNS: usize = 5;

pub(crate) fn preflight(memory_limit: u64, source: &str) -> Result<(), QueryFailure> {
    let source_bytes =
        u64::try_from(source.len()).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let mut required = BASE_BYTES
        .checked_add(source_bytes / 2)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    let pipe_count = source
        .bytes()
        .filter(|byte| *byte == b'|')
        .count()
        .checked_add(1)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    required = required
        .checked_add(
            u64::try_from(pipe_count)
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?
                .checked_mul(PIPE_SLOT_BYTES)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
        )
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    if source
        .trim_start()
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("select"))
    {
        required = required
            .checked_add(SQL_TOKEN_BYTES)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    }
    let has_native_tree = ["array(", "kv("]
        .iter()
        .any(|marker| source.contains(marker));
    let has_linear_native_or_quoted_value = ["string(", "bytes(", "body == \"", "body = \""]
        .iter()
        .any(|marker| source.contains(marker))
        || source.contains('"');
    if has_native_tree {
        required = required
            .checked_add(
                source_bytes
                    .checked_mul(source_bytes)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            )
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    } else if has_linear_native_or_quoted_value {
        required = required
            .checked_add(
                source_bytes
                    .checked_mul(NATIVE_VALUE_BYTES_PER_SOURCE_BYTE)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            )
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    }
    if source.contains("[\"") {
        required = required
            .checked_add(
                source_bytes
                    .checked_mul(PATH_SCRATCH_BYTES_PER_SOURCE_BYTE)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            )
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    }
    if required > memory_limit {
        return Err(QueryFailure::budget_exhausted(
            QueryBudgetDimension::MemoryBytes,
        ));
    }
    Ok(())
}

pub(crate) fn retained_plan_bytes(plan: &LogicalPlan) -> Result<u64, QueryFailure> {
    let mut bytes = u64::try_from(std::mem::size_of::<LogicalPlan>())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    bytes = add_capacity(
        bytes,
        MAX_PLAN_COLUMNS,
        std::mem::size_of::<ProjectionColumn>(),
    )?;
    bytes = projection_memory(bytes, plan.projection())?;
    if let Some(aggregate) = plan.aggregate() {
        bytes = add_capacity(
            bytes,
            MAX_PLAN_COLUMNS,
            std::mem::size_of::<ProjectionColumn>(),
        )?;
        bytes = projection_memory(bytes, aggregate.group_by())?;
    }
    if let Some(filter) = plan.filter() {
        bytes = bytes
            .checked_add(128)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        if let FilterPredicate::BodyEquals(value) = filter {
            bytes = bytes
                .checked_add(
                    u64::try_from(
                        value
                            .retained_heap_bytes()
                            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
                )
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        }
        if let FilterPredicate::AttributeEquals(query) = filter {
            bytes = bytes
                .checked_add(
                    u64::try_from(
                        query
                            .retained_memory_bytes()
                            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
                )
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        }
    }
    Ok(bytes)
}

fn add_capacity(bytes: u64, capacity: usize, slot_bytes: usize) -> Result<u64, QueryFailure> {
    let capacity =
        u64::try_from(capacity).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let slot_bytes =
        u64::try_from(slot_bytes).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    bytes
        .checked_add(
            capacity
                .checked_mul(slot_bytes)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
        )
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))
}

fn projection_memory(mut bytes: u64, columns: &[ProjectionColumn]) -> Result<u64, QueryFailure> {
    for column in columns {
        if let ProjectionColumn::Attribute(path) = column {
            bytes = path_memory(bytes, path)?;
        }
    }
    Ok(bytes)
}

fn path_memory(mut bytes: u64, path: &positron_signals::SchemaPath) -> Result<u64, QueryFailure> {
    bytes = add_capacity(
        bytes,
        positron_signals::SchemaPath::system_max_segments(),
        std::mem::size_of::<String>(),
    )?;
    for segment in path.segments() {
        bytes = bytes
            .checked_add(
                u64::try_from(segment.capacity())
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
            )
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_planning_arithmetic_rejects_capacity_overflow() {
        assert!(add_capacity(u64::MAX, 1, 1).is_err());
        assert!(add_capacity(0, usize::MAX, usize::MAX).is_err());
        let path = positron_signals::SchemaPath::root(
            positron_domain::value::AttributeNamespace::Record,
            "key".to_owned(),
        )
        .expect("bounded test path");
        assert!(path_memory(u64::MAX, &path).is_err());
    }
}
