use std::error::Error;

use positron_query::QueryCursor;

use super::support::KernelFixture;

#[path = "correlation/composition.rs"]
mod composition;
#[path = "correlation/matching.rs"]
mod matching;
#[path = "correlation/resources.rs"]
mod resources;
#[path = "correlation/resume.rs"]
mod resume;

pub(super) fn budget() -> positron_query::QueryBudget {
    positron_query::QueryBudget::new(1_048_576, 1_024, 1_024, 1_048_576, 1_048_576, 60)
        .expect("fixture budget")
}

/// Re-authenticates a bounded paired cursor after a test mutates one semantic field.
pub(super) fn rewritten_cursor(
    kernel: &KernelFixture,
    cursor: &QueryCursor,
    rewrite: impl FnOnce(&mut Vec<u8>),
) -> Result<QueryCursor, Box<dyn Error>> {
    let bytes = cursor.as_bytes();
    let payload_length = bytes
        .len()
        .checked_sub(32)
        .ok_or("correlation cursor omitted its authentication tag")?;
    let mut payload = bytes
        .get(..payload_length)
        .ok_or("correlation cursor payload is truncated")?
        .to_vec();
    rewrite(&mut payload);
    let protector = kernel.ledger()?.control_tokens();
    let initial = protector.authenticate_query_cursor(b"query-cursor-v6", &payload)?;
    payload
        .get_mut(8..16)
        .ok_or("correlation cursor omitted its epoch")?
        .copy_from_slice(&initial.epoch().to_be_bytes());
    let authentication = protector.authenticate_query_cursor(b"query-cursor-v6", &payload)?;
    payload.extend_from_slice(&authentication.tag());
    Ok(QueryCursor::from_bytes(&payload)?)
}
