use crate::QueryCursor;

use super::{TailCursor, TailCursorState, TailPosition};

pub fn fuzz_tail_cursor(data: &[u8]) {
    if data.len() > 4_096 {
        return;
    }
    let _ = QueryCursor::from_bytes(data);
    let protector = positron_kernel::fuzz_control_token_protector();
    let principal = positron_domain::identity::PrincipalId::from_bytes([1; 16])
        .expect("fuzz principal fixture is valid");
    let tenant = positron_domain::identity::TenantId::from_bytes([2; 16])
        .expect("fuzz tenant fixture is valid");
    let shard =
        positron_domain::routing::VirtualShardId::new(1).expect("fuzz shard fixture is valid");
    let state = TailCursorState::new(
        principal,
        tenant,
        7,
        [3; 32],
        [5; 32],
        vec![TailPosition::new(
            shard,
            positron_domain::routing::CommitPosition::origin(),
        )],
        60,
        0,
        [4; 32],
    )
    .expect("fuzz cursor state is valid");
    let cursor = TailCursor::encode(&protector, &state).expect("fuzz cursor encodes");
    let decoded = TailCursor::decode(&protector, &cursor).expect("fuzz cursor decodes");
    assert_eq!(decoded, state);
    let _ = TailCursor::from_bytes(data);
    if !data.is_empty() {
        let mut mutated = cursor.as_bytes().to_vec();
        for (index, byte) in data.iter().enumerate().take(mutated.len()) {
            if let Some(slot) = mutated.get_mut(index) {
                *slot ^= *byte;
            }
        }
        let _ = TailCursor::from_bytes(&mutated)
            .and_then(|cursor| TailCursor::decode(&protector, &cursor));
    }
}
