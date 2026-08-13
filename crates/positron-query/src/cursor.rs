use hmac::{Hmac, KeyInit, Mac};
use positron_domain::identity::{PrincipalId, TenantId};
use sha2::Sha256;

use crate::{LogicalPlan, QueryBudget, QueryFailure, QueryFailureCode};

const MAGIC: [u8; 8] = *b"POSQCR01";
const PAYLOAD_BYTES: usize = 280;
const CURSOR_BYTES: usize = PAYLOAD_BYTES + 32;

/// Opaque authenticated continuation with one fixed bounded representation.
#[derive(Clone, Eq, PartialEq)]
pub struct QueryCursor(Vec<u8>);

impl QueryCursor {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, QueryFailure> {
        if bytes.len() != CURSOR_BYTES {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for QueryCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QueryCursor { <opaque> }")
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CursorState {
    pub(crate) principal: PrincipalId,
    pub(crate) tenant: TenantId,
    pub(crate) authorization_generation: u64,
    pub(crate) catalog_identity: [u8; 32],
    pub(crate) catalog_generation: u64,
    pub(crate) frontier: u64,
    pub(crate) plan: LogicalPlan,
    pub(crate) offset: u16,
    pub(crate) sequence: u64,
    pub(crate) prior_digest: [u8; 32],
    pub(crate) lease_identity: [u8; 16],
    pub(crate) expiry: u64,
    pub(crate) budget: QueryBudget,
    pub(crate) scanned_bytes: u64,
    pub(crate) decoded_records: u64,
    pub(crate) output_rows: u64,
    pub(crate) output_bytes: u64,
}

pub(crate) fn encode(
    key: &[u8; 32],
    epoch: u32,
    state: CursorState,
) -> Result<QueryCursor, QueryFailure> {
    let mut bytes = Vec::with_capacity(CURSOR_BYTES);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&state.principal.to_bytes());
    bytes.extend_from_slice(&state.tenant.to_bytes());
    bytes.extend_from_slice(&state.authorization_generation.to_be_bytes());
    bytes.extend_from_slice(&state.catalog_identity);
    bytes.extend_from_slice(&state.catalog_generation.to_be_bytes());
    bytes.extend_from_slice(&state.frontier.to_be_bytes());
    bytes.extend_from_slice(&state.plan.limit().to_be_bytes());
    bytes.extend_from_slice(&plan_digest(state.plan));
    bytes.extend_from_slice(&state.offset.to_be_bytes());
    bytes.extend_from_slice(&state.sequence.to_be_bytes());
    bytes.extend_from_slice(&state.prior_digest);
    bytes.extend_from_slice(&state.lease_identity);
    bytes.extend_from_slice(&state.expiry.to_be_bytes());
    for value in [
        state.budget.scanned_bytes(),
        state.budget.decoded_records(),
        state.budget.output_rows(),
        state.budget.output_bytes(),
        state.budget.memory_bytes(),
        state.budget.wall_seconds(),
        state.scanned_bytes,
        state.decoded_records,
        state.output_rows,
        state.output_bytes,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    Ok(QueryCursor(bytes))
}

pub(crate) fn lease_identity(
    key: &[u8; 32],
    principal: PrincipalId,
    tenant: TenantId,
    catalog_identity: [u8; 32],
    frontier: u64,
    expiry: u64,
) -> Result<[u8; 16], QueryFailure> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    mac.update(b"positron-snapshot-lease-v1\0");
    mac.update(&principal.to_bytes());
    mac.update(&tenant.to_bytes());
    mac.update(&catalog_identity);
    mac.update(&frontier.to_be_bytes());
    mac.update(&expiry.to_be_bytes());
    let authentication = mac.finalize().into_bytes();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&authentication[..16]);
    Ok(identity)
}

pub(crate) fn decode(
    key: &[u8; 32],
    epoch: u32,
    cursor: &QueryCursor,
) -> Result<CursorState, QueryFailure> {
    let (payload, authentication) = cursor
        .as_bytes()
        .split_at_checked(PAYLOAD_BYTES)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    mac.update(payload);
    mac.verify_slice(authentication)
        .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let mut reader = Reader::new(payload);
    if reader.array::<8>()? != MAGIC || reader.u32()? != epoch {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    let principal = PrincipalId::from_bytes(reader.array()?)
        .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let tenant = TenantId::from_bytes(reader.array()?)
        .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let authorization_generation = reader.u64()?;
    let catalog_identity = reader.array()?;
    let catalog_generation = reader.u64()?;
    let frontier = reader.u64()?;
    let plan = LogicalPlan::logs(reader.u16()?);
    if reader.array::<32>()? != plan_digest(plan) {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    let offset = reader.u16()?;
    let sequence = reader.u64()?;
    let prior_digest = reader.array()?;
    let lease_identity = reader.array()?;
    let expiry = reader.u64()?;
    let budget = QueryBudget::new(
        reader.u64()?,
        reader.u64()?,
        reader.u64()?,
        reader.u64()?,
        reader.u64()?,
        reader.u64()?,
    )
    .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let state = CursorState {
        principal,
        tenant,
        authorization_generation,
        catalog_identity,
        catalog_generation,
        frontier,
        plan,
        offset,
        sequence,
        prior_digest,
        lease_identity,
        expiry,
        budget,
        scanned_bytes: reader.u64()?,
        decoded_records: reader.u64()?,
        output_rows: reader.u64()?,
        output_bytes: reader.u64()?,
    };
    if !reader.empty()
        || state.plan.limit() == 0
        || state.lease_identity.iter().all(|byte| *byte == 0)
    {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    Ok(state)
}

fn plan_digest(plan: LogicalPlan) -> [u8; 32] {
    use sha2::Digest;
    let mut digest = Sha256::new();
    digest.update(b"positron-query-plan-v1\0logs\0");
    digest.update(plan.limit().to_be_bytes());
    digest.finalize().into()
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], QueryFailure> {
        let (value, rest) = self
            .bytes
            .split_at_checked(N)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        self.bytes = rest;
        value
            .try_into()
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))
    }

    fn u16(&mut self) -> Result<u16, QueryFailure> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, QueryFailure> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, QueryFailure> {
        self.array().map(u64::from_be_bytes)
    }

    const fn empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use positron_domain::identity::{PrincipalId, TenantId};

    use super::{CursorState, decode, encode};
    use crate::{LogicalPlan, QueryBudget, QueryFailureCode};

    #[test]
    fn authenticated_cursor_rejects_zero_plan_and_lease_invariants() {
        let key = [0xC1; 32];
        let mut state = valid_state();
        state.lease_identity = [0; 16];
        let cursor = encode(&key, 1, state).expect("authenticated cursor");
        assert!(matches!(
            decode(&key, 1, &cursor),
            Err(failure) if failure.code() == QueryFailureCode::InvalidCursor
        ));

        state = valid_state();
        state.plan = LogicalPlan::logs(0);
        let cursor = encode(&key, 1, state).expect("authenticated cursor");
        assert!(matches!(
            decode(&key, 1, &cursor),
            Err(failure) if failure.code() == QueryFailureCode::InvalidCursor
        ));
    }

    fn valid_state() -> CursorState {
        CursorState {
            principal: PrincipalId::from_bytes([1; 16]).expect("principal"),
            tenant: TenantId::from_bytes([2; 16]).expect("tenant"),
            authorization_generation: 1,
            catalog_identity: [3; 32],
            catalog_generation: 1,
            frontier: 0,
            plan: LogicalPlan::logs(1),
            offset: 0,
            sequence: 0,
            prior_digest: [0; 32],
            lease_identity: [4; 16],
            expiry: 60,
            budget: QueryBudget::new(1, 1, 1, 1, 1, 1).expect("budget"),
            scanned_bytes: 0,
            decoded_records: 0,
            output_rows: 0,
            output_bytes: 0,
        }
    }
}
