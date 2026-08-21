use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{ControlTokenAuthentication, ControlTokenFailure, ControlTokenProtector};

use crate::{
    LogicalPlan, QueryBudget, QueryFailure, QueryFailureCode, TemporalAxis, TemporalRange,
};

const MAGIC: [u8; 8] = *b"POSQCR01";
const CURSOR_PURPOSE: &[u8] = b"query-cursor-v1";
const V1_PAYLOAD_BYTES: usize = 309;
const PAYLOAD_BYTES: usize = 341;
const V1_CURSOR_BYTES: usize = V1_PAYLOAD_BYTES + 32;
const CURSOR_BYTES: usize = PAYLOAD_BYTES + 32;

/// Opaque authenticated continuation with one fixed bounded representation.
#[derive(Clone, Eq, PartialEq)]
pub struct QueryCursor(Vec<u8>);

impl QueryCursor {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, QueryFailure> {
        if !matches!(bytes.len(), V1_CURSOR_BYTES | CURSOR_BYTES) {
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

#[derive(Clone)]
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
    pub(crate) started_at: u64,
    pub(crate) last_observed_at: u64,
    pub(crate) cpu_work_units: u64,
    pub(crate) elapsed_wall_seconds: u64,
    pub(crate) cancellation: crate::QueryCancellation,
}

pub(crate) fn encode(
    protector: &ControlTokenProtector<'_>,
    state: CursorState,
) -> Result<QueryCursor, QueryFailure> {
    let mut bytes = Vec::with_capacity(CURSOR_BYTES);
    bytes.extend_from_slice(&MAGIC);
    let epoch_offset = bytes.len();
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes.extend_from_slice(&state.principal.to_bytes());
    bytes.extend_from_slice(&state.tenant.to_bytes());
    bytes.extend_from_slice(&state.authorization_generation.to_be_bytes());
    bytes.extend_from_slice(&state.catalog_identity);
    bytes.extend_from_slice(&state.catalog_generation.to_be_bytes());
    bytes.extend_from_slice(&state.frontier.to_be_bytes());
    bytes.push(match state.plan.temporal_axis() {
        TemporalAxis::QueryTime => 1,
        TemporalAxis::EventTime => 2,
    });
    bytes.extend_from_slice(
        &state
            .plan
            .temporal_range()
            .start_nanoseconds()
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&state.plan.temporal_range().end_nanoseconds().to_be_bytes());
    bytes.extend_from_slice(&state.plan.limit().to_be_bytes());
    bytes.extend_from_slice(&plan_digest(protector, &state.plan)?);
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
        state.budget.cpu_work_units(),
        state.budget.wall_seconds(),
        state.budget.maximum_time_range_nanoseconds(),
        state.scanned_bytes,
        state.decoded_records,
        state.output_rows,
        state.output_bytes,
        state.started_at,
        state.last_observed_at,
        state.cpu_work_units,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    let authentication = protector
        .authenticate(CURSOR_PURPOSE, &bytes)
        .map_err(map_protection_failure)?;
    bytes
        .get_mut(epoch_offset..epoch_offset + 8)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?
        .copy_from_slice(&authentication.epoch().to_be_bytes());
    let authentication = protector
        .authenticate(CURSOR_PURPOSE, &bytes)
        .map_err(map_protection_failure)?;
    bytes.extend_from_slice(&authentication.tag());
    Ok(QueryCursor(bytes))
}

pub(crate) fn decode(
    protector: &ControlTokenProtector<'_>,
    cursor: &QueryCursor,
) -> Result<CursorState, QueryFailure> {
    let payload_bytes = cursor.as_bytes().len().saturating_sub(32);
    let (payload, authentication) = cursor
        .as_bytes()
        .split_at_checked(payload_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let epoch = payload
        .get(8..16)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let tag = authentication
        .try_into()
        .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let authentication = ControlTokenAuthentication::new(epoch, tag)
        .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    protector
        .verify(CURSOR_PURPOSE, payload, authentication)
        .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let mut reader = Reader::new(payload);
    if reader.array::<8>()? != MAGIC || reader.u64()? != epoch {
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
    let axis = match reader.array::<1>()?[0] {
        1 => TemporalAxis::QueryTime,
        2 => TemporalAxis::EventTime,
        _ => return Err(QueryFailure::new(QueryFailureCode::InvalidCursor)),
    };
    let range = TemporalRange::new(reader.i64()?, reader.i64()?)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let plan = LogicalPlan::logs(axis, range, reader.u16()?);
    if reader.array::<32>()? != plan_digest(protector, &plan)? {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    let offset = reader.u16()?;
    let sequence = reader.u64()?;
    let prior_digest = reader.array()?;
    let lease_identity = reader.array()?;
    let expiry = reader.u64()?;
    let scanned_budget = reader.u64()?;
    let decoded_budget = reader.u64()?;
    let output_rows_budget = reader.u64()?;
    let output_bytes_budget = reader.u64()?;
    let memory_budget = reader.u64()?;
    let (cpu_work_units, wall_budget) = if payload_bytes == V1_PAYLOAD_BYTES {
        (None, reader.u64()?)
    } else {
        (Some(reader.u64()?), reader.u64()?)
    };
    let budget = QueryBudget::new(
        scanned_budget,
        decoded_budget,
        output_rows_budget,
        output_bytes_budget,
        memory_budget,
        wall_budget,
    )
    .and_then(|budget| match cpu_work_units {
        Some(cpu) => budget.with_cpu_work_units(cpu),
        None => Ok(budget),
    })
    .and_then(|budget| budget.with_maximum_time_range_nanoseconds(reader.u64()?))
    .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let scanned_bytes = reader.u64()?;
    let decoded_records = reader.u64()?;
    let output_rows = reader.u64()?;
    let output_bytes = reader.u64()?;
    let (started_at, last_observed_at, actual_cpu_work_units) = if payload_bytes == V1_PAYLOAD_BYTES
    {
        let started = expiry.saturating_sub(budget.wall_seconds());
        (started, started, 0)
    } else {
        (reader.u64()?, reader.u64()?, reader.u64()?)
    };
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
        scanned_bytes,
        decoded_records,
        output_rows,
        output_bytes,
        started_at,
        last_observed_at,
        cpu_work_units: actual_cpu_work_units,
        elapsed_wall_seconds: last_observed_at.saturating_sub(started_at),
        cancellation: crate::QueryCancellation::new(),
    };
    if !reader.empty()
        || state.plan.limit() == 0
        || state.lease_identity.iter().all(|byte| *byte == 0)
    {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    Ok(state)
}

fn plan_digest(
    protector: &ControlTokenProtector<'_>,
    plan: &LogicalPlan,
) -> Result<[u8; 32], QueryFailure> {
    let mut encoding = Vec::with_capacity(19);
    encoding.push(match plan.temporal_axis() {
        TemporalAxis::QueryTime => 1,
        TemporalAxis::EventTime => 2,
    });
    encoding.extend_from_slice(&plan.temporal_range().start_nanoseconds().to_be_bytes());
    encoding.extend_from_slice(&plan.temporal_range().end_nanoseconds().to_be_bytes());
    encoding.extend_from_slice(&plan.limit().to_be_bytes());
    protector
        .digest(b"query-plan-v1", &encoding)
        .map_err(map_protection_failure)
}

fn map_protection_failure(failure: ControlTokenFailure) -> QueryFailure {
    match failure {
        ControlTokenFailure::InvalidInput | ControlTokenFailure::LimitExceeded => {
            QueryFailure::new(QueryFailureCode::InvalidCursor)
        },
        ControlTokenFailure::Authentication | ControlTokenFailure::Custody => {
            QueryFailure::new(QueryFailureCode::Internal)
        },
    }
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

    fn u64(&mut self) -> Result<u64, QueryFailure> {
        self.array().map(u64::from_be_bytes)
    }

    fn i64(&mut self) -> Result<i64, QueryFailure> {
        self.array().map(i64::from_be_bytes)
    }

    const fn empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
