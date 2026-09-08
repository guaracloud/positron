use super::{
    CURRENT_PREFIX_BYTES, CURSOR_BYTES, MAX_PLAN_SOURCE_BYTES, PAYLOAD_BYTES, QueryCursor,
    V5_CURSOR_BYTES, V5_PAYLOAD_BYTES,
};
use crate::{QueryFailure, QueryFailureCode};
use positron_kernel::ControlTokenFailure;
#[cfg(fuzzing)]
use positron_kernel::ControlTokenProtector;

#[cfg(fuzzing)]
pub(crate) fn fuzz_reauthenticate(
    protector: &ControlTokenProtector<'_>,
    bytes: &mut [u8],
) -> Result<(), QueryFailure> {
    let payload_bytes = bytes
        .len()
        .checked_sub(32)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let payload = bytes
        .get(..payload_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let authentication = protector
        .authenticate_query_cursor(super::CURSOR_PURPOSE, payload)
        .map_err(map_protection_failure)?;
    bytes
        .get_mut(8..16)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?
        .copy_from_slice(&authentication.epoch().to_be_bytes());
    let payload = bytes
        .get(..payload_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let authentication = protector
        .authenticate_query_cursor(super::CURSOR_PURPOSE, payload)
        .map_err(map_protection_failure)?;
    bytes
        .get_mut(payload_bytes..)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?
        .copy_from_slice(&authentication.tag());
    Ok(())
}

pub(super) fn map_protection_failure(failure: ControlTokenFailure) -> QueryFailure {
    match failure {
        ControlTokenFailure::InvalidInput | ControlTokenFailure::LimitExceeded => {
            QueryFailure::new(QueryFailureCode::InvalidCursor)
        },
        ControlTokenFailure::Authentication | ControlTokenFailure::Custody => {
            QueryFailure::new(QueryFailureCode::Internal)
        },
    }
}

pub(crate) fn source_length(cursor: &QueryCursor) -> Result<u64, QueryFailure> {
    let payload_bytes = match cursor.as_bytes().len() {
        CURSOR_BYTES => PAYLOAD_BYTES,
        V5_CURSOR_BYTES => V5_PAYLOAD_BYTES,
        _ => return Ok(0),
    };
    if payload_bytes < CURRENT_PREFIX_BYTES + 12 {
        return Ok(0);
    }
    let payload = cursor
        .as_bytes()
        .get(..payload_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let language = payload
        .get(CURRENT_PREFIX_BYTES + 9)
        .copied()
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    if !matches!(language, 1 | 2) {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    let length = payload
        .get(CURRENT_PREFIX_BYTES + 10..CURRENT_PREFIX_BYTES + 12)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
    let length = usize::from(length);
    if length > MAX_PLAN_SOURCE_BYTES {
        return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
    }
    u64::try_from(length).map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], QueryFailure> {
        let (value, rest) = self
            .bytes
            .split_at_checked(N)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        self.bytes = rest;
        value
            .try_into()
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))
    }

    pub(super) fn bytes(&mut self, length: usize) -> Result<&'a [u8], QueryFailure> {
        let (value, rest) = self
            .bytes
            .split_at_checked(length)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        self.bytes = rest;
        Ok(value)
    }

    pub(super) fn u16(&mut self) -> Result<u16, QueryFailure> {
        self.array().map(u16::from_be_bytes)
    }

    pub(super) fn u64(&mut self) -> Result<u64, QueryFailure> {
        self.array().map(u64::from_be_bytes)
    }

    pub(super) fn i64(&mut self) -> Result<i64, QueryFailure> {
        self.array().map(i64::from_be_bytes)
    }

    pub(super) const fn empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use positron_domain::identity::{PrincipalId, TenantId};
    use positron_kernel::ControlTokenProtector;

    use super::{
        CURRENT_PREFIX_BYTES, CURSOR_BYTES, ControlTokenFailure, QueryCursor, QueryFailureCode,
        map_protection_failure, source_length,
    };
    use crate::cursor::{CursorState, encode};
    use crate::{
        LogicalPlan, QueryBudget, QueryCancellation, TemporalAxis, TemporalRange,
        query_service::QueryLanguage,
    };

    const CORRELATED_SOURCE: &[u8] =
        b"pipeline:v1 logs | range query_time -100 100 | correlate trace | limit 1";

    fn correlated_state(protector: &ControlTokenProtector<'_>) -> CursorState {
        let budget = QueryBudget::new(1_024, 16, 16, 1_024, 16_384, 60)
            .expect("test budget is valid")
            .with_cpu_work_units(1_024)
            .expect("test CPU budget is valid");
        let plan = LogicalPlan::logs(
            TemporalAxis::QueryTime,
            TemporalRange::new(-100, 100).expect("ordered test range"),
            1,
        )
        .with_log_to_trace_correlation();
        let plan_digest = plan
            .canonical_digest(protector)
            .expect("correlated test plan has a bounded digest");
        CursorState {
            principal: PrincipalId::from_bytes([1; 16]).expect("test principal"),
            tenant: TenantId::from_bytes([2; 16]).expect("test tenant"),
            authorization_generation: 7,
            catalog_identity: [3; 32],
            catalog_generation: 8,
            frontier: 1,
            plan: Arc::new(plan),
            source: Some(Arc::from(CORRELATED_SOURCE.to_vec().into_boxed_slice())),
            language: Some(QueryLanguage::Pipeline),
            plan_digest,
            resume_key: None,
            sequence: 0,
            prior_digest: [0; 32],
            lease_identity: [4; 16],
            trace_catalog_identity: Some([5; 32]),
            trace_catalog_generation: Some(9),
            trace_frontier: Some(2),
            trace_lease_identity: Some([6; 16]),
            expiry: 60,
            budget,
            scanned_bytes: 0,
            decoded_records: 0,
            physical_scanned_bytes: 0,
            physical_decoded_records: 0,
            output_rows: 0,
            output_bytes: 0,
            physical_output_rows: 0,
            physical_output_bytes: 0,
            memory_peak_bytes: 0,
            physical_memory_peak_bytes: 0,
            started_at: 0,
            last_observed_at: 0,
            cpu_work_units: 0,
            elapsed_wall_seconds: 0,
            physical_cpu_work_units: 0,
            physical_elapsed_wall_seconds: 0,
            reduced_pruning: false,
            resume_count: 0,
            repeated_batch_count: 0,
            cancellation: QueryCancellation::new(),
        }
    }

    #[test]
    fn protection_failures_keep_the_cursor_failure_boundary_closed() {
        assert_eq!(
            map_protection_failure(ControlTokenFailure::InvalidInput).code(),
            QueryFailureCode::InvalidCursor
        );
        assert_eq!(
            map_protection_failure(ControlTokenFailure::LimitExceeded).code(),
            QueryFailureCode::InvalidCursor
        );
        assert_eq!(
            map_protection_failure(ControlTokenFailure::Authentication).code(),
            QueryFailureCode::Internal
        );
        assert_eq!(
            map_protection_failure(ControlTokenFailure::Custody).code(),
            QueryFailureCode::Internal
        );
    }

    #[test]
    fn source_length_rejects_unknown_language_and_checked_overflow() {
        assert_eq!(
            source_length(&QueryCursor(vec![0; CURSOR_BYTES - 1]))
                .expect("legacy-sized input is handled before allocation"),
            0
        );

        let mut bytes = vec![0_u8; CURSOR_BYTES];
        bytes[CURRENT_PREFIX_BYTES + 9] = 3;
        assert_eq!(
            source_length(&QueryCursor(bytes.clone()))
                .expect_err("unknown language must fail closed")
                .code(),
            QueryFailureCode::InvalidCursor
        );

        bytes[CURRENT_PREFIX_BYTES + 9] = 1;
        bytes[CURRENT_PREFIX_BYTES + 10..CURRENT_PREFIX_BYTES + 12]
            .copy_from_slice(&4_097_u16.to_be_bytes());
        assert_eq!(
            source_length(&QueryCursor(bytes))
                .expect_err("source length above the checked cap must fail closed")
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }

    #[test]
    fn cursor_encoding_rejects_a_partial_paired_snapshot_binding() {
        let protector = positron_kernel::fuzz_control_token_protector();
        let mut state = correlated_state(&protector);
        state.trace_frontier = None;

        assert_eq!(
            encode(&protector, state)
                .expect_err("partial paired state cannot create an authenticated cursor")
                .code(),
            QueryFailureCode::InvalidCursor
        );
    }

    #[test]
    fn paired_cursor_source_length_counts_the_retained_utf8_source_before_admission() {
        let protector = positron_kernel::fuzz_control_token_protector();
        let cursor = encode(&protector, correlated_state(&protector))
            .expect("complete paired cursor state encodes");

        assert_eq!(
            source_length(&cursor).expect("complete paired cursor preserves its source length"),
            u64::try_from(CORRELATED_SOURCE.len()).expect("test source fits u64")
        );
    }
}
