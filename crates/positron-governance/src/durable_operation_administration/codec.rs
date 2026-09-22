//! Durable-operation persisted-record and audit codecs.

use positron_domain::identity::PrincipalId;

use super::{
    DurableOperation, DurableOperationBoundary, DurableOperationCancellation,
    DurableOperationFailure, DurableOperationKind, DurableOperationPhase, DurableOperationRequest,
    DurableOperationRetry, DurableOperationStatus, DurableOperationTerminalError,
};
use crate::AdministrativeIdempotencyKey;

const OPERATION_MAGIC: [u8; 8] = *b"POSOPR01";
const EXPIRED_OPERATION_BINDING_MAGIC: [u8; 8] = *b"POSOPX01";
const OPERATION_AUDIT_MAGIC: [u8; 8] = *b"POSOPA04";

pub(super) fn encode_operation(operation: DurableOperation) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(169);
    encoded.extend_from_slice(&OPERATION_MAGIC);
    encoded.extend_from_slice(&operation.operation_id().to_bytes());
    encoded.extend_from_slice(&operation.request.principal.to_bytes());
    encoded.extend_from_slice(&operation.request.idempotency.to_bytes());
    encoded.push(operation.request.kind.code());
    encoded.extend_from_slice(&operation.request.target_identity.unwrap_or([0; 16]));
    encoded.extend_from_slice(&operation.request.accepted_generation.to_be_bytes());
    encoded.extend_from_slice(&operation.request.accepted_at_unix_seconds.to_be_bytes());
    encoded.extend_from_slice(&operation.request.digest);
    encoded.push(operation.status.code());
    encoded.push(operation.phase.code());
    encoded.push(operation.progress_percent);
    encoded.push(operation.retry.code());
    encoded.push(operation.cancellation.code());
    encoded.push(operation.boundary.code());
    encoded.push(
        operation
            .terminal_error
            .map_or(0, DurableOperationTerminalError::code),
    );
    encoded.extend_from_slice(&operation.updated_at_unix_seconds.to_be_bytes());
    encoded.extend_from_slice(
        &operation
            .completed_at_unix_seconds
            .unwrap_or(0)
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&operation.revision.to_be_bytes());
    match operation.cancellation_idempotency {
        Some(idempotency) => {
            encoded.push(1);
            encoded.extend_from_slice(&idempotency.to_bytes());
        },
        None => {
            encoded.push(0);
            encoded.extend_from_slice(&[0; 16]);
        },
    }
    encoded
}

#[cfg(test)]
pub(crate) fn pending_operation_fixture(request: DurableOperationRequest) -> Vec<u8> {
    encode_operation(DurableOperation::accepted(request))
}

pub(super) fn encode_expired_binding(request: DurableOperationRequest) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(97);
    encoded.extend_from_slice(&EXPIRED_OPERATION_BINDING_MAGIC);
    encoded.extend_from_slice(&request.principal.to_bytes());
    encoded.extend_from_slice(&request.idempotency.to_bytes());
    encoded.push(request.kind.code());
    encoded.extend_from_slice(&request.target_identity.unwrap_or([0; 16]));
    encoded.extend_from_slice(&request.accepted_generation.to_be_bytes());
    encoded.extend_from_slice(&request.digest);
    encoded
}

pub(super) fn decode_expired_binding(
    encoded: &[u8],
) -> Result<Option<ExpiredOperationBinding>, DurableOperationFailure> {
    if !encoded.starts_with(&EXPIRED_OPERATION_BINDING_MAGIC) {
        return Ok(None);
    }
    if encoded.len() != 97 {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let mut offset = 8_usize;
    let principal = PrincipalId::from_bytes(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let idempotency = AdministrativeIdempotencyKey::new(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let kind = DurableOperationKind::from_code(take_byte(encoded, &mut offset)?)?;
    let target_identity = {
        let target = take_array::<16>(encoded, &mut offset)?;
        (!target.iter().all(|byte| *byte == 0)).then_some(target)
    };
    let accepted_generation = take_u64(encoded, &mut offset)?;
    let digest = take_array(encoded, &mut offset)?;
    if accepted_generation == 0 || digest.iter().all(|byte| *byte == 0) || offset != encoded.len() {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    Ok(Some(ExpiredOperationBinding {
        request: DurableOperationRequest {
            principal,
            idempotency,
            kind,
            target_identity,
            accepted_generation,
            accepted_at_unix_seconds: 1,
            digest,
        },
    }))
}

pub(super) fn decode_operation(
    encoded: &[u8],
) -> Result<Option<DurableOperation>, DurableOperationFailure> {
    if !encoded.starts_with(&OPERATION_MAGIC) {
        return Ok(None);
    }
    if encoded.len() != 169 {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let mut offset = 8_usize;
    let operation_id = take_array::<16>(encoded, &mut offset)?;
    let principal = PrincipalId::from_bytes(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let idempotency = AdministrativeIdempotencyKey::new(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let kind = DurableOperationKind::from_code(take_byte(encoded, &mut offset)?)?;
    let target = take_array(encoded, &mut offset)?;
    let target_identity = (!target.iter().all(|byte| *byte == 0)).then_some(target);
    let accepted_generation = take_u64(encoded, &mut offset)?;
    let accepted_at_unix_seconds = take_u64(encoded, &mut offset)?;
    let digest = take_array(encoded, &mut offset)?;
    let request = DurableOperationRequest {
        principal,
        idempotency,
        kind,
        target_identity,
        accepted_generation,
        accepted_at_unix_seconds,
        digest,
    };
    if request.operation_id().to_bytes() != operation_id
        || accepted_generation == 0
        || accepted_at_unix_seconds == 0
    {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let status = DurableOperationStatus::from_code(take_byte(encoded, &mut offset)?)?;
    let phase = DurableOperationPhase::from_code(take_byte(encoded, &mut offset)?)?;
    let progress_percent = take_byte(encoded, &mut offset)?;
    if progress_percent > 100 {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let retry = DurableOperationRetry::from_code(take_byte(encoded, &mut offset)?)?;
    let cancellation = DurableOperationCancellation::from_code(take_byte(encoded, &mut offset)?)?;
    let boundary = DurableOperationBoundary::from_code(take_byte(encoded, &mut offset)?)?;
    let terminal_error = match take_byte(encoded, &mut offset)? {
        0 => None,
        code => Some(DurableOperationTerminalError::from_code(code)?),
    };
    let updated_at_unix_seconds = take_u64(encoded, &mut offset)?;
    let completed = take_u64(encoded, &mut offset)?;
    let revision = take_u64(encoded, &mut offset)?;
    let cancellation_idempotency = match take_byte(encoded, &mut offset)? {
        0 => {
            if !take_array::<16>(encoded, &mut offset)?
                .iter()
                .all(|byte| *byte == 0)
            {
                return Err(DurableOperationFailure::PersistenceUnavailable);
            }
            None
        },
        1 => Some(
            AdministrativeIdempotencyKey::new(take_array(encoded, &mut offset)?)
                .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?,
        ),
        _ => return Err(DurableOperationFailure::PersistenceUnavailable),
    };
    if updated_at_unix_seconds < accepted_at_unix_seconds
        || revision == 0
        || offset != encoded.len()
    {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let completed_at_unix_seconds = if completed == 0 {
        None
    } else {
        Some(completed)
    };
    if status.is_terminal() != completed_at_unix_seconds.is_some()
        || (status == DurableOperationStatus::Failed && terminal_error.is_none())
        || (status != DurableOperationStatus::Failed && terminal_error.is_some())
        || (status == DurableOperationStatus::Cancelled) != cancellation_idempotency.is_some()
    {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    Ok(Some(DurableOperation {
        request,
        status,
        phase,
        progress_percent,
        retry,
        cancellation,
        boundary,
        terminal_error,
        cancellation_idempotency,
        updated_at_unix_seconds,
        completed_at_unix_seconds,
        revision,
    }))
}

pub(super) fn take_array<const N: usize>(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], DurableOperationFailure> {
    let end = offset
        .checked_add(N)
        .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
    let bytes = encoded
        .get(*offset..end)
        .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
    *offset = end;
    bytes
        .try_into()
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
}

pub(super) fn take_byte(encoded: &[u8], offset: &mut usize) -> Result<u8, DurableOperationFailure> {
    take_array::<1>(encoded, offset).map(|[value]| value)
}
pub(super) fn take_u64(encoded: &[u8], offset: &mut usize) -> Result<u64, DurableOperationFailure> {
    Ok(u64::from_be_bytes(take_array(encoded, offset)?))
}

pub(super) fn encode_audit(operation: DurableOperation) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(94);
    encoded.extend_from_slice(&OPERATION_AUDIT_MAGIC);
    encoded.extend_from_slice(&operation.operation_id().to_bytes());
    encoded.extend_from_slice(&operation.request.principal.to_bytes());
    encoded.extend_from_slice(&operation.request.target_identity.unwrap_or([0; 16]));
    encoded.push(0);
    encoded.push(operation.request.kind.code());
    encoded.push(operation.status.code());
    encoded.push(operation.phase.code());
    encoded.extend_from_slice(&operation.request.idempotency.to_bytes());
    encoded.extend_from_slice(&operation.request.accepted_generation.to_be_bytes());
    encoded.push(operation.progress_percent);
    encoded.extend_from_slice(&operation.revision.to_be_bytes());
    match operation.cancellation_idempotency {
        Some(idempotency) => {
            encoded.push(1);
            encoded.extend_from_slice(&idempotency.to_bytes());
        },
        None => {
            encoded.push(0);
            encoded.extend_from_slice(&[0; 16]);
        },
    }
    encoded
}

/// Exercises the bounded persisted-record decoder with hostile bytes.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_durable_operation_record(data: &[u8]) {
    let _ = decode_operation(data);
    let _ = decode_expired_binding(data);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExpiredOperationBinding {
    pub(super) request: DurableOperationRequest,
}

impl ExpiredOperationBinding {
    pub(super) fn exact_replay(
        self,
        request: DurableOperationRequest,
    ) -> Result<(), DurableOperationFailure> {
        self.request
            .has_same_semantics(request)
            .then_some(())
            .ok_or(DurableOperationFailure::IdempotencyConflict)
    }
}
