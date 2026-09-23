//! Kernel-owned encrypted, append-only payloads for bounded durable Query exports.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use positron_domain::identity::TenantId;
use rustix::fs::{self as unix_fs, Mode, OFlags};
use sha2::{Digest, Sha256};

use crate::{
    Catalog, CatalogFailure, CatalogFailureCode, CatalogObject, CatalogProposal, FormatEpoch,
    SnapshotLeaseId, TransactionId,
};

const DESCRIPTOR_MAGIC: [u8; 8] = *b"POSEXP04";
const LEGACY_DESCRIPTOR_MAGIC: [u8; 8] = *b"POSEXP03";
const PAYLOAD_MAGIC: [u8; 8] = *b"POEXBAT1";
const MANIFEST_MAGIC: [u8; 8] = *b"POEXMAN1";
const EXPORT_DIRECTORY: &str = "exports";
const PAYLOAD_NAME: &str = "payload";
const INITIAL_CURSOR_NAME: &str = "initial";
const MANIFEST_NAME: &str = "manifest";
const TERMINAL_EVIDENCE_NAME: &str = "terminal";
const MAX_EXPORT_BATCHES: u64 = 1_024;
const MAX_EXPORT_BATCH_BYTES: usize = 1_048_576;
// Query cursors have their own authenticated 8 KiB wire ceiling. A durable
// export checkpoint must retain the complete opaque cursor rather than impose
// a smaller second limit that makes a valid first page unresumable.
const MAX_CONTINUATION_CURSOR_BYTES: usize = crate::QUERY_CURSOR_MAX_PAYLOAD_BYTES;
/// Maximum protected Query-owned terminal manifest bytes (1,024 batch receipts).
pub const MAX_EXPORT_MANIFEST_BYTES: usize = 42_496;
const MAX_EXPORT_BYTES: u64 = 1_073_741_824;
const MAX_PROTECTED_RECORD_BYTES: usize =
    MAX_EXPORT_BATCH_BYTES + MAX_CONTINUATION_CURSOR_BYTES + 512;
const PAYLOAD_FIXED_BYTES: usize = 54;
const INITIAL_CURSOR_FIXED_BYTES: usize = 170;
const MANIFEST_FIXED_BYTES: usize = 12;
const MAX_PROTECTED_MANIFEST_BYTES: usize = MAX_EXPORT_MANIFEST_BYTES + 512;
/// Query owns this opaque terminal truth encoding.  Kernel bounds, protects,
/// and binds it to the committed final output record without interpreting it.
pub const MAX_EXPORT_TERMINAL_EVIDENCE_BYTES: usize = 256;
const TERMINAL_EVIDENCE_MAGIC: [u8; 8] = *b"POEXTER1";
const TERMINAL_EVIDENCE_FIXED_BYTES: usize = 12;
const MAX_PROTECTED_TERMINAL_EVIDENCE_BYTES: usize = MAX_EXPORT_TERMINAL_EVIDENCE_BYTES + 512;
const MAX_PROTECTED_INITIAL_CURSOR_BYTES: usize = MAX_CONTINUATION_CURSOR_BYTES + 512;
const INITIAL_CURSOR_MAGIC: [u8; 8] = *b"POEXINI2";
const EXPORT_OUTPUT_BINDING_BYTES: usize = 160;
const DESCRIPTOR_BYTES: usize = 296;
const LEGACY_DESCRIPTOR_BYTES: usize = 264;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportOutputFailureCode {
    InvalidBinding,
    Expired,
    LimitExceeded,
    ResourceAdmissionRefused,
    StorageUnavailable,
    IntegrityCorruption,
    AuthenticationFailed,
    IdempotencyConflict,
    ConcurrentWriter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportOutputFailure {
    code: ExportOutputFailureCode,
}
impl ExportOutputFailure {
    const fn new(code: ExportOutputFailureCode) -> Self {
        Self { code }
    }
    #[must_use]
    pub const fn code(self) -> ExportOutputFailureCode {
        self.code
    }
}
impl std::fmt::Display for ExportOutputFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("protected export output failed")
    }
}
impl std::error::Error for ExportOutputFailure {}

/// Stable, authenticated caller intent for one durable export operation.
///
/// The operation identity is accepted by governance before Query admits a
/// snapshot. It addresses the protected initial preparation independently of
/// later Catalog generations or clock readings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportOutputRequest {
    operation_id: [u8; 16],
    tenant: TenantId,
    destination: [u8; 16],
    request_digest: [u8; 32],
}

impl ExportOutputRequest {
    pub fn new(
        operation_id: [u8; 16],
        tenant: TenantId,
        destination: [u8; 16],
        request_digest: [u8; 32],
    ) -> Result<Self, ExportOutputFailure> {
        if operation_id.iter().all(|byte| *byte == 0)
            || destination.iter().all(|byte| *byte == 0)
            || request_digest.iter().all(|byte| *byte == 0)
        {
            return Err(fail(ExportOutputFailureCode::InvalidBinding));
        }
        Ok(Self {
            operation_id,
            tenant,
            destination,
            request_digest,
        })
    }
    #[must_use]
    pub const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }
    #[must_use]
    pub const fn tenant(self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn destination(self) -> [u8; 16] {
        self.destination
    }
    #[must_use]
    pub const fn request_digest(self) -> [u8; 32] {
        self.request_digest
    }
}

/// Immutable identity binding for one bounded durable export payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportOutputBinding {
    operation_id: [u8; 16],
    tenant: TenantId,
    destination: [u8; 16],
    request_digest: [u8; 32],
    snapshot_identity: [u8; 32],
    snapshot_generation: u64,
    snapshot_frontier: u64,
    lease: SnapshotLeaseId,
    lease_started_at: u64,
    lease_expiry_at: u64,
}
impl ExportOutputBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantId,
        destination: [u8; 16],
        request_digest: [u8; 32],
        snapshot_identity: [u8; 32],
        snapshot_generation: u64,
        snapshot_frontier: u64,
        lease: SnapshotLeaseId,
        lease_started_at: u64,
        lease_expiry_at: u64,
    ) -> Result<Self, ExportOutputFailure> {
        let request = ExportOutputRequest::new(
            legacy_operation_id(
                tenant,
                destination,
                request_digest,
                snapshot_identity,
                snapshot_generation,
                snapshot_frontier,
                lease,
                lease_started_at,
                lease_expiry_at,
            ),
            tenant,
            destination,
            request_digest,
        )?;
        Self::new_for_operation(
            request,
            snapshot_identity,
            snapshot_generation,
            snapshot_frontier,
            lease,
            lease_started_at,
            lease_expiry_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_operation(
        request: ExportOutputRequest,
        snapshot_identity: [u8; 32],
        snapshot_generation: u64,
        snapshot_frontier: u64,
        lease: SnapshotLeaseId,
        lease_started_at: u64,
        lease_expiry_at: u64,
    ) -> Result<Self, ExportOutputFailure> {
        if snapshot_identity.iter().all(|byte| *byte == 0)
            || snapshot_generation == 0
            || lease_expiry_at <= lease_started_at
            || lease_expiry_at
                .checked_sub(lease_started_at)
                .is_none_or(|ttl| ttl > crate::MAX_SNAPSHOT_LEASE_TTL_SECONDS)
        {
            return Err(ExportOutputFailure::new(
                ExportOutputFailureCode::InvalidBinding,
            ));
        }
        Ok(Self {
            operation_id: request.operation_id,
            tenant: request.tenant,
            destination: request.destination,
            request_digest: request.request_digest,
            snapshot_identity,
            snapshot_generation,
            snapshot_frontier,
            lease,
            lease_started_at,
            lease_expiry_at,
        })
    }
    #[must_use]
    pub const fn request(self) -> ExportOutputRequest {
        ExportOutputRequest {
            operation_id: self.operation_id,
            tenant: self.tenant,
            destination: self.destination,
            request_digest: self.request_digest,
        }
    }
    #[must_use]
    pub const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }
    #[must_use]
    pub const fn tenant(self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn destination(self) -> [u8; 16] {
        self.destination
    }
    #[must_use]
    pub const fn request_digest(self) -> [u8; 32] {
        self.request_digest
    }
    #[must_use]
    pub const fn snapshot_identity(self) -> [u8; 32] {
        self.snapshot_identity
    }
    #[must_use]
    pub const fn snapshot_generation(self) -> u64 {
        self.snapshot_generation
    }
    #[must_use]
    pub const fn snapshot_frontier(self) -> u64 {
        self.snapshot_frontier
    }
    #[must_use]
    pub const fn lease(self) -> SnapshotLeaseId {
        self.lease
    }
    #[must_use]
    pub const fn lease_started_at(self) -> u64 {
        self.lease_started_at
    }
    #[must_use]
    pub const fn lease_expiry_at(self) -> u64 {
        self.lease_expiry_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportBatchReceipt {
    sequence: u64,
    digest: [u8; 32],
}
impl ExportBatchReceipt {
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// The last encrypted payload checkpoint, including its opaque continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportOutputCheckpoint {
    receipt: ExportBatchReceipt,
    continuation_cursor: Option<Vec<u8>>,
}

/// A Kernel Resource Governor grant held from export-batch serialization
/// through durable append. Query acquires it before materializing canonical
/// bytes so serialization cannot bypass output admission.
#[must_use = "a pre-serialization export reservation must remain held through append"]
pub struct ExportOutputBatchReservation<'authority> {
    output_identity: [u8; 16],
    tenant: TenantId,
    payload_bytes: usize,
    _capacity: crate::ResourceReservation<'authority>,
}
impl ExportOutputCheckpoint {
    #[must_use]
    pub const fn receipt(&self) -> ExportBatchReceipt {
        self.receipt
    }
    #[must_use]
    pub fn continuation_cursor(&self) -> Option<Vec<u8>> {
        self.continuation_cursor.clone()
    }
}

/// Fixed Catalog progress plus a kernel-owned encrypted append-only payload file.
#[derive(Clone, Debug)]
pub struct ExportOutput {
    identity: [u8; 16],
    binding: ExportOutputBinding,
    next_sequence: u64,
    retained_bytes: u64,
    last_digest: [u8; 32],
    terminal_evidence_digest: [u8; 32],
    manifest_digest: [u8; 32],
}

impl ExportOutput {
    /// Recovers an initial preparation addressed by the accepted durable
    /// operation. The record is authenticated before its original snapshot
    /// binding can be returned, and an expired preparation remains terminal.
    pub fn recover_initial(
        catalog: &Catalog<'_>,
        request: ExportOutputRequest,
        observed_at: u64,
    ) -> Result<Option<Self>, ExportOutputFailure> {
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        let identity = output_identity_for_operation(request.operation_id);
        match Self::reopen_unlocked(catalog, identity) {
            Ok(output) => {
                if output.binding.request() != request {
                    return Err(fail(ExportOutputFailureCode::AuthenticationFailed));
                }
                output.require_live(observed_at)?;
                let prepared = read_initial_preparation(catalog, identity)?
                    .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
                if prepared.binding != output.binding {
                    return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
                }
                Ok(Some(output))
            },
            Err(error) if error.code() == ExportOutputFailureCode::StorageUnavailable => {
                let Some(prepared) = read_initial_preparation(catalog, identity)? else {
                    return Ok(None);
                };
                if prepared.binding.request() != request {
                    return Err(fail(ExportOutputFailureCode::AuthenticationFailed));
                }
                let output = Self {
                    identity,
                    binding: prepared.binding,
                    next_sequence: 0,
                    retained_bytes: 0,
                    last_digest: [0; 32],
                    terminal_evidence_digest: [0; 32],
                    manifest_digest: [0; 32],
                };
                output.require_live(observed_at)?;
                ensure_payload_file(catalog, identity, true)?;
                output.publish(catalog)?;
                Ok(Some(output))
            },
            Err(error) => Err(error),
        }
    }

    /// Finds the sole protected output for an authenticated export request.
    /// This recovery lookup exposes no payload and rejects ambiguous Catalog
    /// state before a restarted Query operation can attach to it.
    pub fn find_for_request(
        catalog: &Catalog<'_>,
        tenant: TenantId,
        destination: [u8; 16],
        request_digest: [u8; 32],
    ) -> Result<Option<Self>, ExportOutputFailure> {
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        let snapshot = catalog.pin().map_err(map_catalog_failure)?;
        let mut found = None;
        for object_identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(object_identity)
                .map_err(map_catalog_failure)?
                .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
            let Some(output) = decode_descriptor(bytes)? else {
                continue;
            };
            let binding = output.binding;
            if binding.tenant == tenant
                && binding.destination == destination
                && binding.request_digest == request_digest
                && found.replace(output).is_some()
            {
                return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
            }
        }
        if let Some(output) = found {
            let _capacity = output.reserve_scan(catalog)?;
            scan_records(catalog, &output, |_, _| Ok(()))?;
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }
    pub fn create(
        catalog: &Catalog<'_>,
        binding: ExportOutputBinding,
    ) -> Result<Self, ExportOutputFailure> {
        let identity = output_identity(binding);
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        match Self::reopen_unlocked(catalog, identity) {
            Ok(existing) if existing.binding == binding => Ok(existing),
            Ok(_) => Err(fail(ExportOutputFailureCode::IdempotencyConflict)),
            Err(error) if error.code() == ExportOutputFailureCode::StorageUnavailable => {
                let output = Self {
                    identity,
                    binding,
                    next_sequence: 0,
                    retained_bytes: 0,
                    last_digest: [0; 32],
                    terminal_evidence_digest: [0; 32],
                    manifest_digest: [0; 32],
                };
                ensure_payload_file(catalog, identity, true)?;
                output.publish(catalog)?;
                Ok(output)
            },
            Err(error) => Err(error),
        }
    }

    /// Creates an output only after its original authenticated Query cursor is
    /// protected. An exact retry can therefore restore the bound snapshot even
    /// if the descriptor publication was interrupted or later Catalog state
    /// has advanced.
    pub fn create_with_initial_cursor(
        catalog: &Catalog<'_>,
        binding: ExportOutputBinding,
        initial_cursor: &[u8],
    ) -> Result<Self, ExportOutputFailure> {
        if initial_cursor.is_empty() || initial_cursor.len() > MAX_CONTINUATION_CURSOR_BYTES {
            return Err(fail(ExportOutputFailureCode::LimitExceeded));
        }
        let identity = output_identity(binding);
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        match Self::reopen_unlocked(catalog, identity) {
            Ok(existing) if existing.binding == binding => {
                let stored = read_initial_preparation(catalog, identity)?
                    .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
                if stored.binding == binding && stored.cursor == initial_cursor {
                    Ok(existing)
                } else {
                    Err(fail(ExportOutputFailureCode::IdempotencyConflict))
                }
            },
            Ok(_) => Err(fail(ExportOutputFailureCode::IdempotencyConflict)),
            Err(error) if error.code() == ExportOutputFailureCode::StorageUnavailable => {
                let output = Self {
                    identity,
                    binding,
                    next_sequence: 0,
                    retained_bytes: 0,
                    last_digest: [0; 32],
                    terminal_evidence_digest: [0; 32],
                    manifest_digest: [0; 32],
                };
                match read_initial_preparation(catalog, identity)? {
                    Some(stored)
                        if stored.binding != binding || stored.cursor != initial_cursor =>
                    {
                        return Err(fail(ExportOutputFailureCode::IdempotencyConflict));
                    },
                    Some(_) => {},
                    None => write_initial_preparation(catalog, &output, initial_cursor)?,
                }
                ensure_payload_file(catalog, identity, true)?;
                output.publish(catalog)?;
                Ok(output)
            },
            Err(error) => Err(error),
        }
    }
    pub fn reopen(catalog: &Catalog<'_>, identity: [u8; 16]) -> Result<Self, ExportOutputFailure> {
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        Self::reopen_unlocked(catalog, identity)
    }
    fn reopen_unlocked(
        catalog: &Catalog<'_>,
        identity: [u8; 16],
    ) -> Result<Self, ExportOutputFailure> {
        if identity.iter().all(|byte| *byte == 0) {
            return Err(fail(ExportOutputFailureCode::InvalidBinding));
        }
        let snapshot = catalog.pin().map_err(map_catalog_failure)?;
        let mut found = None;
        for object_identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(object_identity)
                .map_err(map_catalog_failure)?
                .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
            if let Some(output) = decode_descriptor(bytes)?
                && output.identity == identity
                && found.replace(output).is_some()
            {
                return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
            }
        }
        let output = found.ok_or_else(|| fail(ExportOutputFailureCode::StorageUnavailable))?;
        let _capacity = output.reserve_scan(catalog)?;
        scan_records(catalog, &output, |_, _| Ok(()))?;
        Ok(output)
    }
    pub fn append_batch(
        &mut self,
        catalog: &Catalog<'_>,
        observed_at: u64,
        sequence: u64,
        digest: [u8; 32],
        bytes: &[u8],
        continuation_cursor: Option<&[u8]>,
    ) -> Result<ExportBatchReceipt, ExportOutputFailure> {
        self.require_live(observed_at)?;
        self.validate_batch(digest, bytes, continuation_cursor)?;
        let reservation = self.reserve_append(catalog, bytes.len())?;
        self.append_batch_reserved(
            catalog,
            observed_at,
            sequence,
            digest,
            bytes,
            continuation_cursor,
            reservation,
        )
    }

    /// Commits Query-owned terminal truth with the final Result Batch. The
    /// evidence is opaque to Kernel, but the descriptor only publishes it with
    /// the final batch it attests so crash recovery never has to infer a
    /// terminal outcome from an absent cursor.
    #[allow(clippy::too_many_arguments)]
    pub fn append_terminal_batch_reserved(
        &mut self,
        catalog: &Catalog<'_>,
        observed_at: u64,
        sequence: u64,
        digest: [u8; 32],
        bytes: &[u8],
        terminal_evidence: &[u8],
        reservation: ExportOutputBatchReservation<'_>,
    ) -> Result<ExportBatchReceipt, ExportOutputFailure> {
        self.require_live(observed_at)?;
        self.validate_batch(digest, bytes, None)?;
        validate_terminal_evidence(terminal_evidence)?;
        let required_payload_bytes = bytes
            .len()
            .checked_add(MAX_EXPORT_BATCH_BYTES)
            .and_then(|value| value.checked_add(MAX_PROTECTED_RECORD_BYTES))
            .and_then(|value| value.checked_add(MAX_PROTECTED_RECORD_BYTES))
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        if reservation.output_identity != self.identity
            || reservation.tenant != self.binding.tenant
            || reservation.payload_bytes < required_payload_bytes
        {
            return Err(fail(ExportOutputFailureCode::ResourceAdmissionRefused));
        }
        self.append_batch_with_reservation(
            catalog,
            sequence,
            digest,
            bytes,
            None,
            Some(terminal_evidence),
            reservation,
        )
    }

    /// Reserves the bounded worst-case batch working set before Query
    /// serializes a canonical Result Batch.
    pub fn reserve_next_batch<'authority>(
        &self,
        catalog: &'authority Catalog<'_>,
    ) -> Result<ExportOutputBatchReservation<'authority>, ExportOutputFailure> {
        if self.next_sequence >= MAX_EXPORT_BATCHES {
            return Err(fail(ExportOutputFailureCode::LimitExceeded));
        }
        let payload_bytes = MAX_EXPORT_BATCH_BYTES
            .checked_add(MAX_EXPORT_BATCH_BYTES)
            .and_then(|bytes| bytes.checked_add(MAX_PROTECTED_RECORD_BYTES))
            .and_then(|bytes| bytes.checked_add(MAX_PROTECTED_RECORD_BYTES))
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        let capacity = catalog
            .reserve_export_output(
                self.binding.tenant,
                payload_bytes,
                MAX_PROTECTED_RECORD_BYTES,
            )
            .map_err(map_catalog_failure)?;
        Ok(ExportOutputBatchReservation {
            output_identity: self.identity,
            tenant: self.binding.tenant,
            payload_bytes,
            _capacity: capacity,
        })
    }

    /// Appends a canonical batch beneath a reservation acquired before
    /// serialization. The grant is consumed on every terminal path.
    #[allow(clippy::too_many_arguments)]
    pub fn append_batch_reserved(
        &mut self,
        catalog: &Catalog<'_>,
        observed_at: u64,
        sequence: u64,
        digest: [u8; 32],
        bytes: &[u8],
        continuation_cursor: Option<&[u8]>,
        reservation: ExportOutputBatchReservation<'_>,
    ) -> Result<ExportBatchReceipt, ExportOutputFailure> {
        self.require_live(observed_at)?;
        self.validate_batch(digest, bytes, continuation_cursor)?;
        let required_payload_bytes = bytes
            .len()
            .checked_add(MAX_EXPORT_BATCH_BYTES)
            .and_then(|value| value.checked_add(MAX_PROTECTED_RECORD_BYTES))
            .and_then(|value| value.checked_add(MAX_PROTECTED_RECORD_BYTES))
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        if reservation.output_identity != self.identity
            || reservation.tenant != self.binding.tenant
            || reservation.payload_bytes < required_payload_bytes
        {
            return Err(fail(ExportOutputFailureCode::ResourceAdmissionRefused));
        }
        self.append_batch_with_reservation(
            catalog,
            sequence,
            digest,
            bytes,
            continuation_cursor,
            None,
            reservation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_batch_with_reservation(
        &mut self,
        catalog: &Catalog<'_>,
        sequence: u64,
        digest: [u8; 32],
        bytes: &[u8],
        continuation_cursor: Option<&[u8]>,
        terminal_evidence: Option<&[u8]>,
        _reservation: ExportOutputBatchReservation<'_>,
    ) -> Result<ExportBatchReceipt, ExportOutputFailure> {
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        if sequence < self.next_sequence {
            let mut existing = None;
            scan_records(catalog, self, |record_sequence, record| {
                if record_sequence == sequence {
                    existing = Some(record.clone());
                }
                Ok(())
            })?;
            let existing =
                existing.ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
            return if existing.digest == digest
                && existing.bytes == bytes
                && existing.continuation_cursor.as_deref() == continuation_cursor
                && self.matches_terminal_replay(catalog, terminal_evidence)?
            {
                Ok(ExportBatchReceipt { sequence, digest })
            } else {
                Err(fail(ExportOutputFailureCode::IdempotencyConflict))
            };
        }
        let tail = inspect_payload_tail(catalog, self)?;
        let count = self
            .next_sequence
            .checked_add(u64::from(tail.orphan.is_some()))
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        if sequence < count {
            let existing = tail
                .orphan
                .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
            return if existing.digest == digest
                && existing.bytes == bytes
                && existing.continuation_cursor.as_deref() == continuation_cursor
                && self.matches_terminal_orphan(catalog, terminal_evidence)?
            {
                if sequence == self.next_sequence {
                    let mut successor = self.clone();
                    successor.next_sequence = sequence
                        .checked_add(1)
                        .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
                    successor.retained_bytes = tail.length;
                    successor.last_digest = digest;
                    if let Some(evidence) = terminal_evidence {
                        successor.terminal_evidence_digest = digest_bytes(evidence);
                    }
                    successor.publish(catalog)?;
                    *self = successor;
                }
                Ok(ExportBatchReceipt { sequence, digest })
            } else {
                Err(fail(ExportOutputFailureCode::IdempotencyConflict))
            };
        }
        if sequence != count || sequence >= MAX_EXPORT_BATCHES {
            return Err(fail(ExportOutputFailureCode::IdempotencyConflict));
        }
        if terminal_evidence.is_some()
            && (continuation_cursor.is_some() || self.terminal_evidence_digest != [0; 32])
        {
            return Err(fail(ExportOutputFailureCode::InvalidBinding));
        }
        let terminal_digest = terminal_evidence.map(digest_bytes);
        if let Some(evidence) = terminal_evidence {
            create_terminal_evidence_file(catalog, self.binding.tenant, self.identity, evidence)?;
        }
        let plaintext = encode_payload(sequence, digest, bytes, continuation_cursor)?;
        let protected = catalog
            .protect_export_output(
                payload_identity(self.identity, sequence),
                FormatEpoch::CATALOG_V2,
                &plaintext,
            )
            .map_err(map_catalog_failure)?;
        if protected.len() > MAX_PROTECTED_RECORD_BYTES {
            return Err(fail(ExportOutputFailureCode::LimitExceeded));
        }
        let durable_bytes = protected
            .len()
            .checked_add(4)
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        let next_bytes = tail
            .length
            .checked_add(
                u64::try_from(durable_bytes)
                    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?,
            )
            .filter(|total| *total <= MAX_EXPORT_BYTES)
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        let mut payload = ensure_payload_file(catalog, self.identity, false)?;
        payload.seek(SeekFrom::End(0)).map_err(map_io_failure)?;
        payload
            .write_all(
                &u32::try_from(protected.len())
                    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?
                    .to_be_bytes(),
            )
            .map_err(map_io_failure)?;
        payload.write_all(&protected).map_err(map_io_failure)?;
        payload.sync_all().map_err(map_io_failure)?;
        let mut successor = self.clone();
        successor.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        successor.retained_bytes = next_bytes;
        successor.last_digest = digest;
        if let Some(terminal_digest) = terminal_digest {
            successor.terminal_evidence_digest = terminal_digest;
        }
        successor.publish(catalog)?;
        *self = successor;
        Ok(ExportBatchReceipt { sequence, digest })
    }

    fn matches_terminal_replay(
        &self,
        catalog: &Catalog<'_>,
        terminal_evidence: Option<&[u8]>,
    ) -> Result<bool, ExportOutputFailure> {
        match terminal_evidence {
            None => Ok(self.terminal_evidence_digest == [0; 32]),
            Some(evidence) => {
                if self.terminal_evidence_digest != digest_bytes(evidence) {
                    return Ok(false);
                }
                Ok(read_terminal_evidence_unlocked(catalog, self)? == evidence)
            },
        }
    }

    fn matches_terminal_orphan(
        &self,
        catalog: &Catalog<'_>,
        terminal_evidence: Option<&[u8]>,
    ) -> Result<bool, ExportOutputFailure> {
        if self.terminal_evidence_digest != [0; 32] {
            return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
        }
        match terminal_evidence {
            Some(evidence) => Ok(read_unpublished_terminal_evidence(catalog, self.identity)?
                .as_deref()
                == Some(evidence)),
            None => Ok(read_unpublished_terminal_evidence(catalog, self.identity)?.is_none()),
        }
    }

    /// Commits Query-owned terminal truth for an export that produced no
    /// Result Batches. Its descriptor publication is the same authoritative
    /// crash-recovery boundary as a terminal batch publication.
    pub fn write_terminal_evidence(
        &mut self,
        catalog: &Catalog<'_>,
        observed_at: u64,
        terminal_evidence: &[u8],
    ) -> Result<(), ExportOutputFailure> {
        self.require_live(observed_at)?;
        validate_terminal_evidence(terminal_evidence)?;
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        let digest = digest_bytes(terminal_evidence);
        if self.terminal_evidence_digest != [0; 32] {
            return if self.terminal_evidence_digest == digest
                && read_terminal_evidence_unlocked(catalog, self)? == terminal_evidence
            {
                Ok(())
            } else {
                Err(fail(ExportOutputFailureCode::IdempotencyConflict))
            };
        }
        create_terminal_evidence_file(
            catalog,
            self.binding.tenant,
            self.identity,
            terminal_evidence,
        )?;
        let mut successor = self.clone();
        successor.terminal_evidence_digest = digest;
        successor.publish(catalog)?;
        *self = successor;
        Ok(())
    }

    /// Promotes an authenticated terminal payload that reached stable storage
    /// before its descriptor publication was interrupted. The Kernel verifies
    /// the protected terminal artifact and final payload together, then makes
    /// the original terminal truth descriptor-visible without asking Query to
    /// reconstruct or re-execute it.
    pub fn recover_terminal_orphan(
        &mut self,
        catalog: &Catalog<'_>,
        observed_at: u64,
    ) -> Result<Option<Vec<u8>>, ExportOutputFailure> {
        self.require_live(observed_at)?;
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        if self.terminal_evidence_digest != [0; 32] {
            return Ok(Some(read_terminal_evidence_unlocked(catalog, self)?));
        }
        let tail = inspect_payload_tail(catalog, self)?;
        let evidence = read_unpublished_terminal_evidence(catalog, self.identity)?;
        if tail.orphan.is_none()
            && tail.length == 0
            && self.next_sequence == 0
            && let Some(evidence) = evidence
        {
            let mut successor = self.clone();
            successor.terminal_evidence_digest = digest_bytes(&evidence);
            successor.publish(catalog)?;
            *self = successor;
            return Ok(Some(evidence));
        }
        let Some(orphan) = tail.orphan else {
            return Ok(None);
        };
        if orphan.continuation_cursor.is_some() {
            return Ok(None);
        }
        let Some(evidence) = evidence else {
            return Ok(None);
        };
        let mut successor = self.clone();
        successor.next_sequence = successor
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        successor.retained_bytes = tail.length;
        successor.last_digest = orphan.digest;
        successor.terminal_evidence_digest = digest_bytes(&evidence);
        successor.publish(catalog)?;
        *self = successor;
        Ok(Some(evidence))
    }

    /// Atomically makes one bounded Query-owned terminal manifest durable.
    ///
    /// The manifest bytes are encrypted under this output identity. An exact
    /// replay after an ambiguous write succeeds; a differing replay fails.
    pub fn write_manifest(
        &mut self,
        catalog: &Catalog<'_>,
        observed_at: u64,
        bytes: &[u8],
    ) -> Result<(), ExportOutputFailure> {
        self.require_live(observed_at)?;
        if bytes.is_empty() || bytes.len() > MAX_EXPORT_MANIFEST_BYTES {
            return Err(fail(ExportOutputFailureCode::LimitExceeded));
        }
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        let digest = digest_bytes(bytes);
        if self.manifest_digest != [0; 32] {
            let existing = read_manifest_unlocked(catalog, self)?;
            return if self.manifest_digest == digest && existing == bytes {
                Ok(())
            } else {
                Err(fail(ExportOutputFailureCode::IdempotencyConflict))
            };
        }
        if let Some(existing) = read_unpublished_manifest(catalog, self.identity)? {
            if existing != bytes {
                return Err(fail(ExportOutputFailureCode::IdempotencyConflict));
            }
        } else {
            let plaintext = encode_manifest(bytes)?;
            let protected = catalog
                .protect_export_output(
                    manifest_identity(self.identity),
                    FormatEpoch::CATALOG_V2,
                    &plaintext,
                )
                .map_err(map_catalog_failure)?;
            if protected.len() > MAX_PROTECTED_MANIFEST_BYTES {
                return Err(fail(ExportOutputFailureCode::LimitExceeded));
            }
            let _capacity = catalog
                .reserve_export_output(self.binding.tenant, bytes.len(), protected.len())
                .map_err(map_catalog_failure)?;
            create_manifest_file(catalog, self.identity, &protected)?;
        }
        let mut successor = self.clone();
        successor.manifest_digest = digest;
        successor.publish(catalog)?;
        *self = successor;
        Ok(())
    }
    /// Reads the authenticated durable terminal manifest, when publication completed.
    pub fn read_manifest(
        &self,
        catalog: &Catalog<'_>,
        observed_at: u64,
    ) -> Result<Option<Vec<u8>>, ExportOutputFailure> {
        self.require_live(observed_at)?;
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        if self.manifest_digest == [0; 32] {
            return Ok(None);
        }
        Ok(Some(read_manifest_unlocked(catalog, self)?))
    }

    /// Returns terminal truth only after the descriptor that binds its digest
    /// has been durably published. An orphaned evidence file is never a result.
    pub fn read_terminal_evidence(
        &self,
        catalog: &Catalog<'_>,
        observed_at: u64,
    ) -> Result<Option<Vec<u8>>, ExportOutputFailure> {
        self.require_live(observed_at)?;
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        if self.terminal_evidence_digest == [0; 32] {
            return Ok(None);
        }
        Ok(Some(read_terminal_evidence_unlocked(catalog, self)?))
    }

    /// Reads the authenticated original Query cursor retained before this
    /// output descriptor became visible.
    pub fn initial_cursor(
        &self,
        catalog: &Catalog<'_>,
        observed_at: u64,
    ) -> Result<Option<Vec<u8>>, ExportOutputFailure> {
        self.require_live(observed_at)?;
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        let prepared = read_initial_preparation(catalog, self.identity)?;
        match prepared {
            Some(prepared) if prepared.binding == self.binding => Ok(Some(prepared.cursor)),
            Some(_) => Err(fail(ExportOutputFailureCode::IntegrityCorruption)),
            None => Ok(None),
        }
    }
    pub fn read_batch(
        &self,
        catalog: &Catalog<'_>,
        observed_at: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, ExportOutputFailure> {
        self.require_live(observed_at)?;
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        if sequence >= self.next_sequence {
            return Err(fail(ExportOutputFailureCode::StorageUnavailable));
        }
        let _capacity = self.reserve_scan(catalog)?;
        let mut selected = None;
        scan_records(catalog, self, |record_sequence, record| {
            if record_sequence == sequence {
                selected = Some(record.bytes.clone());
            }
            Ok(())
        })?;
        selected.ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))
    }
    pub fn latest_checkpoint(
        &self,
        catalog: &Catalog<'_>,
        observed_at: u64,
    ) -> Result<Option<ExportOutputCheckpoint>, ExportOutputFailure> {
        self.require_live(observed_at)?;
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        let _capacity = self.reserve_scan(catalog)?;
        let scan = scan_records(catalog, self, |_, _| Ok(()))?;
        let Some(record) = scan.committed else {
            return Ok(None);
        };
        let sequence = self
            .next_sequence
            .checked_sub(1)
            .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
        Ok(Some(ExportOutputCheckpoint {
            receipt: ExportBatchReceipt {
                sequence,
                digest: record.digest,
            },
            continuation_cursor: record.continuation_cursor,
        }))
    }
    /// Returns the bounded, ordered receipts needed to rebuild a durable
    /// Query manifest after process restart. Payload bytes remain protected
    /// and are deliberately not exposed by this checkpoint view.
    pub fn batch_receipts(
        &self,
        catalog: &Catalog<'_>,
        observed_at: u64,
    ) -> Result<Vec<ExportBatchReceipt>, ExportOutputFailure> {
        self.require_live(observed_at)?;
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(
                usize::try_from(self.next_sequence)
                    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?,
            )
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
        let _capacity = self.reserve_scan(catalog)?;
        scan_records(catalog, self, |sequence, record| {
            if sequence < self.next_sequence {
                receipts.push(ExportBatchReceipt {
                    sequence,
                    digest: record.digest,
                });
            }
            Ok(())
        })?;
        Ok(receipts)
    }
    #[must_use]
    pub const fn identity(&self) -> [u8; 16] {
        self.identity
    }
    #[must_use]
    pub const fn binding(&self) -> ExportOutputBinding {
        self.binding
    }
    #[must_use]
    pub const fn batch_count(&self) -> u64 {
        self.next_sequence
    }
    #[must_use]
    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }
    #[must_use]
    pub const fn latest_receipt(&self) -> Option<ExportBatchReceipt> {
        if self.next_sequence == 0 {
            None
        } else {
            Some(ExportBatchReceipt {
                sequence: self.next_sequence - 1,
                digest: self.last_digest,
            })
        }
    }
    fn require_live(&self, observed_at: u64) -> Result<(), ExportOutputFailure> {
        if observed_at < self.binding.lease_started_at || observed_at > self.binding.lease_expiry_at
        {
            Err(fail(ExportOutputFailureCode::Expired))
        } else {
            Ok(())
        }
    }

    fn validate_batch(
        &self,
        digest: [u8; 32],
        bytes: &[u8],
        continuation_cursor: Option<&[u8]>,
    ) -> Result<(), ExportOutputFailure> {
        if bytes.is_empty()
            || bytes.len() > MAX_EXPORT_BATCH_BYTES
            || digest == [0; 32]
            || continuation_cursor
                .is_some_and(|cursor| cursor.len() > MAX_CONTINUATION_CURSOR_BYTES)
        {
            Err(fail(ExportOutputFailureCode::LimitExceeded))
        } else {
            Ok(())
        }
    }

    fn reserve_append<'authority>(
        &self,
        catalog: &'authority Catalog<'_>,
        canonical_bytes: usize,
    ) -> Result<ExportOutputBatchReservation<'authority>, ExportOutputFailure> {
        let payload_bytes = canonical_bytes
            .checked_add(MAX_EXPORT_BATCH_BYTES)
            .and_then(|bytes| bytes.checked_add(MAX_PROTECTED_RECORD_BYTES))
            .and_then(|bytes| bytes.checked_add(MAX_PROTECTED_RECORD_BYTES))
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        let capacity = catalog
            .reserve_export_output(
                self.binding.tenant,
                payload_bytes,
                MAX_PROTECTED_RECORD_BYTES,
            )
            .map_err(map_catalog_failure)?;
        Ok(ExportOutputBatchReservation {
            output_identity: self.identity,
            tenant: self.binding.tenant,
            payload_bytes,
            _capacity: capacity,
        })
    }

    fn reserve_scan<'authority>(
        &self,
        catalog: &'authority Catalog<'_>,
    ) -> Result<ExportOutputBatchReservation<'authority>, ExportOutputFailure> {
        let payload_bytes = MAX_EXPORT_BATCH_BYTES
            .checked_add(MAX_PROTECTED_RECORD_BYTES)
            .and_then(|bytes| bytes.checked_add(MAX_PROTECTED_RECORD_BYTES))
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        let capacity = catalog
            .reserve_export_output(self.binding.tenant, payload_bytes, 0)
            .map_err(map_catalog_failure)?;
        Ok(ExportOutputBatchReservation {
            output_identity: self.identity,
            tenant: self.binding.tenant,
            payload_bytes,
            _capacity: capacity,
        })
    }

    fn publish(&self, catalog: &Catalog<'_>) -> Result<(), ExportOutputFailure> {
        let snapshot = catalog.pin().map_err(map_catalog_failure)?;
        let mut objects = Vec::new();
        for object_identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(object_identity)
                .map_err(map_catalog_failure)?
                .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
            if decode_descriptor(bytes)?.is_some_and(|existing| existing.identity == self.identity)
            {
                continue;
            }
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?);
        }
        objects.push(CatalogObject::new(encode_descriptor(self)?).map_err(map_catalog_failure)?);
        let transaction =
            TransactionId::new(transaction_identity(self, snapshot.identity().to_bytes()))
                .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
        let format_epoch = snapshot
            .format_epoch()
            .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
        let proposal = CatalogProposal::new(transaction, format_epoch, objects)
            .map_err(map_catalog_failure)?;
        catalog
            .commit(snapshot.identity(), proposal, None)
            .map_err(map_catalog_failure)?;
        Ok(())
    }
}

#[derive(Clone)]
struct PayloadRecord {
    digest: [u8; 32],
    bytes: Vec<u8>,
    continuation_cursor: Option<Vec<u8>>,
    durable_bytes: u64,
}
#[derive(Clone)]
struct PayloadRecordMetadata {
    digest: [u8; 32],
    continuation_cursor: Option<Vec<u8>>,
}

struct PayloadScan {
    committed: Option<PayloadRecordMetadata>,
}

struct PayloadTail {
    length: u64,
    orphan: Option<PayloadRecord>,
}

fn inspect_payload_tail(
    catalog: &Catalog<'_>,
    output: &ExportOutput,
) -> Result<PayloadTail, ExportOutputFailure> {
    let mut file = ensure_payload_file(catalog, output.identity, false)?;
    let length = file.metadata().map_err(map_io_failure)?.len();
    if length > MAX_EXPORT_BYTES || length < output.retained_bytes {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    if length == output.retained_bytes {
        return Ok(PayloadTail {
            length,
            orphan: None,
        });
    }
    let remaining = length
        .checked_sub(output.retained_bytes)
        .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
    if remaining <= 4 {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    file.seek(SeekFrom::Start(output.retained_bytes))
        .map_err(map_io_failure)?;
    let mut prefix = [0; 4];
    file.read_exact(&mut prefix)
        .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?;
    let encoded_length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    if encoded_length == 0 || encoded_length > MAX_PROTECTED_RECORD_BYTES {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let expected = u64::try_from(encoded_length)
        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?
        .checked_add(4)
        .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
    if expected != remaining {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let mut encrypted = vec![0; encoded_length];
    file.read_exact(&mut encrypted)
        .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?;
    let plaintext = catalog
        .open_export_output(
            payload_identity(output.identity, output.next_sequence),
            FormatEpoch::CATALOG_V2,
            &encrypted,
        )
        .map_err(map_catalog_failure)?;
    let mut orphan = decode_payload(output.next_sequence, &plaintext)?;
    orphan.durable_bytes = expected;
    Ok(PayloadTail {
        length,
        orphan: Some(orphan),
    })
}

fn scan_records(
    catalog: &Catalog<'_>,
    output: &ExportOutput,
    mut inspect: impl FnMut(u64, &PayloadRecord) -> Result<(), ExportOutputFailure>,
) -> Result<PayloadScan, ExportOutputFailure> {
    let mut file = ensure_payload_file(catalog, output.identity, false)?;
    let length = file.metadata().map_err(map_io_failure)?.len();
    if length > MAX_EXPORT_BYTES {
        return Err(fail(ExportOutputFailureCode::LimitExceeded));
    }
    file.seek(SeekFrom::Start(0)).map_err(map_io_failure)?;
    let mut count = 0_u64;
    let mut consumed = 0_u64;
    let mut committed = None;
    while consumed < length {
        if count >= MAX_EXPORT_BATCHES {
            return Err(fail(ExportOutputFailureCode::LimitExceeded));
        }
        let mut prefix = [0; 4];
        file.read_exact(&mut prefix)
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?;
        let encoded_length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
        if encoded_length == 0 || encoded_length > MAX_PROTECTED_RECORD_BYTES {
            return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
        }
        consumed = consumed
            .checked_add(
                u64::try_from(encoded_length)
                    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?
                    .checked_add(4)
                    .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?,
            )
            .filter(|total| *total <= length)
            .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
        let mut encrypted = vec![0; encoded_length];
        file.read_exact(&mut encrypted)
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?;
        let sequence = count;
        let plaintext = catalog
            .open_export_output(
                payload_identity(output.identity, sequence),
                FormatEpoch::CATALOG_V2,
                &encrypted,
            )
            .map_err(map_catalog_failure)?;
        let mut record = decode_payload(sequence, &plaintext)?;
        record.durable_bytes = u64::try_from(encoded_length)
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?
            .checked_add(4)
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        if sequence == output.next_sequence.checked_sub(1).unwrap_or(u64::MAX) {
            committed = Some(PayloadRecordMetadata {
                digest: record.digest,
                continuation_cursor: record.continuation_cursor.clone(),
            });
        }
        inspect(sequence, &record)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
    }
    if consumed != length
        || count < output.next_sequence
        || count > output.next_sequence.saturating_add(1)
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    if count == output.next_sequence && consumed != output.retained_bytes {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    if output.next_sequence > 0
        && committed.as_ref().map(|record| record.digest) != Some(output.last_digest)
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    Ok(PayloadScan { committed })
}
fn ensure_payload_file(
    catalog: &Catalog<'_>,
    identity: [u8; 16],
    create: bool,
) -> Result<File, ExportOutputFailure> {
    let root = catalog.export_output_root().map_err(map_catalog_failure)?;
    let exports = open_directory(&root, EXPORT_DIRECTORY, create)?;
    let output = open_directory(&exports, &hex(identity), create)?;
    let flags = if create {
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC
    } else {
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC
    };
    let file = unix_fs::openat(&output, PAYLOAD_NAME, flags, Mode::RUSR | Mode::WUSR)
        .map(File::from)
        .map_err(map_errno)?;
    let metadata = file.metadata().map_err(map_io_failure)?;
    if !metadata.file_type().is_file() {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
        }
    }
    if create {
        file.sync_all().map_err(map_io_failure)?;
        exports.sync_all().map_err(map_io_failure)?;
        output.sync_all().map_err(map_io_failure)?;
        root.sync_all().map_err(map_io_failure)?;
    }
    Ok(file)
}
fn create_manifest_file(
    catalog: &Catalog<'_>,
    identity: [u8; 16],
    protected: &[u8],
) -> Result<(), ExportOutputFailure> {
    let root = catalog.export_output_root().map_err(map_catalog_failure)?;
    let exports = open_directory(&root, EXPORT_DIRECTORY, true)?;
    let output = open_directory(&exports, &hex(identity), true)?;
    let mut file = unix_fs::openat(
        &output,
        MANIFEST_NAME,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(map_errno)?;
    file.write_all(protected).map_err(map_io_failure)?;
    file.sync_all().map_err(map_io_failure)?;
    output.sync_all().map_err(map_io_failure)?;
    exports.sync_all().map_err(map_io_failure)?;
    root.sync_all().map_err(map_io_failure)?;
    Ok(())
}

fn write_initial_preparation(
    catalog: &Catalog<'_>,
    output: &ExportOutput,
    cursor: &[u8],
) -> Result<(), ExportOutputFailure> {
    let plaintext = encode_initial_preparation(output.binding, cursor)?;
    let protected = catalog
        .protect_export_output(
            initial_cursor_identity(output.identity),
            FormatEpoch::CATALOG_V2,
            &plaintext,
        )
        .map_err(map_catalog_failure)?;
    if protected.len() > MAX_PROTECTED_INITIAL_CURSOR_BYTES {
        return Err(fail(ExportOutputFailureCode::LimitExceeded));
    }
    let _capacity = catalog
        .reserve_export_output(output.binding.tenant, cursor.len(), protected.len())
        .map_err(map_catalog_failure)?;
    create_named_protected_file(catalog, output.identity, INITIAL_CURSOR_NAME, &protected)
}

fn create_named_protected_file(
    catalog: &Catalog<'_>,
    identity: [u8; 16],
    name: &str,
    protected: &[u8],
) -> Result<(), ExportOutputFailure> {
    let root = catalog.export_output_root().map_err(map_catalog_failure)?;
    let exports = open_directory(&root, EXPORT_DIRECTORY, true)?;
    let output = open_directory(&exports, &hex(identity), true)?;
    let mut file = unix_fs::openat(
        &output,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(map_errno)?;
    file.write_all(protected).map_err(map_io_failure)?;
    file.sync_all().map_err(map_io_failure)?;
    output.sync_all().map_err(map_io_failure)?;
    exports.sync_all().map_err(map_io_failure)?;
    root.sync_all().map_err(map_io_failure)?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InitialPreparation {
    binding: ExportOutputBinding,
    cursor: Vec<u8>,
}

fn read_initial_preparation(
    catalog: &Catalog<'_>,
    identity: [u8; 16],
) -> Result<Option<InitialPreparation>, ExportOutputFailure> {
    let Some(protected) = read_named_protected_file(
        catalog,
        identity,
        INITIAL_CURSOR_NAME,
        MAX_PROTECTED_INITIAL_CURSOR_BYTES,
    )?
    else {
        return Ok(None);
    };
    let plaintext = catalog
        .open_export_output(
            initial_cursor_identity(identity),
            FormatEpoch::CATALOG_V2,
            &protected,
        )
        .map_err(map_catalog_failure)?;
    Ok(Some(decode_initial_preparation(&plaintext)?))
}

fn read_named_protected_file(
    catalog: &Catalog<'_>,
    identity: [u8; 16],
    name: &str,
    maximum_bytes: usize,
) -> Result<Option<Vec<u8>>, ExportOutputFailure> {
    let root = catalog.export_output_root().map_err(map_catalog_failure)?;
    let exports = match open_directory(&root, EXPORT_DIRECTORY, false) {
        Ok(directory) => directory,
        Err(error) if error.code() == ExportOutputFailureCode::StorageUnavailable => {
            return Ok(None);
        },
        Err(error) => return Err(error),
    };
    let output = match open_directory(&exports, &hex(identity), false) {
        Ok(directory) => directory,
        Err(error) if error.code() == ExportOutputFailureCode::StorageUnavailable => {
            return Ok(None);
        },
        Err(error) => return Err(error),
    };
    let file = match unix_fs::openat(
        &output,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(map_errno(error)),
    };
    let metadata = file.metadata().map_err(map_io_failure)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_bytes as u64
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
        }
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    let mut protected = vec![0; length];
    let mut reader = file;
    reader.read_exact(&mut protected).map_err(map_io_failure)?;
    Ok(Some(protected))
}

fn read_unpublished_manifest(
    catalog: &Catalog<'_>,
    identity: [u8; 16],
) -> Result<Option<Vec<u8>>, ExportOutputFailure> {
    let root = catalog.export_output_root().map_err(map_catalog_failure)?;
    let exports = match open_directory(&root, EXPORT_DIRECTORY, false) {
        Ok(directory) => directory,
        Err(error) if error.code() == ExportOutputFailureCode::StorageUnavailable => {
            return Ok(None);
        },
        Err(error) => return Err(error),
    };
    let output = match open_directory(&exports, &hex(identity), false) {
        Ok(directory) => directory,
        Err(error) if error.code() == ExportOutputFailureCode::StorageUnavailable => {
            return Ok(None);
        },
        Err(error) => return Err(error),
    };
    let file = match unix_fs::openat(
        &output,
        MANIFEST_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(map_errno(error)),
    };
    let metadata = file.metadata().map_err(map_io_failure)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_PROTECTED_MANIFEST_BYTES as u64
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
        }
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    let mut protected = vec![0; length];
    let mut reader = file;
    reader.read_exact(&mut protected).map_err(map_io_failure)?;
    let plaintext = catalog
        .open_export_output(
            manifest_identity(identity),
            FormatEpoch::CATALOG_V2,
            &protected,
        )
        .map_err(map_catalog_failure)?;
    Ok(Some(decode_manifest(&plaintext)?))
}
fn read_manifest_unlocked(
    catalog: &Catalog<'_>,
    output: &ExportOutput,
) -> Result<Vec<u8>, ExportOutputFailure> {
    let manifest = read_unpublished_manifest(catalog, output.identity)?
        .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
    if digest_bytes(&manifest) != output.manifest_digest {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    Ok(manifest)
}

fn create_terminal_evidence_file(
    catalog: &Catalog<'_>,
    tenant: TenantId,
    identity: [u8; 16],
    evidence: &[u8],
) -> Result<(), ExportOutputFailure> {
    validate_terminal_evidence(evidence)?;
    if let Some(existing) = read_unpublished_terminal_evidence(catalog, identity)? {
        return if existing == evidence {
            Ok(())
        } else {
            Err(fail(ExportOutputFailureCode::IdempotencyConflict))
        };
    }
    let plaintext = encode_terminal_evidence(evidence)?;
    let protected = catalog
        .protect_export_output(
            terminal_evidence_identity(identity),
            FormatEpoch::CATALOG_V2,
            &plaintext,
        )
        .map_err(map_catalog_failure)?;
    if protected.len() > MAX_PROTECTED_TERMINAL_EVIDENCE_BYTES {
        return Err(fail(ExportOutputFailureCode::LimitExceeded));
    }
    let _capacity = catalog
        .reserve_export_output(tenant, evidence.len(), protected.len())
        .map_err(map_catalog_failure)?;
    create_named_protected_file(catalog, identity, TERMINAL_EVIDENCE_NAME, &protected)
}

fn read_unpublished_terminal_evidence(
    catalog: &Catalog<'_>,
    identity: [u8; 16],
) -> Result<Option<Vec<u8>>, ExportOutputFailure> {
    let Some(protected) = read_named_protected_file(
        catalog,
        identity,
        TERMINAL_EVIDENCE_NAME,
        MAX_PROTECTED_TERMINAL_EVIDENCE_BYTES,
    )?
    else {
        return Ok(None);
    };
    let plaintext = catalog
        .open_export_output(
            terminal_evidence_identity(identity),
            FormatEpoch::CATALOG_V2,
            &protected,
        )
        .map_err(map_catalog_failure)?;
    Ok(Some(decode_terminal_evidence(&plaintext)?))
}

fn read_terminal_evidence_unlocked(
    catalog: &Catalog<'_>,
    output: &ExportOutput,
) -> Result<Vec<u8>, ExportOutputFailure> {
    let evidence = read_unpublished_terminal_evidence(catalog, output.identity)?
        .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
    if digest_bytes(&evidence) != output.terminal_evidence_digest {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    Ok(evidence)
}

fn validate_terminal_evidence(bytes: &[u8]) -> Result<(), ExportOutputFailure> {
    if bytes.is_empty() || bytes.len() > MAX_EXPORT_TERMINAL_EVIDENCE_BYTES {
        return Err(fail(ExportOutputFailureCode::LimitExceeded));
    }
    Ok(())
}

fn encode_terminal_evidence(bytes: &[u8]) -> Result<Vec<u8>, ExportOutputFailure> {
    validate_terminal_evidence(bytes)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(
            TERMINAL_EVIDENCE_FIXED_BYTES
                .checked_add(bytes.len())
                .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?,
        )
        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    payload.extend_from_slice(&TERMINAL_EVIDENCE_MAGIC);
    payload.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?
            .to_be_bytes(),
    );
    payload.extend_from_slice(bytes);
    Ok(payload)
}

fn decode_terminal_evidence(bytes: &[u8]) -> Result<Vec<u8>, ExportOutputFailure> {
    if bytes.len() < TERMINAL_EVIDENCE_FIXED_BYTES
        || bytes.get(..8) != Some(TERMINAL_EVIDENCE_MAGIC.as_slice())
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let length = usize::try_from(u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    ))
    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    if length == 0
        || length > MAX_EXPORT_TERMINAL_EVIDENCE_BYTES
        || bytes.len() != TERMINAL_EVIDENCE_FIXED_BYTES.saturating_add(length)
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    Ok(bytes[TERMINAL_EVIDENCE_FIXED_BYTES..].to_vec())
}
fn encode_manifest(bytes: &[u8]) -> Result<Vec<u8>, ExportOutputFailure> {
    if bytes.is_empty() || bytes.len() > MAX_EXPORT_MANIFEST_BYTES {
        return Err(fail(ExportOutputFailureCode::LimitExceeded));
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(MANIFEST_FIXED_BYTES + bytes.len())
        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    payload.extend_from_slice(&MANIFEST_MAGIC);
    payload.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?
            .to_be_bytes(),
    );
    payload.extend_from_slice(bytes);
    Ok(payload)
}
fn decode_manifest(bytes: &[u8]) -> Result<Vec<u8>, ExportOutputFailure> {
    if bytes.len() < MANIFEST_FIXED_BYTES || bytes.get(..8) != Some(MANIFEST_MAGIC.as_slice()) {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let length = usize::try_from(u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    ))
    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    if length == 0
        || length > MAX_EXPORT_MANIFEST_BYTES
        || bytes.len() != MANIFEST_FIXED_BYTES.saturating_add(length)
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    Ok(bytes[MANIFEST_FIXED_BYTES..].to_vec())
}

fn encode_initial_preparation(
    binding: ExportOutputBinding,
    cursor: &[u8],
) -> Result<Vec<u8>, ExportOutputFailure> {
    if cursor.is_empty() || cursor.len() > MAX_CONTINUATION_CURSOR_BYTES {
        return Err(fail(ExportOutputFailureCode::LimitExceeded));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            INITIAL_CURSOR_FIXED_BYTES
                .checked_add(cursor.len())
                .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?,
        )
        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    bytes.extend_from_slice(&INITIAL_CURSOR_MAGIC);
    encode_binding(&mut bytes, binding);
    bytes.extend_from_slice(
        &u16::try_from(cursor.len())
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(cursor);
    Ok(bytes)
}

fn decode_initial_preparation(bytes: &[u8]) -> Result<InitialPreparation, ExportOutputFailure> {
    if bytes.len() < INITIAL_CURSOR_FIXED_BYTES
        || bytes.get(..8) != Some(INITIAL_CURSOR_MAGIC.as_slice())
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let binding_end = 8_usize
        .checked_add(EXPORT_OUTPUT_BINDING_BYTES)
        .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
    let binding = decode_binding(
        bytes
            .get(8..binding_end)
            .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    )?;
    let length_end = binding_end
        .checked_add(2)
        .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
    let length = usize::from(u16::from_be_bytes(
        bytes[binding_end..length_end]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    ));
    if length == 0
        || length > MAX_CONTINUATION_CURSOR_BYTES
        || bytes.len() != INITIAL_CURSOR_FIXED_BYTES.saturating_add(length)
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    Ok(InitialPreparation {
        binding,
        cursor: bytes[INITIAL_CURSOR_FIXED_BYTES..].to_vec(),
    })
}

fn open_directory(parent: &File, name: &str, create: bool) -> Result<File, ExportOutputFailure> {
    if create {
        match unix_fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {},
            Err(error) => return Err(map_errno(error)),
        }
    }
    unix_fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(map_errno)
}
fn encode_payload(
    sequence: u64,
    digest: [u8; 32],
    bytes: &[u8],
    continuation_cursor: Option<&[u8]>,
) -> Result<Vec<u8>, ExportOutputFailure> {
    let cursor = continuation_cursor.unwrap_or_default();
    let cursor_length =
        u16::try_from(cursor.len()).map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    let capacity = PAYLOAD_FIXED_BYTES
        .checked_add(cursor.len())
        .and_then(|value| value.checked_add(bytes.len()))
        .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(capacity)
        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    payload.extend_from_slice(&PAYLOAD_MAGIC);
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&digest);
    payload.extend_from_slice(&cursor_length.to_be_bytes());
    payload.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?
            .to_be_bytes(),
    );
    payload.extend_from_slice(cursor);
    payload.extend_from_slice(bytes);
    Ok(payload)
}
fn decode_payload(sequence: u64, bytes: &[u8]) -> Result<PayloadRecord, ExportOutputFailure> {
    if bytes.len() < PAYLOAD_FIXED_BYTES || bytes.get(..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let stored = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    );
    let cursor_length = usize::from(u16::from_be_bytes(
        bytes[48..50]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    ));
    let len = usize::try_from(u32::from_be_bytes(
        bytes[50..54]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    ))
    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    let expected = PAYLOAD_FIXED_BYTES
        .checked_add(cursor_length)
        .and_then(|value| value.checked_add(len))
        .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
    if stored != sequence
        || cursor_length > MAX_CONTINUATION_CURSOR_BYTES
        || len == 0
        || len > MAX_EXPORT_BATCH_BYTES
        || bytes.len() != expected
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let mut digest = [0; 32];
    digest.copy_from_slice(&bytes[16..48]);
    if digest == [0; 32] {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let cursor_end = PAYLOAD_FIXED_BYTES
        .checked_add(cursor_length)
        .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
    let continuation_cursor =
        (!cursor_length.eq(&0)).then(|| bytes[PAYLOAD_FIXED_BYTES..cursor_end].to_vec());
    Ok(PayloadRecord {
        digest,
        bytes: bytes[cursor_end..].to_vec(),
        continuation_cursor,
        durable_bytes: 0,
    })
}
fn encode_descriptor(output: &ExportOutput) -> Result<Vec<u8>, ExportOutputFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(DESCRIPTOR_BYTES)
        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    bytes.extend_from_slice(&DESCRIPTOR_MAGIC);
    bytes.extend_from_slice(&output.identity);
    encode_binding(&mut bytes, output.binding);
    bytes.extend_from_slice(&output.next_sequence.to_be_bytes());
    bytes.extend_from_slice(&output.retained_bytes.to_be_bytes());
    bytes.extend_from_slice(&output.last_digest);
    bytes.extend_from_slice(&output.terminal_evidence_digest);
    bytes.extend_from_slice(&output.manifest_digest);
    Ok(bytes)
}
fn decode_descriptor(bytes: &[u8]) -> Result<Option<ExportOutput>, ExportOutputFailure> {
    let magic = bytes
        .get(..8)
        .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
    let legacy = magic == LEGACY_DESCRIPTOR_MAGIC;
    if !legacy && magic != DESCRIPTOR_MAGIC {
        return Ok(None);
    }
    let expected_bytes = if legacy {
        LEGACY_DESCRIPTOR_BYTES
    } else {
        DESCRIPTOR_BYTES
    };
    if bytes.len() != expected_bytes {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let mut identity = [0; 16];
    identity.copy_from_slice(&bytes[8..24]);
    let binding = decode_binding(&bytes[24..184])?;
    let next = u64::from_be_bytes(
        bytes[184..192]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    );
    let retained = u64::from_be_bytes(
        bytes[192..200]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    );
    let mut last = [0; 32];
    last.copy_from_slice(&bytes[200..232]);
    let mut terminal_evidence_digest = [0; 32];
    let mut manifest_digest = [0; 32];
    if legacy {
        manifest_digest.copy_from_slice(&bytes[232..264]);
    } else {
        terminal_evidence_digest.copy_from_slice(&bytes[232..264]);
        manifest_digest.copy_from_slice(&bytes[264..296]);
    }
    if identity != output_identity(binding)
        || next > MAX_EXPORT_BATCHES
        || retained > MAX_EXPORT_BYTES
        || (next == 0 && last != [0; 32])
        || (next > 0 && last == [0; 32])
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    Ok(Some(ExportOutput {
        identity,
        binding,
        next_sequence: next,
        retained_bytes: retained,
        last_digest: last,
        terminal_evidence_digest,
        manifest_digest,
    }))
}
fn output_identity(binding: ExportOutputBinding) -> [u8; 16] {
    output_identity_for_operation(binding.operation_id)
}

fn output_identity_for_operation(operation_id: [u8; 16]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.operation.v1\0");
    hash.update(operation_id);
    let digest: [u8; 32] = hash.finalize().into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    identity
}

#[allow(clippy::too_many_arguments)]
fn legacy_operation_id(
    tenant: TenantId,
    destination: [u8; 16],
    request_digest: [u8; 32],
    snapshot_identity: [u8; 32],
    snapshot_generation: u64,
    snapshot_frontier: u64,
    lease: SnapshotLeaseId,
    lease_started_at: u64,
    lease_expiry_at: u64,
) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.legacy-operation.v1\0");
    hash.update(tenant.to_bytes());
    hash.update(destination);
    hash.update(request_digest);
    hash.update(snapshot_identity);
    hash.update(snapshot_generation.to_be_bytes());
    hash.update(snapshot_frontier.to_be_bytes());
    hash.update(lease.to_bytes());
    hash.update(lease_started_at.to_be_bytes());
    hash.update(lease_expiry_at.to_be_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    let mut operation_id = [0; 16];
    operation_id.copy_from_slice(&digest[..16]);
    operation_id
}

fn encode_binding(bytes: &mut Vec<u8>, binding: ExportOutputBinding) {
    bytes.extend_from_slice(&binding.operation_id);
    bytes.extend_from_slice(&binding.tenant.to_bytes());
    bytes.extend_from_slice(&binding.destination);
    bytes.extend_from_slice(&binding.request_digest);
    bytes.extend_from_slice(&binding.snapshot_identity);
    bytes.extend_from_slice(&binding.snapshot_generation.to_be_bytes());
    bytes.extend_from_slice(&binding.snapshot_frontier.to_be_bytes());
    bytes.extend_from_slice(&binding.lease.to_bytes());
    bytes.extend_from_slice(&binding.lease_started_at.to_be_bytes());
    bytes.extend_from_slice(&binding.lease_expiry_at.to_be_bytes());
}

fn decode_binding(bytes: &[u8]) -> Result<ExportOutputBinding, ExportOutputFailure> {
    if bytes.len() != EXPORT_OUTPUT_BINDING_BYTES {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let request = ExportOutputRequest::new(
        bounded_array(bytes, 0)?,
        TenantId::from_bytes(bounded_array(bytes, 16)?)
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
        bounded_array(bytes, 32)?,
        bounded_array(bytes, 48)?,
    )?;
    ExportOutputBinding::new_for_operation(
        request,
        bounded_array(bytes, 80)?,
        u64::from_be_bytes(bounded_array(bytes, 112)?),
        u64::from_be_bytes(bounded_array(bytes, 120)?),
        SnapshotLeaseId::new(bounded_array(bytes, 128)?)
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
        u64::from_be_bytes(bounded_array(bytes, 144)?),
        u64::from_be_bytes(bounded_array(bytes, 152)?),
    )
}

fn bounded_array<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], ExportOutputFailure> {
    let end = start
        .checked_add(N)
        .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
    bytes
        .get(start..end)
        .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?
        .try_into()
        .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))
}
fn manifest_identity(output: [u8; 16]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.manifest.v1\0");
    hash.update(output);
    hash.finalize().into()
}
fn terminal_evidence_identity(output: [u8; 16]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.terminal-evidence.v1\0");
    hash.update(output);
    hash.finalize().into()
}
fn initial_cursor_identity(output: [u8; 16]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.initial-cursor.v1\0");
    hash.update(output);
    hash.finalize().into()
}
fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn payload_identity(output: [u8; 16], sequence: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.payload.v2\0");
    hash.update(output);
    hash.update(sequence.to_be_bytes());
    hash.finalize().into()
}
fn transaction_identity(output: &ExportOutput, predecessor: [u8; 32]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.transition.v2\0");
    hash.update(output.identity);
    hash.update(output.next_sequence.to_be_bytes());
    hash.update(output.last_digest);
    hash.update(output.terminal_evidence_digest);
    hash.update(output.manifest_digest);
    hash.update(predecessor);
    let digest: [u8; 32] = hash.finalize().into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    identity
}
fn hex<const N: usize>(bytes: [u8; N]) -> String {
    let mut value = String::with_capacity(N * 2);
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            value.push(char::from(
                nibble + if nibble < 10 { b'0' } else { b'a' - 10 },
            ));
        }
    }
    value
}
fn fail(code: ExportOutputFailureCode) -> ExportOutputFailure {
    ExportOutputFailure::new(code)
}
fn map_catalog_failure(failure: CatalogFailure) -> ExportOutputFailure {
    let code = match failure.code() {
        CatalogFailureCode::InvalidInput => ExportOutputFailureCode::InvalidBinding,
        CatalogFailureCode::LimitExceeded => ExportOutputFailureCode::LimitExceeded,
        CatalogFailureCode::IdempotencyConflict => ExportOutputFailureCode::IdempotencyConflict,
        CatalogFailureCode::StorageUnavailable => ExportOutputFailureCode::StorageUnavailable,
        CatalogFailureCode::IntegrityCorruption => ExportOutputFailureCode::IntegrityCorruption,
        CatalogFailureCode::AuthenticationFailed => ExportOutputFailureCode::AuthenticationFailed,
        CatalogFailureCode::ConcurrentWriter => ExportOutputFailureCode::ConcurrentWriter,
        CatalogFailureCode::ResourceAdmissionRefused
        | CatalogFailureCode::StaleGeneration
        | CatalogFailureCode::UnsupportedFormat => {
            ExportOutputFailureCode::ResourceAdmissionRefused
        },
    };
    fail(code)
}
fn map_errno(error: rustix::io::Errno) -> ExportOutputFailure {
    if matches!(error, rustix::io::Errno::NOENT) {
        fail(ExportOutputFailureCode::StorageUnavailable)
    } else if matches!(error, rustix::io::Errno::NOSPC | rustix::io::Errno::DQUOT) {
        fail(ExportOutputFailureCode::ResourceAdmissionRefused)
    } else {
        fail(ExportOutputFailureCode::StorageUnavailable)
    }
}
fn map_io_failure(error: std::io::Error) -> ExportOutputFailure {
    match error.raw_os_error() {
        Some(raw)
            if raw == rustix::io::Errno::NOSPC.raw_os_error()
                || raw == rustix::io::Errno::DQUOT.raw_os_error() =>
        {
            fail(ExportOutputFailureCode::ResourceAdmissionRefused)
        },
        _ => fail(ExportOutputFailureCode::StorageUnavailable),
    }
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_export_output_record(data: &[u8]) {
    if data.len() > MAX_PROTECTED_RECORD_BYTES {
        return;
    }
    let _ = decode_descriptor(data);
    let _ = decode_payload(0, data);
    let _ = decode_manifest(data);
    let _ = decode_initial_preparation(data);
    let _ = decode_terminal_evidence(data);
}
