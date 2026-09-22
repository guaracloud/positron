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

const DESCRIPTOR_MAGIC: [u8; 8] = *b"POSEXP02";
const PAYLOAD_MAGIC: [u8; 8] = *b"POEXBAT1";
const MANIFEST_MAGIC: [u8; 8] = *b"POEXMAN1";
const EXPORT_DIRECTORY: &str = "exports";
const PAYLOAD_NAME: &str = "payload";
const MANIFEST_NAME: &str = "manifest";
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
const MANIFEST_FIXED_BYTES: usize = 12;
const MAX_PROTECTED_MANIFEST_BYTES: usize = MAX_EXPORT_MANIFEST_BYTES + 512;
const DESCRIPTOR_BYTES: usize = 248;

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

/// Immutable identity binding for one bounded durable export payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportOutputBinding {
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
        if destination.iter().all(|byte| *byte == 0)
            || request_digest.iter().all(|byte| *byte == 0)
            || snapshot_identity.iter().all(|byte| *byte == 0)
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
            tenant,
            destination,
            request_digest,
            snapshot_identity,
            snapshot_generation,
            snapshot_frontier,
            lease,
            lease_started_at,
            lease_expiry_at,
        })
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
    manifest_digest: [u8; 32],
}

impl ExportOutput {
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
        Ok(found)
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
                    manifest_digest: [0; 32],
                };
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
        found.ok_or_else(|| fail(ExportOutputFailureCode::StorageUnavailable))
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
        if bytes.is_empty()
            || bytes.len() > MAX_EXPORT_BATCH_BYTES
            || digest == [0; 32]
            || continuation_cursor
                .is_some_and(|cursor| cursor.len() > MAX_CONTINUATION_CURSOR_BYTES)
        {
            return Err(fail(ExportOutputFailureCode::LimitExceeded));
        }
        let _operation = catalog
            .export_output_operation
            .lock()
            .map_err(|_| fail(ExportOutputFailureCode::ConcurrentWriter))?;
        let records = read_records(catalog, self)?;
        let count = u64::try_from(records.len())
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
        if count < self.next_sequence {
            return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
        }
        if sequence < count {
            let existing = records
                .get(
                    usize::try_from(sequence)
                        .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?,
                )
                .ok_or_else(|| fail(ExportOutputFailureCode::IntegrityCorruption))?;
            return if existing.digest == digest
                && existing.bytes == bytes
                && existing.continuation_cursor.as_deref() == continuation_cursor
            {
                Ok(ExportBatchReceipt { sequence, digest })
            } else {
                Err(fail(ExportOutputFailureCode::IdempotencyConflict))
            };
        }
        if sequence != count || sequence >= MAX_EXPORT_BATCHES {
            return Err(fail(ExportOutputFailureCode::IdempotencyConflict));
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
        let next_bytes = total_record_bytes(&records)?
            .checked_add(
                u64::try_from(durable_bytes)
                    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?,
            )
            .filter(|total| *total <= MAX_EXPORT_BYTES)
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))?;
        let _capacity = catalog
            .reserve_export_output(self.binding.tenant, bytes.len(), durable_bytes)
            .map_err(map_catalog_failure)?;
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
        successor.publish(catalog)?;
        *self = successor;
        Ok(ExportBatchReceipt { sequence, digest })
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
        read_records(catalog, self)?
            .get(
                usize::try_from(sequence)
                    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?,
            )
            .map(|record| record.bytes.clone())
            .ok_or_else(|| fail(ExportOutputFailureCode::StorageUnavailable))
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
        let Some(record) = read_records(catalog, self)?.pop() else {
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
        let records = read_records(catalog, self)?;
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(records.len())
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
        for (index, record) in records.iter().enumerate() {
            receipts.push(ExportBatchReceipt {
                sequence: u64::try_from(index)
                    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?,
                digest: record.digest,
            });
        }
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
        let transaction = TransactionId::new(transaction_identity(self))
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
        let proposal = CatalogProposal::new(
            transaction,
            snapshot.format_epoch().unwrap_or(FormatEpoch::CATALOG_V2),
            objects,
        )
        .map_err(map_catalog_failure)?;
        catalog
            .commit(snapshot.identity(), proposal, None)
            .map_err(map_catalog_failure)?;
        Ok(())
    }
}

struct PayloadRecord {
    digest: [u8; 32],
    bytes: Vec<u8>,
    continuation_cursor: Option<Vec<u8>>,
    durable_bytes: u64,
}
fn read_records(
    catalog: &Catalog<'_>,
    output: &ExportOutput,
) -> Result<Vec<PayloadRecord>, ExportOutputFailure> {
    let mut file = ensure_payload_file(catalog, output.identity, false)?;
    let length = file.metadata().map_err(map_io_failure)?.len();
    if length > MAX_EXPORT_BYTES {
        return Err(fail(ExportOutputFailureCode::LimitExceeded));
    }
    file.seek(SeekFrom::Start(0)).map_err(map_io_failure)?;
    let mut records = Vec::new();
    let mut consumed = 0_u64;
    while consumed < length {
        if records.len()
            >= usize::try_from(MAX_EXPORT_BATCHES)
                .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?
        {
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
        let sequence = u64::try_from(records.len())
            .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
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
        records.push(record);
    }
    let count =
        u64::try_from(records.len()).map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?;
    if consumed != length
        || count < output.next_sequence
        || count > output.next_sequence.saturating_add(1)
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    if count == output.next_sequence && total_record_bytes(&records)? != output.retained_bytes {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    if output.next_sequence > 0
        && records
            .get(
                usize::try_from(output.next_sequence - 1)
                    .map_err(|_| fail(ExportOutputFailureCode::LimitExceeded))?,
            )
            .map(|record| record.digest)
            != Some(output.last_digest)
    {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    Ok(records)
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
    bytes.extend_from_slice(&output.binding.tenant.to_bytes());
    bytes.extend_from_slice(&output.binding.destination);
    bytes.extend_from_slice(&output.binding.request_digest);
    bytes.extend_from_slice(&output.binding.snapshot_identity);
    bytes.extend_from_slice(&output.binding.snapshot_generation.to_be_bytes());
    bytes.extend_from_slice(&output.binding.snapshot_frontier.to_be_bytes());
    bytes.extend_from_slice(&output.binding.lease.to_bytes());
    bytes.extend_from_slice(&output.binding.lease_started_at.to_be_bytes());
    bytes.extend_from_slice(&output.binding.lease_expiry_at.to_be_bytes());
    bytes.extend_from_slice(&output.next_sequence.to_be_bytes());
    bytes.extend_from_slice(&output.retained_bytes.to_be_bytes());
    bytes.extend_from_slice(&output.last_digest);
    bytes.extend_from_slice(&output.manifest_digest);
    Ok(bytes)
}
fn decode_descriptor(bytes: &[u8]) -> Result<Option<ExportOutput>, ExportOutputFailure> {
    if bytes.get(..8) != Some(DESCRIPTOR_MAGIC.as_slice()) {
        return Ok(None);
    }
    if bytes.len() != DESCRIPTOR_BYTES {
        return Err(fail(ExportOutputFailureCode::IntegrityCorruption));
    }
    let sixteen = |start, end| {
        bytes[start..end]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))
    };
    let mut identity = [0; 16];
    identity.copy_from_slice(&bytes[8..24]);
    let tenant = TenantId::from_bytes(sixteen(24, 40)?)
        .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?;
    let mut destination = [0; 16];
    destination.copy_from_slice(&bytes[40..56]);
    let mut request = [0; 32];
    request.copy_from_slice(&bytes[56..88]);
    let mut snapshot = [0; 32];
    snapshot.copy_from_slice(&bytes[88..120]);
    let generation = u64::from_be_bytes(
        bytes[120..128]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    );
    let frontier = u64::from_be_bytes(
        bytes[128..136]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    );
    let lease = SnapshotLeaseId::new(sixteen(136, 152)?)
        .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?;
    let started = u64::from_be_bytes(
        bytes[152..160]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    );
    let expiry = u64::from_be_bytes(
        bytes[160..168]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    );
    let next = u64::from_be_bytes(
        bytes[168..176]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    );
    let retained = u64::from_be_bytes(
        bytes[176..184]
            .try_into()
            .map_err(|_| fail(ExportOutputFailureCode::IntegrityCorruption))?,
    );
    let mut last = [0; 32];
    last.copy_from_slice(&bytes[184..216]);
    let mut manifest_digest = [0; 32];
    manifest_digest.copy_from_slice(&bytes[216..248]);
    let binding = ExportOutputBinding::new(
        tenant,
        destination,
        request,
        snapshot,
        generation,
        frontier,
        lease,
        started,
        expiry,
    )?;
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
        manifest_digest,
    }))
}
fn output_identity(binding: ExportOutputBinding) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.binding.v2\0");
    hash.update(binding.tenant.to_bytes());
    hash.update(binding.destination);
    hash.update(binding.request_digest);
    hash.update(binding.snapshot_identity);
    hash.update(binding.snapshot_generation.to_be_bytes());
    hash.update(binding.snapshot_frontier.to_be_bytes());
    hash.update(binding.lease.to_bytes());
    hash.update(binding.lease_started_at.to_be_bytes());
    hash.update(binding.lease_expiry_at.to_be_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    identity
}
fn manifest_identity(output: [u8; 16]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.manifest.v1\0");
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
fn transaction_identity(output: &ExportOutput) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"positron.export-output.transition.v2\0");
    hash.update(output.identity);
    hash.update(output.next_sequence.to_be_bytes());
    hash.update(output.last_digest);
    hash.update(output.manifest_digest);
    let digest: [u8; 32] = hash.finalize().into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    identity
}
fn total_record_bytes(records: &[PayloadRecord]) -> Result<u64, ExportOutputFailure> {
    records.iter().try_fold(0_u64, |total, record| {
        total
            .checked_add(record.durable_bytes)
            .ok_or_else(|| fail(ExportOutputFailureCode::LimitExceeded))
    })
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
}
