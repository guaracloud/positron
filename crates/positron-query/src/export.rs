//! Bounded, authenticated export materialization over the native query stream.

use std::sync::Arc;

use crate::{
    QueryBatch, QueryCursor, QueryEvent, QueryFailure, QueryFailureCode, QueryHeader, QueryStats,
    QueryTerminal,
};

const REQUEST_DOMAIN: &[u8] = b"query-export-request-v2";
const MANIFEST_DOMAIN: &[u8] = b"query-export-manifest-v1";
const MAX_MANIFEST_BATCHES: usize = 1_024;
const MANIFEST_WIRE_MAGIC: &[u8; 8] = b"POSQEM01";
const TERMINAL_EVIDENCE_MAGIC: &[u8; 8] = b"POSQET01";

/// Immutable identity of the preconfigured protected output destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportDestination([u8; 16]);

impl ExportDestination {
    /// Validates an identity returned only by the configured runtime authority.
    fn configured(identity: [u8; 16]) -> Result<Self, QueryFailure> {
        (!identity.iter().all(|byte| *byte == 0))
            .then_some(Self(identity))
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))
    }

    #[must_use]
    pub const fn identity(self) -> [u8; 16] {
        self.0
    }
}

/// The protected output boundary. Implementations must reject a substituted
/// destination and make a complete batch durable before returning success.
pub trait ExportSink {
    /// Opens the protected destination only after the Query Snapshot and
    /// Snapshot Lease are known. Implementations must bind both identities
    /// before accepting any Result Batch.
    fn start(&mut self, _header: &QueryHeader) -> Result<(), QueryFailure> {
        Ok(())
    }

    fn write_batch(
        &mut self,
        destination: ExportDestination,
        batch: &QueryBatch,
        continuation: Option<&QueryCursor>,
    ) -> Result<(), QueryFailure>;

    /// Commits the final batch with the Query-owned terminal truth that it
    /// attests. Durable sinks override this so recovery never infers a result
    /// from a missing continuation cursor; observation sinks retain the
    /// ordinary batch callback.
    fn write_terminal_batch(
        &mut self,
        destination: ExportDestination,
        batch: &QueryBatch,
        _terminal: &ExportTerminal,
    ) -> Result<(), QueryFailure> {
        self.write_batch(destination, batch, None)
    }

    /// Commits terminal truth for an empty export. Durable sinks bind it to
    /// their protected descriptor; observation sinks have no durable state.
    fn persist_terminal(&mut self, _terminal: &ExportTerminal) -> Result<(), QueryFailure> {
        Ok(())
    }

    /// Returns the identity of the kernel-owned protected output, if this
    /// sink materializes one. Observation-only sinks remain supported for the
    /// non-durable streaming API, but durable operations always return one.
    fn output_identity(&self) -> Option<[u8; 16]> {
        None
    }

    /// Makes cancellation unavailable immediately before the irreversible
    /// protected-output boundary. The observation-only stream has no such
    /// boundary.
    fn cross_output_boundary(&mut self) -> Result<(), QueryFailure> {
        Ok(())
    }

    /// Makes the signed terminal manifest durable after all output batches.
    fn persist_manifest(&mut self, _bytes: &[u8]) -> Result<(), QueryFailure> {
        Ok(())
    }
}

struct KernelExportSink<'catalog, 'kernel, 'observer> {
    catalog: &'catalog positron_kernel::Catalog<'kernel>,
    tenant: positron_domain::identity::TenantId,
    destination: ExportDestination,
    request_digest: [u8; 32],
    clock: Arc<dyn crate::QueryClock>,
    output: Option<positron_kernel::ExportOutput>,
    observer: &'observer mut dyn ExportSink,
    operation_id: positron_governance::OperationId,
    context: positron_governance::AuthorizedContext,
    first_batch_started: bool,
}

impl KernelExportSink<'_, '_, '_> {
    fn now(&self) -> Result<u64, QueryFailure> {
        self.clock
            .now_seconds()
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
    }

    fn ensure_running(&self) -> Result<(), QueryFailure> {
        let operation = positron_governance::DurableOperationAdministration::inspect(
            self.catalog,
            self.operation_id,
        )
        .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
        match operation.status() {
            positron_governance::DurableOperationStatus::Running => Ok(()),
            positron_governance::DurableOperationStatus::Cancelled => {
                Err(QueryFailure::new(QueryFailureCode::Cancelled))
            },
            _ => Err(QueryFailure::new(QueryFailureCode::AuthorizationChanged)),
        }
    }

    fn map_output_failure(failure: positron_kernel::ExportOutputFailure) -> QueryFailure {
        use positron_kernel::ExportOutputFailureCode as Code;
        let code = match failure.code() {
            Code::Expired => QueryFailureCode::SnapshotExpired,
            Code::LimitExceeded => QueryFailureCode::ResourceExhausted,
            Code::ResourceAdmissionRefused => QueryFailureCode::ResourceAdmissionRefused,
            Code::StorageUnavailable | Code::ConcurrentWriter => QueryFailureCode::StoreUnavailable,
            Code::IntegrityCorruption | Code::AuthenticationFailed => {
                QueryFailureCode::MalformedPersistentData
            },
            Code::InvalidBinding | Code::IdempotencyConflict => QueryFailureCode::Unauthorized,
        };
        QueryFailure::new(code)
    }

    fn cross_output_boundary_once(&mut self) -> Result<(), QueryFailure> {
        if !self.first_batch_started {
            positron_governance::DurableOperationAdministration::drain_query_export(
                self.catalog,
                self.context,
                self.operation_id,
                self.now()?,
            )
            .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
            self.first_batch_started = true;
        }
        Ok(())
    }

    fn has_durable_batch(&self) -> bool {
        self.first_batch_started && self.output.is_some()
    }
}

impl ExportSink for KernelExportSink<'_, '_, '_> {
    fn start(&mut self, header: &QueryHeader) -> Result<(), QueryFailure> {
        self.ensure_running()?;
        let observed_at = self.now()?;
        let lease = positron_kernel::SnapshotLeaseId::new(header.lease().identity())
            .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
        let snapshot = header.snapshot();
        if let Some(output) = &self.output {
            let binding = output.binding();
            if binding.tenant() != self.tenant
                || binding.destination() != self.destination.identity()
                || binding.request_digest() != self.request_digest
                || binding.snapshot_identity() != snapshot.identity()
                || binding.snapshot_generation() != snapshot.generation()
                || binding.snapshot_frontier() != snapshot.frontier()
                || binding.lease() != lease
                || binding.lease_expiry_at() != header.lease().expiry()
            {
                return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
            }
            return self.observer.start(header);
        }
        let request = positron_kernel::ExportOutputRequest::new(
            self.operation_id.to_bytes(),
            self.tenant,
            self.destination.identity(),
            self.request_digest,
        )
        .map_err(Self::map_output_failure)?;
        let binding = positron_kernel::ExportOutputBinding::new_for_operation(
            request,
            snapshot.identity(),
            snapshot.generation(),
            snapshot.frontier(),
            lease,
            observed_at,
            header.lease().expiry(),
        )
        .map_err(Self::map_output_failure)?;
        let initial_cursor = header
            .initial_cursor()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let output = positron_kernel::ExportOutput::create_with_initial_cursor(
            self.catalog,
            binding,
            initial_cursor.as_bytes(),
        )
        .map_err(Self::map_output_failure)?;
        if output.binding() != binding {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        self.output = Some(output);
        self.observer.start(header)
    }

    fn write_batch(
        &mut self,
        destination: ExportDestination,
        batch: &QueryBatch,
        continuation: Option<&QueryCursor>,
    ) -> Result<(), QueryFailure> {
        self.ensure_running()?;
        if destination != self.destination {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        self.cross_output_boundary_once()?;
        let observed_at = self.now()?;
        let output = self
            .output
            .as_mut()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let reservation = output
            .reserve_next_batch(self.catalog)
            .map_err(Self::map_output_failure)?;
        let canonical_bytes = batch.canonical_export_bytes()?;
        let receipt = output
            .append_batch_reserved(
                self.catalog,
                observed_at,
                batch.sequence(),
                batch.digest(),
                &canonical_bytes,
                continuation.map(QueryCursor::as_bytes),
                reservation,
            )
            .map_err(Self::map_output_failure)?;
        if receipt.sequence() != batch.sequence() || receipt.digest() != batch.digest() {
            return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
        }
        self.observer.write_batch(destination, batch, continuation)
    }

    fn write_terminal_batch(
        &mut self,
        destination: ExportDestination,
        batch: &QueryBatch,
        terminal: &ExportTerminal,
    ) -> Result<(), QueryFailure> {
        self.ensure_running()?;
        if destination != self.destination {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        self.cross_output_boundary_once()?;
        let observed_at = self.now()?;
        let terminal_evidence = terminal_evidence_bytes(terminal)?;
        let output = self
            .output
            .as_mut()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let reservation = output
            .reserve_next_batch(self.catalog)
            .map_err(Self::map_output_failure)?;
        let canonical_bytes = batch.canonical_export_bytes()?;
        let receipt = output
            .append_terminal_batch_reserved(
                self.catalog,
                observed_at,
                batch.sequence(),
                batch.digest(),
                &canonical_bytes,
                &terminal_evidence,
                reservation,
            )
            .map_err(Self::map_output_failure)?;
        if receipt.sequence() != batch.sequence() || receipt.digest() != batch.digest() {
            return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
        }
        self.observer.write_batch(destination, batch, None)
    }

    fn persist_terminal(&mut self, terminal: &ExportTerminal) -> Result<(), QueryFailure> {
        self.ensure_running()?;
        self.cross_output_boundary_once()?;
        let observed_at = self.now()?;
        let terminal_evidence = terminal_evidence_bytes(terminal)?;
        self.output
            .as_mut()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?
            .write_terminal_evidence(self.catalog, observed_at, &terminal_evidence)
            .map_err(Self::map_output_failure)
    }

    fn output_identity(&self) -> Option<[u8; 16]> {
        self.output
            .as_ref()
            .map(positron_kernel::ExportOutput::identity)
    }

    fn cross_output_boundary(&mut self) -> Result<(), QueryFailure> {
        self.cross_output_boundary_once()
    }

    fn persist_manifest(&mut self, bytes: &[u8]) -> Result<(), QueryFailure> {
        self.cross_output_boundary_once()?;
        let observed_at = self.now()?;
        self.output
            .as_mut()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?
            .write_manifest(self.catalog, observed_at, bytes)
            .map_err(Self::map_output_failure)
    }
}

/// One immutable exported Result Batch receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportBatch {
    sequence: u64,
    digest: [u8; 32],
}

impl ExportBatch {
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// The truthful terminal export outcome, copied from the underlying query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportTerminal {
    Complete(QueryStats),
    Incomplete(crate::QueryIncomplete),
}

impl ExportTerminal {
    #[must_use]
    pub const fn stats(&self) -> QueryStats {
        match self {
            Self::Complete(stats) => *stats,
            Self::Incomplete(incomplete) => incomplete.stats(),
        }
    }
}

/// Signed incremental export receipt. Its signature binds the requested
/// destination, ordered batch digests, Result Digest, and terminal truth.
#[derive(Clone, Debug)]
pub struct ExportManifest {
    destination: ExportDestination,
    output_identity: Option<[u8; 16]>,
    request_digest: [u8; 32],
    snapshot: crate::ResultSnapshot,
    batches: Vec<ExportBatch>,
    terminal: ExportTerminal,
    authentication: positron_kernel::ControlTokenAuthentication,
    signature: Option<positron_kernel::ExportManifestSignature>,
}

/// The durable-operation identity and its signed output manifest.
#[derive(Clone, Debug)]
pub struct DurableExportReceipt {
    operation_id: positron_governance::OperationId,
    manifest: ExportManifest,
}

impl DurableExportReceipt {
    #[must_use]
    pub const fn operation_id(&self) -> positron_governance::OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn manifest(&self) -> &ExportManifest {
        &self.manifest
    }
}

impl ExportManifest {
    #[must_use]
    pub const fn destination(&self) -> ExportDestination {
        self.destination
    }

    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Returns the exact Query Snapshot whose output this manifest attests.
    #[must_use]
    pub const fn snapshot(&self) -> crate::ResultSnapshot {
        self.snapshot
    }

    /// Returns the exact kernel-owned protected payload identity for a
    /// durable export. Observation-only pipeline exports have no such output.
    #[must_use]
    pub const fn output_identity(&self) -> Option<[u8; 16]> {
        self.output_identity
    }

    #[must_use]
    pub fn batches(&self) -> &[ExportBatch] {
        &self.batches
    }

    #[must_use]
    pub fn batch_count(&self) -> usize {
        self.batches.len()
    }

    #[must_use]
    pub const fn terminal(&self) -> &ExportTerminal {
        &self.terminal
    }

    #[must_use]
    pub const fn result_digest(&self) -> [u8; 32] {
        self.terminal.stats().result_digest()
    }

    /// Returns the Instance Integrity Key signature for a durable export.
    #[must_use]
    pub const fn signature(&self) -> Option<positron_kernel::ExportManifestSignature> {
        self.signature
    }

    fn payload(&self) -> Result<Vec<u8>, QueryFailure> {
        manifest_payload(
            self.destination,
            self.output_identity,
            self.request_digest,
            self.snapshot,
            &self.batches,
            &self.terminal,
        )
    }
}

fn manifest_payload(
    destination: ExportDestination,
    output_identity: Option<[u8; 16]>,
    request_digest: [u8; 32],
    snapshot: crate::ResultSnapshot,
    batches: &[ExportBatch],
    terminal: &ExportTerminal,
) -> Result<Vec<u8>, QueryFailure> {
    if batches.len() > MAX_MANIFEST_BATCHES {
        return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
    }
    let batch_count = u16::try_from(batches.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(16 + 1 + 16 + 32 + 32 + 8 + 8 + 2 + batches.len() * 40 + 33)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    payload.extend_from_slice(&destination.identity());
    match output_identity {
        Some(identity) => {
            payload.push(1);
            payload.extend_from_slice(&identity);
        },
        None => payload.push(0),
    }
    payload.extend_from_slice(&request_digest);
    payload.extend_from_slice(&snapshot.identity());
    payload.extend_from_slice(&snapshot.generation().to_be_bytes());
    payload.extend_from_slice(&snapshot.frontier().to_be_bytes());
    payload.extend_from_slice(&batch_count.to_be_bytes());
    for batch in batches {
        payload.extend_from_slice(&batch.sequence.to_be_bytes());
        payload.extend_from_slice(&batch.digest);
    }
    match terminal {
        ExportTerminal::Complete(_) => payload.push(1),
        ExportTerminal::Incomplete(incomplete) => {
            payload.push(2);
            payload.push(incomplete.code() as u8);
        },
    }
    payload.extend_from_slice(&terminal.stats().result_digest());
    Ok(payload)
}

fn durable_manifest_bytes(manifest: &ExportManifest) -> Result<Vec<u8>, QueryFailure> {
    let output_identity = manifest
        .output_identity
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    let mut output = Vec::new();
    let signature = manifest
        .signature
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    let capacity = 8_usize
        .checked_add(16 + 16 + 32 + 32 + 8 + 8 + 2 + 179 + 8 + 32 + 2 + 32 + 32 + 64)
        .and_then(|base| base.checked_add(manifest.batches.len().checked_mul(40)?))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    output
        .try_reserve_exact(capacity)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    output.extend_from_slice(MANIFEST_WIRE_MAGIC);
    output.extend_from_slice(&manifest.destination.identity());
    output.extend_from_slice(&output_identity);
    output.extend_from_slice(&manifest.request_digest);
    output.extend_from_slice(&manifest.snapshot.identity());
    output.extend_from_slice(&manifest.snapshot.generation().to_be_bytes());
    output.extend_from_slice(&manifest.snapshot.frontier().to_be_bytes());
    let count = u16::try_from(manifest.batches.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    output.extend_from_slice(&count.to_be_bytes());
    for batch in &manifest.batches {
        output.extend_from_slice(&batch.sequence.to_be_bytes());
        output.extend_from_slice(&batch.digest);
    }
    match &manifest.terminal {
        ExportTerminal::Complete(stats) => {
            output.push(1);
            output.push(0);
            stats.append_durable_export_encoding(&mut output)?;
        },
        ExportTerminal::Incomplete(incomplete) => {
            output.push(2);
            output.push(query_failure_code(incomplete.code()));
            incomplete
                .stats()
                .append_durable_export_encoding(&mut output)?;
        },
    }
    output.extend_from_slice(&manifest.authentication.epoch().to_be_bytes());
    output.extend_from_slice(&manifest.authentication.tag());
    output.extend_from_slice(&signature.integrity_identity().public_key());
    output.extend_from_slice(&signature.integrity_identity().fingerprint());
    output.extend_from_slice(&signature.bytes());
    Ok(output)
}

fn terminal_evidence_bytes(terminal: &ExportTerminal) -> Result<Vec<u8>, QueryFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(8 + 2 + 179)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    bytes.extend_from_slice(TERMINAL_EVIDENCE_MAGIC);
    match terminal {
        ExportTerminal::Complete(stats) => {
            bytes.push(1);
            bytes.push(0);
            stats.append_durable_export_encoding(&mut bytes)?;
        },
        ExportTerminal::Incomplete(incomplete) => {
            bytes.push(2);
            bytes.push(query_failure_code(incomplete.code()));
            incomplete
                .stats()
                .append_durable_export_encoding(&mut bytes)?;
        },
    }
    Ok(bytes)
}

fn terminal_from_evidence(bytes: &[u8]) -> Result<ExportTerminal, QueryFailure> {
    let mut offset = 0;
    if read_manifest_array::<8>(bytes, &mut offset)? != *TERMINAL_EVIDENCE_MAGIC {
        return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
    }
    let terminal_tag = read_manifest_byte(bytes, &mut offset)?;
    let failure_tag = read_manifest_byte(bytes, &mut offset)?;
    let stats = QueryStats::from_durable_export_encoding(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
    }
    match terminal_tag {
        1 if failure_tag == 0 => Ok(ExportTerminal::Complete(stats)),
        2 => Ok(ExportTerminal::Incomplete(crate::QueryIncomplete::new(
            QueryFailure::new(query_failure_code_from(failure_tag)?),
            stats,
        ))),
        _ => Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData)),
    }
}

fn durable_manifest_from_bytes(bytes: &[u8]) -> Result<ExportManifest, QueryFailure> {
    let mut offset = 0;
    if read_manifest_array::<8>(bytes, &mut offset)? != *MANIFEST_WIRE_MAGIC {
        return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
    }
    let destination = ExportDestination::configured(read_manifest_array(bytes, &mut offset)?)?;
    let output_identity = read_manifest_array(bytes, &mut offset)?;
    if output_identity.iter().all(|byte| *byte == 0) {
        return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
    }
    let request_digest = read_manifest_array(bytes, &mut offset)?;
    let snapshot = crate::ResultSnapshot::new(
        read_manifest_array(bytes, &mut offset)?,
        u64::from_be_bytes(read_manifest_array(bytes, &mut offset)?),
        u64::from_be_bytes(read_manifest_array(bytes, &mut offset)?),
    );
    let count = usize::from(u16::from_be_bytes(read_manifest_array(bytes, &mut offset)?));
    if count > MAX_MANIFEST_BATCHES {
        return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
    }
    let mut batches = Vec::new();
    batches
        .try_reserve_exact(count)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    for expected in 0..count {
        let sequence = u64::from_be_bytes(read_manifest_array(bytes, &mut offset)?);
        if sequence
            != u64::try_from(expected)
                .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?
        {
            return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
        }
        batches.push(ExportBatch {
            sequence,
            digest: read_manifest_array(bytes, &mut offset)?,
        });
    }
    let terminal_tag = read_manifest_byte(bytes, &mut offset)?;
    let failure_tag = read_manifest_byte(bytes, &mut offset)?;
    let stats = QueryStats::from_durable_export_encoding(bytes, &mut offset)?;
    let terminal = match terminal_tag {
        1 if failure_tag == 0 => ExportTerminal::Complete(stats),
        2 => ExportTerminal::Incomplete(crate::QueryIncomplete::new(
            QueryFailure::new(query_failure_code_from(failure_tag)?),
            stats,
        )),
        _ => return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData)),
    };
    let epoch = u64::from_be_bytes(read_manifest_array(bytes, &mut offset)?);
    let authentication = positron_kernel::ControlTokenAuthentication::new(
        epoch,
        read_manifest_array(bytes, &mut offset)?,
    )
    .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    let signature_identity = positron_kernel::BootstrapIntegrityIdentity::from_pinned(
        read_manifest_array(bytes, &mut offset)?,
        read_manifest_array(bytes, &mut offset)?,
    )
    .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    let signature = positron_kernel::ExportManifestSignature::new(
        signature_identity,
        read_manifest_array(bytes, &mut offset)?,
    )
    .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    if offset != bytes.len() {
        return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
    }
    Ok(ExportManifest {
        destination,
        output_identity: Some(output_identity),
        request_digest,
        snapshot,
        batches,
        terminal,
        authentication,
        signature: Some(signature),
    })
}

/// Exercises the bounded durable terminal and manifest decoders with hostile
/// persisted bytes.
#[cfg(fuzzing)]
pub(crate) fn fuzz_durable_export_records(data: &[u8]) {
    const MAX_FUZZ_RECORD_BYTES: usize = 65_536;
    if data.len() > MAX_FUZZ_RECORD_BYTES {
        return;
    }
    let _ = terminal_from_evidence(data);
    let _ = durable_manifest_from_bytes(data);
}

fn read_manifest_byte(bytes: &[u8], offset: &mut usize) -> Result<u8, QueryFailure> {
    let byte = *bytes
        .get(*offset)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    *offset = offset
        .checked_add(1)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    Ok(byte)
}

fn read_manifest_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], QueryFailure> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    let bytes = bytes
        .get(*offset..end)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    let array = bytes
        .try_into()
        .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    *offset = end;
    Ok(array)
}

fn query_failure_code(code: QueryFailureCode) -> u8 {
    match code {
        QueryFailureCode::Unauthorized => 1,
        QueryFailureCode::IdempotencyConflict => 14,
        QueryFailureCode::InvalidBudget => 2,
        QueryFailureCode::BudgetExhausted => 3,
        QueryFailureCode::InvalidCursor => 4,
        QueryFailureCode::SnapshotExpired => 5,
        QueryFailureCode::AuthorizationChanged => 6,
        QueryFailureCode::Cancelled => 7,
        QueryFailureCode::ResourceAdmissionRefused => 8,
        QueryFailureCode::ResourceExhausted => 9,
        QueryFailureCode::UnsupportedQuery => 10,
        QueryFailureCode::StoreUnavailable => 11,
        QueryFailureCode::MalformedPersistentData => 12,
        QueryFailureCode::Internal => 13,
    }
}

fn query_failure_code_from(code: u8) -> Result<QueryFailureCode, QueryFailure> {
    match code {
        1 => Ok(QueryFailureCode::Unauthorized),
        14 => Ok(QueryFailureCode::IdempotencyConflict),
        2 => Ok(QueryFailureCode::InvalidBudget),
        3 => Ok(QueryFailureCode::BudgetExhausted),
        4 => Ok(QueryFailureCode::InvalidCursor),
        5 => Ok(QueryFailureCode::SnapshotExpired),
        6 => Ok(QueryFailureCode::AuthorizationChanged),
        7 => Ok(QueryFailureCode::Cancelled),
        8 => Ok(QueryFailureCode::ResourceAdmissionRefused),
        9 => Ok(QueryFailureCode::ResourceExhausted),
        10 => Ok(QueryFailureCode::UnsupportedQuery),
        11 => Ok(QueryFailureCode::StoreUnavailable),
        12 => Ok(QueryFailureCode::MalformedPersistentData),
        13 => Ok(QueryFailureCode::Internal),
        _ => Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData)),
    }
}

fn catalog_integrity_identity(
    catalog: &positron_kernel::Catalog<'_>,
) -> Result<positron_kernel::BootstrapIntegrityIdentity, QueryFailure> {
    let snapshot = catalog
        .pin()
        .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
    let (_, governance) = snapshot
        .governance_object()
        .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    positron_kernel::BootstrapIntegrityIdentity::from_pinned(
        governance.integrity_public_key(),
        governance.integrity_key_fingerprint(),
    )
    .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))
}

fn verify_durable_export_signature(
    catalog: &positron_kernel::Catalog<'_>,
    manifest: &ExportManifest,
) -> Result<(), QueryFailure> {
    let signature = manifest
        .signature()
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    signature
        .verify(catalog_integrity_identity(catalog)?, &manifest.payload()?)
        .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))
}

fn map_operation_failure(failure: positron_governance::DurableOperationFailure) -> QueryFailure {
    use positron_governance::DurableOperationFailure as Failure;
    let code = match failure {
        Failure::IdempotencyConflict => QueryFailureCode::IdempotencyConflict,
        Failure::PersistenceUnavailable => QueryFailureCode::StoreUnavailable,
        Failure::Unauthorized => QueryFailureCode::Unauthorized,
        _ => QueryFailureCode::Internal,
    };
    QueryFailure::new(code)
}

fn durable_query_failure(
    failure: &QueryFailure,
) -> positron_governance::DurableOperationTerminalError {
    use positron_governance::{
        DurableOperationTerminalError, DurableQueryBudgetDimension, DurableQueryExportFailure,
        DurableQueryExportFailureCode,
    };

    let code = match failure.code() {
        QueryFailureCode::Unauthorized => DurableQueryExportFailureCode::Unauthorized,
        QueryFailureCode::IdempotencyConflict => DurableQueryExportFailureCode::IdempotencyConflict,
        QueryFailureCode::InvalidBudget => DurableQueryExportFailureCode::InvalidBudget,
        QueryFailureCode::BudgetExhausted => DurableQueryExportFailureCode::BudgetExhausted,
        QueryFailureCode::InvalidCursor => DurableQueryExportFailureCode::InvalidCursor,
        QueryFailureCode::SnapshotExpired => DurableQueryExportFailureCode::SnapshotExpired,
        QueryFailureCode::AuthorizationChanged => {
            DurableQueryExportFailureCode::AuthorizationChanged
        },
        QueryFailureCode::Cancelled => DurableQueryExportFailureCode::Cancelled,
        QueryFailureCode::ResourceAdmissionRefused => {
            DurableQueryExportFailureCode::ResourceAdmissionRefused
        },
        QueryFailureCode::ResourceExhausted => DurableQueryExportFailureCode::ResourceExhausted,
        QueryFailureCode::UnsupportedQuery => DurableQueryExportFailureCode::UnsupportedQuery,
        QueryFailureCode::StoreUnavailable => DurableQueryExportFailureCode::StoreUnavailable,
        QueryFailureCode::MalformedPersistentData => {
            DurableQueryExportFailureCode::MalformedPersistentData
        },
        QueryFailureCode::Internal => DurableQueryExportFailureCode::Internal,
    };
    let limiting_budget = match failure.limiting_budget() {
        Some(crate::QueryBudgetDimension::ScannedBytes) => {
            Some(DurableQueryBudgetDimension::ScannedBytes)
        },
        Some(crate::QueryBudgetDimension::DecodedRecords) => {
            Some(DurableQueryBudgetDimension::DecodedRecords)
        },
        Some(crate::QueryBudgetDimension::OutputRows) => {
            Some(DurableQueryBudgetDimension::OutputRows)
        },
        Some(crate::QueryBudgetDimension::OutputBytes) => {
            Some(DurableQueryBudgetDimension::OutputBytes)
        },
        Some(crate::QueryBudgetDimension::MemoryBytes) => {
            Some(DurableQueryBudgetDimension::MemoryBytes)
        },
        Some(crate::QueryBudgetDimension::CpuWorkUnits) => {
            Some(DurableQueryBudgetDimension::CpuWorkUnits)
        },
        Some(crate::QueryBudgetDimension::WallSeconds) => {
            Some(DurableQueryBudgetDimension::WallSeconds)
        },
        Some(crate::QueryBudgetDimension::MaximumTimeRangeNanoseconds) => {
            Some(DurableQueryBudgetDimension::MaximumTimeRangeNanoseconds)
        },
        None => None,
    };
    DurableOperationTerminalError::QueryFailure(DurableQueryExportFailure::new(
        code,
        limiting_budget,
    ))
}

fn query_failure_from_durable(
    failure: positron_governance::DurableQueryExportFailure,
) -> QueryFailure {
    use positron_governance::{DurableQueryBudgetDimension, DurableQueryExportFailureCode};

    let code = match failure.code() {
        DurableQueryExportFailureCode::Unauthorized => QueryFailureCode::Unauthorized,
        DurableQueryExportFailureCode::IdempotencyConflict => QueryFailureCode::IdempotencyConflict,
        DurableQueryExportFailureCode::InvalidBudget => QueryFailureCode::InvalidBudget,
        DurableQueryExportFailureCode::BudgetExhausted => QueryFailureCode::BudgetExhausted,
        DurableQueryExportFailureCode::InvalidCursor => QueryFailureCode::InvalidCursor,
        DurableQueryExportFailureCode::SnapshotExpired => QueryFailureCode::SnapshotExpired,
        DurableQueryExportFailureCode::AuthorizationChanged => {
            QueryFailureCode::AuthorizationChanged
        },
        DurableQueryExportFailureCode::Cancelled => QueryFailureCode::Cancelled,
        DurableQueryExportFailureCode::ResourceAdmissionRefused => {
            QueryFailureCode::ResourceAdmissionRefused
        },
        DurableQueryExportFailureCode::ResourceExhausted => QueryFailureCode::ResourceExhausted,
        DurableQueryExportFailureCode::UnsupportedQuery => QueryFailureCode::UnsupportedQuery,
        DurableQueryExportFailureCode::StoreUnavailable => QueryFailureCode::StoreUnavailable,
        DurableQueryExportFailureCode::MalformedPersistentData => {
            QueryFailureCode::MalformedPersistentData
        },
        DurableQueryExportFailureCode::Internal => QueryFailureCode::Internal,
    };
    match failure.limiting_budget() {
        Some(DurableQueryBudgetDimension::ScannedBytes) => {
            QueryFailure::for_budget(code, crate::QueryBudgetDimension::ScannedBytes)
        },
        Some(DurableQueryBudgetDimension::DecodedRecords) => {
            QueryFailure::for_budget(code, crate::QueryBudgetDimension::DecodedRecords)
        },
        Some(DurableQueryBudgetDimension::OutputRows) => {
            QueryFailure::for_budget(code, crate::QueryBudgetDimension::OutputRows)
        },
        Some(DurableQueryBudgetDimension::OutputBytes) => {
            QueryFailure::for_budget(code, crate::QueryBudgetDimension::OutputBytes)
        },
        Some(DurableQueryBudgetDimension::MemoryBytes) => {
            QueryFailure::for_budget(code, crate::QueryBudgetDimension::MemoryBytes)
        },
        Some(DurableQueryBudgetDimension::CpuWorkUnits) => {
            QueryFailure::for_budget(code, crate::QueryBudgetDimension::CpuWorkUnits)
        },
        Some(DurableQueryBudgetDimension::WallSeconds) => {
            QueryFailure::for_budget(code, crate::QueryBudgetDimension::WallSeconds)
        },
        Some(DurableQueryBudgetDimension::MaximumTimeRangeNanoseconds) => QueryFailure::for_budget(
            code,
            crate::QueryBudgetDimension::MaximumTimeRangeNanoseconds,
        ),
        Some(DurableQueryBudgetDimension::None) | None => QueryFailure::new(code),
    }
}

impl<'kernel, 'catalog, 'ledger> crate::QueryService<'kernel, 'catalog, 'ledger> {
    /// Runs an export beneath the Catalog-backed Durable Operation lifecycle.
    ///
    /// The operation is accepted before Query Snapshot admission, remains
    /// running after an acknowledgement-ambiguous output failure, and reaches
    /// a terminal durable state only after a truthful manifest exists.
    #[allow(clippy::too_many_arguments)]
    pub fn export_pipeline_as_operation(
        &self,
        catalog: &'catalog positron_kernel::Catalog<'kernel>,
        signer: &positron_kernel::ExportManifestSigner,
        context: positron_governance::AuthorizedContext,
        idempotency: positron_governance::AdministrativeIdempotencyKey,
        source: &str,
        budget: crate::QueryBudget,
        destination_name: &str,
        sink: &mut dyn ExportSink,
    ) -> Result<DurableExportReceipt, QueryFailure> {
        self.export_as_operation(
            catalog,
            signer,
            context,
            idempotency,
            source,
            budget,
            destination_name,
            crate::query_service::QueryLanguage::Pipeline,
            sink,
        )
    }

    /// Runs a bounded read-only SQL export through the same durable executor
    /// as a native pipeline export.
    #[allow(clippy::too_many_arguments)]
    pub fn export_sql_as_operation(
        &self,
        catalog: &'catalog positron_kernel::Catalog<'kernel>,
        signer: &positron_kernel::ExportManifestSigner,
        context: positron_governance::AuthorizedContext,
        idempotency: positron_governance::AdministrativeIdempotencyKey,
        source: &str,
        budget: crate::QueryBudget,
        destination_name: &str,
        sink: &mut dyn ExportSink,
    ) -> Result<DurableExportReceipt, QueryFailure> {
        self.export_as_operation(
            catalog,
            signer,
            context,
            idempotency,
            source,
            budget,
            destination_name,
            crate::query_service::QueryLanguage::Sql,
            sink,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn export_as_operation(
        &self,
        catalog: &'catalog positron_kernel::Catalog<'kernel>,
        signer: &positron_kernel::ExportManifestSigner,
        context: positron_governance::AuthorizedContext,
        idempotency: positron_governance::AdministrativeIdempotencyKey,
        source: &str,
        budget: crate::QueryBudget,
        destination_name: &str,
        language: crate::query_service::QueryLanguage,
        sink: &mut dyn ExportSink,
    ) -> Result<DurableExportReceipt, QueryFailure> {
        if signer.identity() != catalog_integrity_identity(catalog)? {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let tenant = self.validate_current_query_context(context)?;
        let existing = positron_governance::DurableOperationAdministration::inspect_by_idempotency(
            catalog,
            idempotency,
        )
        .map_err(map_operation_failure)?;
        let (destination, generation, accepted_at) = match existing {
            Some(operation) => {
                if operation.kind() != positron_governance::DurableOperationKind::QueryExport
                    || operation.request().principal() != context.principal_id()
                    || operation.request().applicable_tenant() != Some(tenant)
                {
                    return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
                }
                let destination = ExportDestination(
                    operation
                        .target_identity()
                        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?,
                );
                (
                    destination,
                    operation.request().accepted_generation(),
                    operation.request().accepted_at_unix_seconds(),
                )
            },
            None => (
                self.resolve_export_destination_for_tenant(tenant, destination_name)?,
                self.current_query_catalog(context)?.2,
                self.now()?,
            ),
        };
        let request_digest =
            self.export_request_digest(source, budget, destination_name, destination, language)?;
        let request = positron_governance::DurableOperationRequest::query_export(
            context.principal_id(),
            tenant,
            idempotency,
            destination.identity(),
            generation,
            accepted_at,
            request_digest,
        )
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let accepted = positron_governance::DurableOperationAdministration::accept_query_export(
            catalog, context, request,
        )
        .map_err(map_operation_failure)?;
        let operation_id = accepted.operation_id();
        let output_request = positron_kernel::ExportOutputRequest::new(
            operation_id.to_bytes(),
            tenant,
            destination.identity(),
            request_digest,
        )
        .map_err(KernelExportSink::map_output_failure)?;
        let recovered_output =
            positron_kernel::ExportOutput::recover_initial(catalog, output_request, self.now()?)
                .map_err(KernelExportSink::map_output_failure)?;
        if accepted.status() == positron_governance::DurableOperationStatus::Failed {
            if let Some(failure) = accepted
                .terminal_error()
                .and_then(positron_governance::DurableOperationTerminalError::query_failure)
            {
                return Err(query_failure_from_durable(failure));
            }
            let output =
                recovered_output.ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            return self.resolve_durable_export(
                catalog,
                context,
                operation_id,
                output.identity(),
                destination_name,
            );
        }
        if accepted.status() == positron_governance::DurableOperationStatus::Succeeded {
            let output = recovered_output
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
            return self.resolve_durable_export(
                catalog,
                context,
                operation_id,
                output.identity(),
                destination_name,
            );
        }
        if accepted.status() == positron_governance::DurableOperationStatus::Running
            && recovered_output.is_some()
        {
            return self.resume_as_durable_export(
                catalog,
                signer,
                context,
                operation_id,
                source,
                budget,
                destination_name,
                language,
                sink,
            );
        }
        if accepted.status() == positron_governance::DurableOperationStatus::Pending {
            let _running = positron_governance::DurableOperationAdministration::begin_query_export(
                catalog,
                context,
                operation_id,
                self.now()?,
            )
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        }
        let mut kernel_sink = KernelExportSink {
            catalog,
            tenant,
            destination,
            request_digest,
            clock: Arc::clone(&self.clock),
            output: None,
            observer: sink,
            operation_id,
            context,
            first_batch_started: false,
        };
        let query = match self.plan(context, source, budget, language) {
            Ok(query) => query,
            Err(failure) => {
                positron_governance::DurableOperationAdministration::fail_query_export(
                    catalog,
                    context,
                    operation_id,
                    self.now()?,
                    durable_query_failure(&failure),
                )
                .map_err(map_operation_failure)?;
                return Err(failure);
            },
        };
        let mut manifest = match self.export_planned_query(
            context,
            query,
            destination,
            request_digest,
            &mut kernel_sink,
        ) {
            Ok(manifest) => manifest,
            Err(failure) => {
                if !kernel_sink.has_durable_batch()
                    && !matches!(
                        failure.code(),
                        QueryFailureCode::StoreUnavailable | QueryFailureCode::Cancelled
                    )
                {
                    positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        durable_query_failure(&failure),
                    )
                    .map_err(map_operation_failure)?;
                }
                return Err(failure);
            },
        };
        if manifest.output_identity().is_none() {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        let signature = signer
            .sign(&manifest.payload()?)
            .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
        manifest.signature = Some(signature);
        let persisted_manifest = durable_manifest_bytes(&manifest)?;
        kernel_sink.persist_manifest(&persisted_manifest)?;
        match manifest.terminal() {
            ExportTerminal::Complete(_) => {
                positron_governance::DurableOperationAdministration::succeed_query_export(
                    catalog,
                    context,
                    operation_id,
                    self.now()?,
                )
            },
            ExportTerminal::Incomplete(_) => {
                positron_governance::DurableOperationAdministration::fail_published_query_export(
                    catalog,
                    context,
                    operation_id,
                    self.now()?,
                    positron_governance::DurableOperationTerminalError::HandlerRejected,
                )
            },
        }
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        Ok(DurableExportReceipt {
            operation_id,
            manifest,
        })
    }

    /// Reattaches to a completed durable export after process restart and
    /// verifies its protected, signed terminal manifest before returning it.
    pub fn resolve_durable_export(
        &self,
        catalog: &'catalog positron_kernel::Catalog<'kernel>,
        context: positron_governance::AuthorizedContext,
        operation_id: positron_governance::OperationId,
        output_identity: [u8; 16],
        destination_name: &str,
    ) -> Result<DurableExportReceipt, QueryFailure> {
        let destination = self.resolve_export_destination(context, destination_name)?;
        let tenant = self.validate_current_query_context(context)?;
        let operation =
            positron_governance::DurableOperationAdministration::inspect(catalog, operation_id)
                .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?;
        if operation.kind() != positron_governance::DurableOperationKind::QueryExport
            || operation.request().principal() != context.principal_id()
            || operation.target_identity() != Some(destination.identity())
        {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let output = positron_kernel::ExportOutput::reopen(catalog, output_identity)
            .map_err(KernelExportSink::map_output_failure)?;
        if operation.request().applicable_tenant() != Some(tenant)
            || output.binding().operation_id() != operation_id.to_bytes()
            || output.binding().tenant() != tenant
            || output.binding().destination() != destination.identity()
            || operation.request().query_export_request_digest()
                != Some(output.binding().request_digest())
        {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let manifest_bytes = output
            .read_manifest(catalog, self.now()?)
            .map_err(KernelExportSink::map_output_failure)?
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
        let manifest = durable_manifest_from_bytes(&manifest_bytes)?;
        if manifest.destination() != destination
            || manifest.output_identity() != Some(output_identity)
            || manifest.request_digest() != output.binding().request_digest()
            || manifest.snapshot().identity() != output.binding().snapshot_identity()
            || manifest.snapshot().generation() != output.binding().snapshot_generation()
            || manifest.snapshot().frontier() != output.binding().snapshot_frontier()
        {
            return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
        }
        self.verify_export_manifest(&manifest)?;
        verify_durable_export_signature(catalog, &manifest)?;
        match operation.status() {
            positron_governance::DurableOperationStatus::Running => {
                let _transition = match manifest.terminal() {
                    ExportTerminal::Complete(_) => {
                        positron_governance::DurableOperationAdministration::succeed_query_export(
                            catalog,
                            context,
                            operation_id,
                            self.now()?,
                        )
                    },
                    ExportTerminal::Incomplete(_) => {
                        positron_governance::DurableOperationAdministration::fail_published_query_export(
                            catalog,
                            context,
                            operation_id,
                            self.now()?,
                            positron_governance::DurableOperationTerminalError::HandlerRejected,
                        )
                    },
                }
                .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
            },
            positron_governance::DurableOperationStatus::Succeeded
            | positron_governance::DurableOperationStatus::Failed => {},
            positron_governance::DurableOperationStatus::Pending
            | positron_governance::DurableOperationStatus::Cancelled => {
                return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
            },
        }
        Ok(DurableExportReceipt {
            operation_id,
            manifest,
        })
    }

    /// Continues an interrupted durable export from its kernel-protected
    /// checkpoint. The cursor reconstructs the original snapshot and
    /// cumulative budget; current tenant authorization is checked again by
    /// the ordinary Query resume seam before any new protected batch is
    /// written.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_durable_export(
        &self,
        catalog: &'catalog positron_kernel::Catalog<'kernel>,
        signer: &positron_kernel::ExportManifestSigner,
        context: positron_governance::AuthorizedContext,
        operation_id: positron_governance::OperationId,
        source: &str,
        budget: crate::QueryBudget,
        destination_name: &str,
        sink: &mut dyn ExportSink,
    ) -> Result<DurableExportReceipt, QueryFailure> {
        self.resume_as_durable_export(
            catalog,
            signer,
            context,
            operation_id,
            source,
            budget,
            destination_name,
            crate::query_service::QueryLanguage::Pipeline,
            sink,
        )
    }

    /// Resumes an interrupted bounded SQL export through its original cursor,
    /// Snapshot Lease, and cumulative budget.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_sql_durable_export(
        &self,
        catalog: &'catalog positron_kernel::Catalog<'kernel>,
        signer: &positron_kernel::ExportManifestSigner,
        context: positron_governance::AuthorizedContext,
        operation_id: positron_governance::OperationId,
        source: &str,
        budget: crate::QueryBudget,
        destination_name: &str,
        sink: &mut dyn ExportSink,
    ) -> Result<DurableExportReceipt, QueryFailure> {
        self.resume_as_durable_export(
            catalog,
            signer,
            context,
            operation_id,
            source,
            budget,
            destination_name,
            crate::query_service::QueryLanguage::Sql,
            sink,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resume_as_durable_export(
        &self,
        catalog: &'catalog positron_kernel::Catalog<'kernel>,
        signer: &positron_kernel::ExportManifestSigner,
        context: positron_governance::AuthorizedContext,
        operation_id: positron_governance::OperationId,
        source: &str,
        budget: crate::QueryBudget,
        destination_name: &str,
        language: crate::query_service::QueryLanguage,
        sink: &mut dyn ExportSink,
    ) -> Result<DurableExportReceipt, QueryFailure> {
        if signer.identity() != catalog_integrity_identity(catalog)? {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let operation =
            positron_governance::DurableOperationAdministration::inspect(catalog, operation_id)
                .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?;
        if operation.kind() != positron_governance::DurableOperationKind::QueryExport
            || operation.request().principal() != context.principal_id()
        {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let tenant = match self.validate_current_query_context(context) {
            Ok(tenant) => tenant,
            Err(failure) => {
                let terminal_failure = match failure.code() {
                    QueryFailureCode::StoreUnavailable => failure,
                    _ => QueryFailure::new(QueryFailureCode::AuthorizationChanged),
                };
                if operation.status() == positron_governance::DurableOperationStatus::Running {
                    positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        durable_query_failure(&terminal_failure),
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                }
                return Err(terminal_failure);
            },
        };
        if operation.request().applicable_tenant() != Some(tenant) {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let accepted_destination = ExportDestination(
            operation
                .target_identity()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?,
        );
        let current_request_digest = self.export_request_digest(
            source,
            budget,
            destination_name,
            accepted_destination,
            language,
        )?;
        let request_digest = current_request_digest;
        if operation.request().query_export_request_digest() != Some(request_digest) {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        if operation.status() == positron_governance::DurableOperationStatus::Failed
            && let Some(failure) = operation
                .terminal_error()
                .and_then(positron_governance::DurableOperationTerminalError::query_failure)
        {
            return Err(query_failure_from_durable(failure));
        }
        let configured_destination =
            match self.resolve_export_destination_for_tenant(tenant, destination_name) {
                Ok(destination) if destination == accepted_destination => Some(destination),
                Ok(_) => None,
                Err(failure) if failure.code() == QueryFailureCode::Unauthorized => None,
                Err(failure) => return Err(failure),
            };
        let destination = match configured_destination {
            Some(destination) => destination,
            None => {
                let failure = QueryFailure::new(QueryFailureCode::AuthorizationChanged);
                if operation.status() == positron_governance::DurableOperationStatus::Running {
                    positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        durable_query_failure(&failure),
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                }
                return Err(failure);
            },
        };
        let mut output = match positron_kernel::ExportOutput::recover_initial(
            catalog,
            positron_kernel::ExportOutputRequest::new(
                operation_id.to_bytes(),
                tenant,
                destination.identity(),
                request_digest,
            )
            .map_err(KernelExportSink::map_output_failure)?,
            self.now()?,
        ) {
            Ok(Some(output)) => output,
            Ok(None) => return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable)),
            Err(error) => {
                let failure = KernelExportSink::map_output_failure(error);
                if error.code() == positron_kernel::ExportOutputFailureCode::Expired
                    && operation.status() == positron_governance::DurableOperationStatus::Running
                {
                    positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        durable_query_failure(&failure),
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                }
                return Err(failure);
            },
        };
        let binding = output.binding();
        if binding.tenant() != tenant
            || binding.destination() != destination.identity()
            || binding.request_digest() != request_digest
        {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let output_boundary_crossed = match operation.phase() {
            positron_governance::DurableOperationPhase::Preflight => false,
            positron_governance::DurableOperationPhase::Draining => true,
            _ => return Err(QueryFailure::new(QueryFailureCode::AuthorizationChanged)),
        };
        let manifest = match output.read_manifest(catalog, self.now()?) {
            Ok(manifest) => manifest,
            Err(error) => {
                let failure = KernelExportSink::map_output_failure(error);
                if error.code() == positron_kernel::ExportOutputFailureCode::Expired
                    && operation.status() == positron_governance::DurableOperationStatus::Running
                {
                    positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        durable_query_failure(&failure),
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                }
                return Err(failure);
            },
        };
        if manifest.is_some() {
            return self.resolve_durable_export(
                catalog,
                context,
                operation_id,
                output.identity(),
                destination_name,
            );
        }
        let terminal_evidence = output
            .recover_terminal_orphan(catalog, self.now()?)
            .map_err(KernelExportSink::map_output_failure)?;
        let terminal_evidence = match terminal_evidence {
            Some(evidence) => Some(evidence),
            None => output
                .read_terminal_evidence(catalog, self.now()?)
                .map_err(KernelExportSink::map_output_failure)?,
        };
        if let Some(evidence) = terminal_evidence {
            if !output_boundary_crossed {
                return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
            }
            let terminal = terminal_from_evidence(&evidence)?;
            let mut manifest = self.manifest_from_durable_terminal(
                catalog,
                &output,
                self.now()?,
                destination,
                request_digest,
                budget,
                terminal,
            )?;
            let signature = signer
                .sign(&manifest.payload()?)
                .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
            manifest.signature = Some(signature);
            let mut kernel_sink = KernelExportSink {
                catalog,
                tenant,
                destination,
                request_digest,
                clock: Arc::clone(&self.clock),
                output: Some(output),
                observer: sink,
                operation_id,
                context,
                first_batch_started: true,
            };
            kernel_sink.persist_manifest(&durable_manifest_bytes(&manifest)?)?;
            match (operation.status(), manifest.terminal()) {
                (
                    positron_governance::DurableOperationStatus::Running,
                    ExportTerminal::Complete(_),
                ) => {
                    positron_governance::DurableOperationAdministration::succeed_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                },
                (
                    positron_governance::DurableOperationStatus::Running,
                    ExportTerminal::Incomplete(_),
                ) => {
                    positron_governance::DurableOperationAdministration::fail_published_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        positron_governance::DurableOperationTerminalError::HandlerRejected,
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                },
                (
                    positron_governance::DurableOperationStatus::Succeeded,
                    ExportTerminal::Complete(_),
                )
                | (
                    positron_governance::DurableOperationStatus::Failed,
                    ExportTerminal::Incomplete(_),
                ) => {},
                (positron_governance::DurableOperationStatus::Cancelled, _) => {
                    return Err(QueryFailure::new(QueryFailureCode::Cancelled));
                },
                _ => return Err(QueryFailure::new(QueryFailureCode::AuthorizationChanged)),
            }
            return Ok(DurableExportReceipt {
                operation_id,
                manifest,
            });
        }
        match operation.status() {
            positron_governance::DurableOperationStatus::Running => {},
            positron_governance::DurableOperationStatus::Cancelled => {
                return Err(QueryFailure::new(QueryFailureCode::Cancelled));
            },
            _ => return Err(QueryFailure::new(QueryFailureCode::AuthorizationChanged)),
        }
        let checkpoint = output
            .latest_checkpoint(catalog, self.now()?)
            .map_err(KernelExportSink::map_output_failure)?;
        let (cursor, batches) = match checkpoint {
            Some(checkpoint) => {
                let cursor = checkpoint
                    .continuation_cursor()
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                let cursor = QueryCursor::from_bytes(&cursor)
                    .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
                let receipts = output
                    .batch_receipts(catalog, self.now()?)
                    .map_err(KernelExportSink::map_output_failure)?;
                if receipts.last().copied() != Some(checkpoint.receipt()) {
                    return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
                }
                let mut batches = Vec::new();
                batches
                    .try_reserve_exact(receipts.len())
                    .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
                for receipt in receipts {
                    batches.push(ExportBatch {
                        sequence: receipt.sequence(),
                        digest: receipt.digest(),
                    });
                }
                (cursor, batches)
            },
            None => {
                let cursor = output
                    .initial_cursor(catalog, self.now()?)
                    .map_err(KernelExportSink::map_output_failure)?
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                let cursor = QueryCursor::from_bytes(&cursor)
                    .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
                (cursor, Vec::new())
            },
        };
        let stream = match self.resume(context, &cursor) {
            Ok(stream) => stream,
            Err(failure) => {
                if failure.code() != QueryFailureCode::StoreUnavailable {
                    positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        durable_query_failure(&failure),
                    )
                    .map_err(map_operation_failure)?;
                }
                return Err(failure);
            },
        };
        let mut kernel_sink = KernelExportSink {
            catalog,
            tenant,
            destination,
            request_digest,
            clock: Arc::clone(&self.clock),
            output: Some(output),
            observer: sink,
            operation_id,
            context,
            first_batch_started: output_boundary_crossed,
        };
        let mut manifest = self.export_stream(
            context,
            stream,
            batches,
            destination,
            request_digest,
            &mut kernel_sink,
        )?;
        let signature = signer
            .sign(&manifest.payload()?)
            .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
        manifest.signature = Some(signature);
        kernel_sink.persist_manifest(&durable_manifest_bytes(&manifest)?)?;
        match manifest.terminal() {
            ExportTerminal::Complete(_) => {
                positron_governance::DurableOperationAdministration::succeed_query_export(
                    catalog,
                    context,
                    operation_id,
                    self.now()?,
                )
            },
            ExportTerminal::Incomplete(_) => {
                positron_governance::DurableOperationAdministration::fail_published_query_export(
                    catalog,
                    context,
                    operation_id,
                    self.now()?,
                    positron_governance::DurableOperationTerminalError::HandlerRejected,
                )
            },
        }
        .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
        Ok(DurableExportReceipt {
            operation_id,
            manifest,
        })
    }

    /// Verifies that a returned manifest still binds its protected destination,
    /// ordered batch receipts, terminal state, and Result Digest.
    pub fn verify_export_manifest(&self, manifest: &ExportManifest) -> Result<(), QueryFailure> {
        let payload = manifest.payload()?;
        self.ledger
            .control_tokens()
            .verify_export_manifest(MANIFEST_DOMAIN, &payload, manifest.authentication)
            .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))
    }

    /// Verifies a manifest only for the exact protected destination configured
    /// when the export was accepted.
    pub fn verify_export_manifest_for_destination(
        &self,
        manifest: &ExportManifest,
        destination: ExportDestination,
    ) -> Result<(), QueryFailure> {
        if manifest.destination() != destination {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        self.verify_export_manifest(manifest)
    }

    fn resolve_export_destination(
        &self,
        context: positron_governance::AuthorizedContext,
        name: &str,
    ) -> Result<ExportDestination, QueryFailure> {
        let tenant = self.validate_current_query_context(context)?;
        self.resolve_export_destination_for_tenant(tenant, name)
    }

    fn resolve_export_destination_for_tenant(
        &self,
        tenant: positron_domain::identity::TenantId,
        name: &str,
    ) -> Result<ExportDestination, QueryFailure> {
        let resolver = self
            .export_destination_resolver
            .as_ref()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?;
        let identity = resolver
            .resolve(tenant, name)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?;
        ExportDestination::configured(identity)
    }

    /// Computes the current Query-export idempotency intent. It binds the
    /// caller-supplied destination name as well as the configured protected
    /// identity, language, cumulative budget, and source; global durable
    /// operation and governance identities remain unchanged.
    fn export_request_digest(
        &self,
        source: &str,
        budget: crate::QueryBudget,
        destination_name: &str,
        destination: ExportDestination,
        language: crate::query_service::QueryLanguage,
    ) -> Result<[u8; 32], QueryFailure> {
        let destination_name_length = u16::try_from(destination_name.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(
                source
                    .len()
                    .checked_add(destination_name.len())
                    .and_then(|length| length.checked_add(destination.identity().len()))
                    .and_then(|length| length.checked_add(66))
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?,
            )
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        payload.extend_from_slice(&destination.identity());
        payload.extend_from_slice(&destination_name_length.to_be_bytes());
        payload.extend_from_slice(destination_name.as_bytes());
        payload.push(match language {
            crate::query_service::QueryLanguage::Pipeline => 1,
            crate::query_service::QueryLanguage::Sql => 2,
        });
        for limit in [
            budget.scanned_bytes(),
            budget.decoded_records(),
            budget.output_rows(),
            budget.output_bytes(),
            budget.memory_bytes(),
            budget.cpu_work_units(),
            budget.wall_seconds(),
            budget.maximum_time_range_nanoseconds(),
        ] {
            payload.extend_from_slice(&limit.to_be_bytes());
        }
        payload.extend_from_slice(source.as_bytes());
        self.ledger
            .control_tokens()
            .digest_query_cursor(REQUEST_DOMAIN, &payload)
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
    }

    fn export_planned_query(
        &self,
        context: positron_governance::AuthorizedContext,
        query: crate::PlannedQuery<'kernel>,
        destination: ExportDestination,
        request_digest: [u8; 32],
        sink: &mut dyn ExportSink,
    ) -> Result<ExportManifest, QueryFailure> {
        self.export_stream(
            context,
            self.execute_page(query)?,
            Vec::new(),
            destination,
            request_digest,
            sink,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn manifest_from_durable_terminal(
        &self,
        catalog: &positron_kernel::Catalog<'_>,
        output: &positron_kernel::ExportOutput,
        observed_at: u64,
        destination: ExportDestination,
        request_digest: [u8; 32],
        budget: crate::QueryBudget,
        terminal: ExportTerminal,
    ) -> Result<ExportManifest, QueryFailure> {
        let receipts = output
            .batch_receipts(catalog, observed_at)
            .map_err(KernelExportSink::map_output_failure)?;
        let mut batches = Vec::new();
        batches
            .try_reserve_exact(receipts.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        for receipt in receipts {
            batches.push(ExportBatch {
                sequence: receipt.sequence(),
                digest: receipt.digest(),
            });
        }
        let terminal_matches_batches = match batches.last() {
            Some(last) => terminal.stats().last_sequence() == Some(last.sequence()),
            None => terminal.stats().last_sequence().is_none(),
        };
        if !terminal_matches_batches || terminal.stats().cumulative_budget() != budget {
            return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
        }
        let snapshot = crate::ResultSnapshot::new(
            output.binding().snapshot_identity(),
            output.binding().snapshot_generation(),
            output.binding().snapshot_frontier(),
        );
        let payload = manifest_payload(
            destination,
            Some(output.identity()),
            request_digest,
            snapshot,
            &batches,
            &terminal,
        )?;
        let authentication = self
            .ledger
            .control_tokens()
            .authenticate_export_manifest(MANIFEST_DOMAIN, &payload)
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        Ok(ExportManifest {
            destination,
            output_identity: Some(output.identity()),
            request_digest,
            snapshot,
            batches,
            terminal,
            authentication,
            signature: None,
        })
    }

    fn export_stream(
        &self,
        context: positron_governance::AuthorizedContext,
        mut stream: crate::QueryStream<'ledger>,
        mut batches: Vec<ExportBatch>,
        destination: ExportDestination,
        request_digest: [u8; 32],
        sink: &mut dyn ExportSink,
    ) -> Result<ExportManifest, QueryFailure> {
        if batches.len() > MAX_MANIFEST_BATCHES
            || batches
                .iter()
                .enumerate()
                .any(|(index, batch)| u64::try_from(index).ok() != Some(batch.sequence()))
        {
            return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
        }
        let mut pending_batch = None;
        let mut snapshot = None;
        let mut terminal_evidence_persisted = false;
        let terminal = loop {
            let event = stream
                .next()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            match event {
                QueryEvent::Header(header) => {
                    if snapshot.is_some_and(|bound| bound != header.snapshot()) {
                        return Err(QueryFailure::new(QueryFailureCode::Internal));
                    }
                    snapshot = Some(header.snapshot());
                    sink.start(&header)?;
                },
                QueryEvent::Batch(batch) => {
                    if pending_batch.replace(batch).is_some() {
                        return Err(QueryFailure::new(QueryFailureCode::Internal));
                    }
                },
                QueryEvent::Terminal(QueryTerminal::Complete(stats)) => {
                    if let Some(batch) = pending_batch.take() {
                        let expected = u64::try_from(batches.len())
                            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
                        if batch.sequence() != expected || batches.len() == MAX_MANIFEST_BATCHES {
                            return Err(QueryFailure::new(QueryFailureCode::Internal));
                        }
                        if let Err(failure) = sink.write_terminal_batch(
                            destination,
                            &batch,
                            &ExportTerminal::Complete(stats),
                        ) {
                            stream.retain_for_durable_recovery();
                            return Err(failure);
                        }
                        terminal_evidence_persisted = true;
                        batches.push(ExportBatch {
                            sequence: batch.sequence(),
                            digest: batch.digest(),
                        });
                    }
                    break ExportTerminal::Complete(stats);
                },
                QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)) => {
                    if let Some(batch) = pending_batch.take() {
                        let expected = u64::try_from(batches.len())
                            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
                        if batch.sequence() != expected || batches.len() == MAX_MANIFEST_BATCHES {
                            return Err(QueryFailure::new(QueryFailureCode::Internal));
                        }
                        if let Err(failure) = sink.write_terminal_batch(
                            destination,
                            &batch,
                            &ExportTerminal::Incomplete(incomplete.clone()),
                        ) {
                            stream.retain_for_durable_recovery();
                            return Err(failure);
                        }
                        terminal_evidence_persisted = true;
                        batches.push(ExportBatch {
                            sequence: batch.sequence(),
                            digest: batch.digest(),
                        });
                    }
                    break ExportTerminal::Incomplete(incomplete);
                },
                QueryEvent::Terminal(QueryTerminal::Continued(cursor)) => {
                    let batch = pending_batch
                        .take()
                        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
                    let expected = u64::try_from(batches.len())
                        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
                    if batch.sequence() != expected || batches.len() == MAX_MANIFEST_BATCHES {
                        return Err(QueryFailure::new(QueryFailureCode::Internal));
                    }
                    sink.write_batch(destination, &batch, Some(&cursor))?;
                    batches.push(ExportBatch {
                        sequence: batch.sequence(),
                        digest: batch.digest(),
                    });
                    stream = self.resume(context, &cursor)?;
                },
            }
        };
        if !terminal_evidence_persisted {
            sink.persist_terminal(&terminal)?;
        }
        sink.cross_output_boundary()?;
        let output_identity = sink.output_identity();
        let snapshot = snapshot.ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let payload = manifest_payload(
            destination,
            output_identity,
            request_digest,
            snapshot,
            &batches,
            &terminal,
        )?;
        let authentication = self
            .ledger
            .control_tokens()
            .authenticate_export_manifest(MANIFEST_DOMAIN, &payload)
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        Ok(ExportManifest {
            destination,
            output_identity,
            request_digest,
            snapshot,
            batches,
            terminal,
            authentication,
            signature: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExportDestination, ExportTerminal, durable_manifest_from_bytes, manifest_payload,
        terminal_evidence_bytes, terminal_from_evidence,
    };
    use crate::stream::QueryCounters;
    use crate::{
        QueryBudget, QueryFailure, QueryFailureCode, QueryIncomplete, QueryStats, ResultSnapshot,
    };

    #[test]
    fn terminal_evidence_round_trips_an_incomplete_terminal() {
        let budget = QueryBudget::new(10, 11, 12, 13, 14, 16)
            .expect("fixture budget")
            .with_cpu_work_units(15)
            .expect("fixture cpu budget");
        let terminal = ExportTerminal::Incomplete(QueryIncomplete::new(
            QueryFailure::new(QueryFailureCode::BudgetExhausted),
            QueryStats::new(
                QueryCounters {
                    records: 1,
                    scanned_bytes: 2,
                    decoded_records: 3,
                    output_bytes: 4,
                    memory_peak_bytes: 5,
                    cpu_work_units: 6,
                    wall_seconds: 7,
                },
                Some(0),
                [0x71; 32],
                budget,
                0,
                0,
            ),
        ));

        let evidence = terminal_evidence_bytes(&terminal).expect("bounded evidence");
        assert_eq!(
            terminal_from_evidence(&evidence).expect("authenticated format"),
            terminal
        );
    }

    #[test]
    fn durable_terminal_decoder_rejects_invalid_tags_and_trailing_bytes() {
        let terminal = ExportTerminal::Complete(QueryStats::new(
            QueryCounters {
                records: 0,
                scanned_bytes: 0,
                decoded_records: 0,
                output_bytes: 0,
                memory_peak_bytes: 0,
                cpu_work_units: 0,
                wall_seconds: 0,
            },
            None,
            [0x61; 32],
            QueryBudget::new(10, 11, 12, 13, 14, 16).expect("fixture budget"),
            0,
            0,
        ));
        let evidence = terminal_evidence_bytes(&terminal).expect("bounded evidence");

        let mut invalid_tag = evidence.clone();
        invalid_tag[8] = 3;
        assert_eq!(
            terminal_from_evidence(&invalid_tag)
                .expect_err("unknown terminal tag")
                .code(),
            QueryFailureCode::MalformedPersistentData
        );

        let mut trailing = evidence;
        trailing.push(0);
        assert_eq!(
            terminal_from_evidence(&trailing)
                .expect_err("trailing durable bytes")
                .code(),
            QueryFailureCode::MalformedPersistentData
        );
        assert_eq!(
            durable_manifest_from_bytes(b"POSQEM01")
                .expect_err("truncated manifest")
                .code(),
            QueryFailureCode::MalformedPersistentData
        );
    }

    #[test]
    fn signed_manifest_payload_binds_the_complete_query_snapshot_descriptor() {
        let destination = ExportDestination::configured([0x11; 16]).expect("fixture destination");
        let snapshot = ResultSnapshot::new([0x22; 32], 7, 9);
        let budget = QueryBudget::new(1, 1, 1, 1, 1, 1).expect("fixture budget");
        let terminal = ExportTerminal::Complete(QueryStats::new(
            QueryCounters {
                records: 0,
                scanned_bytes: 0,
                decoded_records: 0,
                output_bytes: 0,
                memory_peak_bytes: 0,
                cpu_work_units: 0,
                wall_seconds: 0,
            },
            None,
            [0x33; 32],
            budget,
            0,
            0,
        ));

        let payload = manifest_payload(
            destination,
            Some([0x44; 16]),
            [0x55; 32],
            snapshot,
            &[],
            &terminal,
        )
        .expect("bounded manifest payload");

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x11; 16]);
        expected.push(1);
        expected.extend_from_slice(&[0x44; 16]);
        expected.extend_from_slice(&[0x55; 32]);
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&7_u64.to_be_bytes());
        expected.extend_from_slice(&9_u64.to_be_bytes());
        expected.extend_from_slice(&0_u16.to_be_bytes());
        expected.push(1);
        expected.extend_from_slice(&[0x33; 32]);
        assert_eq!(payload, expected);

        let signer = positron_kernel::ExportManifestSigner::from_seed(Box::new([0x66; 32]))
            .expect("fixture signer");
        let signature = signer.sign(&payload).expect("sign fixture payload");
        signature
            .verify(signer.identity(), &expected)
            .expect("independent canonical payload verifies");
        let mut substituted = expected;
        substituted[65] ^= 1;
        assert!(signature.verify(signer.identity(), &substituted).is_err());
    }
}
