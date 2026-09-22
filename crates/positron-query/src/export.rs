//! Bounded, authenticated export materialization over the native query stream.

use std::sync::Arc;

use crate::{
    QueryBatch, QueryCursor, QueryEvent, QueryFailure, QueryFailureCode, QueryHeader, QueryStats,
    QueryTerminal,
};

const REQUEST_DOMAIN: &[u8] = b"query-export-request-v1";
const MANIFEST_DOMAIN: &[u8] = b"query-export-manifest-v1";
const MAX_MANIFEST_BATCHES: usize = 1_024;
const MANIFEST_WIRE_MAGIC: &[u8; 8] = b"POSQEM01";

/// Immutable identity of the preconfigured protected output destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportDestination([u8; 16]);

impl ExportDestination {
    /// Validates one non-secret destination identity before execution starts.
    pub fn new(identity: [u8; 16]) -> Result<Self, QueryFailure> {
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
        let binding = positron_kernel::ExportOutputBinding::new(
            self.tenant,
            self.destination.identity(),
            self.request_digest,
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

fn durable_manifest_from_bytes(bytes: &[u8]) -> Result<ExportManifest, QueryFailure> {
    let mut offset = 0;
    if read_manifest_array::<8>(bytes, &mut offset)? != *MANIFEST_WIRE_MAGIC {
        return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
    }
    let destination = ExportDestination::new(read_manifest_array(bytes, &mut offset)?)?;
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

impl<'kernel, 'catalog, 'ledger> crate::QueryService<'kernel, 'catalog, 'ledger> {
    /// Executes a total-order pipeline as a bounded incremental export.
    ///
    /// Each sink acknowledgement follows the immutable Result Batch boundary;
    /// no transport disconnect can be treated as export completion.
    pub fn export_pipeline(
        &self,
        context: positron_governance::AuthorizedContext,
        source: &str,
        budget: crate::QueryBudget,
        destination: ExportDestination,
        sink: &mut dyn ExportSink,
    ) -> Result<ExportManifest, QueryFailure> {
        let request_digest = self.export_request_digest(source, budget, destination)?;
        let query = self.plan_pipeline(context, source, budget)?;
        self.export_planned_query(context, query, destination, request_digest, sink)
    }

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
        source: &str,
        budget: crate::QueryBudget,
        destination: ExportDestination,
        sink: &mut dyn ExportSink,
    ) -> Result<DurableExportReceipt, QueryFailure> {
        if signer.identity() != catalog_integrity_identity(catalog)? {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let request_digest = self.export_request_digest(source, budget, destination)?;
        let generation = self.current_query_catalog(context)?.2;
        let accepted_at = self.now()?;
        let mut key = [0_u8; 16];
        key.copy_from_slice(
            request_digest
                .get(..16)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
        );
        if key.iter().all(|byte| *byte == 0) {
            key[0] = 1;
        }
        let request = positron_governance::DurableOperationRequest::query_export(
            context.principal_id(),
            positron_governance::AdministrativeIdempotencyKey::new(key)
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
            destination.identity(),
            generation,
            accepted_at,
            request_digest,
        )
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let accepted = positron_governance::DurableOperationAdministration::accept_query_export(
            catalog, context, request,
        )
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let operation_id = accepted.operation_id();
        let _running = positron_governance::DurableOperationAdministration::begin_query_export(
            catalog,
            context,
            operation_id,
            self.now()?,
        )
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let tenant = self.validate_current_query_context(context)?;
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
        let query = match self.plan_pipeline(context, source, budget) {
            Ok(query) => query,
            Err(failure) => {
                let _ = positron_governance::DurableOperationAdministration::fail_query_export(
                    catalog,
                    context,
                    operation_id,
                    self.now()?,
                    positron_governance::DurableOperationTerminalError::HandlerRejected,
                );
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
                    let _ = positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        positron_governance::DurableOperationTerminalError::HandlerRejected,
                    );
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
                positron_governance::DurableOperationAdministration::fail_query_export(
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
        destination: ExportDestination,
    ) -> Result<DurableExportReceipt, QueryFailure> {
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
        if output.binding().tenant() != tenant
            || output.binding().destination() != destination.identity()
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
                        positron_governance::DurableOperationAdministration::fail_query_export(
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
        destination: ExportDestination,
        sink: &mut dyn ExportSink,
    ) -> Result<DurableExportReceipt, QueryFailure> {
        if signer.identity() != catalog_integrity_identity(catalog)? {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let request_digest = self.export_request_digest(source, budget, destination)?;
        let operation =
            positron_governance::DurableOperationAdministration::inspect(catalog, operation_id)
                .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?;
        if operation.kind() != positron_governance::DurableOperationKind::QueryExport
            || operation.request().principal() != context.principal_id()
            || operation.target_identity() != Some(destination.identity())
            || operation.request().query_export_request_digest() != Some(request_digest)
        {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let tenant = match self.validate_current_query_context(context) {
            Ok(tenant) => tenant,
            Err(failure) => {
                if operation.status() == positron_governance::DurableOperationStatus::Running {
                    positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        positron_governance::DurableOperationTerminalError::HandlerRejected,
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                }
                return Err(match failure.code() {
                    QueryFailureCode::StoreUnavailable => failure,
                    _ => QueryFailure::new(QueryFailureCode::AuthorizationChanged),
                });
            },
        };
        let output = positron_kernel::ExportOutput::find_for_request(
            catalog,
            tenant,
            destination.identity(),
            request_digest,
        )
        .map_err(KernelExportSink::map_output_failure)?
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
        let binding = output.binding();
        if binding.tenant() != tenant
            || binding.destination() != destination.identity()
            || binding.request_digest() != request_digest
        {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let manifest = match output.read_manifest(catalog, self.now()?) {
            Ok(manifest) => manifest,
            Err(error) => {
                if error.code() == positron_kernel::ExportOutputFailureCode::Expired
                    && operation.status() == positron_governance::DurableOperationStatus::Running
                {
                    positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        positron_governance::DurableOperationTerminalError::HandlerRejected,
                    )
                    .map_err(|_| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                }
                return Err(KernelExportSink::map_output_failure(error));
            },
        };
        if manifest.is_some() {
            return self.resolve_durable_export(
                catalog,
                context,
                operation_id,
                output.identity(),
                destination,
            );
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
                    let _ = positron_governance::DurableOperationAdministration::fail_query_export(
                        catalog,
                        context,
                        operation_id,
                        self.now()?,
                        positron_governance::DurableOperationTerminalError::HandlerRejected,
                    );
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
            first_batch_started: true,
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
                positron_governance::DurableOperationAdministration::fail_query_export(
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

    fn export_request_digest(
        &self,
        source: &str,
        budget: crate::QueryBudget,
        destination: ExportDestination,
    ) -> Result<[u8; 32], QueryFailure> {
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(source.len() + destination.identity().len() + 64)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        payload.extend_from_slice(&destination.identity());
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
                        sink.write_batch(destination, &batch, None)?;
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
                        sink.write_batch(destination, &batch, None)?;
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
    use super::{ExportDestination, ExportTerminal, manifest_payload};
    use crate::stream::QueryCounters;
    use crate::{QueryBudget, QueryStats, ResultSnapshot};

    #[test]
    fn signed_manifest_payload_binds_the_complete_query_snapshot_descriptor() {
        let destination = ExportDestination::new([0x11; 16]).expect("fixture destination");
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
