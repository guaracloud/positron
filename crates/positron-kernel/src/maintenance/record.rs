use super::*;

const RECORD_MAGIC: &[u8; 8] = b"PMTC0003";
const PREVIOUS_RECORD_MAGIC: &[u8; 8] = b"PMTC0002";

pub(super) fn encode_record(
    state: &TaskState,
) -> Result<MaintenanceTaskRecord, MaintenanceFailure> {
    let task = &state.task;
    let checkpoint_bytes = state
        .checkpoint
        .as_ref()
        .map_or(0, |checkpoint| checkpoint.opaque_progress.len());
    let capacity =
        encoded_record_capacity(task.inputs.len(), task.outputs.len(), checkpoint_bytes)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(&task.identity.to_bytes());
    bytes.push(class_code(task.class));
    encode_scope(&mut bytes, task.scope);
    bytes.push(trigger_code(task.trigger));
    bytes.push(u8::from(task.emergency_compaction));
    bytes.push(priority_code(task.priority()));
    push_u64(&mut bytes, task.preconditions.catalog_generation);
    push_u64(&mut bytes, task.preconditions.resource_generation);
    push_u64(&mut bytes, task.not_before);
    bytes.push(u8::try_from(task.inputs.len()).map_err(|_| MaintenanceFailure::CapacityExceeded)?);
    for input in &task.inputs {
        bytes.extend_from_slice(&input.to_bytes());
    }
    bytes.push(u8::try_from(task.outputs.len()).map_err(|_| MaintenanceFailure::CapacityExceeded)?);
    for output in &task.outputs {
        bytes.extend_from_slice(&output.to_bytes());
    }
    for dimension in ResourceDimension::ALL {
        push_u64(&mut bytes, task.reservations.get(dimension));
    }
    bytes.push(phase_code(state.phase));
    push_u64(&mut bytes, state.submitted_at);
    bytes.push(u8::from(state.pause_until.is_some()));
    push_u64(&mut bytes, state.pause_until.unwrap_or(0));
    bytes.push(u8::from(state.cancellation_requested));
    push_u64(&mut bytes, state.dispatches);
    bytes.push(u8::from(state.checkpoint.is_some()));
    if let Some(checkpoint) = &state.checkpoint {
        push_u64(&mut bytes, checkpoint.sequence);
        push_u32(&mut bytes, checkpoint.completed_inputs);
        push_u32(
            &mut bytes,
            u32::try_from(checkpoint.opaque_progress.len())
                .map_err(|_| MaintenanceFailure::CapacityExceeded)?,
        );
        bytes.extend_from_slice(&checkpoint.opaque_progress);
    }
    Ok(MaintenanceTaskRecord(bytes))
}

pub(super) fn encoded_record_capacity(
    inputs: usize,
    outputs: usize,
    checkpoint_bytes: usize,
) -> Result<usize, MaintenanceFailure> {
    let objects = inputs
        .checked_add(outputs)
        .ok_or(MaintenanceFailure::CapacityExceeded)?;
    RECORD_MAGIC
        .len()
        .checked_add(16 + 3 + 16 + 6 + 16 + 1 + 1 + 1 + 8 + 8 + 1 + 8)
        .and_then(|size| size.checked_add(objects.checked_mul(32)?))
        .and_then(|size| {
            size.checked_add(11 * 8 + 1 + 8 + 1 + 1 + 8 + 1 + 8 + 4 + 4 + checkpoint_bytes)
        })
        .ok_or(MaintenanceFailure::CapacityExceeded)
}

pub(super) fn decode_record(bytes: &[u8]) -> Result<TaskState, MaintenanceFailure> {
    let mut cursor = RecordCursor::new(bytes);
    let magic = cursor.take_exact(RECORD_MAGIC.len())?;
    let includes_not_before = if magic == RECORD_MAGIC {
        true
    } else if magic == PREVIOUS_RECORD_MAGIC {
        false
    } else {
        return Err(MaintenanceFailure::InvalidInput);
    };
    let identity = MaintenanceTaskId::new(cursor.array_16()?)?;
    let class = class_from_code(cursor.byte()?)?;
    let scope = decode_scope(&mut cursor)?;
    let trigger = trigger_from_code(cursor.byte()?)?;
    let emergency_compaction = match cursor.byte()? {
        0 => false,
        1 if class == MaintenanceTaskClass::Compaction && trigger == MaintenanceTrigger::Event => {
            true
        },
        _ => return Err(MaintenanceFailure::InvalidInput),
    };
    let priority = priority_from_code(cursor.byte()?)?;
    let preconditions = MaintenancePreconditions::new(cursor.u64()?, cursor.u64()?)?;
    let not_before = if includes_not_before {
        cursor.u64()?
    } else {
        0
    };
    let inputs = decode_objects(&mut cursor)?;
    let outputs = decode_objects(&mut cursor)?;
    let mut amounts = [0_u64; 11];
    for slot in &mut amounts {
        *slot = cursor.u64()?;
    }
    let mut task = MaintenanceTask::with_contract_not_before(
        identity,
        class,
        scope,
        trigger,
        preconditions,
        inputs,
        outputs,
        ResourceAmounts::new(amounts),
        not_before,
    )?;
    task.emergency_compaction = emergency_compaction;
    if priority != task.priority() {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let phase = phase_from_code(cursor.byte()?)?;
    let submitted_at = cursor.u64()?;
    let pause_until = match cursor.byte()? {
        0 => {
            let _ = cursor.u64()?;
            None
        },
        1 => Some(cursor.u64()?),
        _ => return Err(MaintenanceFailure::InvalidInput),
    };
    let cancellation_requested = match cursor.byte()? {
        0 => false,
        1 => true,
        _ => return Err(MaintenanceFailure::InvalidInput),
    };
    let dispatches = cursor.u64()?;
    let checkpoint = match cursor.byte()? {
        0 => None,
        1 => {
            let sequence = cursor.u64()?;
            let completed = cursor.u32()?;
            let length =
                usize::try_from(cursor.u32()?).map_err(|_| MaintenanceFailure::InvalidInput)?;
            let progress = cursor.take_exact(length)?.to_vec();
            Some(MaintenanceCheckpoint::new(sequence, completed, progress)?)
        },
        _ => return Err(MaintenanceFailure::InvalidInput),
    };
    if !cursor.is_finished() {
        return Err(MaintenanceFailure::InvalidInput);
    }
    Ok(TaskState {
        task,
        phase,
        submitted_at,
        checkpoint,
        pause_until,
        cancellation_requested,
        dispatches,
        terminal_order: None,
        active_dispatch: None,
    })
}

fn decode_objects(
    cursor: &mut RecordCursor<'_>,
) -> Result<Vec<MaintenanceObjectId>, MaintenanceFailure> {
    let count = usize::from(cursor.byte()?);
    if count > MAX_TASK_OBJECTS {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    for _ in 0..count {
        values.push(MaintenanceObjectId::new(cursor.array_32()?)?);
    }
    Ok(values)
}

fn encode_scope(bytes: &mut Vec<u8>, scope: MaintenanceScope) {
    match scope {
        MaintenanceScope::System => bytes.push(0),
        MaintenanceScope::Tenant(tenant) => {
            bytes.push(1);
            bytes.extend_from_slice(&tenant.to_bytes());
            bytes.push(0);
            push_u32(bytes, 0);
        },
        MaintenanceScope::Segment {
            tenant,
            signal,
            shard,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&tenant.to_bytes());
            bytes.push(match signal {
                SignalKind::Logs => 1,
                SignalKind::Traces => 2,
            });
            push_u32(bytes, shard.value());
        },
    }
}

fn decode_scope(cursor: &mut RecordCursor<'_>) -> Result<MaintenanceScope, MaintenanceFailure> {
    match cursor.byte()? {
        0 => Ok(MaintenanceScope::System),
        1 => {
            let tenant = TenantId::from_bytes(cursor.array_16()?)
                .map_err(|_| MaintenanceFailure::InvalidInput)?;
            let signal = match cursor.byte()? {
                0 => None,
                1 => Some(SignalKind::Logs),
                2 => Some(SignalKind::Traces),
                _ => return Err(MaintenanceFailure::InvalidInput),
            };
            let shard = match cursor.u32()? {
                0 => None,
                value => {
                    Some(VirtualShardId::new(value).map_err(|_| MaintenanceFailure::InvalidInput)?)
                },
            };
            if signal.is_some() != shard.is_some() {
                return Err(MaintenanceFailure::InvalidInput);
            }
            match (signal, shard) {
                (None, None) => Ok(MaintenanceScope::tenant(tenant)),
                (Some(signal), Some(shard)) => Ok(MaintenanceScope::segment(tenant, signal, shard)),
                (None, Some(_)) | (Some(_), None) => Err(MaintenanceFailure::InvalidInput),
            }
        },
        _ => Err(MaintenanceFailure::InvalidInput),
    }
}

fn class_code(class: MaintenanceTaskClass) -> u8 {
    class as u8
}
fn class_from_code(code: u8) -> Result<MaintenanceTaskClass, MaintenanceFailure> {
    const CLASSES: [MaintenanceTaskClass; 22] = [
        MaintenanceTaskClass::ActiveSegmentRoll,
        MaintenanceTaskClass::Compaction,
        MaintenanceTaskClass::RetentionPublication,
        MaintenanceTaskClass::RetentionReclamation,
        MaintenanceTaskClass::CatalogReclamation,
        MaintenanceTaskClass::OrphanReclamation,
        MaintenanceTaskClass::IntegrityScrub,
        MaintenanceTaskClass::QuarantineFollowUp,
        MaintenanceTaskClass::SchemaStatistics,
        MaintenanceTaskClass::SchemaPromotion,
        MaintenanceTaskClass::SchemaDemotion,
        MaintenanceTaskClass::GovernanceAuditCheckpoint,
        MaintenanceTaskClass::KeyRewrap,
        MaintenanceTaskClass::EnvelopeVerification,
        MaintenanceTaskClass::Migration,
        MaintenanceTaskClass::RepositoryVerification,
        MaintenanceTaskClass::RepositoryCleanup,
        MaintenanceTaskClass::BackupSnapshot,
        MaintenanceTaskClass::DurableExport,
        MaintenanceTaskClass::SnapshotLeaseExpiry,
        MaintenanceTaskClass::CompletedOperationExpiry,
        MaintenanceTaskClass::TenantPurge,
    ];
    CLASSES
        .get(usize::from(code))
        .copied()
        .ok_or(MaintenanceFailure::InvalidInput)
}
fn trigger_code(trigger: MaintenanceTrigger) -> u8 {
    match trigger {
        MaintenanceTrigger::Event => 0,
        MaintenanceTrigger::Scheduled => 1,
        MaintenanceTrigger::AgeDerived => 2,
    }
}
fn trigger_from_code(code: u8) -> Result<MaintenanceTrigger, MaintenanceFailure> {
    match code {
        0 => Ok(MaintenanceTrigger::Event),
        1 => Ok(MaintenanceTrigger::Scheduled),
        2 => Ok(MaintenanceTrigger::AgeDerived),
        _ => Err(MaintenanceFailure::InvalidInput),
    }
}
fn priority_code(priority: MaintenancePriority) -> u8 {
    match priority {
        MaintenancePriority::Ordinary => 0,
        MaintenancePriority::Required => 1,
        MaintenancePriority::Urgent => 2,
        MaintenancePriority::Durability => 3,
    }
}
fn priority_from_code(code: u8) -> Result<MaintenancePriority, MaintenanceFailure> {
    match code {
        0 => Ok(MaintenancePriority::Ordinary),
        1 => Ok(MaintenancePriority::Required),
        2 => Ok(MaintenancePriority::Urgent),
        3 => Ok(MaintenancePriority::Durability),
        _ => Err(MaintenanceFailure::InvalidInput),
    }
}
fn phase_code(phase: MaintenanceTaskPhase) -> u8 {
    match phase {
        MaintenanceTaskPhase::Queued => 0,
        MaintenanceTaskPhase::Running => 1,
        MaintenanceTaskPhase::Deferred => 2,
        MaintenanceTaskPhase::Cancelled => 3,
        MaintenanceTaskPhase::Succeeded => 4,
        MaintenanceTaskPhase::Failed => 5,
    }
}
fn phase_from_code(code: u8) -> Result<MaintenanceTaskPhase, MaintenanceFailure> {
    match code {
        0 => Ok(MaintenanceTaskPhase::Queued),
        1 => Ok(MaintenanceTaskPhase::Running),
        2 => Ok(MaintenanceTaskPhase::Deferred),
        3 => Ok(MaintenanceTaskPhase::Cancelled),
        4 => Ok(MaintenanceTaskPhase::Succeeded),
        5 => Ok(MaintenanceTaskPhase::Failed),
        _ => Err(MaintenanceFailure::InvalidInput),
    }
}
fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

struct RecordCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> RecordCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take_exact(&mut self, length: usize) -> Result<&'a [u8], MaintenanceFailure> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(MaintenanceFailure::InvalidInput)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MaintenanceFailure::InvalidInput)?;
        self.position = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, MaintenanceFailure> {
        self.take_exact(1)?
            .first()
            .copied()
            .ok_or(MaintenanceFailure::InvalidInput)
    }
    fn array_16(&mut self) -> Result<[u8; 16], MaintenanceFailure> {
        self.take_exact(16)?
            .try_into()
            .map_err(|_| MaintenanceFailure::InvalidInput)
    }
    fn array_32(&mut self) -> Result<[u8; 32], MaintenanceFailure> {
        self.take_exact(32)?
            .try_into()
            .map_err(|_| MaintenanceFailure::InvalidInput)
    }
    fn u64(&mut self) -> Result<u64, MaintenanceFailure> {
        Ok(u64::from_be_bytes(
            self.take_exact(8)?
                .try_into()
                .map_err(|_| MaintenanceFailure::InvalidInput)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, MaintenanceFailure> {
        Ok(u32::from_be_bytes(
            self.take_exact(4)?
                .try_into()
                .map_err(|_| MaintenanceFailure::InvalidInput)?,
        ))
    }
    const fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

pub(super) fn record_identity(
    bytes: &[u8],
) -> Result<Option<MaintenanceTaskId>, MaintenanceFailure> {
    if !bytes.starts_with(RECORD_MAGIC) && !bytes.starts_with(PREVIOUS_RECORD_MAGIC) {
        return Ok(None);
    }
    decode_record(bytes).map(|state| Some(state.task.identity))
}

const WINDOW_MAGIC: &[u8; 8] = b"PMTW0001";

pub(super) fn encode_window(window: &MaintenanceWindow) -> Result<Vec<u8>, MaintenanceFailure> {
    let count = window.deferred.len();
    let capacity = WINDOW_MAGIC
        .len()
        .checked_add(8)
        .and_then(|size| size.checked_add(1))
        .and_then(|size| size.checked_add(count))
        .ok_or(MaintenanceFailure::CapacityExceeded)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    bytes.extend_from_slice(WINDOW_MAGIC);
    bytes.extend_from_slice(&window.until.to_be_bytes());
    bytes.push(u8::try_from(count).map_err(|_| MaintenanceFailure::CapacityExceeded)?);
    for class in &window.deferred {
        bytes.push(class_code(*class));
    }
    Ok(bytes)
}

pub(super) fn window_record(bytes: &[u8]) -> Result<Option<MaintenanceWindow>, MaintenanceFailure> {
    if !bytes.starts_with(WINDOW_MAGIC) {
        return Ok(None);
    }
    let mut cursor = RecordCursor::new(bytes);
    if cursor.take_exact(WINDOW_MAGIC.len())? != WINDOW_MAGIC {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let until = cursor.u64()?;
    if until == 0 {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let count = usize::from(cursor.byte()?);
    if count > MaintenanceTaskClass::COUNT {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let mut deferred = BTreeSet::new();
    for _ in 0..count {
        let class = class_from_code(cursor.byte()?)?;
        if !class.deferrable() || !deferred.insert(class) {
            return Err(MaintenanceFailure::InvalidInput);
        }
    }
    if !cursor.is_finished() {
        return Err(MaintenanceFailure::InvalidInput);
    }
    Ok(Some(MaintenanceWindow { deferred, until }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_task_record_decodes_with_an_immediately_eligible_schedule() {
        let state = TaskState {
            task: MaintenanceTask::with_contract_not_before(
                MaintenanceTaskId::new([7; 16]).expect("identity"),
                MaintenanceTaskClass::SchemaPromotion,
                MaintenanceScope::system(),
                MaintenanceTrigger::Scheduled,
                MaintenancePreconditions::new(3, 1).expect("preconditions"),
                Vec::new(),
                Vec::new(),
                ResourceAmounts::new([1; 11]),
                99,
            )
            .expect("task"),
            phase: MaintenanceTaskPhase::Queued,
            submitted_at: 7,
            checkpoint: None,
            pause_until: None,
            cancellation_requested: false,
            dispatches: 0,
            terminal_order: None,
            active_dispatch: None,
        };
        let mut legacy = encode_record(&state).expect("v3 encoding").0;
        legacy[..RECORD_MAGIC.len()].copy_from_slice(PREVIOUS_RECORD_MAGIC);
        // Magic, identity, class, system scope, trigger, emergency, priority,
        // then the two precondition generations precede the v3 due-time field.
        legacy.drain(45..53);
        let decoded = decode_record(&legacy).expect("v2 decoding");
        assert_eq!(decoded.task.not_before(), 0);
        assert_eq!(decoded.task.class(), MaintenanceTaskClass::SchemaPromotion);
    }

    #[test]
    fn snapshot_lease_expiry_rejects_noncanonical_durable_contracts() {
        let identity = MaintenanceTaskId::new([7; 16]).expect("identity");
        let preconditions = MaintenancePreconditions::new(3, 1).expect("preconditions");
        let reservation = ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]);
        assert!(
            MaintenanceTask::with_contract_not_before(
                identity,
                MaintenanceTaskClass::SnapshotLeaseExpiry,
                MaintenanceScope::system(),
                MaintenanceTrigger::Scheduled,
                preconditions,
                vec![MaintenanceObjectId::new([8; 32]).expect("object")],
                Vec::new(),
                reservation,
                9,
            )
            .is_err()
        );
        assert!(
            MaintenanceTask::with_contract_not_before(
                identity,
                MaintenanceTaskClass::SnapshotLeaseExpiry,
                MaintenanceScope::segment(
                    positron_domain::identity::TenantId::from_bytes([9; 16]).expect("tenant"),
                    positron_domain::routing::SignalKind::Logs,
                    positron_domain::routing::VirtualShardId::new(1).expect("shard"),
                ),
                MaintenanceTrigger::Scheduled,
                preconditions,
                vec![MaintenanceObjectId::new([8; 32]).expect("object")],
                Vec::new(),
                reservation,
                9,
            )
            .is_ok()
        );
    }
}
