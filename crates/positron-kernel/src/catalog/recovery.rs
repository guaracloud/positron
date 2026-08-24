use std::collections::BTreeMap;

use super::codec::{decode_audit, decode_commit, snapshot_from_record, transaction_digest};
use super::storage::CatalogStorage;
use super::types::AuditFrontier;
use super::{
    CatalogFailure, CatalogFailureCode, CatalogGenerationId, CatalogSecret, CatalogSnapshot,
    CatalogState, CommitRecord, InstanceId, MAX_RECOVERED_AUDIT_BYTES, TransactionId,
    TransactionOutcome, reserve_history, retained_artifact_bytes,
};

pub(super) fn recover(
    storage: &CatalogStorage,
    secret: &CatalogSecret,
    instance: InstanceId,
) -> Result<CatalogState, CatalogFailure> {
    let marker_scan = storage.markers(secret)?;
    if marker_scan.authentication_failures != 0 {
        return Err(CatalogFailure::new(
            CatalogFailureCode::AuthenticationFailed,
        ));
    }
    if marker_scan.verified.is_empty() {
        return Ok(CatalogState {
            current: CatalogSnapshot::origin(),
            audit: Vec::new(),
            transactions: BTreeMap::new(),
            retained_history_bytes: 0,
        });
    }

    let mut by_number = BTreeMap::new();
    let mut highest_number = 0_u64;
    let mut highest_generation = CatalogGenerationId::ORIGIN;
    for (generation, number) in &marker_scan.verified {
        if by_number.insert(*number, *generation).is_some() {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        if *number > highest_number {
            highest_number = *number;
            highest_generation = *generation;
        }
    }
    let mut chain = Vec::new();
    let mut retained_history_bytes = marker_scan
        .verified
        .len()
        .checked_mul(super::storage::MARKER_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    let mut generation = highest_generation;
    let mut expected_number = highest_number;
    loop {
        let encoded = storage.read_commit(secret, instance, generation)?;
        retained_history_bytes = reserve_history(
            retained_history_bytes,
            retained_artifact_bytes(encoded.len())?,
            highest_number,
        )?;
        let record = decode_commit(generation, &encoded)?;
        if !record.format_epoch.is_catalog_readable() {
            return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
        }
        if record.instance != instance || record.number != expected_number {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let predecessor = record.predecessor;
        chain.push(record);
        if expected_number == 1 {
            if predecessor != CatalogGenerationId::ORIGIN {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
            break;
        }
        expected_number -= 1;
        if by_number.get(&expected_number) != Some(&predecessor) {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        generation = predecessor;
    }
    chain.reverse();
    let mut predecessor_generation = CatalogGenerationId::ORIGIN;
    let mut predecessor_number = 0_u64;
    let mut predecessor_audit = AuditFrontier::ORIGIN;
    let mut audit = Vec::new();
    let mut audit_bytes = 0_usize;
    let mut transactions: BTreeMap<TransactionId, TransactionOutcome> = BTreeMap::new();
    for record in chain {
        if record.predecessor != predecessor_generation || record.number != predecessor_number + 1 {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        let visible_audit = if record.audit_frontier == predecessor_audit {
            None
        } else {
            if record.audit_frontier.position != predecessor_audit.position + 1 {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
            let encoded = storage.read_audit(
                secret,
                instance,
                record.audit_frontier.position,
                record.audit_frontier.hash,
            )?;
            retained_history_bytes = reserve_history(
                retained_history_bytes,
                retained_artifact_bytes(encoded.len())?,
                highest_number,
            )?;
            let decoded = decode_audit(&encoded)?;
            if decoded.position != record.audit_frontier.position
                || decoded.hash != record.audit_frontier.hash
                || decoded.predecessor_hash != predecessor_audit.hash
                || decoded.transaction != record.transaction
            {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
            audit_bytes = audit_bytes
                .checked_add(decoded.intent.len())
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
            if audit_bytes > MAX_RECOVERED_AUDIT_BYTES {
                return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
            }
            audit.push(decoded.clone());
            Some(decoded)
        };
        if transaction_digest(
            record.format_epoch,
            &record.objects,
            visible_audit.as_ref().map(|entry| entry.intent()),
        )? != record.transaction_digest
        {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        predecessor_generation = record.generation;
        predecessor_number = record.number;
        predecessor_audit = record.audit_frontier;
        match transactions.get(&record.transaction) {
            Some(outcome) if outcome.digest != record.transaction_digest => {
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            },
            Some(_) => return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption)),
            None => {
                transactions.insert(
                    record.transaction,
                    TransactionOutcome {
                        digest: record.transaction_digest,
                        record,
                        audit: visible_audit,
                    },
                );
            },
        }
    }
    let latest = transactions
        .values()
        .find(|outcome| outcome.record.generation == highest_generation)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let current = load_snapshot(storage, secret, instance, &latest.record)?;
    Ok(CatalogState {
        current,
        audit,
        transactions,
        retained_history_bytes,
    })
}

pub(super) fn load_snapshot(
    storage: &CatalogStorage,
    secret: &CatalogSecret,
    instance: InstanceId,
    record: &CommitRecord,
) -> Result<CatalogSnapshot, CatalogFailure> {
    let mut objects = BTreeMap::new();
    for identity in &record.objects {
        let object = storage.read_object(secret, instance, *identity, record.format_epoch)?;
        objects.insert(*identity, object);
    }
    Ok(snapshot_from_record(record, objects))
}
