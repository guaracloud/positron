use super::*;

use std::sync::{Mutex, atomic::AtomicBool};

use positron_kernel::{CatalogGenerationId, CompactionBlock};

struct ReplacePolicyOnFirstCancellation<'catalog, 'authority> {
    catalog: &'catalog Catalog<'authority>,
    expected: Mutex<Option<CatalogGenerationId>>,
    proposal: Mutex<Option<CatalogProposal>>,
    committed: AtomicBool,
    replace_on_cancellation: bool,
    replace_on_scan: bool,
}

impl ScanCancellation for ReplacePolicyOnFirstCancellation<'_, '_> {
    fn is_cancelled(&self) -> bool {
        if self.replace_on_cancellation {
            self.replace_once();
        }
        false
    }
}

impl ScanObserver for ReplacePolicyOnFirstCancellation<'_, '_> {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        if self.replace_on_scan {
            self.replace_once();
        }
        Ok(())
    }
}

impl ReplacePolicyOnFirstCancellation<'_, '_> {
    fn replace_once(&self) {
        let expected = self.expected.lock().ok().and_then(|mut value| value.take());
        let proposal = self.proposal.lock().ok().and_then(|mut value| value.take());
        if let Some((expected, proposal)) = expected.zip(proposal) {
            self.committed.store(
                self.catalog.commit(expected, proposal, None).is_ok(),
                std::sync::atomic::Ordering::Release,
            );
        }
    }
}

fn retention_replacement(
    catalog: &Catalog<'_>,
    instance: InstanceId,
    tenant: TenantId,
    retention_seconds: u64,
    transaction: TransactionId,
) -> Result<(CatalogGenerationId, CatalogProposal), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .filter_map(|identity| {
            let bytes = basis.object(identity).ok().flatten()?;
            (!bytes.starts_with(b"POSGOV03")).then(|| CatalogObject::new(bytes.to_vec()).ok())?
        })
        .collect::<Vec<_>>();
    objects.push(CatalogObject::new(
        super::retention_contract::governance_fixture(
            instance.to_bytes(),
            tenant,
            retention_seconds,
        )?,
    )?);
    Ok((
        basis.identity(),
        CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)?,
    ))
}

fn unrelated_catalog_update(
    catalog: &Catalog<'_>,
    transaction: TransactionId,
) -> Result<(CatalogGenerationId, CatalogProposal), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .map(|identity| {
            basis
                .object(identity)
                .map_err(Into::into)
                .and_then(|bytes| {
                    CatalogObject::new(bytes.ok_or("Catalog fixture object disappeared")?.to_vec())
                        .map_err(Into::into)
                })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.push(CatalogObject::new(
        b"unrelated-policy-preserving-churn".to_vec(),
    )?);
    Ok((
        basis.identity(),
        CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects)?,
    ))
}

fn record(body: &str) -> Result<LogRecord, Box<dyn Error>> {
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string(body.to_owned())),
        vec![],
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving policy rejected the compaction fixture".into());
    };
    Ok(LogRecord::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        *evaluated,
    )?)
}

#[path = "compaction/bucket_selection.rs"]
mod bucket_selection;
#[path = "compaction/failure_recovery.rs"]
mod failure_recovery;
#[path = "compaction/policy_races.rs"]
mod policy_races;
#[path = "compaction/semantic_equivalence.rs"]
mod semantic_equivalence;
