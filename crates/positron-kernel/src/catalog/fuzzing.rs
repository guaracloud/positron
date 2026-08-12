use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{MountQualification, PrimaryDataVolume};

use super::{
    AuditIntent, Catalog, CatalogFileEvent, CatalogObject, CatalogProposal, CatalogSecret,
    FormatEpoch, InstanceId, TransactionId, with_catalog_fault,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct FuzzRoot(PathBuf);

impl FuzzRoot {
    fn new() -> Option<Self> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-catalog-fuzz-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).ok()?;
        Some(Self(path))
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove catalog fuzz root: {error}");
        }
    }
}

pub(super) fn fuzz_catalog_stateful(data: &[u8]) {
    if data.len() > 128 {
        return;
    }
    let Some(root) = FuzzRoot::new() else {
        return;
    };
    let Some(volume) = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost).ok()
    else {
        return;
    };
    let instance = InstanceId::new(nonzero_id(1)).expect("fixed instance identity is nonzero");
    let Ok(catalog) = Catalog::open(volume, instance, secret()) else {
        return;
    };
    let event = fault_event(data.first().copied().unwrap_or_default());
    let transaction = data.get(1).copied().unwrap_or(2).max(1);
    let payload = if data.len() > 2 {
        data[2..].to_vec()
    } else {
        vec![1]
    };
    let proposal = || {
        CatalogProposal::new(
            TransactionId::new(nonzero_id(transaction))?,
            FormatEpoch::new(1)?,
            vec![CatalogObject::new(payload.clone())?],
        )
    };
    let expected = catalog.pin().expect("fresh catalog pins").identity();
    let result = with_catalog_fault(event, || {
        catalog.commit(
            expected,
            proposal().expect("bounded nonempty proposal is valid"),
            Some(AuditIntent::new(vec![transaction]).expect("bounded audit is valid")),
        )
    });
    drop(catalog);

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
        .expect("fuzz catalog releases volume ownership");
    let recovered =
        Catalog::open(volume, instance, secret()).expect("fault leaves recoverable state");
    let number = recovered.pin().expect("recovered catalog pins").number();
    assert!(number <= 1);
    assert_eq!(
        recovered
            .governance_audit_records()
            .expect("recovered audit reads")
            .len() as u64,
        number
    );
    if result.is_ok() {
        assert_eq!(number, 1);
    }
}

fn secret() -> CatalogSecret {
    CatalogSecret::from_owned(Box::new([0xf1; 32]))
}

fn nonzero_id(last: u8) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[15] = last.max(1);
    bytes
}

fn fault_event(selector: u8) -> CatalogFileEvent {
    let events = [
        CatalogFileEvent::WriteObject,
        CatalogFileEvent::PartialObjectWrite,
        CatalogFileEvent::SynchronizeObject,
        CatalogFileEvent::SynchronizeObjectDirectory,
        CatalogFileEvent::ReserveAudit,
        CatalogFileEvent::WriteAudit,
        CatalogFileEvent::PartialAuditWrite,
        CatalogFileEvent::SynchronizeAudit,
        CatalogFileEvent::SynchronizeAuditDirectory,
        CatalogFileEvent::WriteCommit,
        CatalogFileEvent::PartialCommitWrite,
        CatalogFileEvent::SynchronizeCommit,
        CatalogFileEvent::SynchronizeCommitDirectory,
        CatalogFileEvent::WriteMarker,
        CatalogFileEvent::PartialMarkerWrite,
        CatalogFileEvent::SynchronizeMarker,
        CatalogFileEvent::RenameMarker,
        CatalogFileEvent::SynchronizeGenerationDirectory,
    ];
    events[usize::from(selector) % events.len()]
}
