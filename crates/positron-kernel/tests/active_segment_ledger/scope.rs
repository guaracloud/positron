use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, LedgerFailureCode, MountQualification,
    PreparedStoreBlock, PrimaryDataVolume, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
    WorkClass,
};

use super::support::{TemporaryRoot, establish_kernel_authority};

type ArtifactTree = Vec<(PathBuf, Vec<u8>)>;

#[test]
fn prepared_block_scope_is_refused_before_any_ledger_or_artifact_mutation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let ledger_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(8)?);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        ledger_scope,
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    let before_files = artifact_tree(root.path())?;
    let before_ingest = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::Ingest);

    for (scope, marker) in [
        (
            SegmentScope::new(
                TenantId::from_bytes([0x42; 16])?,
                SignalKind::Logs,
                VirtualShardId::new(8)?,
            ),
            0x68,
        ),
        (
            SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(8)?),
            0x69,
        ),
    ] {
        let failure = ledger
            .append(PreparedStoreBlock::new(
                scope,
                StoreBlockIdentity::new([marker; 16])?,
                b"wrong-scope".to_vec(),
            )?)
            .expect_err("physical scope mismatch must precede durability work");
        assert_eq!(failure.code(), LedgerFailureCode::PhysicalScopeMismatch);
        assert!(ledger.snapshot()?.blocks().is_empty());
        assert_eq!(artifact_tree(root.path())?, before_files);
        assert_eq!(
            authority
                .governor()
                .inspect()?
                .outstanding_for(WorkClass::Ingest),
            before_ingest
        );
    }

    let receipt = ledger.append(PreparedStoreBlock::new(
        ledger_scope,
        StoreBlockIdentity::new([0x6a; 16])?,
        b"correct-scope".to_vec(),
    )?)?;
    assert_eq!(receipt.position().value(), 1);
    assert_eq!(ledger.snapshot()?.blocks()[0].payload(), b"correct-scope");
    Ok(())
}

fn artifact_tree(root: &Path) -> Result<ArtifactTree, Box<dyn Error>> {
    let mut artifacts = Vec::new();
    collect_artifacts(root, root, &mut artifacts)?;
    artifacts.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(artifacts)
}

fn collect_artifacts(
    root: &Path,
    directory: &Path,
    artifacts: &mut Vec<(PathBuf, Vec<u8>)>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_artifacts(root, &path, artifacts)?;
        } else {
            artifacts.push((path.strip_prefix(root)?.to_owned(), fs::read(path)?));
        }
    }
    Ok(())
}
