use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use super::super::format::{SegmentMetadata, SegmentState, encode_metadata};
use super::super::{LedgerFailureCode, SegmentId, SegmentScope};
use super::support::{TemporaryRoot, establish_authority};
use crate::catalog::{
    Catalog, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch, InstanceId, TransactionId,
};
use crate::{MountQualification, PrimaryDataVolume};

#[test]
fn reachable_scopes_are_tenant_filtered_deduplicated_and_canonical() -> Result<(), Box<dyn Error>> {
    with_catalog(|catalog, tenant| {
        let shard_7 = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(7)?);
        let shard_3 = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(3)?);
        let traces = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(1)?);
        let other_tenant = SegmentScope::new(
            TenantId::from_bytes([0x72; 16])?,
            SignalKind::Logs,
            VirtualShardId::new(2)?,
        );
        publish(
            catalog,
            &[
                metadata(shard_7, 1, SegmentState::Active)?,
                metadata(shard_3, 2, SegmentState::Active)?,
                metadata(shard_7, 3, SegmentState::Sealed)?,
                metadata(traces, 4, SegmentState::Active)?,
                metadata(other_tenant, 5, SegmentState::Active)?,
            ],
            None,
            0x81,
        )?;

        assert_eq!(
            catalog
                .pin()?
                .reachable_ledger_scopes(tenant, SignalKind::Logs)?,
            vec![shard_3, shard_7]
        );
        Ok(())
    })
}

#[test]
fn scope_discovery_rejects_malformed_metadata_and_keeps_snapshots_immutable()
-> Result<(), Box<dyn Error>> {
    with_catalog(|catalog, tenant| {
        let first = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
        publish(
            catalog,
            &[metadata(first, 1, SegmentState::Active)?],
            None,
            0x82,
        )?;
        let pinned = catalog.pin()?;
        let second = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(2)?);
        publish(
            catalog,
            &[
                metadata(first, 1, SegmentState::Active)?,
                metadata(second, 2, SegmentState::Active)?,
            ],
            None,
            0x83,
        )?;
        assert_eq!(
            pinned.reachable_ledger_scopes(tenant, SignalKind::Logs)?,
            vec![first]
        );
        assert_eq!(
            catalog
                .pin()?
                .reachable_ledger_scopes(tenant, SignalKind::Logs)?,
            vec![first, second]
        );

        publish(catalog, &[], Some(b"PSEGMET1\0".as_slice()), 0x84)?;
        let failure = catalog
            .pin()?
            .reachable_ledger_scopes(tenant, SignalKind::Logs)
            .expect_err("recognized malformed metadata must fail closed");
        assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
        Ok(())
    })
}

fn metadata(
    scope: SegmentScope,
    seed: u8,
    state: SegmentState,
) -> Result<SegmentMetadata, Box<dyn Error>> {
    Ok(SegmentMetadata {
        scope,
        id: SegmentId::new([seed; 16])?,
        state,
        base_position: CommitPosition::origin(),
    })
}

fn publish(
    catalog: &Catalog<'_>,
    metadata: &[SegmentMetadata],
    malformed: Option<&[u8]>,
    transaction: u8,
) -> Result<(), Box<dyn Error>> {
    let mut objects = Vec::new();
    objects.try_reserve_exact(metadata.len() + usize::from(malformed.is_some()))?;
    for value in metadata {
        objects.push(CatalogObject::new(encode_metadata(*value))?);
    }
    if let Some(value) = malformed {
        objects.push(CatalogObject::new(value.to_vec())?);
    }
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction; 16])?,
            FormatEpoch::new(1)?,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

fn with_catalog(
    action: impl FnOnce(&Catalog<'_>, TenantId) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x61; 16])?,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    action(&catalog, TenantId::from_bytes([0x64; 16])?)
}
