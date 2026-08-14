use std::error::Error;
use std::sync::Arc;

use positron_ingest::load_schema_checkpoint;
use positron_kernel::{
    CatalogObject, CatalogProposal, FormatEpoch, StoreBlockIdentity, TransactionId,
};
use prost::Message;

use super::super::{ServiceFailure, ServiceHandle};
use super::schema_maintenance::{Fixture, open_catalog, request};

#[test]
fn bootstrap_rejects_a_structurally_valid_mismatched_replay_frontier() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("frontier").encode_to_vec())?
            .accepted_records(),
        1
    );

    let catalog = open_catalog(&initialized)?;
    let basis = catalog.pin()?;
    let current = load_schema_checkpoint(&basis, initialized.tenant)
        .map_err(|_| "schema checkpoint")?
        .ok_or("missing schema checkpoint")?;
    let scope = basis
        .reachable_ledger_scopes(
            initialized.tenant,
            positron_domain::routing::SignalKind::Logs,
        )?
        .into_iter()
        .next()
        .ok_or("missing log scope")?;
    let mut forged = current.clone();
    let count = forged.len().checked_sub(8).ok_or("checkpoint trailer")?;
    forged[count..].copy_from_slice(&1_u64.to_be_bytes());
    forged.extend_from_slice(&scope.shard_id().value().to_be_bytes());
    forged.extend_from_slice(
        &positron_domain::routing::CommitPosition::origin()
            .next()?
            .value()
            .to_be_bytes(),
    );
    forged.extend_from_slice(&StoreBlockIdentity::new([0xd1; 16])?.to_bytes());
    forged.extend_from_slice(&[0xd2; 32]);

    let mut objects = Vec::new();
    objects.try_reserve_exact(basis.object_identities().count())?;
    for identity in basis.object_identities() {
        let bytes = basis.object(identity)?.ok_or("missing Catalog object")?;
        if bytes != current {
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
    }
    objects.push(CatalogObject::new(forged)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xd3; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    drop((basis, catalog, services));

    assert!(matches!(
        ServiceHandle::new(Arc::clone(&initialized)),
        Err(ServiceFailure::CorruptState)
    ));
    Ok(())
}
