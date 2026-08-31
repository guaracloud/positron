use std::error::Error;

use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{IngestOutcome, IngestPolicy, LogIngest};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, MountQualification,
    SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use positron_signals::{LogScan, LogStore, ScanLimit};

use super::super::support::temporary_roots;

pub(crate) fn attributed_instance(
    label: &str,
) -> Result<
    (
        positron_runtime::InitializedInstance,
        positron_governance::AuthorizedContext,
    ),
    Box<dyn Error>,
> {
    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or(label)?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    Ok((instance, context))
}

pub(crate) fn ingest_and_scan<'fixture>(
    fixture: &'fixture super::super::support::Fixture,
    batch: positron_ingest::NativeLogBatch<'fixture>,
    policy: &IngestPolicy,
    marker: u8,
) -> Result<positron_signals::LogScanResult<'fixture>, Box<dyn Error>> {
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([marker; 16])?,
        CatalogSecret::from_owned(Box::new([marker + 1; 32]), Box::new([marker + 2; 32])),
    )?;
    let shard = VirtualShardId::new(u32::from(marker))?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([marker + 3; 32])),
    )?;
    let outcome = LogIngest::new(
        &fixture.authority,
        &ledger,
        policy,
        fixture.tenant,
        shard,
        super::super::schema_support::session(fixture)?,
    )
    .accept(batch, StoreBlockIdentity::new([marker + 4; 16])?);
    if !matches!(outcome, IngestOutcome::Full(_) | IngestOutcome::Partial(_)) {
        return Err("policy-transformed batch did not commit".into());
    }
    let snapshot = ledger.snapshot()?;
    LogStore::new()
        .scan(
            fixture.authority.governor(),
            fixture.tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1_024)?),
        )
        .map_err(Into::into)
}
