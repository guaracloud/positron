use std::fmt::Debug;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use positron_domain::identity::TenantId;
use positron_domain::routing::VirtualShardId;
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{CandidateAttributeValue, ValueLimitProfile};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{IngestPolicy, PolicyEvaluation, PolicyReceiver};
use positron_kernel::{
    ActiveSegmentLedger, FixedLifecycleClockSource, LifecycleClock, ResourceAmounts,
    ResourceDimension, StorageKernelResourceAuthority, StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_query::{
    QueryBudget, QueryClock, QueryClockFailure, QueryService, QueryWorkFailure, QueryWorkMeter,
    QueryWorkStage, TailSourceSet,
};
use positron_signals::{LogRecord, LogStore};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

pub(super) struct FuzzRoot(PathBuf);

impl FuzzRoot {
    pub(super) fn new() -> Result<Self, String> {
        let root = std::env::temp_dir().join(format!(
            "positron-query-tail-fuzz-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("data")).map_err(describe)?;
        let secrets = root.join("secrets");
        fs::create_dir_all(&secrets).map_err(describe)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).map_err(describe)?;
        }
        Ok(Self(root))
    }

    pub(super) fn paths(&self) -> Result<super::BootstrapPaths, String> {
        super::BootstrapPaths::new(
            self.0.join("data").as_path(),
            self.0.join("secrets").as_path(),
            positron_kernel::MountQualification::LocalHost,
        )
        .map_err(describe)
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            panic!("tail fuzz temporary-root cleanup failed: {error}");
        }
    }
}

#[derive(Default)]
pub(super) struct Branches {
    pub(super) polls: u64,
    pub(super) repeats: u64,
    pub(super) acknowledgements: u64,
    pub(super) resumes: u64,
    pub(super) forged: u64,
    pub(super) malformed: u64,
    pub(super) cancellations: u64,
    pub(super) budgets: u64,
    pub(super) cleanup: u64,
}

pub(super) fn describe<E: Debug>(error: E) -> String {
    format!("{error:?}")
}

pub(super) struct FuzzClock;

impl QueryClock for FuzzClock {
    fn now_seconds(&self) -> Result<u64, QueryClockFailure> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| QueryClockFailure)
    }
}

pub(super) struct FuzzWorkMeter;

impl QueryWorkMeter for FuzzWorkMeter {
    fn units(&self, _stage: QueryWorkStage) -> Result<u64, QueryWorkFailure> {
        Ok(0)
    }
}

pub(super) fn budget() -> Result<QueryBudget, String> {
    QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)
        .map_err(describe)?
        .with_cpu_work_units(4)
        .map_err(describe)
}

pub(super) fn append_valid<'kernel, 'catalog>(
    authority: &'kernel StorageKernelResourceAuthority,
    ledger: &ActiveSegmentLedger<'kernel, 'catalog>,
    tenant: TenantId,
    shard: VirtualShardId,
    identity: u8,
    event_time: i64,
    body: &str,
) -> Result<(), String> {
    let candidate = positron_ingest::NativeLogCandidate::new(
        Some(event_time),
        None,
        Some(CandidateAttributeValue::string(body.to_owned())),
        Vec::new(),
        positron_ingest::LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)
        .map_err(describe)?
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .map_err(describe)?
    else {
        return Err("fuzz fixture policy rejected a valid record".to_owned());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)
            .map_err(describe)?;
    let amounts =
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576).map_err(describe)?;
    let claim = WorkClaim::tenant(tenant, WorkKind::Ingest, amounts).map_err(describe)?;
    let capacity = authority.governor().reserve(claim).map_err(describe)?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(50)));
    let identity = StoreBlockIdentity::new([identity; 16]).map_err(describe)?;
    let block = LogStore::new()
        .prepare(capacity, &clock, tenant, shard, identity, vec![record])
        .map_err(describe)?
        .into_store_block();
    ledger.append(block).map(|_| ()).map_err(describe)
}

pub(super) fn sources<'kernel, 'catalog, 'ledger>(
    first: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    second: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
) -> Result<TailSourceSet<'kernel, 'catalog, 'ledger>, String> {
    let first_reader = first.reader().map_err(describe)?;
    let second_reader = second.reader().map_err(describe)?;
    TailSourceSet::new(vec![first_reader, second_reader])
        .map_err(|error| format!("sources: {error:?}"))
}

pub(super) fn plan<'kernel, 'catalog, 'ledger>(
    service: &QueryService<'kernel, 'catalog, 'ledger>,
    context: positron_governance::AuthorizedContext,
    source: &str,
    budget: QueryBudget,
) -> Result<positron_query::PlannedQuery<'kernel>, String> {
    service
        .plan_pipeline(context, source, budget)
        .map_err(|error| format!("plan: {error:?}"))
}

pub(super) fn credential(claim: &super::BootstrapClaim) -> Result<PresentedCredential, String> {
    let query_secret = claim
        .query_secret()
        .ok_or_else(|| "bootstrap did not issue a query credential".to_owned())?;
    PresentedCredential::parse(query_secret).map_err(describe)
}

pub(super) fn query_context(
    instance: &super::InitializedInstance,
    credential: PresentedCredential,
) -> Result<positron_governance::AuthorizedContext, String> {
    instance
        .attribute(
            credential,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        )
        .map_err(describe)
}
