#![no_main]

use std::cell::OnceCell;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use libfuzzer_sys::fuzz_target;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, ArrayValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::value::{AttributeNamespace, AttributeValueKind};
use positron_governance::{
    AuthorizedContext, CompatibilityHints, PresentedCredential, RequestedIntent,
};
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, FixedAdmissionGroupPlanner, IngestPolicy, LogIngest,
    OtlpLogsReceiver, PolicyAction, PolicyAttributePath, PolicyPredicate, PolicyReceiver,
    PolicyRule, PolicyTarget, TenantSchemaRegistry, TenantSchemaSession,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, DiskPressureThresholds, GovernorPolicy,
    InstanceId, InventoryCardinalityLimits, MountQualification, ObservedResourceEnvironment,
    OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume, RecoveryPoolCapacities, RecoveryReserve,
    RegisteredResourceBounds, ResourceAmounts, ResourceDimension, ResourceGovernorConfiguration,
    ResourceInventory, SegmentProtectionKey, SegmentScope, StorageKernelResourceAuthority,
    StoreBlockIdentity, TenantQuota,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use prost::Message;

const MAX_INPUT_BYTES: usize = 4_096;

thread_local! {
    static FIXTURE: OnceCell<Option<FuzzFixture>> = const { OnceCell::new() };
}

struct FuzzFixture {
    tenant: TenantId,
    context: AuthorizedContext,
    authority: &'static StorageKernelResourceAuthority,
    ledger: &'static ActiveSegmentLedger<'static, 'static>,
    schema: TenantSchemaSession,
    _root: FuzzRoot,
}

struct FuzzRoot(PathBuf);

impl FuzzFixture {
    fn establish() -> Option<Self> {
        Self::try_establish().ok()
    }

    fn try_establish() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "positron-policy-fuzz-{}-{nonce}",
            std::process::id()
        ));
        let runtime_data = root.join("runtime-data");
        let runtime_secrets = root.join("runtime-secrets");
        let kernel_data = root.join("kernel-data");
        fs::create_dir_all(&runtime_data)?;
        fs::create_dir_all(&runtime_secrets)?;
        fs::create_dir_all(&kernel_data)?;
        set_owner_only(&runtime_secrets)?;
        let paths = BootstrapPaths::new(
            &runtime_data,
            &runtime_secrets,
            MountQualification::LocalHost,
        )?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let tenant = instance.default_tenant_id();
        let context = instance.attribute(
            PresentedCredential::parse(claim.ingest_secret().ok_or("missing credential")?)?,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        )?;
        let authority = Box::leak(Box::new(establish_authority(&kernel_data, tenant)?));
        let catalog = Box::leak(Box::new(Catalog::open(
            authority,
            InstanceId::new([0x81; 16])?,
            CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
        )?));
        let shard = VirtualShardId::new(1)?;
        let ledger = Box::leak(Box::new(ActiveSegmentLedger::open(
            authority,
            catalog,
            SegmentScope::new(tenant, SignalKind::Logs, shard),
            SegmentProtectionKey::from_owned(Box::new([0x84; 32])),
        )?));
        let schema = TenantSchemaRegistry::new(1)?.session(tenant, authority.governor())?;
        Ok(Self {
            tenant,
            context,
            authority,
            ledger,
            schema,
            _root: FuzzRoot(root),
        })
    }

    fn exercise(&self, data: &[u8]) {
        let Ok(policy) = compile_policy(data) else {
            return;
        };
        let request = AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
            self.context,
            self.authority.governor(),
            request(data).encode_to_vec(),
        );
        let Ok(request) = request else {
            return;
        };
        let Ok(batch) = OtlpLogsReceiver::new().decode(request) else {
            return;
        };
        let Ok(shard) = VirtualShardId::new(1) else {
            return;
        };
        let Ok(mut groups) = batch.into_admission_groups(&FixedAdmissionGroupPlanner::new(shard))
        else {
            return;
        };
        let Some(group) = groups.next() else {
            return;
        };
        let _ = LogIngest::new(
            self.authority,
            self.ledger,
            &policy,
            self.tenant,
            shard,
            self.schema.clone(),
        )
        .accept(group.into_batch(), block_identity(data));
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn compile_policy(data: &[u8]) -> Result<IngestPolicy, Box<dyn Error>> {
    let mut rules = Vec::new();
    for (index, chunk) in data.chunks(4).take(63).enumerate() {
        let selector = chunk.first().copied().unwrap_or_default();
        let path = policy_path(selector)?;
        let predicate = match selector % 7 {
            0 => PolicyPredicate::attribute_exists(path.clone()),
            1 => PolicyPredicate::body_exact_text(body_text(data))?,
            2 => PolicyPredicate::signal_store(SignalKind::Logs),
            3 => PolicyPredicate::receiver(receiver(selector)),
            4 => PolicyPredicate::attribute_type(path.clone(), AttributeValueKind::String),
            5 => PolicyPredicate::service_identity("fuzz-service")?,
            _ => PolicyPredicate::log_severity(i32::from(selector)),
        };
        let target = if selector & 1 == 0 {
            PolicyTarget::body()
        } else {
            PolicyTarget::attribute(path)
        };
        let action = match selector % 4 {
            0 => PolicyAction::Remove(target),
            1 => PolicyAction::Redact(target),
            2 => PolicyAction::TruncateBytes(target, u32::from(selector)),
            _ => PolicyAction::TruncateElements(target, u16::from(selector)),
        };
        rules.push(PolicyRule::new(
            format!("fuzz-rule-{index}"),
            vec![predicate],
            action,
        )?);
    }
    rules.push(PolicyRule::new(
        "terminal-reject",
        Vec::new(),
        PolicyAction::Reject,
    )?);
    Ok(IngestPolicy::compile(81, rules)?)
}

fn receiver(selector: u8) -> PolicyReceiver {
    match (selector / 7) % 7 {
        0 => PolicyReceiver::OtlpGrpc,
        1 => PolicyReceiver::OtlpHttpProtobuf,
        2 => PolicyReceiver::OtlpHttpJson,
        3 => PolicyReceiver::LokiPushJson,
        4 => PolicyReceiver::LokiPushProtobuf,
        5 => PolicyReceiver::LokiOtlpProtobuf,
        _ => PolicyReceiver::LokiOtlpJson,
    }
}

fn policy_path(selector: u8) -> Result<PolicyAttributePath, Box<dyn Error>> {
    let path = match selector % 3 {
        0 => PolicyAttributePath::new(AttributeNamespace::Record, "secret")?,
        1 => PolicyAttributePath::new(AttributeNamespace::Record, "items")?.array_index(0)?,
        _ => PolicyAttributePath::new(AttributeNamespace::Record, "payload")?.key("token")?,
    };
    Ok(if selector & 0x40 == 0 {
        path
    } else {
        path.at_occurrence(u16::from(selector & 3))
    })
}

fn request(data: &[u8]) -> ExportLogsServiceRequest {
    let body = body_text(data);
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(opentelemetry_proto::tonic::resource::v1::Resource {
                attributes: vec![attribute("service.name", text("fuzz-service"))],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 1,
                    severity_number: i32::from(data.first().copied().unwrap_or_default()),
                    body: Some(text(&body)),
                    attributes: vec![
                        attribute("secret", text(&body)),
                        attribute(
                            "items",
                            AnyValue {
                                value: Some(any_value::Value::ArrayValue(ArrayValue {
                                    values: vec![text(&body), text("tail")],
                                })),
                            },
                        ),
                        attribute(
                            "payload",
                            AnyValue {
                                value: Some(any_value::Value::KvlistValue(
                                    opentelemetry_proto::tonic::common::v1::KeyValueList {
                                        values: vec![attribute("token", text(&body))],
                                    },
                                )),
                            },
                        ),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn body_text(data: &[u8]) -> String {
    data.iter()
        .copied()
        .take(128)
        .map(|byte| char::from(b'a' + byte % 26))
        .collect()
}

fn text(value: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(value.to_owned())),
    }
}

fn attribute(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(value),
        ..Default::default()
    }
}

fn block_identity(data: &[u8]) -> StoreBlockIdentity {
    let mut identity = [0_u8; 16];
    for (index, byte) in data.iter().copied().enumerate() {
        identity[index % 16] ^= byte;
    }
    identity[0] |= 1;
    StoreBlockIdentity::new(identity).expect("forced nonzero identity")
}

fn establish_authority(
    path: &Path,
    tenant: positron_domain::identity::TenantId,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let volume = PrimaryDataVolume::acquire(path, MountQualification::LocalHost)?;
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
    let observed = ObservedResourceEnvironment::observe(
        &volume,
        RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])?,
    )?;
    let large = ResourceAmounts::new([
        90_000_000, 4, 4, 90_000_000, 70_000, 4, 4, 4, 4, 16, 40_000_000,
    ]);
    let small = uniform(2);
    let durability = add(add(large, large)?, large)?;
    let recovery = add(add(add(durability, large)?, large)?, uniform(12))?;
    let ordinary = ResourceAmounts::new([
        5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
    ]);
    let raw = add(
        add(recovery, ordinary)?,
        cardinality.governor_bootstrap_overhead(1)?,
    )?;
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery)?,
        cardinality,
        DiskPressureThresholds::new(
            recovery.get(ResourceDimension::DiskHeadroomBytes),
            recovery.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery.get(ResourceDimension::DiskHeadroomBytes) + 2,
            disk,
        )?,
    )?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary)?],
        OrdinaryPoolPolicy::new(uniform(8), uniform(6), uniform(4), uniform(2))?,
    )?;
    let pools = RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(inventory, policy, pools)?,
    )
    .map_err(|_| "authority establishment failed")?)
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn add(left: ResourceAmounts, right: ResourceAmounts) -> Result<ResourceAmounts, Box<dyn Error>> {
    let value = |dimension| {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or("capacity overflow")
    };
    Ok(ResourceAmounts::new([
        value(ResourceDimension::MemoryBytes)?,
        value(ResourceDimension::QueueSlots)?,
        value(ResourceDimension::TaskSlots)?,
        value(ResourceDimension::BufferCacheBytes)?,
        value(ResourceDimension::BatchItems)?,
        value(ResourceDimension::LeaseSlots)?,
        value(ResourceDimension::RetrySlots)?,
        value(ResourceDimension::IoPermits)?,
        value(ResourceDimension::CpuWorkUnits)?,
        value(ResourceDimension::FileDescriptors)?,
        value(ResourceDimension::DiskHeadroomBytes)?,
    ]))
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    FIXTURE.with(|fixture| {
        if let Some(fixture) = fixture.get_or_init(FuzzFixture::establish) {
            fixture.exercise(data);
        }
    });
});
