use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId};
use positron_kernel::{
    DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits, MountQualification,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    StorageKernelResourceAuthority, TenantQuota,
};
use prost::Message;

use crate::AuthenticatedOtlpLogsRequest;

const DIMENSIONS: usize = 11;

pub struct Fixture {
    pub authority: StorageKernelResourceAuthority,
    pub tenant: TenantId,
    _root: TemporaryRoot,
}

pub fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let tenant = TenantId::from_bytes([2; 16])?;
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
    let recovery_capacity = add(add(add(durability, large)?, large)?, uniform(12))?;
    let ordinary_capacity = ResourceAmounts::new([
        5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
    ]);
    let governed = add(recovery_capacity, ordinary_capacity)?;
    let raw = add(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery_capacity)?,
        cardinality,
        DiskPressureThresholds::new(
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes),
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 2,
            disk,
        )?,
    )?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary_capacity)?],
        OrdinaryPoolPolicy::new(uniform(8), uniform(6), uniform(4), uniform(2))?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)?;
    let authority = StorageKernelResourceAuthority::establish(volume, configuration)
        .map_err(|_| "kernel authority establishment failed")?;
    Ok(Fixture {
        authority,
        tenant,
        _root: root,
    })
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; DIMENSIONS])
}

fn add(
    left: ResourceAmounts,
    right: ResourceAmounts,
) -> Result<ResourceAmounts, Box<dyn std::error::Error>> {
    let value = |dimension| -> Result<u64, Box<dyn std::error::Error>> {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or_else(|| "resource capacity overflow".into())
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

struct TemporaryRoot(std::path::PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-ingest-test-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn attribution() -> TenantAttribution {
    TenantAttribution::new(
        PrincipalId::from_bytes([1; 16]).expect("principal"),
        Scope::Ingest,
        TenantId::from_bytes([2; 16]).expect("tenant"),
    )
    .expect("ingest attribution")
}

pub fn protobuf_request() -> AuthenticatedOtlpLogsRequest<'static> {
    protobuf_with_bodies(&["paid"])
}

pub fn protobuf_with_bodies(bodies: &[&str]) -> AuthenticatedOtlpLogsRequest<'static> {
    AuthenticatedOtlpLogsRequest::test_only_protobuf(attribution(), protobuf_bytes(bodies))
}

pub fn protobuf_bytes(bodies: &[&str]) -> Vec<u8> {
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![text_attribute("service.name", "checkout")],
                ..Resource::default()
            }),
            scope_logs: vec![ScopeLogs {
                log_records: bodies
                    .iter()
                    .enumerate()
                    .map(|(index, body)| LogRecord {
                        time_unix_nano: 42 + u64::try_from(index).expect("test record bound"),
                        observed_time_unix_nano: 84
                            + u64::try_from(index).expect("test record bound"),
                        body: Some(text(body)),
                        attributes: vec![text_attribute("order.id", "A-1")],
                        ..LogRecord::default()
                    })
                    .collect(),
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };
    request.encode_to_vec()
}

fn text(value: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(value.to_owned())),
    }
}

fn text_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(text(value)),
        ..KeyValue::default()
    }
}
