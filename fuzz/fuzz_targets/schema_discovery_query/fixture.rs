use std::cell::Cell;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord as OtlpLogRecord, ResourceLogs, ScopeLogs};
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{AttributeNamespace, ValidatedAttributeValue};
use positron_governance::{
    AuthorizedContext, CompatibilityHints, PresentedCredential, RequestedIntent,
};
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, FixedAdmissionGroupPlanner, IngestOutcome, IngestPolicy,
    LogIngest, OtlpLogsReceiver, SchemaDiscoveryRequest, TenantSchemaRegistry, TenantSchemaSession,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, SegmentProtectionKey, SegmentScope,
    StorageKernelResourceAuthority, StoreBlockIdentity,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use positron_signals::{
    LogScan, LogStore, OccurrenceSelector, ScanLimit, SchemaCatalog, SchemaPath, SchemaQuery,
    SchemaValue, ScannedLogRecord,
};
use prost::Message;

use super::authority;

const MAX_ATTRIBUTES: usize = 32;
const MAX_PERSISTED_BLOCKS: u64 = 32;
const FALLBACK_KEY: &str = "fuzz-fallback";
const FALLBACK_VALUE: &str = "fallback";

pub struct FuzzFixture {
    tenant: TenantId,
    context: AuthorizedContext,
    authority: &'static StorageKernelResourceAuthority,
    ledger: &'static ActiveSegmentLedger<'static, 'static>,
    session: TenantSchemaSession,
    blocks: Cell<u64>,
    _root: FuzzRoot,
}

struct FuzzRoot(PathBuf);

impl FuzzFixture {
    pub fn establish() -> Option<Self> {
        Self::try_establish().ok()
    }

    fn try_establish() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "positron-schema-fuzz-{}-{nonce}",
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
        let authority = Box::leak(Box::new(authority::establish(&kernel_data, tenant)?));
        let catalog = Box::leak(Box::new(Catalog::open(
            authority,
            InstanceId::new([0x91; 16])?,
            CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
        )?));
        let shard = VirtualShardId::new(1)?;
        let ledger = Box::leak(Box::new(ActiveSegmentLedger::open(
            authority,
            catalog,
            SegmentScope::new(tenant, SignalKind::Logs, shard),
            SegmentProtectionKey::from_owned(Box::new([0x94; 32])),
        )?));
        let session = TenantSchemaRegistry::new(1)?.session(tenant, authority.governor())?;
        Ok(Self {
            tenant,
            context,
            authority,
            ledger,
            session,
            blocks: Cell::new(0),
            _root: FuzzRoot(root),
        })
    }

    pub fn exercise(&self, data: &[u8]) {
        if self.blocks.get() < MAX_PERSISTED_BLOCKS {
            self.ingest(data);
        }
        let Ok(snapshot) = self.ledger.snapshot() else {
            return;
        };
        let key = key(data.first().copied().unwrap_or_default());
        let Ok(path) = SchemaPath::root(AttributeNamespace::Record, key.clone()) else {
            return;
        };
        let _ = self.session.record_query_use(
            self.tenant,
            &path,
            &snapshot,
            self.authority.governor(),
        );
        let Ok(checkpoint) = self.session.checkpoint() else {
            return;
        };
        let Ok(catalog) = SchemaCatalog::decode_catalog_object(checkpoint.catalog_bytes()) else {
            return;
        };
        let Some(exact_value) = exact_value(data) else {
            return;
        };
        let Ok(limit) = ScanLimit::new(32) else {
            return;
        };
        let Ok(all_result) = LogStore::new().scan(
            self.authority.governor(),
            self.tenant,
            &snapshot,
            LogScan::all(limit),
        ) else {
            return;
        };
        for selector in [
            OccurrenceSelector::Index(0),
            OccurrenceSelector::Index(1),
            OccurrenceSelector::Any,
            OccurrenceSelector::All,
        ] {
            let exact_query = SchemaQuery::value(
                path.clone(),
                selector,
                exact_value.clone(),
            );
            let Ok(exact_result) = LogStore::new().scan_schema(
                self.authority.governor(),
                self.tenant,
                &snapshot,
                LogScan::all(limit),
                &catalog,
                &exact_query,
            ) else {
                continue;
            };
            let expected = all_result
                .records()
                .iter()
                .filter(|record| reference_matches(record, &key, selector, &exact_value))
                .map(ScannedLogRecord::commit_position)
                .collect::<Vec<_>>();
            let actual = exact_result
                .records()
                .iter()
                .map(ScannedLogRecord::commit_position)
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "exact scalar query changed logical results");
        }
        let fallback_path = SchemaPath::root(AttributeNamespace::Record, FALLBACK_KEY.to_owned())
            .ok();
        if let Some(fallback_path) = fallback_path {
            let fallback_query = SchemaQuery::value(
                fallback_path,
                OccurrenceSelector::Any,
                SchemaValue::string(FALLBACK_VALUE),
            );
            let Ok(fallback_result) = LogStore::new().scan_schema(
                self.authority.governor(),
                self.tenant,
                &snapshot,
                LogScan::all(limit),
                &catalog,
                &fallback_query,
            ) else {
                return;
            };
            if self.blocks.get() > 0 {
                assert_eq!(fallback_result.records().len(), self.blocks.get() as usize);
                assert!(
                    fallback_result.reduced_pruning(),
                    "unpromoted fallback path must report reduced pruning"
                );
            }
        }
        let requested = usize::from(data.get(1).copied().unwrap_or_default() % 32);
        if let Ok(request) = SchemaDiscoveryRequest::page(0, requested, requested / 2) {
            let _ = self.session.discover(self.tenant, request);
        }
    }

    fn ingest(&self, data: &[u8]) {
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
        let next = self.blocks.get().saturating_add(1);
        let identity = block_identity(next);
        let Ok(policy) = IngestPolicy::preserving(1) else {
            return;
        };
        let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));
        let outcome = LogIngest::new(
            self.authority,
            self.ledger,
            &clock,
            &policy,
            self.tenant,
            shard,
            self.session.clone(),
        )
        .accept(group.into_batch(), identity);
        if matches!(outcome, IngestOutcome::Full(_) | IngestOutcome::Partial(_)) {
            self.blocks.set(next);
        }
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request(data: &[u8]) -> ExportLogsServiceRequest {
    let mut attributes = data
        .chunks(3)
        .take(MAX_ATTRIBUTES)
        .map(|chunk| {
            let byte = chunk.first().copied().unwrap_or_default();
            let value = match byte % 6 {
                0 => None,
                1 => Some(any_value::Value::StringValue(format!("v{byte:02x}"))),
                2 => Some(any_value::Value::IntValue(i64::from(byte))),
                3 => Some(any_value::Value::BoolValue(byte & 1 == 1)),
                4 => Some(any_value::Value::DoubleValue(f64::from(byte) + 0.5)),
                _ => Some(any_value::Value::BytesValue(chunk.to_vec())),
            };
            KeyValue {
                key: key(byte),
                value: Some(AnyValue { value }),
                ..Default::default()
            }
        })
        .collect::<Vec<_>>();
    attributes.push(KeyValue {
        key: FALLBACK_KEY.to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(FALLBACK_VALUE.to_owned())),
        }),
        ..Default::default()
    });
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![OtlpLogRecord {
                    time_unix_nano: 1,
                    attributes,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn exact_value(data: &[u8]) -> Option<SchemaValue> {
    let chunk = data.chunks(3).next()?;
    let byte = *chunk.first()?;
    Some(match byte % 6 {
        0 => SchemaValue::null(),
        1 => SchemaValue::string(format!("v{byte:02x}")),
        2 => SchemaValue::signed_integer(i64::from(byte)),
        3 => SchemaValue::boolean(byte & 1 == 1),
        4 => SchemaValue::floating_point_bits((f64::from(byte) + 0.5).to_bits()),
        _ => SchemaValue::bytes(chunk.to_vec()),
    })
}

fn reference_matches(
    record: &ScannedLogRecord,
    key: &str,
    selector: OccurrenceSelector,
    expected: &SchemaValue,
) -> bool {
    let mut values = record
        .attributes()
        .iter()
        .filter(|attribute| {
            let occurrences = attribute.occurrences();
            occurrences.namespace() == AttributeNamespace::Record && occurrences.key() == key
        })
        .flat_map(|attribute| {
            let occurrences = attribute.occurrences();
            (0..occurrences.len()).filter_map(move |index| occurrences.occurrence(index))
        });
    match selector {
        OccurrenceSelector::Index(index) => values
            .nth(index)
            .is_some_and(|value| reference_value_matches(value, expected)),
        OccurrenceSelector::Any => values.any(|value| reference_value_matches(value, expected)),
        OccurrenceSelector::All => {
            let mut found = false;
            let matches = values.inspect(|_| found = true).all(|value| {
                reference_value_matches(value, expected)
            });
            found && matches
        },
    }
}

fn reference_value_matches(value: &ValidatedAttributeValue, expected: &SchemaValue) -> bool {
    match expected {
        SchemaValue::Null => value.is_null(),
        SchemaValue::Boolean(expected) => value.as_boolean() == Some(*expected),
        SchemaValue::SignedInteger(expected) => value.as_signed_integer() == Some(*expected),
        SchemaValue::FloatingPointBits(expected) => {
            value.as_floating_point_bits() == Some(*expected)
        },
        SchemaValue::String(expected) => value.as_str() == Some(expected),
        SchemaValue::Bytes(expected) => value.as_bytes() == Some(expected),
        SchemaValue::Kind(expected) => value.kind() == *expected,
    }
}

fn key(byte: u8) -> String {
    format!("k{:02x}", byte % 64)
}

fn block_identity(sequence: u64) -> StoreBlockIdentity {
    let mut bytes = [0_u8; 16];
    bytes[8..].copy_from_slice(&sequence.to_be_bytes());
    StoreBlockIdentity::new(bytes).expect("positive sequence is a valid identity")
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
