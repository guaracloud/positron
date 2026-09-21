#![no_main]

use std::fs;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_api::{
    api_keys::{ApiKeyRequest, ApiKeyResponse},
    tenant_aliases::TenantAliasBindRequest,
};
use positron_domain::identity::{ExternalTenantAlias, PrincipalId, Scope, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CatalogRootRotationStage, CompatibilityHints,
    GovernanceAuditEntry, PresentedCredential, RequestedIntent, ResourceGeneration,
    TenantCreateConfiguration,
};
use positron_kernel::MountQualification;
use positron_runtime::{
    BootstrapFailureCode, BootstrapPaths, InitializationPlan, InstanceBootstrap,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct FuzzRoots {
    parent: PathBuf,
    data: PathBuf,
    secrets: PathBuf,
}

impl FuzzRoots {
    fn new() -> Option<Self> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir().join(format!(
            "positron-bootstrap-fuzz-{}-{sequence}",
            std::process::id()
        ));
        let data = parent.join("data");
        let secrets = parent.join("secrets");
        fs::create_dir(&parent).ok()?;
        fs::create_dir(&data).ok()?;
        fs::create_dir(&secrets).ok()?;
        set_owner_only(&secrets).ok()?;
        Some(Self {
            parent,
            data,
            secrets,
        })
    }

    fn paths(&self) -> Option<BootstrapPaths> {
        BootstrapPaths::new(&self.data, &self.secrets, MountQualification::LocalHost).ok()
    }
}

impl Drop for FuzzRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn corrupt(path: &Path, selector: usize) {
    let Ok(mut bytes) = fs::read(path) else {
        return;
    };
    if bytes.is_empty() {
        return;
    }
    let index = selector % bytes.len();
    if let Some(byte) = bytes.get_mut(index) {
        *byte ^= 0x80;
        let _ = fs::write(path, bytes);
    }
}

/// Corrupt every bounded artifact in one Catalog directory.  An audit-retention
/// publication stores its signed anchor and reclamation receipt as separate,
/// encrypted Catalog objects, so selecting one filename would not prove that
/// both authenticated objects fence recovery.
fn corrupt_catalog_artifacts(root: &Path, directory: &str, selector: usize) -> bool {
    let directory = root.join(directory);
    let Ok(entries) = fs::read_dir(directory) else {
        return false;
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() || paths.len() > 64 {
        return false;
    }
    for (index, path) in paths.iter().enumerate() {
        corrupt(path, selector.wrapping_add(index));
    }
    true
}

fn heterogeneous_rotation_entries(data: &[u8], first_position: u64) -> Vec<GovernanceAuditEntry> {
    let mut provider_key_reference = [0_u8; 16];
    let provider_bytes = data.get(..data.len().min(16)).unwrap_or_default();
    provider_key_reference[..provider_bytes.len()].copy_from_slice(provider_bytes);
    if provider_key_reference.iter().all(|byte| *byte == 0) {
        provider_key_reference[0] = 1;
    }
    let mut epoch_bytes = [0_u8; 8];
    let epoch_source = data.get(16..data.len().min(24)).unwrap_or_default();
    epoch_bytes[..epoch_source.len()].copy_from_slice(epoch_source);
    let key_epoch = u64::from_be_bytes(epoch_bytes).max(1);
    let mut transaction_id = provider_key_reference;
    transaction_id[15] ^= 0x80;
    if transaction_id.iter().all(|byte| *byte == 0) {
        transaction_id[0] = 1;
    }

    [b"started".as_slice(), b"verified", b"completed"]
        .into_iter()
        .enumerate()
        .map(|(index, stage)| {
            let mut intent = b"catalog-root-rotation-v1\0".to_vec();
            intent.extend_from_slice(stage);
            intent.push(0);
            intent.extend_from_slice(&provider_key_reference);
            intent.extend_from_slice(&key_epoch.to_be_bytes());
            intent.extend_from_slice(b"fuzz-sensitive-metadata");
            intent.extend_from_slice(data.get(..data.len().min(24)).unwrap_or_default());
            let entry = positron_governance::fuzz_decode_governance_audit(
                first_position + u64::try_from(index).expect("bounded stage"),
                transaction_id,
                &intent,
            )
            .expect("complete known rotation schema");
            let rendered = format!("{entry:?} {entry}");
            assert!(!rendered.contains("fuzz-sensitive-metadata"));
            entry
        })
        .collect()
}

fn retention_audit_boundaries(data: &[u8]) {
    let transaction = [0x51; 16];
    let mut digest = [0_u8; 32];
    let copied = data.len().min(digest.len());
    digest[..copied].copy_from_slice(&data[..copied]);
    if digest.iter().all(|byte| *byte == 0) {
        digest[0] = 1;
    }
    let mut intent = b"POSTRT01".to_vec();
    intent.extend_from_slice(&1_725_000_003_u64.to_be_bytes());
    intent.extend_from_slice(&transaction);
    intent.extend_from_slice(&[0x52; 16]);
    intent.extend_from_slice(&[0x53; 16]);
    intent.extend_from_slice(&1_u64.to_be_bytes());
    intent.extend_from_slice(&2_u64.to_be_bytes());
    intent.extend_from_slice(&86_400_u64.to_be_bytes());
    intent.extend_from_slice(&digest);

    let entry = positron_governance::fuzz_decode_governance_audit(5, transaction, &intent)
        .expect("canonical retention audit is accepted");
    let retention = entry
        .as_tenant_retention_update()
        .expect("canonical retention audit is typed");
    assert_eq!(entry.action(), "tenant.retention.update");
    assert_eq!(retention.tenant_id().to_bytes(), [0x53; 16]);
    assert_eq!(retention.expected_generation().get(), 1);
    assert_eq!(retention.generation().get(), 2);
    assert_eq!(retention.idempotency_key().to_bytes(), transaction);
    assert_eq!(retention.request_digest(), digest);
    assert!(
        !format!("{entry:?} {entry}").contains("86400"),
        "audit rendering must not disclose the requested retention duration"
    );

    for length in [0, 7, 8, intent.len() - 1] {
        assert!(
            positron_governance::fuzz_decode_governance_audit(5, transaction, &intent[..length])
                .is_err()
        );
    }
    let mut zero_digest = intent.clone();
    let digest_start = zero_digest.len() - digest.len();
    zero_digest[digest_start..].fill(0);
    assert!(
        positron_governance::fuzz_decode_governance_audit(5, transaction, &zero_digest).is_err()
    );
    let mut stale_generation = intent.clone();
    let generation_start = 8 + 8 + 16 + 16 + 16 + 8;
    stale_generation[generation_start..generation_start + 8].copy_from_slice(&1_u64.to_be_bytes());
    assert!(
        positron_governance::fuzz_decode_governance_audit(5, transaction, &stale_generation)
            .is_err()
    );
    let mut trailing = intent;
    trailing.push(0);
    assert!(positron_governance::fuzz_decode_governance_audit(5, transaction, &trailing).is_err());
}

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let _ = ApiKeyRequest::decode(data);
    let _ = TenantAliasBindRequest::decode(data);
    if let Ok(response) = ApiKeyResponse::decode(data) {
        assert_eq!(format!("{response:?}"), "ApiKeyResponse { <redacted> }");
    }
    positron_governance::fuzz_parse_governance(&data[..split], &data[split..]);
    retention_audit_boundaries(data);
    let rotations = heterogeneous_rotation_entries(data, 2);
    assert_eq!(rotations.len(), 3);
    assert_eq!(
        rotations
            .iter()
            .map(|entry| entry.position())
            .collect::<Vec<_>>(),
        [2, 3, 4]
    );
    assert_eq!(
        rotations
            .iter()
            .map(|entry| entry.as_catalog_root_rotation().expect("rotation").stage())
            .collect::<Vec<_>>(),
        [
            CatalogRootRotationStage::Started,
            CatalogRootRotationStage::Verified,
            CatalogRootRotationStage::Completed,
        ]
    );
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(credential) = PresentedCredential::parse(text) {
            assert!(!format!("{credential:?}").contains(text));
        }
        let _ = CompatibilityHints::external_tenant_alias(text);
    }
    if data.is_empty() || data.len() > 24 || data[0] & 7 != 0 {
        return;
    }
    let Some(roots) = FuzzRoots::new() else {
        return;
    };
    let Some(paths) = roots.paths() else {
        return;
    };
    let mut identity = None;
    let mut integrity = None;
    let mut claim_released = false;
    let mut credential = None;
    let mut tenant_key: Option<(PrincipalId, String, Scope)> = None;
    let mut credential_generation = 1_u64;
    let mut lifecycle_generation = 1_u64;
    let mut alias_generation = 1_u64;
    let mut retention_generation = 1_u64;
    let mut audit_retention_generation = 1_u64;
    let mut secondary_tenant = None;
    let mut storage_tampered = false;
    for (index, command) in data.iter().copied().enumerate() {
        match command & 15 {
            0 | 1 => {
                if let Ok(instance) =
                    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())
                {
                    assert_eq!(
                        identity.get_or_insert(instance.instance_id()),
                        &instance.instance_id()
                    );
                    assert_eq!(
                        integrity.get_or_insert(instance.integrity_key_fingerprint()),
                        &instance.integrity_key_fingerprint()
                    );
                }
            },
            2 => {
                if let Ok(instance) = InstanceBootstrap::reopen(&paths) {
                    assert_eq!(
                        identity.get_or_insert(instance.instance_id()),
                        &instance.instance_id()
                    );
                    assert_eq!(
                        integrity.get_or_insert(instance.integrity_key_fingerprint()),
                        &instance.integrity_key_fingerprint()
                    );
                }
            },
            3 => match InstanceBootstrap::claim(&paths) {
                Ok(claim) => {
                    assert!(!claim_released);
                    assert!(claim.secret().starts_with("pos_"));
                    assert_eq!(claim.secret().len(), 68);
                    claim_released = true;
                    credential = Some(claim.secret().to_owned());
                },
                Err(failure) if claim_released => {
                    assert_eq!(failure.code(), BootstrapFailureCode::ClaimUnavailable);
                },
                Err(_) => {},
            },
            4 => {
                corrupt(&roots.secrets.join("bootstrap-claim.v1"), index);
                storage_tampered = true;
            },
            5 => {
                corrupt(&roots.data.join(".positron-bootstrap.initialized"), index);
                storage_tampered = true;
            },
            6 => {
                if let (Some(secret), Ok(instance)) =
                    (credential.as_deref(), InstanceBootstrap::reopen(&paths))
                {
                    let presented = PresentedCredential::parse(secret)
                        .expect("a claimed credential retains canonical syntax");
                    let authorized = instance
                        .attribute(
                            presented,
                            RequestedIntent::SystemAdministration,
                            CompatibilityHints::none(),
                        )
                        .expect("the claimed bootstrap principal remains authoritative");
                    assert_eq!(authorized.tenant_attribution(), None);
                    let audit = instance
                        .inspect_governance_for_fixture(authorized)
                        .expect("system administration authorizes governance inspection");
                    assert!(!audit.audit_records().is_empty());
                    let audit_len = audit.audit_records().len();
                    let next_position = u64::try_from(audit_len).expect("bounded audit chain") + 1;
                    let rotations = heterogeneous_rotation_entries(data, next_position);
                    let heterogeneous = audit
                        .audit_records()
                        .iter()
                        .chain(rotations.iter())
                        .collect::<Vec<_>>();
                    assert_eq!(heterogeneous.len(), audit_len + rotations.len());
                    for (index, entry) in heterogeneous.iter().enumerate() {
                        assert_eq!(
                            entry.position(),
                            u64::try_from(index).expect("bounded audit chain") + 1
                        );
                    }
                    let presented = PresentedCredential::parse(secret)
                        .expect("a claimed credential retains canonical syntax");
                    assert!(
                        instance
                            .attribute(
                                presented,
                                RequestedIntent::Ingest,
                                CompatibilityHints::none(),
                            )
                            .is_err()
                    );
                    let hinted = PresentedCredential::parse(secret)
                        .expect("a claimed credential retains canonical syntax");
                    assert!(
                        instance
                            .attribute(
                                hinted,
                                RequestedIntent::SystemAdministration,
                                CompatibilityHints::external_tenant_alias("forged")
                                    .expect("bounded fuzz hint"),
                            )
                            .is_err()
                    );
                    let adversarial = PresentedCredential::parse(secret)
                        .expect("a claimed credential retains canonical syntax");
                    let failure = instance
                        .attribute(
                            adversarial,
                            RequestedIntent::SystemAdministration,
                            CompatibilityHints::fuzz_adversarial(&data[index..]),
                        )
                        .expect_err("proxy and nested tenant claims cannot select authority");
                    assert_eq!(failure.to_string(), "credential or authority was rejected");
                }
            },
            7 => {
                if let (Some(secret), Ok(instance)) =
                    (credential.as_deref(), InstanceBootstrap::reopen(&paths))
                {
                    let context = instance
                        .attribute(
                            PresentedCredential::parse(secret)
                                .expect("claimed credential remains canonical"),
                            RequestedIntent::SystemAdministration,
                            CompatibilityHints::none(),
                        )
                        .expect("claimed credential remains authoritative");
                    if let Some(other) = FuzzRoots::new()
                        && let Some(other_paths) = other.paths()
                        && let Ok(other_instance) = InstanceBootstrap::initialize(
                            &other_paths,
                            InitializationPlan::non_interactive(),
                        )
                    {
                        assert!(
                            other_instance
                                .inspect_governance_for_fixture(context)
                                .is_err()
                        );
                    }
                }
            },
            8 => {
                if let (Some(root_secret), Ok(instance)) =
                    (credential.as_deref(), InstanceBootstrap::reopen(&paths))
                {
                    let Ok(administrator) = instance.attribute(
                        PresentedCredential::parse(root_secret)
                            .expect("claimed credential remains canonical"),
                        RequestedIntent::SystemAdministration,
                        CompatibilityHints::none(),
                    ) else {
                        continue;
                    };
                    let scope = if command & 0x10 == 0 {
                        Scope::Query
                    } else {
                        Scope::Ingest
                    };
                    let intent = if scope == Scope::Query {
                        RequestedIntent::Query
                    } else {
                        RequestedIntent::Ingest
                    };
                    let idempotency = AdministrativeIdempotencyKey::new(
                        [u8::try_from(index).expect("bounded input") + 1; 16],
                    )
                    .expect("nonzero idempotency");
                    let expected =
                        ResourceGeneration::new(credential_generation).expect("bounded generation");
                    if let Ok(created) =
                        instance.create_api_key(administrator, scope, None, expected, idempotency)
                    {
                        let key_secret = created
                            .secret()
                            .expect("new API key is shown exactly once")
                            .to_owned();
                        assert_eq!(key_secret.len(), 68);
                        assert!(!format!("{created:?}").contains(&key_secret));
                        let attributed = instance.attribute(
                            PresentedCredential::parse(&key_secret)
                                .expect("generated API key remains canonical"),
                            intent,
                            CompatibilityHints::none(),
                        );
                        assert!(attributed.is_ok());
                        let confused_deputy = instance.attribute(
                            PresentedCredential::parse(&key_secret)
                                .expect("generated API key remains canonical"),
                            intent,
                            CompatibilityHints::fuzz_adversarial(&data[index..]),
                        );
                        assert!(
                            confused_deputy.is_err(),
                            "untrusted proxy or nested tenant claims cannot change a valid tenant key"
                        );
                        assert!(
                            instance
                                .attribute(
                                    PresentedCredential::parse(&key_secret)
                                        .expect("generated API key remains canonical"),
                                    RequestedIntent::SystemAdministration,
                                    CompatibilityHints::none(),
                                )
                                .is_err()
                        );
                        let replay = instance.create_api_key(
                            instance
                                .attribute(
                                    PresentedCredential::parse(root_secret).expect("claim syntax"),
                                    RequestedIntent::SystemAdministration,
                                    CompatibilityHints::none(),
                                )
                                .expect("bootstrap credential remains administrator"),
                            scope,
                            None,
                            expected,
                            idempotency,
                        );
                        if let Ok(replay) = replay {
                            assert_eq!(replay.principal_id(), created.principal_id());
                            assert!(replay.secret().is_none());
                        }
                        tenant_key = Some((created.principal_id(), key_secret, scope));
                        credential_generation = credential_generation.saturating_add(1);
                    }
                }
            },
            9 => {
                if let (Some(secret), Some((principal, old_secret, scope)), Ok(instance)) = (
                    credential.as_deref(),
                    tenant_key.take(),
                    InstanceBootstrap::reopen(&paths),
                ) {
                    let Ok(administrator) = instance.attribute(
                        PresentedCredential::parse(secret).expect("claim syntax"),
                        RequestedIntent::SystemAdministration,
                        CompatibilityHints::none(),
                    ) else {
                        tenant_key = Some((principal, old_secret, scope));
                        continue;
                    };
                    let idempotency = AdministrativeIdempotencyKey::new(
                        [u8::try_from(index).expect("bounded input") + 1; 16],
                    )
                    .expect("nonzero idempotency");
                    let expected =
                        ResourceGeneration::new(credential_generation).expect("bounded generation");
                    if let Ok(successor) =
                        instance.rotate_api_key(administrator, principal, expected, idempotency)
                    {
                        let successor_secret = successor
                            .secret()
                            .expect("rotated API key is shown exactly once")
                            .to_owned();
                        let intent = if scope == Scope::Query {
                            RequestedIntent::Query
                        } else {
                            RequestedIntent::Ingest
                        };
                        for presented in [&old_secret, &successor_secret] {
                            assert!(
                                instance
                                    .attribute(
                                        PresentedCredential::parse(presented)
                                            .expect("generated API key remains canonical"),
                                        intent,
                                        CompatibilityHints::none(),
                                    )
                                    .is_ok()
                            );
                        }
                        tenant_key = Some((successor.principal_id(), successor_secret, scope));
                        credential_generation = credential_generation.saturating_add(1);
                    } else {
                        tenant_key = Some((principal, old_secret, scope));
                    }
                }
            },
            10 => {
                if let (Some(secret), Some((principal, key_secret, scope)), Ok(instance)) = (
                    credential.as_deref(),
                    tenant_key.take(),
                    InstanceBootstrap::reopen(&paths),
                ) {
                    if let Ok(administrator) = instance.attribute(
                        PresentedCredential::parse(secret).expect("claim syntax"),
                        RequestedIntent::SystemAdministration,
                        CompatibilityHints::none(),
                    ) {
                        let idempotency = AdministrativeIdempotencyKey::new(
                            [u8::try_from(index).expect("bounded input") + 1; 16],
                        )
                        .expect("nonzero idempotency");
                        let expected = ResourceGeneration::new(credential_generation)
                            .expect("bounded generation");
                        if instance
                            .revoke_api_key(administrator, principal, expected, idempotency)
                            .is_ok()
                        {
                            assert!(
                                instance
                                    .attribute(
                                        PresentedCredential::parse(&key_secret)
                                            .expect("generated API key remains canonical"),
                                        if scope == Scope::Query {
                                            RequestedIntent::Query
                                        } else {
                                            RequestedIntent::Ingest
                                        },
                                        CompatibilityHints::none(),
                                    )
                                    .is_err()
                            );
                            credential_generation = credential_generation.saturating_add(1);
                        } else {
                            tenant_key = Some((principal, key_secret, scope));
                        }
                    }
                }
            },
            11 => {
                if let (Some(root_secret), Ok(instance)) =
                    (credential.as_deref(), InstanceBootstrap::reopen(&paths))
                {
                    let Ok(administrator) = instance.attribute(
                        PresentedCredential::parse(root_secret)
                            .expect("claimed credential remains canonical"),
                        RequestedIntent::SystemAdministration,
                        CompatibilityHints::none(),
                    ) else {
                        continue;
                    };
                    let target = match (command >> 4) & 7 {
                        0 => TenantLifecycleState::Active,
                        1 => TenantLifecycleState::ReadOnly,
                        2 => TenantLifecycleState::Suspended,
                        3 => TenantLifecycleState::Purging,
                        _ => TenantLifecycleState::Purged,
                    };
                    let idempotency = AdministrativeIdempotencyKey::new(
                        [u8::try_from(index).expect("bounded input") + 1; 16],
                    )
                    .expect("nonzero idempotency");
                    let expected = ResourceGeneration::new(lifecycle_generation)
                        .expect("bounded lifecycle generation");
                    if let Ok(transition) = instance.transition_tenant_lifecycle(
                        administrator,
                        instance.default_tenant_id(),
                        target,
                        expected,
                        idempotency,
                    ) {
                        assert_eq!(transition.to(), target);
                        assert_eq!(
                            transition.resource_generation().get(),
                            lifecycle_generation + 1
                        );
                        let replay = instance.transition_tenant_lifecycle(
                            instance
                                .attribute(
                                    PresentedCredential::parse(root_secret).expect("claim syntax"),
                                    RequestedIntent::SystemAdministration,
                                    CompatibilityHints::none(),
                                )
                                .expect("bootstrap credential remains administrator"),
                            instance.default_tenant_id(),
                            target,
                            expected,
                            idempotency,
                        );
                        assert_eq!(replay.expect("exact lifecycle retry"), transition);
                        lifecycle_generation = lifecycle_generation.saturating_add(1);
                        if let Some((_, key_secret, scope)) = tenant_key.as_ref() {
                            let intent = if *scope == Scope::Query {
                                RequestedIntent::Query
                            } else {
                                RequestedIntent::Ingest
                            };
                            let attributed = instance.attribute(
                                PresentedCredential::parse(key_secret)
                                    .expect("generated API key remains canonical"),
                                intent,
                                CompatibilityHints::none(),
                            );
                            let allowed = target == TenantLifecycleState::Active
                                || (target == TenantLifecycleState::ReadOnly
                                    && *scope == Scope::Query);
                            assert_eq!(attributed.is_ok(), allowed);
                        }
                    }
                }
            },
            12 => {
                if alias_generation != 1 {
                    continue;
                }
                if let (Some(root_secret), Ok(instance)) =
                    (credential.as_deref(), InstanceBootstrap::reopen(&paths))
                {
                    let Ok(administrator) = instance.attribute(
                        PresentedCredential::parse(root_secret)
                            .expect("claimed credential remains canonical"),
                        RequestedIntent::SystemAdministration,
                        CompatibilityHints::none(),
                    ) else {
                        continue;
                    };
                    let idempotency = AdministrativeIdempotencyKey::new(
                        [u8::try_from(index).expect("bounded input") + 1; 16],
                    )
                    .expect("nonzero idempotency");
                    let expected = ResourceGeneration::new(alias_generation)
                        .expect("bounded alias generation");
                    let tenant = secondary_tenant
                        .filter(|_| command & 0x10 != 0)
                        .unwrap_or_else(|| instance.default_tenant_id());
                    let alias_text = format!("loki.fuzz-{index}");
                    let alias = ExternalTenantAlias::parse(&alias_text)
                        .expect("generated alias remains canonical");
                    if let Ok(binding) = instance.bind_tenant_alias(
                        administrator,
                        tenant,
                        alias.clone(),
                        expected,
                        idempotency,
                    ) {
                        assert_eq!(binding.alias_generation().get(), alias_generation + 1);
                        let replay = instance.bind_tenant_alias(
                            administrator,
                            tenant,
                            alias,
                            expected,
                            idempotency,
                        );
                        assert_eq!(replay.expect("exact alias retry"), binding);
                        alias_generation = alias_generation.saturating_add(1);
                    }
                }
            },
            13 => {
                if let (Some(root_secret), Ok(instance)) =
                    (credential.as_deref(), InstanceBootstrap::reopen(&paths))
                {
                    let Ok(administrator) = instance.attribute(
                        PresentedCredential::parse(root_secret)
                            .expect("claimed credential remains canonical"),
                        RequestedIntent::SystemAdministration,
                        CompatibilityHints::none(),
                    ) else {
                        continue;
                    };
                    let tenant = instance.default_tenant_id();
                    let reduction = NonZeroU64::new(86_400).expect("fixed retention reduction");
                    if let Ok(preview) =
                        instance.inspect_tenant_retention_impact(administrator, tenant, reduction)
                    {
                        assert_eq!(preview.tenant(), tenant);
                        assert_eq!(preview.retention_generation().get(), retention_generation);
                        assert_eq!(preview.proposed_retention_seconds(), reduction);
                        assert!(preview.catalog_generation() > 0);
                        assert!(preview.confirmation_digest().iter().any(|byte| *byte != 0));
                        for scope in preview.scopes() {
                            assert_eq!(scope.scope().tenant_id(), tenant);
                            assert_eq!(scope.catalog_identity(), preview.catalog_identity());
                            assert_eq!(scope.catalog_generation(), preview.catalog_generation());
                        }
                        let idempotency = AdministrativeIdempotencyKey::new(
                            [u8::try_from(index).expect("bounded input") + 0x40; 16],
                        )
                        .expect("nonzero idempotency");
                        if let Ok(updated) = instance.update_tenant_retention(
                            administrator,
                            tenant,
                            reduction,
                            ResourceGeneration::new(retention_generation)
                                .expect("bounded retention generation"),
                            Some(&preview),
                            idempotency,
                        ) {
                            assert_eq!(
                                updated.retention_generation().get(),
                                retention_generation + 1
                            );
                            drop(instance);
                            let reopened = InstanceBootstrap::reopen(&paths)
                                .expect("committed retention successor reopens");
                            let replay = reopened.update_tenant_retention(
                                reopened
                                    .attribute(
                                        PresentedCredential::parse(root_secret)
                                            .expect("claim syntax"),
                                        RequestedIntent::SystemAdministration,
                                        CompatibilityHints::none(),
                                    )
                                    .expect("bootstrap credential remains administrator"),
                                tenant,
                                reduction,
                                ResourceGeneration::new(retention_generation)
                                    .expect("bounded retention generation"),
                                Some(&preview),
                                idempotency,
                            );
                            assert_eq!(replay.expect("exact retention recovery retry"), updated);
                            retention_generation = retention_generation.saturating_add(1);
                            let instance = reopened;
                            let expanded = NonZeroU64::new(
                                2_592_000_u64
                                    .checked_add(retention_generation)
                                    .expect("bounded fuzz retention"),
                            )
                            .expect("nonzero fuzz retention");
                            let idempotency = AdministrativeIdempotencyKey::new(
                                [u8::try_from(index).expect("bounded input") + 1; 16],
                            )
                            .expect("nonzero idempotency");
                            if let Ok(updated) = instance.update_tenant_retention(
                                administrator,
                                tenant,
                                expanded,
                                ResourceGeneration::new(retention_generation)
                                    .expect("bounded retention generation"),
                                None,
                                idempotency,
                            ) {
                                assert_eq!(
                                    updated.retention_generation().get(),
                                    retention_generation + 1
                                );
                                let replay = instance.update_tenant_retention(
                                    administrator,
                                    tenant,
                                    expanded,
                                    ResourceGeneration::new(retention_generation)
                                        .expect("bounded retention generation"),
                                    None,
                                    idempotency,
                                );
                                assert_eq!(replay.expect("exact retention retry"), updated);
                                retention_generation = retention_generation.saturating_add(1);
                            }
                        }
                    }
                }
            },
            14 => {
                if secondary_tenant.is_some() {
                    continue;
                }
                if let (Some(root_secret), Ok(instance)) =
                    (credential.as_deref(), InstanceBootstrap::reopen(&paths))
                {
                    let Ok(administrator) = instance.attribute(
                        PresentedCredential::parse(root_secret)
                            .expect("claimed credential remains canonical"),
                        RequestedIntent::SystemAdministration,
                        CompatibilityHints::none(),
                    ) else {
                        continue;
                    };
                    let tenant = TenantId::from_bytes([0xe4; 16])
                        .expect("fixed secondary tenant identifier");
                    let configuration = TenantCreateConfiguration::new(
                        TenantSlug::parse_canonical("fuzz-secondary")
                            .expect("fixed secondary tenant slug"),
                        "Fuzz secondary tenant",
                        2_592_000,
                        1,
                        [1; 11],
                    );
                    let idempotency = AdministrativeIdempotencyKey::new([0xe5; 16])
                        .expect("fixed secondary idempotency");
                    if let Ok(created) = instance.create_tenant(
                        administrator,
                        tenant,
                        configuration.clone(),
                        idempotency,
                    ) {
                        assert_eq!(created.tenant_id(), tenant);
                        assert_eq!(created.resource_generation().get(), 2);
                        let replay = instance.create_tenant(
                            instance
                                .attribute(
                                    PresentedCredential::parse(root_secret).expect("claim syntax"),
                                    RequestedIntent::SystemAdministration,
                                    CompatibilityHints::none(),
                                )
                                .expect("bootstrap credential remains administrator"),
                            tenant,
                            configuration,
                            idempotency,
                        );
                        assert_eq!(replay.expect("exact secondary tenant retry"), created);
                        let inspection = instance
                            .inspect_tenant(
                                instance
                                    .attribute(
                                        PresentedCredential::parse(root_secret)
                                            .expect("claim syntax"),
                                        RequestedIntent::SystemAdministration,
                                        CompatibilityHints::none(),
                                    )
                                    .expect("bootstrap credential remains administrator"),
                                tenant,
                            )
                            .expect("canonical profile-bearing tenant record is readable");
                        assert_eq!(inspection.tenant_id(), tenant);
                        assert_eq!(inspection.slug(), "fuzz-secondary");
                        assert_eq!(inspection.display_name(), "Fuzz secondary tenant");
                        assert_eq!(inspection.retention_seconds(), 2_592_000);
                        assert_eq!(inspection.retention_generation().get(), 1);
                        secondary_tenant = Some(tenant);
                    }
                }
            },
            _ => {
                if let (Some(root_secret), Ok(instance)) =
                    (credential.as_deref(), InstanceBootstrap::reopen(&paths))
                {
                    let Ok(administrator) = instance.attribute(
                        PresentedCredential::parse(root_secret)
                            .expect("claimed credential remains canonical"),
                        RequestedIntent::SystemAdministration,
                        CompatibilityHints::none(),
                    ) else {
                        continue;
                    };
                    let limit = NonZeroU64::new(u64::from(command >> 4).max(1))
                        .expect("bounded nonzero audit retention limit");
                    let key = AdministrativeIdempotencyKey::new(
                        [u8::try_from(index).expect("bounded input") + 0x80; 16],
                    )
                    .expect("nonzero idempotency");
                    let expected = ResourceGeneration::new(audit_retention_generation)
                        .expect("bounded audit-retention generation");
                    let fault_injected = command & 0x20 != 0;
                    let updated =
                        positron_kernel::fuzz_compaction_publication_fault(fault_injected, || {
                            instance.update_system_audit_retention(
                                administrator,
                                limit,
                                expected,
                                key,
                            )
                        });
                    if let Ok(updated) = updated {
                        assert_eq!(
                            updated.policy_generation().get(),
                            audit_retention_generation + 1
                        );
                        // This selector reaches the two new Catalog objects
                        // (the signed anchor and its reclamation receipt) only
                        // after their atomic publication.  Recovery must fence
                        // the tampered retained history.
                        if command & 0x80 != 0 && command & 0x40 == 0 {
                            assert!(corrupt_catalog_artifacts(
                                &roots.data,
                                "catalog/objects",
                                index,
                            ));
                            storage_tampered = true;
                        }
                        // A restart must release the live primary-volume
                        // authority first.  Retaining this instance turns the
                        // probe into an unsupported concurrent open rather
                        // than durable recovery.
                        drop(instance);
                        let reopened = match InstanceBootstrap::reopen(&paths) {
                            Ok(reopened) => reopened,
                            Err(_) if fault_injected || storage_tampered => continue,
                            Err(failure) => panic!(
                                "a normal committed retention successor must reopen: {failure:?}"
                            ),
                        };
                        let replay = reopened.update_system_audit_retention(
                            reopened
                                .attribute(
                                    PresentedCredential::parse(root_secret).expect("claim syntax"),
                                    RequestedIntent::SystemAdministration,
                                    CompatibilityHints::none(),
                                )
                                .expect("bootstrap credential remains administrator"),
                            limit,
                            expected,
                            key,
                        );
                        assert_eq!(replay.expect("exact audit-retention retry"), updated);
                        reopened
                            .verify_governance_audit_history(
                                reopened
                                    .attribute(
                                        PresentedCredential::parse(root_secret)
                                            .expect("claim syntax"),
                                        RequestedIntent::SystemAdministration,
                                        CompatibilityHints::none(),
                                    )
                                    .expect("bootstrap credential remains administrator"),
                                None,
                            )
                            .expect("retained anchor and suffix remain verified after replay");
                        if command & 0x40 != 0 {
                            let checkpoint = reopened
                                .publish_governance_audit_checkpoint(
                                    reopened
                                        .attribute(
                                            PresentedCredential::parse(root_secret)
                                                .expect("claim syntax"),
                                            RequestedIntent::SystemAdministration,
                                            CompatibilityHints::none(),
                                        )
                                        .expect("bootstrap credential remains administrator"),
                                )
                                .expect("retained audit checkpoint publishes");
                            reopened
                                .verify_governance_audit_history(
                                    reopened
                                        .attribute(
                                            PresentedCredential::parse(root_secret)
                                                .expect("claim syntax"),
                                            RequestedIntent::SystemAdministration,
                                            CompatibilityHints::none(),
                                        )
                                        .expect("bootstrap credential remains administrator"),
                                    Some(&checkpoint),
                                )
                                .expect("signed checkpoint verifies the retained suffix");
                            // A checkpoint has its own authenticated frame,
                            // separate from Catalog objects.  This selector
                            // exercises recovery's checkpoint fence after a
                            // retention anchor already exists.
                            if command & 0x80 != 0 {
                                assert!(corrupt_catalog_artifacts(
                                    &roots.data,
                                    "catalog/governance-audit-checkpoints",
                                    index,
                                ));
                                assert!(InstanceBootstrap::reopen(&paths).is_err());
                            }
                        }
                        audit_retention_generation = audit_retention_generation.saturating_add(1);
                    }
                } else {
                    let _ = InstanceBootstrap::classify(&paths);
                }
            },
        }
    }
});
