#![no_main]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_api::api_keys::{ApiKeyRequest, ApiKeyResponse};
use positron_governance::{
    AdministrativeIdempotencyKey, CatalogRootRotationStage, CompatibilityHints,
    GovernanceAuditEntry, PresentedCredential, RequestedIntent, ResourceGeneration,
};
use positron_domain::identity::{PrincipalId, Scope};
use positron_runtime::{
    BootstrapFailureCode, BootstrapPaths, InitializationPlan, InstanceBootstrap,
};
use positron_kernel::MountQualification;

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

fn heterogeneous_rotation_entries(
    data: &[u8],
    first_position: u64,
) -> Vec<GovernanceAuditEntry> {
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

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let _ = ApiKeyRequest::decode(data);
    if let Ok(response) = ApiKeyResponse::decode(data) {
        assert_eq!(format!("{response:?}"), "ApiKeyResponse { <redacted> }");
    }
    positron_governance::fuzz_parse_governance(&data[..split], &data[split..]);
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
            4 => corrupt(&roots.secrets.join("bootstrap-claim.v1"), index),
            5 => corrupt(&roots.data.join(".positron-bootstrap.initialized"), index),
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
                    let next_position = u64::try_from(audit_len)
                        .expect("bounded audit chain")
                        + 1;
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
                    assert_eq!(
                        failure.to_string(),
                        "credential or authority was rejected"
                    );
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
                        assert!(other_instance
                            .inspect_governance_for_fixture(context)
                            .is_err());
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
                    let idempotency = AdministrativeIdempotencyKey::new([
                        u8::try_from(index).expect("bounded input") + 1;
                        16
                    ])
                    .expect("nonzero idempotency");
                    let expected = ResourceGeneration::new(credential_generation)
                        .expect("bounded generation");
                    if let Ok(created) = instance.create_api_key(
                        administrator,
                        scope,
                        None,
                        expected,
                        idempotency,
                    ) {
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
                        assert!(instance
                            .attribute(
                                PresentedCredential::parse(&key_secret)
                                    .expect("generated API key remains canonical"),
                                RequestedIntent::SystemAdministration,
                                CompatibilityHints::none(),
                            )
                            .is_err());
                        let replay = instance.create_api_key(
                            instance
                                .attribute(
                                    PresentedCredential::parse(root_secret)
                                        .expect("claim syntax"),
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
                    let idempotency = AdministrativeIdempotencyKey::new([
                        u8::try_from(index).expect("bounded input") + 1;
                        16
                    ])
                    .expect("nonzero idempotency");
                    let expected = ResourceGeneration::new(credential_generation)
                        .expect("bounded generation");
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
                            assert!(instance
                                .attribute(
                                    PresentedCredential::parse(presented)
                                        .expect("generated API key remains canonical"),
                                    intent,
                                    CompatibilityHints::none(),
                                )
                                .is_ok());
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
                        let idempotency = AdministrativeIdempotencyKey::new([
                            u8::try_from(index).expect("bounded input") + 1;
                            16
                        ])
                        .expect("nonzero idempotency");
                        let expected = ResourceGeneration::new(credential_generation)
                            .expect("bounded generation");
                        if instance
                            .revoke_api_key(administrator, principal, expected, idempotency)
                            .is_ok()
                        {
                            assert!(instance
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
                                .is_err());
                            credential_generation = credential_generation.saturating_add(1);
                        } else {
                            tenant_key = Some((principal, key_secret, scope));
                        }
                    }
                }
            },
            _ => {
                let _ = InstanceBootstrap::classify(&paths);
            },
        }
    }
});
