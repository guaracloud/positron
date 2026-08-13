#![no_main]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_governance::{
    CatalogRootRotationStage, CompatibilityHints, GovernanceAuditEntry, PresentedCredential,
    RequestedIntent,
};
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

fn heterogeneous_rotation_entries(data: &[u8]) -> Vec<GovernanceAuditEntry> {
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
                u64::try_from(index).expect("bounded stage") + 2,
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
    positron_governance::fuzz_parse_governance(&data[..split], &data[split..]);
    let rotations = heterogeneous_rotation_entries(data);
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
    for (index, command) in data.iter().copied().enumerate() {
        match command & 7 {
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
                        .inspect_governance(authorized)
                        .expect("system administration authorizes governance inspection");
                    assert_eq!(audit.audit_records().len(), 1);
                    let heterogeneous = audit
                        .audit_records()
                        .iter()
                        .chain(rotations.iter())
                        .collect::<Vec<_>>();
                    assert_eq!(heterogeneous.len(), 4);
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
                        assert!(other_instance.inspect_governance(context).is_err());
                    }
                }
            },
            _ => {
                let _ = InstanceBootstrap::classify(&paths);
            },
        }
    }
});
