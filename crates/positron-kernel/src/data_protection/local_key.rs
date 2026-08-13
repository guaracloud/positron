//! Local Root Key File bootstrap, custody, and exact-object persistence.

use std::error::Error;
use std::fmt::{Display, Formatter};

mod acl;
mod bootstrap;
mod codec;
mod initialization_io;
mod persistence;
mod runtime_bootstrap;

#[cfg(test)]
mod acl_tests;
#[cfg(test)]
mod codec_tests;
#[cfg(test)]
mod initialization_tests;
#[cfg(test)]
mod persistence_tests;
#[cfg(test)]
#[path = "local_key/tests/runtime_bootstrap.rs"]
mod runtime_bootstrap_tests;
#[cfg(test)]
mod test_support;

use codec::SecretRootKey;

pub use runtime_bootstrap::{
    BootstrapIntegrityIdentity, BootstrapKeyCustody, BootstrapKeyFailure, BootstrapKeyIdentity,
    BootstrapObjectPurpose,
};

#[cfg(fuzzing)]
pub fn fuzz_local_root_key_file(data: &[u8]) {
    let _ = codec::fuzz_local_root_key_file(data);
}

const LOCAL_KEY_FILE_MAGIC: [u8; 8] = *b"POSLKEY1";
const LOCAL_KEY_FILE_VERSION: u16 = 1;
const LOCAL_FILE_PROVIDER: u16 = 1;
const ROOT_KEK_PURPOSE: u16 = 1;
const LOCAL_KEY_FILE_BYTES: usize = 134;
const LOCAL_KEY_FINGERPRINT_DOMAIN: &[u8] = b"positron-local-root-key-fingerprint-v1";
const LOCAL_KEY_CHECKSUM_DOMAIN: &[u8] = b"positron-local-root-key-file-checksum-v1";
const LOCAL_KEY_FILE_NAME: &str = "local-root-key.v1";
const LOCAL_KEY_STAGING_FILE_NAME: &str = "local-root-key.v1.new";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalKeyFailureCode {
    InvalidIdentity,
    HashFailed,
    MalformedFile,
    UnsupportedVersion,
    IntegrityMismatch,
    FingerprintMismatch,
    InvalidLocation,
    UnsafeSecurityDirectory,
    UnsafeAcl,
    AclInspectionFailed,
    AclInspectionUnsupported,
    CreateKeyFileFailed,
    KeyAlreadyExists,
    UnsafeKeyFile,
    EntropyUnavailable,
    ClockUnavailable,
    WriteFailed,
    SynchronizeKeyFileFailed,
    SynchronizeSecurityDirectoryFailed,
    OpenKeyFileFailed,
    IdentityMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalKeyFailure {
    code: LocalKeyFailureCode,
}

impl LocalKeyFailure {
    const fn new(code: LocalKeyFailureCode) -> Self {
        Self { code }
    }
}

impl Display for LocalKeyFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("local Root Key operation failed")
    }
}

impl Error for LocalKeyFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalKeyId([u8; 16]);

impl LocalKeyId {
    fn new(bytes: [u8; 16]) -> Result<Self, LocalKeyFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(LocalKeyFailure::new(LocalKeyFailureCode::InvalidIdentity))
        } else {
            Ok(Self(bytes))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalKeyCreationTime(u64);

impl LocalKeyCreationTime {
    const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalKeyFingerprint([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalCustodyWarning {
    FilesystemCustodyDoesNotProtectCombinedKeyAndDataTheft,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalRecoveryReadiness {
    IndependentRecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalKeyEvidence {
    key_id: LocalKeyId,
    fingerprint: LocalKeyFingerprint,
    creation_time: LocalKeyCreationTime,
    warning: LocalCustodyWarning,
    recovery: LocalRecoveryReadiness,
}

struct VerifiedLocalKey {
    evidence: LocalKeyEvidence,
    root_key: SecretRootKey,
}

impl VerifiedLocalKey {
    const fn evidence(&self) -> LocalKeyEvidence {
        self.evidence
    }
}

impl std::fmt::Debug for VerifiedLocalKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedLocalKey")
            .field("root_key", &"<redacted>")
            .finish()
    }
}
