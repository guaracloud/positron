//! Fixed-width Local Root Key File v1 codec and untrusted-input boundary.

use zeroize::Zeroize;

use crate::data_protection::{CryptoBackend, RustCryptoBackend, SecretKeyBytes};

use super::{
    LOCAL_FILE_PROVIDER, LOCAL_KEY_CHECKSUM_DOMAIN, LOCAL_KEY_FILE_BYTES, LOCAL_KEY_FILE_MAGIC,
    LOCAL_KEY_FILE_VERSION, LOCAL_KEY_FINGERPRINT_DOMAIN, LocalCustodyWarning,
    LocalKeyCreationTime, LocalKeyEvidence, LocalKeyFailure, LocalKeyFailureCode,
    LocalKeyFingerprint, LocalKeyId, LocalRecoveryReadiness, ROOT_KEK_PURPOSE, VerifiedLocalKey,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CodecSecretRelease {
    FingerprintInput,
    FingerprintDigest,
    ChecksumInput,
    ChecksumDigest,
    EncodedFile,
    FuzzCandidate,
}

#[cfg(test)]
pub(super) struct CodecSecretReleaseObservation {
    pub(super) kind: CodecSecretRelease,
    pub(super) zeroized: bool,
    pub(super) observed_len: usize,
}

struct SecretTemporary<T: Zeroize + AsRef<[u8]> + AsMut<[u8]>> {
    value: T,
    kind: CodecSecretRelease,
}

impl<T: Zeroize + AsRef<[u8]> + AsMut<[u8]>> SecretTemporary<T> {
    fn new(value: T, kind: CodecSecretRelease) -> Self {
        Self { value, kind }
    }

    fn as_bytes(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl<T: Zeroize + AsRef<[u8]> + AsMut<[u8]>> std::ops::Deref for SecretTemporary<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: Zeroize + AsRef<[u8]> + AsMut<[u8]>> std::ops::DerefMut for SecretTemporary<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T: Zeroize + AsRef<[u8]> + AsMut<[u8]>> Drop for SecretTemporary<T> {
    fn drop(&mut self) {
        self.value.as_mut().zeroize();
        #[cfg(test)]
        observe_codec_release(self.kind, self.value.as_ref());
        self.value.zeroize();
    }
}

pub(super) struct SecretRootKey(pub(super) SecretKeyBytes);

impl SecretRootKey {
    pub(super) fn from_owned(bytes: Box<[u8; 32]>) -> Self {
        #[cfg(test)]
        if let Some(observer) = SECRET_RELEASE_OBSERVER.with(|slot| slot.borrow().clone()) {
            return Self(SecretKeyBytes::from_owned_with_observer(bytes, observer));
        }
        Self(SecretKeyBytes::from_owned(bytes))
    }

    fn copy_from_slice(bytes: &[u8]) -> Result<Self, LocalKeyFailure> {
        let mut root_key = Self::from_owned(Box::new([0_u8; 32]));
        let destination = root_key.0.expose_to_backend_mut();
        if destination.len() != bytes.len() {
            return Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile));
        }
        destination.copy_from_slice(bytes);
        Ok(root_key)
    }
}

pub(super) struct EncodedLocalKeyFile {
    pub(super) bytes: Box<[u8; LOCAL_KEY_FILE_BYTES]>,
}

impl EncodedLocalKeyFile {
    pub(super) fn zeroed() -> Self {
        Self {
            bytes: Box::new([0_u8; LOCAL_KEY_FILE_BYTES]),
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    #[cfg(test)]
    pub(super) fn from_test_slice(source: &[u8]) -> Result<Self, LocalKeyFailure> {
        let mut encoded = Self::zeroed();
        encoded.write(0..LOCAL_KEY_FILE_BYTES, source)?;
        Ok(encoded)
    }

    fn write(
        &mut self,
        range: std::ops::Range<usize>,
        source: &[u8],
    ) -> Result<(), LocalKeyFailure> {
        let destination = self
            .bytes
            .get_mut(range)
            .ok_or_else(|| LocalKeyFailure::new(LocalKeyFailureCode::HashFailed))?;
        if destination.len() != source.len() {
            return Err(LocalKeyFailure::new(LocalKeyFailureCode::HashFailed));
        }
        destination.copy_from_slice(source);
        Ok(())
    }
}

impl Drop for EncodedLocalKeyFile {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        observe_codec_release(CodecSecretRelease::EncodedFile, self.bytes.as_ref());
    }
}

pub(super) fn encode_file_v1(
    key_id: LocalKeyId,
    creation_time: LocalKeyCreationTime,
    root_key: SecretRootKey,
) -> Result<EncodedLocalKeyFile, LocalKeyFailure> {
    encode_file_v1_with_backend(key_id, creation_time, root_key, &RustCryptoBackend)
}

pub(super) fn encode_file_v1_with_backend(
    key_id: LocalKeyId,
    creation_time: LocalKeyCreationTime,
    root_key: SecretRootKey,
    backend: &impl CryptoBackend,
) -> Result<EncodedLocalKeyFile, LocalKeyFailure> {
    let fingerprint = compute_fingerprint(backend, key_id, creation_time, &root_key)?;

    let mut encoded = EncodedLocalKeyFile::zeroed();
    encoded.write(0..8, &LOCAL_KEY_FILE_MAGIC)?;
    encoded.write(8..10, &LOCAL_KEY_FILE_VERSION.to_be_bytes())?;
    encoded.write(10..12, &LOCAL_FILE_PROVIDER.to_be_bytes())?;
    encoded.write(12..14, &ROOT_KEK_PURPOSE.to_be_bytes())?;
    encoded.write(14..30, &key_id.0)?;
    encoded.write(30..38, &creation_time.0.to_be_bytes())?;
    encoded.write(38..70, fingerprint.as_bytes())?;
    encoded.write(70..102, root_key.0.expose_to_backend())?;

    let content = encoded
        .bytes
        .get(..102)
        .ok_or_else(|| LocalKeyFailure::new(LocalKeyFailureCode::HashFailed))?;
    let checksum = compute_checksum(backend, content)?;
    encoded.write(102..134, checksum.as_bytes())?;
    Ok(encoded)
}

pub(super) fn parse_file_v1(
    encoded: EncodedLocalKeyFile,
) -> Result<VerifiedLocalKey, LocalKeyFailure> {
    parse_file_v1_with_backend(encoded, &RustCryptoBackend)
}

pub(super) fn parse_file_v1_with_backend(
    encoded: EncodedLocalKeyFile,
    backend: &impl CryptoBackend,
) -> Result<VerifiedLocalKey, LocalKeyFailure> {
    let bytes = encoded.as_bytes();
    if bytes.get(0..8) != Some(LOCAL_KEY_FILE_MAGIC.as_slice()) {
        return Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile));
    }
    let version = read_u16(bytes, 8..10)?;
    if version != LOCAL_KEY_FILE_VERSION {
        return Err(LocalKeyFailure::new(
            LocalKeyFailureCode::UnsupportedVersion,
        ));
    }
    if read_u16(bytes, 10..12)? != LOCAL_FILE_PROVIDER
        || read_u16(bytes, 12..14)? != ROOT_KEK_PURPOSE
    {
        return Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile));
    }
    let key_id = LocalKeyId::new(read_array::<16>(bytes, 14..30)?)?;
    let creation_time = LocalKeyCreationTime::from_unix_seconds(read_u64(bytes, 30..38)?);
    let stored_fingerprint = LocalKeyFingerprint(read_array::<32>(bytes, 38..70)?);

    let content = bytes
        .get(..102)
        .ok_or_else(|| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?;
    let computed_checksum = compute_checksum(backend, content)?;
    let stored_checksum = bytes
        .get(102..134)
        .ok_or_else(|| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?;
    if computed_checksum.as_bytes() != stored_checksum {
        return Err(LocalKeyFailure::new(LocalKeyFailureCode::IntegrityMismatch));
    }

    let root_key = SecretRootKey::copy_from_slice(
        bytes
            .get(70..102)
            .ok_or_else(|| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?,
    )?;
    let computed_fingerprint = compute_fingerprint(backend, key_id, creation_time, &root_key)?;
    if computed_fingerprint.as_bytes() != stored_fingerprint.0 {
        return Err(LocalKeyFailure::new(
            LocalKeyFailureCode::FingerprintMismatch,
        ));
    }

    Ok(VerifiedLocalKey {
        evidence: LocalKeyEvidence {
            key_id,
            fingerprint: stored_fingerprint,
            creation_time,
            warning: LocalCustodyWarning::FilesystemCustodyDoesNotProtectCombinedKeyAndDataTheft,
            recovery: LocalRecoveryReadiness::IndependentRecoveryRequired,
        },
        root_key,
    })
}

fn compute_fingerprint(
    backend: &impl CryptoBackend,
    key_id: LocalKeyId,
    creation_time: LocalKeyCreationTime,
    root_key: &SecretRootKey,
) -> Result<SecretTemporary<[u8; 32]>, LocalKeyFailure> {
    let mut input = SecretTemporary::new(
        Vec::with_capacity(LOCAL_KEY_FINGERPRINT_DOMAIN.len() + 2 + 2 + 16 + 8 + 32),
        CodecSecretRelease::FingerprintInput,
    );
    input.extend_from_slice(LOCAL_KEY_FINGERPRINT_DOMAIN);
    input.extend_from_slice(&LOCAL_FILE_PROVIDER.to_be_bytes());
    input.extend_from_slice(&ROOT_KEK_PURPOSE.to_be_bytes());
    input.extend_from_slice(&key_id.0);
    input.extend_from_slice(&creation_time.0.to_be_bytes());
    input.extend_from_slice(root_key.0.expose_to_backend());
    backend
        .sha256(&input)
        .map(|digest| SecretTemporary::new(digest, CodecSecretRelease::FingerprintDigest))
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::HashFailed))
}

fn compute_checksum(
    backend: &impl CryptoBackend,
    content: &[u8],
) -> Result<SecretTemporary<[u8; 32]>, LocalKeyFailure> {
    let mut input = SecretTemporary::new(
        Vec::with_capacity(LOCAL_KEY_CHECKSUM_DOMAIN.len() + content.len()),
        CodecSecretRelease::ChecksumInput,
    );
    input.extend_from_slice(LOCAL_KEY_CHECKSUM_DOMAIN);
    input.extend_from_slice(content);
    backend
        .sha256(&input)
        .map(|digest| SecretTemporary::new(digest, CodecSecretRelease::ChecksumDigest))
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::HashFailed))
}

pub(super) fn parse_local_key_file(bytes: &[u8]) -> Result<VerifiedLocalKey, LocalKeyFailure> {
    if bytes.len() != LOCAL_KEY_FILE_BYTES {
        return Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile));
    }
    let mut encoded = EncodedLocalKeyFile::zeroed();
    encoded.write(0..LOCAL_KEY_FILE_BYTES, bytes)?;
    parse_file_v1(encoded)
}

#[cfg(any(test, fuzzing))]
pub(super) fn fuzz_local_root_key_file(data: &[u8]) {
    const HEX_PREFIX: &[u8] = b"hex:";
    const MAX_FUZZ_INPUT_BYTES: usize = HEX_PREFIX.len() + (LOCAL_KEY_FILE_BYTES * 2);

    let bounded = data
        .get(..data.len().min(MAX_FUZZ_INPUT_BYTES))
        .unwrap_or_default();
    let candidate = bounded
        .strip_prefix(HEX_PREFIX)
        .and_then(decode_bounded_hex)
        .unwrap_or_else(|| {
            SecretTemporary::new(bounded.to_vec(), CodecSecretRelease::FuzzCandidate)
        });
    if let Ok(verified) = parse_local_key_file(&candidate) {
        let evidence = verified.evidence();
        assert_eq!(candidate.len(), LOCAL_KEY_FILE_BYTES);
        assert_eq!(
            evidence.warning,
            LocalCustodyWarning::FilesystemCustodyDoesNotProtectCombinedKeyAndDataTheft
        );
        assert_eq!(
            evidence.recovery,
            LocalRecoveryReadiness::IndependentRecoveryRequired
        );
    }
}

#[cfg(any(test, fuzzing))]
fn decode_bounded_hex(source: &[u8]) -> Option<SecretTemporary<Vec<u8>>> {
    if source.len() != LOCAL_KEY_FILE_BYTES * 2 {
        return None;
    }
    let mut decoded = SecretTemporary::new(
        Vec::with_capacity(LOCAL_KEY_FILE_BYTES),
        CodecSecretRelease::FuzzCandidate,
    );
    for pair in source.chunks_exact(2) {
        let high = fuzz_hex_nibble(*pair.first()?)?;
        let low = fuzz_hex_nibble(*pair.get(1)?)?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

#[cfg(any(test, fuzzing))]
fn fuzz_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn read_u16(bytes: &[u8], range: std::ops::Range<usize>) -> Result<u16, LocalKeyFailure> {
    Ok(u16::from_be_bytes(read_array::<2>(bytes, range)?))
}

fn read_u64(bytes: &[u8], range: std::ops::Range<usize>) -> Result<u64, LocalKeyFailure> {
    Ok(u64::from_be_bytes(read_array::<8>(bytes, range)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    range: std::ops::Range<usize>,
) -> Result<[u8; N], LocalKeyFailure> {
    bytes
        .get(range)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))
}

#[cfg(test)]
thread_local! {
    static SECRET_RELEASE_OBSERVER: std::cell::RefCell<Option<std::rc::Rc<std::cell::Cell<bool>>>> = const { std::cell::RefCell::new(None) };
    static CODEC_SECRET_RELEASE_OBSERVER: std::cell::RefCell<Option<std::rc::Rc<std::cell::RefCell<Vec<CodecSecretReleaseObservation>>>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn with_secret_release_observer<T>(
    observer: std::rc::Rc<std::cell::Cell<bool>>,
    operation: impl FnOnce() -> T,
) -> T {
    SECRET_RELEASE_OBSERVER.with(|slot| {
        let previous = slot.replace(Some(observer));
        let result = operation();
        slot.replace(previous);
        result
    })
}

#[cfg(test)]
pub(super) fn with_codec_secret_release_observer<T>(
    observer: std::rc::Rc<std::cell::RefCell<Vec<CodecSecretReleaseObservation>>>,
    operation: impl FnOnce() -> T,
) -> T {
    CODEC_SECRET_RELEASE_OBSERVER.with(|slot| {
        let previous = slot.replace(Some(observer));
        let result = operation();
        slot.replace(previous);
        result
    })
}

#[cfg(test)]
fn observe_codec_release(kind: CodecSecretRelease, bytes: &[u8]) {
    CODEC_SECRET_RELEASE_OBSERVER.with(|slot| {
        if let Some(observer) = slot.borrow().as_ref() {
            observer.borrow_mut().push(CodecSecretReleaseObservation {
                kind,
                zeroized: bytes.iter().all(|byte| *byte == 0),
                observed_len: bytes.len(),
            });
        }
    });
}
