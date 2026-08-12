use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::{CryptoBackend, RustCryptoBackend, SecretKeyBytes};

struct EntropyFailureBackend;

impl CryptoBackend for EntropyFailureBackend {
    fn seal_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::SealFailed)
    }

    fn open_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _ciphertext: &[u8],
    ) -> Result<super::SecretPlaintext, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::AuthenticationFailed)
    }

    fn sha256(&self, _bytes: &[u8]) -> Result<[u8; 32], super::CryptoBackendFailure> {
        Ok([0_u8; 32])
    }

    fn fill_random(&self, _destination: &mut [u8]) -> Result<(), super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::EntropyUnavailable)
    }
}

struct SealFailureBackend;

impl CryptoBackend for SealFailureBackend {
    fn seal_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::SealFailed)
    }

    fn open_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _ciphertext: &[u8],
    ) -> Result<super::SecretPlaintext, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::AuthenticationFailed)
    }

    fn sha256(&self, _bytes: &[u8]) -> Result<[u8; 32], super::CryptoBackendFailure> {
        Ok([0_u8; 32])
    }

    fn fill_random(&self, _destination: &mut [u8]) -> Result<(), super::CryptoBackendFailure> {
        Ok(())
    }
}

struct HashFailureBackend;

impl CryptoBackend for HashFailureBackend {
    fn seal_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, super::CryptoBackendFailure> {
        let length = plaintext
            .len()
            .checked_add(16)
            .ok_or(super::CryptoBackendFailure::SealFailed)?;
        Ok(vec![0x5a; length])
    }

    fn open_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _ciphertext: &[u8],
    ) -> Result<super::SecretPlaintext, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::AuthenticationFailed)
    }

    fn sha256(&self, _bytes: &[u8]) -> Result<[u8; 32], super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::HashFailed)
    }

    fn fill_random(&self, _destination: &mut [u8]) -> Result<(), super::CryptoBackendFailure> {
        Ok(())
    }
}

struct OpenFailureBackend;

impl CryptoBackend for OpenFailureBackend {
    fn seal_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::SealFailed)
    }

    fn open_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _ciphertext: &[u8],
    ) -> Result<super::SecretPlaintext, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::OpenFailed)
    }

    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], super::CryptoBackendFailure> {
        use sha2::{Digest, Sha256};

        Ok(Sha256::digest(bytes).into())
    }

    fn fill_random(&self, _destination: &mut [u8]) -> Result<(), super::CryptoBackendFailure> {
        Ok(())
    }
}

struct OpenSuccessBackend {
    zeroized_before_release: std::rc::Rc<std::cell::Cell<bool>>,
}

struct SealLengthBackend {
    output_bytes: usize,
    seal_calls: std::cell::Cell<usize>,
}

impl CryptoBackend for SealLengthBackend {
    fn seal_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, super::CryptoBackendFailure> {
        self.seal_calls.set(self.seal_calls.get().saturating_add(1));
        Ok(vec![0x5a; self.output_bytes])
    }

    fn open_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _ciphertext: &[u8],
    ) -> Result<super::SecretPlaintext, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::AuthenticationFailed)
    }

    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], super::CryptoBackendFailure> {
        use sha2::{Digest, Sha256};

        Ok(Sha256::digest(bytes).into())
    }

    fn fill_random(&self, _destination: &mut [u8]) -> Result<(), super::CryptoBackendFailure> {
        Ok(())
    }
}

struct OpenLengthBackend {
    output_bytes: usize,
    zeroized_before_release: std::rc::Rc<std::cell::Cell<bool>>,
}

impl CryptoBackend for OpenLengthBackend {
    fn seal_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::SealFailed)
    }

    fn open_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _ciphertext: &[u8],
    ) -> Result<super::SecretPlaintext, super::CryptoBackendFailure> {
        Ok(super::SecretPlaintext::new_for_test(
            vec![b'P'; self.output_bytes],
            std::rc::Rc::clone(&self.zeroized_before_release),
        ))
    }

    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], super::CryptoBackendFailure> {
        use sha2::{Digest, Sha256};

        Ok(Sha256::digest(bytes).into())
    }

    fn fill_random(&self, _destination: &mut [u8]) -> Result<(), super::CryptoBackendFailure> {
        Ok(())
    }
}

impl CryptoBackend for OpenSuccessBackend {
    fn seal_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, super::CryptoBackendFailure> {
        Err(super::CryptoBackendFailure::SealFailed)
    }

    fn open_aes_256_gcm(
        &self,
        _key: &SecretKeyBytes,
        _nonce: [u8; 12],
        _associated_data: &[u8],
        _ciphertext: &[u8],
    ) -> Result<super::SecretPlaintext, super::CryptoBackendFailure> {
        Ok(super::SecretPlaintext::new_for_test(
            b"backend-owned-plaintext-canary".to_vec(),
            std::rc::Rc::clone(&self.zeroized_before_release),
        ))
    }

    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], super::CryptoBackendFailure> {
        use sha2::{Digest, Sha256};

        Ok(Sha256::digest(bytes).into())
    }

    fn fill_random(&self, _destination: &mut [u8]) -> Result<(), super::CryptoBackendFailure> {
        Ok(())
    }
}

pub(super) fn protected_segment_fixture() -> Result<
    (
        super::ObjectDataKey,
        super::FrameContext,
        super::FrameLimits,
        super::EncryptedFrame,
    ),
    &'static str,
> {
    const FRAME: &[u8; 68] =
        include_bytes!("../../../../../fuzz/corpus/encrypted_frame_open/valid_empty_frame");

    let tenant = TenantId::from_bytes([0x11; 16]).map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(1).map_err(|_| "shard fixture was invalid")?;
    let object = super::FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        super::FrameObjectId::new([0x22; 16]).map_err(|_| "object fixture was invalid")?,
        super::KeyEpoch::new(1),
        super::FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?,
    );
    let context = object
        .frame(
            super::SegmentFramePurpose::StoreBlock,
            super::FrameSequence::new(1),
        )
        .map_err(|_| "frame context fixture was invalid")?;
    let key =
        super::ObjectDataKey::import(super::SecretKeyInput::from_test_bytes([0x33; 32]), object);
    let limits = super::FrameLimits::new(256).map_err(|_| "frame limit fixture was invalid")?;
    let encrypted = super::EncryptedFrame(FRAME.to_vec());
    Ok((key, context, limits, encrypted))
}

fn encoded_frame_declaring_plaintext_bytes(
    plaintext_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    use sha2::{Digest, Sha256};

    let (_, _, _, encrypted) = protected_segment_fixture()?;
    let ciphertext_bytes = plaintext_bytes
        .checked_add(16)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or("declared plaintext fixture exceeded its bound")?;
    let mut encoded = encrypted
        .as_bytes()
        .get(..52)
        .ok_or("frame omitted header")?
        .to_vec();
    encoded
        .get_mut(16..20)
        .ok_or("frame omitted length")?
        .copy_from_slice(&ciphertext_bytes.to_be_bytes());
    let ciphertext = vec![0x5a; ciphertext_bytes as usize];
    let checksum: [u8; 32] = Sha256::digest(&ciphertext).into();
    encoded
        .get_mut(20..52)
        .ok_or("frame omitted checksum")?
        .copy_from_slice(&checksum);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

#[test]
fn rust_crypto_backend_matches_nist_aes_256_gcm_vector() -> Result<(), &'static str> {
    // NIST CAVP AES-GCM example with a 256-bit zero key, 96-bit zero IV,
    // one zero plaintext block, and no AAD. The expected ciphertext and
    // tag are independent published values, not derived by this test.
    // Source: NIST CAVP GCM test vectors, gcmEncryptExtIV256.rsp.
    let backend = RustCryptoBackend;
    let key = SecretKeyBytes::from_owned(Box::new([0_u8; 32]));
    let nonce = [0_u8; 12];
    let plaintext = [0_u8; 16];
    let expected = [
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d,
        0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
        0xb9, 0x19,
    ];

    let actual = backend
        .seal_aes_256_gcm(&key, nonce, &[], &plaintext)
        .map_err(|_| "NIST AES-256-GCM encryption failed")?;

    if actual == expected {
        Ok(())
    } else {
        Err("NIST AES-256-GCM output differed")
    }
}

#[test]
fn entropy_failure_is_typed_and_secret_safe() -> Result<(), &'static str> {
    let (_, context, _, _) = protected_segment_fixture()?;
    let protection = super::DataProtection::with_backend(EntropyFailureBackend);

    let failure = protection
        .generate_object_key(context.object)
        .expect_err("an unavailable entropy source must refuse key generation");

    if failure.code() != super::FrameFailureCode::EntropyUnavailable
        || failure.to_string() != "encrypted frame operation failed"
        || format!("{failure:?}").len() > 96
    {
        return Err("entropy failure was not typed and secret-safe");
    }
    Ok(())
}

#[test]
fn seal_failure_is_typed_and_secret_safe() -> Result<(), &'static str> {
    let (_, context, limits, _) = protected_segment_fixture()?;
    let protection = super::DataProtection::with_backend(SealFailureBackend);
    let key = protection.import_object_key(
        super::SecretKeyInput::from_test_bytes([0x9a; 32]),
        context.object,
    );

    let failure = protection
        .protect_frame(&key, context, b"seal-failure-plaintext-canary", limits)
        .expect_err("a refused seal operation must not create a frame");
    let diagnostic = format!("{failure:?} {failure}");

    if failure.code() != super::FrameFailureCode::SealFailed
        || diagnostic.contains("seal-failure-plaintext-canary")
        || diagnostic.contains("9a9a9a9a")
        || diagnostic.len() > 128
    {
        return Err("seal failure was not typed and secret-safe");
    }
    Ok(())
}

#[test]
fn seal_backend_output_must_match_plaintext_plus_tag() -> Result<(), &'static str> {
    let (_, context, limits, _) = protected_segment_fixture()?;
    let plaintext = b"contract";
    let expected = plaintext.len() + 16;

    for (output_bytes, key_byte) in [(expected - 1, 0xa5), (expected + 1, 0xa7)] {
        let protection = super::DataProtection::with_backend(SealLengthBackend {
            output_bytes,
            seal_calls: std::cell::Cell::new(0),
        });
        let key = protection.import_object_key(
            super::SecretKeyInput::from_test_bytes([key_byte; 32]),
            context.object,
        );
        let failure = protection
            .protect_frame(&key, context, plaintext, limits)
            .expect_err("a backend length-contract violation must not create a frame");
        if failure.code() != super::FrameFailureCode::SealFailed {
            return Err("seal length-contract failure classification differed");
        }
    }
    Ok(())
}

#[test]
fn protection_authority_guard_covers_custom_backends() -> Result<(), &'static str> {
    let (_, context, limits, _) =
        protected_segment_fixture().map_err(|_| "protected segment fixture must be valid")?;
    let context = context
        .object
        .frame(
            super::SegmentFramePurpose::StoreBlock,
            super::FrameSequence::new(0xfafa_fafa_fafa_fafa),
        )
        .map_err(|_| "duplicate-guard context fixture must be valid")?;
    let protection = super::DataProtection::with_backend(SealLengthBackend {
        output_bytes: b"contract".len() + 16,
        seal_calls: std::cell::Cell::new(0),
    });
    let key = protection.import_object_key(
        super::SecretKeyInput::from_test_bytes([0xfa; 32]),
        context.object,
    );

    let _first = protection
        .protect_frame(&key, context, b"contract", limits)
        .map_err(|_| "first custom-backend protection must succeed")?;
    if protection.backend.seal_calls.get() != 1 {
        return Err("first custom-backend protection did not dispatch exactly once");
    }

    let duplicate = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _result = protection.protect_frame(&key, context, b"contract", limits);
    }));
    let panic = duplicate
        .expect_err("the exact duplicate protection authority must panic before backend dispatch");
    let message = panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .ok_or("duplicate-protection panic did not contain a string message")?;
    if message != "test attempted duplicate protection under one DEK and sequence" {
        return Err("duplicate-protection panic message differed");
    }
    if protection.backend.seal_calls.get() != 1 {
        return Err("duplicate protection reached the custom backend");
    }
    Ok(())
}

#[test]
fn owned_secret_input_is_zeroized_before_positron_releases_it() -> Result<(), &'static str> {
    use std::cell::Cell;
    use std::rc::Rc;

    let (_, context, _, _) = protected_segment_fixture()?;
    let protection = super::DataProtection::with_backend(SealFailureBackend);
    let zeroized_before_release = Rc::new(Cell::new(false));
    let input = super::SecretKeyInput::from_owned_for_test(
        Box::new([b'Z'; 32]),
        Rc::clone(&zeroized_before_release),
    );
    let key = protection.import_object_key(input, context.object);

    drop(key);

    if !zeroized_before_release.get() {
        return Err("Positron released an owned key buffer before zeroizing it");
    }
    Ok(())
}

#[test]
fn hash_failure_is_typed_and_returns_no_frame() -> Result<(), &'static str> {
    let (_, context, limits, _) = protected_segment_fixture()?;
    let protection = super::DataProtection::with_backend(HashFailureBackend);
    let key = protection.import_object_key(
        super::SecretKeyInput::from_test_bytes([b'H'; 32]),
        context.object,
    );

    let failure = protection
        .protect_frame(&key, context, b"hash-failure-plaintext-canary", limits)
        .expect_err("a refused checksum must not create a frame");
    let diagnostic = format!("{failure:?} {failure}");

    if failure.code() != super::FrameFailureCode::HashFailed
        || diagnostic.contains("hash-failure-plaintext-canary")
        || diagnostic.contains("HHHHHHHH")
        || diagnostic.len() > 128
    {
        return Err("hash failure was not typed and secret-safe");
    }
    Ok(())
}

#[test]
fn open_backend_failure_is_typed_and_returns_no_plaintext() -> Result<(), &'static str> {
    let (_, context, limits, encrypted) = protected_segment_fixture()?;
    let protection = super::DataProtection::with_backend(OpenFailureBackend);
    let key = protection.import_object_key(
        super::SecretKeyInput::from_test_bytes([0xd3; 32]),
        context.object,
    );

    let failure = protection
        .open_frame(&key, context, encrypted.as_bytes(), limits)
        .expect_err("an unavailable open operation must not expose plaintext");

    if failure.code() != super::FrameFailureCode::OpenFailed
        || failure.to_string() != "encrypted frame operation failed"
        || format!("{failure:?}").len() > 96
    {
        return Err("open backend failure was not typed and secret-safe");
    }
    Ok(())
}

#[test]
fn open_backend_output_must_match_declared_plaintext_and_zeroize_on_error()
-> Result<(), &'static str> {
    let (_, context, limits, _) = protected_segment_fixture()?;
    let expected_plaintext_bytes = 2;
    let encoded = encoded_frame_declaring_plaintext_bytes(expected_plaintext_bytes)?;

    for output_bytes in [expected_plaintext_bytes - 1, expected_plaintext_bytes + 1] {
        let zeroized = std::rc::Rc::new(std::cell::Cell::new(false));
        let protection = super::DataProtection::with_backend(OpenLengthBackend {
            output_bytes,
            zeroized_before_release: std::rc::Rc::clone(&zeroized),
        });
        let key = protection.import_object_key(
            super::SecretKeyInput::from_test_bytes([0xa6; 32]),
            context.object,
        );
        let failure = protection
            .open_frame(&key, context, &encoded, limits)
            .expect_err("a backend length-contract violation must not expose plaintext");
        if failure.code() != super::FrameFailureCode::OpenFailed || !zeroized.get() {
            return Err("open length-contract failure was not typed and zeroizing");
        }
    }
    Ok(())
}

#[test]
fn verified_plaintext_is_zeroized_before_positron_releases_it() -> Result<(), &'static str> {
    let (_, context, limits, _) = protected_segment_fixture()?;
    let encoded = encoded_frame_declaring_plaintext_bytes(b"backend-owned-plaintext-canary".len())?;
    let zeroized_before_release = std::rc::Rc::new(std::cell::Cell::new(false));
    let protection = super::DataProtection::with_backend(OpenSuccessBackend {
        zeroized_before_release: std::rc::Rc::clone(&zeroized_before_release),
    });
    let key = protection.import_object_key(
        super::SecretKeyInput::from_test_bytes([0xd3; 32]),
        context.object,
    );

    let verified = protection
        .open_frame(&key, context, &encoded, limits)
        .map_err(|_| "controlled frame opening failed")?;
    if verified.as_plaintext() != b"backend-owned-plaintext-canary" {
        return Err("controlled backend plaintext differed");
    }
    drop(verified);

    if !zeroized_before_release.get() {
        return Err("Positron released plaintext before zeroizing its owned buffer");
    }
    Ok(())
}

#[test]
fn authenticated_frame_survives_persistent_file_reopen() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TemporaryDirectory(std::path::PathBuf);

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _cleanup_result = fs::remove_dir_all(&self.0);
        }
    }

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = TemporaryDirectory(std::env::temp_dir().join(format!(
        "positron-encrypted-frame-{}-{nonce}",
        std::process::id()
    )));
    fs::create_dir(&root.0)?;
    let path = root.0.join("frame.pfr");
    let tenant = TenantId::from_bytes([0x11; 16])?;
    let shard = VirtualShardId::new(12)?;
    let object = super::FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        super::FrameObjectId::new([0x22; 16])?,
        super::KeyEpoch::new(4),
        super::FormatEpoch::new(1)?,
    );
    let context = object.frame(
        super::SegmentFramePurpose::StoreBlock,
        super::FrameSequence::new(14),
    )?;
    let key =
        super::ObjectDataKey::import(super::SecretKeyInput::from_test_bytes([0x33; 32]), object);
    let limits = super::FrameLimits::new(1024)?;
    let plaintext = b"persisted authenticated frame";
    let encrypted = super::DataProtection::protect_frame(&key, context, plaintext, limits)?;

    let mut output = File::create(&path)?;
    output.write_all(encrypted.as_bytes())?;
    output.sync_all()?;
    drop(output);

    let mut persisted = Vec::new();
    File::open(&path)?.read_to_end(&mut persisted)?;
    if persisted
        .windows(plaintext.len())
        .any(|window| window == plaintext)
    {
        return Err("persisted frame exposed plaintext".into());
    }
    let verified = super::DataProtection::open_frame(&key, context, &persisted, limits)?;
    if verified.as_plaintext() != plaintext {
        return Err("reopened plaintext differed".into());
    }
    Ok(())
}
