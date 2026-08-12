use super::codec::{
    CodecSecretRelease, CodecSecretReleaseObservation, EncodedLocalKeyFile, FuzzLocalKeyOutcome,
    SecretRootKey, encode_file_v1, encode_file_v1_with_backend, fuzz_local_root_key_file,
    parse_file_v1, parse_file_v1_with_backend, parse_local_key_file,
    with_codec_secret_release_observer, with_secret_release_observer,
};
use super::*;

use crate::data_protection::{
    CryptoBackend, CryptoBackendFailure, RustCryptoBackend, SecretKeyBytes, SecretPlaintext,
};
use zeroize::Zeroizing;

const VALID_V1: &str = "504f534c4b455931000100010001000102030405060708090a0b0c0d0e0f000000006b49d2004c346f6ff118118e6b396882ee3249b48f0db74d2d540e2322abf1bf7fbe9c56202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f540bfb8535f93e6e40867c94f3b1739711571e364b1c524d3cbee03e316e573c";
const SUBSTITUTED_KEY_V1: &str = "504f534c4b455931000100010001000102030405060708090a0b0c0d0e0f000000006b49d2004c346f6ff118118e6b396882ee3249b48f0db74d2d540e2322abf1bf7fbe9c56212122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fc88560dea9b87cef33db81cbe435c9c10d3882bc371835081fedf074d2b754b3";

#[test]
fn encode_hash_failure_zeroizes_fingerprint_input_and_root_key() -> Result<(), &'static str> {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let root_key_observer = Rc::new(Cell::new(false));
    let temporary_observer = Rc::new(RefCell::new(Vec::new()));
    let key_id = LocalKeyId::new([1_u8; 16]).map_err(|_| "key-id fixture was invalid")?;
    let observed = with_secret_release_observer(Rc::clone(&root_key_observer), || {
        with_codec_secret_release_observer(Rc::clone(&temporary_observer), || {
            encode_file_v1_with_backend(
                key_id,
                LocalKeyCreationTime::from_unix_seconds(1_800_000_000),
                SecretRootKey::from_owned(Box::new([2_u8; 32])),
                &FailingHashBackend::on_call(1),
            )
        })
    });

    if observed.map(|_| ()) != Err(LocalKeyFailure::new(LocalKeyFailureCode::HashFailed))
        || !root_key_observer.get()
        || !released_zeroized_once(
            temporary_observer.borrow().as_slice(),
            &[CodecSecretRelease::FingerprintInput],
        )
    {
        return Err("encode hash failure released secret material before zeroization");
    }
    Ok(())
}

#[test]
fn encode_checksum_hash_failure_zeroizes_all_secret_custody() -> Result<(), &'static str> {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let root_key_observer = Rc::new(Cell::new(false));
    let temporary_observer = Rc::new(RefCell::new(Vec::new()));
    let key_id = LocalKeyId::new([1_u8; 16]).map_err(|_| "key-id fixture was invalid")?;
    let observed = with_secret_release_observer(Rc::clone(&root_key_observer), || {
        with_codec_secret_release_observer(Rc::clone(&temporary_observer), || {
            encode_file_v1_with_backend(
                key_id,
                LocalKeyCreationTime::from_unix_seconds(1_800_000_000),
                SecretRootKey::from_owned(Box::new([2_u8; 32])),
                &FailingHashBackend::on_call(2),
            )
        })
    });

    if observed.map(|_| ()) != Err(LocalKeyFailure::new(LocalKeyFailureCode::HashFailed))
        || !root_key_observer.get()
        || !released_zeroized_once(
            temporary_observer.borrow().as_slice(),
            &[
                CodecSecretRelease::FingerprintInput,
                CodecSecretRelease::FingerprintDigest,
                CodecSecretRelease::ChecksumInput,
                CodecSecretRelease::EncodedFile,
            ],
        )
    {
        return Err("encode checksum failure released secret material before zeroization");
    }
    Ok(())
}

#[test]
fn parse_checksum_hash_failure_zeroizes_input_and_encoded_custody() -> Result<(), &'static str> {
    use std::cell::RefCell;
    use std::rc::Rc;

    let vector = decode_hex(VALID_V1)?;
    let encoded = EncodedLocalKeyFile::from_test_slice(&vector)
        .map_err(|_| "vector could not enter the bounded parser")?;
    let temporary_observer = Rc::new(RefCell::new(Vec::new()));
    let observed = with_codec_secret_release_observer(Rc::clone(&temporary_observer), || {
        parse_file_v1_with_backend(encoded, &FailingHashBackend::on_call(1))
    });

    if observed.map(|_| ()) != Err(LocalKeyFailure::new(LocalKeyFailureCode::HashFailed))
        || !released_zeroized_once(
            temporary_observer.borrow().as_slice(),
            &[
                CodecSecretRelease::ChecksumInput,
                CodecSecretRelease::EncodedFile,
            ],
        )
    {
        return Err("parse checksum failure released secret material before zeroization");
    }
    Ok(())
}

#[test]
fn parse_fingerprint_hash_failure_zeroizes_all_secret_custody() -> Result<(), &'static str> {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let vector = decode_hex(VALID_V1)?;
    let encoded = EncodedLocalKeyFile::from_test_slice(&vector)
        .map_err(|_| "vector could not enter the bounded parser")?;
    let root_key_observer = Rc::new(Cell::new(false));
    let temporary_observer = Rc::new(RefCell::new(Vec::new()));
    let observed = with_secret_release_observer(Rc::clone(&root_key_observer), || {
        with_codec_secret_release_observer(Rc::clone(&temporary_observer), || {
            parse_file_v1_with_backend(encoded, &FailingHashBackend::on_call(2))
        })
    });

    if observed.map(|_| ()) != Err(LocalKeyFailure::new(LocalKeyFailureCode::HashFailed))
        || !root_key_observer.get()
        || !released_zeroized_once(
            temporary_observer.borrow().as_slice(),
            &[
                CodecSecretRelease::ChecksumInput,
                CodecSecretRelease::ChecksumDigest,
                CodecSecretRelease::FingerprintInput,
                CodecSecretRelease::EncodedFile,
            ],
        )
    {
        return Err("parse fingerprint failure released secret material before zeroization");
    }
    Ok(())
}

#[test]
fn successful_parse_zeroizes_all_temporary_and_root_key_custody() -> Result<(), &'static str> {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let vector = decode_hex(VALID_V1)?;
    let encoded = EncodedLocalKeyFile::from_test_slice(&vector)
        .map_err(|_| "vector could not enter the bounded parser")?;
    let root_key_observer = Rc::new(Cell::new(false));
    let temporary_observer = Rc::new(RefCell::new(Vec::new()));
    let observed = with_secret_release_observer(Rc::clone(&root_key_observer), || {
        with_codec_secret_release_observer(Rc::clone(&temporary_observer), || {
            parse_file_v1(encoded)
        })
    })
    .map_err(|_| "valid custody fixture failed")?;
    drop(observed);

    if !root_key_observer.get()
        || !released_zeroized_once(
            temporary_observer.borrow().as_slice(),
            &[
                CodecSecretRelease::ChecksumInput,
                CodecSecretRelease::ChecksumDigest,
                CodecSecretRelease::FingerprintInput,
                CodecSecretRelease::FingerprintDigest,
                CodecSecretRelease::EncodedFile,
            ],
        )
    {
        return Err("successful parse released secret material before zeroization");
    }
    Ok(())
}

#[test]
fn successful_encode_zeroizes_all_temporary_and_root_key_custody() -> Result<(), &'static str> {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let key_id = LocalKeyId::new([1_u8; 16]).map_err(|_| "key-id fixture was invalid")?;
    let root_key_observer = Rc::new(Cell::new(false));
    let temporary_observer = Rc::new(RefCell::new(Vec::new()));
    let observed = with_secret_release_observer(Rc::clone(&root_key_observer), || {
        with_codec_secret_release_observer(Rc::clone(&temporary_observer), || {
            encode_file_v1(
                key_id,
                LocalKeyCreationTime::from_unix_seconds(1_800_000_000),
                SecretRootKey::from_owned(Box::new([2_u8; 32])),
            )
            .map(drop)
        })
    });

    if observed != Ok(())
        || !root_key_observer.get()
        || !released_zeroized_once(
            temporary_observer.borrow().as_slice(),
            &[
                CodecSecretRelease::FingerprintInput,
                CodecSecretRelease::FingerprintDigest,
                CodecSecretRelease::ChecksumInput,
                CodecSecretRelease::ChecksumDigest,
                CodecSecretRelease::EncodedFile,
            ],
        )
    {
        return Err("successful encode released secret material before zeroization");
    }
    Ok(())
}

#[test]
fn parse_rejections_zeroize_every_owned_secret_buffer() -> Result<(), &'static str> {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let valid = decode_hex(VALID_V1)?;
    let mut malformed = valid.clone();
    *malformed.get_mut(0).ok_or("magic offset missing")? ^= 1;
    let mut unsupported_version = valid.clone();
    *unsupported_version
        .get_mut(9)
        .ok_or("version offset missing")? = 2;
    let mut invalid_identity = valid.clone();
    invalid_identity
        .get_mut(14..30)
        .ok_or("key-id offsets missing")?
        .fill(0);
    let mut checksum_mismatch = valid;
    *checksum_mismatch
        .get_mut(133)
        .ok_or("checksum offset missing")? ^= 1;
    let fingerprint_mismatch = decode_hex(
        "504f534c4b455931000100010001000102030405060708090a0b0c0d0e0f000000006b49d2004d346f6ff118118e6b396882ee3249b48f0db74d2d540e2322abf1bf7fbe9c56202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fe9e675e93c54ba74cd2abe335a99f6211f3f3366ac5111922abd094a633a975f",
    )?;

    for (artifact, expected, releases, root_key_created) in [
        (
            malformed,
            LocalKeyFailureCode::MalformedFile,
            vec![CodecSecretRelease::EncodedFile],
            false,
        ),
        (
            unsupported_version,
            LocalKeyFailureCode::UnsupportedVersion,
            vec![CodecSecretRelease::EncodedFile],
            false,
        ),
        (
            invalid_identity,
            LocalKeyFailureCode::InvalidIdentity,
            vec![CodecSecretRelease::EncodedFile],
            false,
        ),
        (
            checksum_mismatch,
            LocalKeyFailureCode::IntegrityMismatch,
            vec![
                CodecSecretRelease::ChecksumInput,
                CodecSecretRelease::ChecksumDigest,
                CodecSecretRelease::EncodedFile,
            ],
            false,
        ),
        (
            fingerprint_mismatch,
            LocalKeyFailureCode::FingerprintMismatch,
            vec![
                CodecSecretRelease::ChecksumInput,
                CodecSecretRelease::ChecksumDigest,
                CodecSecretRelease::FingerprintInput,
                CodecSecretRelease::FingerprintDigest,
                CodecSecretRelease::EncodedFile,
            ],
            true,
        ),
    ] {
        let root_key_observer = Rc::new(Cell::new(false));
        let temporary_observer = Rc::new(RefCell::new(Vec::new()));
        let observed = with_secret_release_observer(Rc::clone(&root_key_observer), || {
            with_codec_secret_release_observer(Rc::clone(&temporary_observer), || {
                parse_local_key_file(&artifact)
            })
        });
        if observed.map(|_| ()) != Err(LocalKeyFailure::new(expected))
            || root_key_observer.get() != root_key_created
            || !released_zeroized_once(temporary_observer.borrow().as_slice(), &releases)
        {
            return Err("parse rejection released secret material before zeroization");
        }
    }
    Ok(())
}

fn released_zeroized_once(
    observed: &[CodecSecretReleaseObservation],
    expected: &[CodecSecretRelease],
) -> bool {
    observed.len() == expected.len()
        && observed.iter().all(|release| {
            release.zeroized && release.observed_len == expected_release_len(release.kind)
        })
        && expected
            .iter()
            .all(|kind| observed.iter().filter(|seen| seen.kind == *kind).count() == 1)
}

fn expected_release_len(kind: CodecSecretRelease) -> usize {
    match kind {
        CodecSecretRelease::FingerprintInput => {
            LOCAL_KEY_FINGERPRINT_DOMAIN.len() + 2 + 2 + 16 + 8 + 32
        },
        CodecSecretRelease::ChecksumInput => LOCAL_KEY_CHECKSUM_DOMAIN.len() + 102,
        CodecSecretRelease::FingerprintDigest | CodecSecretRelease::ChecksumDigest => 32,
        CodecSecretRelease::EncodedFile | CodecSecretRelease::FuzzCandidate => LOCAL_KEY_FILE_BYTES,
    }
}

struct FailingHashBackend {
    fail_on_call: usize,
    calls: std::cell::Cell<usize>,
}

impl FailingHashBackend {
    fn on_call(fail_on_call: usize) -> Self {
        Self {
            fail_on_call,
            calls: std::cell::Cell::new(0),
        }
    }
}

impl CryptoBackend for FailingHashBackend {
    fn seal_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
        RustCryptoBackend.seal_aes_256_gcm(key, nonce, associated_data, plaintext)
    }

    fn open_aes_256_gcm(
        &self,
        key: &SecretKeyBytes,
        nonce: [u8; 12],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecretPlaintext, CryptoBackendFailure> {
        RustCryptoBackend.open_aes_256_gcm(key, nonce, associated_data, ciphertext)
    }

    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], CryptoBackendFailure> {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        if call == self.fail_on_call {
            Err(CryptoBackendFailure::HashFailed)
        } else {
            CryptoBackend::sha256(&RustCryptoBackend, bytes)
        }
    }

    fn fill_random(&self, destination: &mut [u8]) -> Result<(), CryptoBackendFailure> {
        RustCryptoBackend.fill_random(destination)
    }
}

#[test]
fn local_root_key_file_v1_matches_the_independent_vector() -> Result<(), &'static str> {
    let mut key_id = [0_u8; 16];
    for (offset, byte) in key_id.iter_mut().enumerate() {
        *byte = u8::try_from(offset).map_err(|_| "key-id fixture overflowed")?;
    }
    let mut root_key = Box::new([0_u8; 32]);
    for (offset, byte) in root_key.iter_mut().enumerate() {
        let offset = u8::try_from(offset).map_err(|_| "root-key fixture overflowed")?;
        *byte = 0x20_u8
            .checked_add(offset)
            .ok_or("root-key fixture overflowed")?;
    }
    let expected = decode_hex(VALID_V1)?;

    let actual = encode_file_v1(
        LocalKeyId::new(key_id).map_err(|_| "key-id fixture was invalid")?,
        LocalKeyCreationTime::from_unix_seconds(1_800_000_000),
        SecretRootKey::from_owned(root_key),
    )
    .map_err(|_| "local Root Key File v1 encoding failed")?;

    if actual.as_bytes() == expected.as_slice() {
        Ok(())
    } else {
        Err("local Root Key File v1 differed from its independent vector")
    }
}

#[test]
fn independent_file_v1_decodes_to_opaque_custody_and_recovery_required() -> Result<(), &'static str>
{
    let vector = decode_hex(VALID_V1)?;
    let verified = parse_file_v1(
        EncodedLocalKeyFile::from_test_slice(&vector)
            .map_err(|_| "vector could not enter the bounded parser")?,
    )
    .map_err(|_| "independent file v1 did not verify")?;
    let evidence = verified.evidence();
    let expected_fingerprint =
        decode_hex("4c346f6ff118118e6b396882ee3249b48f0db74d2d540e2322abf1bf7fbe9c56")?;

    if evidence.key_id.0 != [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        || evidence.creation_time != LocalKeyCreationTime::from_unix_seconds(1_800_000_000)
        || evidence.fingerprint.0.as_slice() != expected_fingerprint.as_slice()
        || evidence.warning
            != LocalCustodyWarning::FilesystemCustodyDoesNotProtectCombinedKeyAndDataTheft
        || evidence.recovery != LocalRecoveryReadiness::IndependentRecoveryRequired
    {
        return Err("verified local-key evidence differed");
    }
    let diagnostic = Zeroizing::new(format!("{verified:?}"));
    if diagnostic.contains("20212223") || diagnostic.len() > 320 {
        return Err("verified local-key custody diagnostics exposed secret material");
    }
    Ok(())
}

#[test]
fn untrusted_local_key_file_accepts_only_the_fixed_v1_length() -> Result<(), &'static str> {
    let vector = decode_hex(VALID_V1)?;
    let short = vector
        .get(..LOCAL_KEY_FILE_BYTES - 1)
        .ok_or("short fixture failed")?;
    let mut trailing = vector.clone();
    trailing.push(0xA5);

    if parse_local_key_file(short).map(|_| ())
        != Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))
        || parse_local_key_file(&trailing).map(|_| ())
            != Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))
        || parse_local_key_file(&vector).is_err()
    {
        return Err("bounded local-key parser length contract differed");
    }
    Ok(())
}

#[test]
fn untrusted_v1_rejects_version_provider_purpose_checksum_and_fingerprint_failures()
-> Result<(), &'static str> {
    let valid = decode_hex(VALID_V1)?;
    let fingerprint_mismatch = decode_hex(
        "504f534c4b455931000100010001000102030405060708090a0b0c0d0e0f000000006b49d2004d346f6ff118118e6b396882ee3249b48f0db74d2d540e2322abf1bf7fbe9c56202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fe9e675e93c54ba74cd2abe335a99f6211f3f3366ac5111922abd094a633a975f",
    )?;
    let mut unsupported_version = valid.clone();
    *unsupported_version
        .get_mut(9)
        .ok_or("version offset missing")? = 2;
    let mut wrong_provider = valid.clone();
    *wrong_provider
        .get_mut(11)
        .ok_or("provider offset missing")? = 2;
    let mut wrong_purpose = valid.clone();
    *wrong_purpose.get_mut(13).ok_or("purpose offset missing")? = 2;
    let mut zero_key_id = valid.clone();
    zero_key_id
        .get_mut(14..30)
        .ok_or("key-id offsets missing")?
        .fill(0);
    let mut checksum_mismatch = valid;
    *checksum_mismatch
        .get_mut(133)
        .ok_or("checksum offset missing")? ^= 1;

    for (artifact, expected) in [
        (unsupported_version, LocalKeyFailureCode::UnsupportedVersion),
        (wrong_provider, LocalKeyFailureCode::MalformedFile),
        (wrong_purpose, LocalKeyFailureCode::MalformedFile),
        (zero_key_id, LocalKeyFailureCode::InvalidIdentity),
        (checksum_mismatch, LocalKeyFailureCode::IntegrityMismatch),
        (
            fingerprint_mismatch,
            LocalKeyFailureCode::FingerprintMismatch,
        ),
    ] {
        if parse_local_key_file(&artifact).map(|_| ()) != Err(LocalKeyFailure::new(expected)) {
            return Err("malformed local-key artifact produced the wrong failure");
        }
    }
    Ok(())
}

#[test]
fn checksummed_root_key_substitution_is_rejected_by_immutable_fingerprint()
-> Result<(), &'static str> {
    let substituted = decode_hex(SUBSTITUTED_KEY_V1)?;
    if parse_local_key_file(&substituted).map(|_| ())
        == Err(LocalKeyFailure::new(
            LocalKeyFailureCode::FingerprintMismatch,
        ))
    {
        Ok(())
    } else {
        Err("checksummed Root KEK substitution was not rejected by fingerprint")
    }
}

#[test]
fn parsed_root_key_custody_zeroizes_before_release_on_success_and_fingerprint_failure()
-> Result<(), &'static str> {
    use std::cell::Cell;
    use std::rc::Rc;

    let valid = decode_hex(VALID_V1)?;
    let substituted = decode_hex(SUBSTITUTED_KEY_V1)?;
    let success_observer = Rc::new(Cell::new(false));
    let verified = with_secret_release_observer(Rc::clone(&success_observer), || {
        parse_local_key_file(&valid)
    })
    .map_err(|_| "valid custody fixture failed")?;
    drop(verified);
    let failure_observer = Rc::new(Cell::new(false));
    let failure = with_secret_release_observer(Rc::clone(&failure_observer), || {
        parse_local_key_file(&substituted)
    });

    if success_observer.get()
        && failure_observer.get()
        && failure.map(|_| ())
            == Err(LocalKeyFailure::new(
                LocalKeyFailureCode::FingerprintMismatch,
            ))
    {
        Ok(())
    } else {
        Err("parsed Root KEK custody was released before zeroization")
    }
}

#[test]
fn semantic_local_key_records_are_not_fuzz_mutation_programs() {
    let hex_seed = local_key_hex_seed(VALID_V1);
    assert!(
        fuzz_local_root_key_file(hex_seed.as_slice()) == FuzzLocalKeyOutcome::InvalidProgram,
        "semantic Local Root Key File hex was accepted as a fuzz mutation program"
    );
}

#[test]
fn compact_fuzz_selector_reaches_the_valid_baseline() {
    assert!(
        fuzz_local_root_key_file(b"V")
            == FuzzLocalKeyOutcome::Accepted {
                warning:
                    LocalCustodyWarning::FilesystemCustodyDoesNotProtectCombinedKeyAndDataTheft,
                recovery: LocalRecoveryReadiness::IndependentRecoveryRequired,
            },
        "valid fuzz selector did not reach the published local-key baseline"
    );
}

#[test]
fn compact_fuzz_mutations_reach_structural_integrity_and_fingerprint_failures() {
    for (program, expected) in [
        (
            &[b'V', b'W', 9, 2][..],
            LocalKeyFailureCode::UnsupportedVersion,
        ),
        (&[b'V', b'X', 11, 1][..], LocalKeyFailureCode::MalformedFile),
        (&[b'V', b'W', 13, 2][..], LocalKeyFailureCode::MalformedFile),
        (
            &[b'V', b'T', 133, 0][..],
            LocalKeyFailureCode::MalformedFile,
        ),
        (
            &[b'V', b'A', 1, 0xa5][..],
            LocalKeyFailureCode::MalformedFile,
        ),
        (
            &[b'V', b'R', 135, 0][..],
            LocalKeyFailureCode::MalformedFile,
        ),
        (
            &[b'V', b'X', 133, 1][..],
            LocalKeyFailureCode::IntegrityMismatch,
        ),
        (
            &[b'V', b'W', 38, 0x4d, b'C', b'0', 0][..],
            LocalKeyFailureCode::FingerprintMismatch,
        ),
        (
            &[b'V', b'W', 70, 0x21, b'C', b'0', 0][..],
            LocalKeyFailureCode::FingerprintMismatch,
        ),
    ] {
        assert!(
            fuzz_local_root_key_file(program) == FuzzLocalKeyOutcome::Rejected(expected),
            "compact local-key mutation did not reach its expected parser outcome"
        );
    }
}

#[test]
fn compact_corpus_programs_cover_valid_truncated_and_substituted_key_paths() {
    let valid = include_bytes!("../../../../../fuzz/corpus/local_root_key_file/valid");
    let truncated = include_bytes!("../../../../../fuzz/corpus/local_root_key_file/truncated");
    let substituted_key =
        include_bytes!("../../../../../fuzz/corpus/local_root_key_file/substituted_key");

    assert!(
        matches!(
            fuzz_local_root_key_file(valid),
            FuzzLocalKeyOutcome::Accepted { .. }
        ),
        "valid compact corpus program did not reach acceptance"
    );
    assert!(
        fuzz_local_root_key_file(truncated)
            == FuzzLocalKeyOutcome::Rejected(LocalKeyFailureCode::MalformedFile),
        "truncated compact corpus program did not reach malformed-file rejection"
    );
    assert!(
        fuzz_local_root_key_file(substituted_key)
            == FuzzLocalKeyOutcome::Rejected(LocalKeyFailureCode::FingerprintMismatch),
        "substituted-key compact corpus program did not reach fingerprint rejection"
    );
}

#[test]
fn every_local_key_file_offset_is_reachable_by_compact_overwrite_and_xor_commands() {
    for offset in 0_u8..134_u8 {
        for opcode in [b'W', b'X'] {
            assert!(
                fuzz_local_root_key_file(&[b'V', opcode, offset, 0xa5])
                    != FuzzLocalKeyOutcome::InvalidProgram,
                "valid indexed local-key mutation was rejected"
            );
        }
    }
}

#[test]
fn malformed_or_oversized_fuzz_programs_are_rejected() {
    let oversized = [b'V'; 65];
    for program in [
        &[][..],
        b"Q",
        b"VW",
        &[b'V', 0xff, 0, 0][..],
        &[b'V', b'W', 200, 0][..],
        &[b'V', b'T', 200, 0][..],
        &[b'V', b'A', 17, 0][..],
        &[b'V', b'R', 151, 0][..],
        &[b'V', b'C', 1, 0][..],
        oversized.as_slice(),
    ] {
        assert!(
            fuzz_local_root_key_file(program) == FuzzLocalKeyOutcome::InvalidProgram,
            "invalid local-key fuzz mutation program was accepted"
        );
    }
}

#[test]
fn local_key_fuzz_boundary_zeroizes_internally_synthesized_candidate() {
    use std::cell::RefCell;
    use std::rc::Rc;

    let temporary_observer = Rc::new(RefCell::new(Vec::new()));
    let outcome = with_codec_secret_release_observer(Rc::clone(&temporary_observer), || {
        fuzz_local_root_key_file(b"V")
    });
    let observed = temporary_observer.borrow();

    assert!(
        matches!(outcome, FuzzLocalKeyOutcome::Accepted { .. }),
        "valid compact fuzz selector did not reach the parser"
    );
    assert!(
        observed.iter().all(|release| release.zeroized),
        "local-key fuzz harness released non-zeroized secret custody"
    );
    assert!(
        observed.iter().any(|release| {
            release.kind == CodecSecretRelease::FuzzCandidate
                && release.observed_len == LOCAL_KEY_FILE_BYTES
                && release.zeroized
        }),
        "internally synthesized local-key candidate was not observed as nonempty and zeroized"
    );
}

fn local_key_hex_seed(encoded: &str) -> Zeroizing<Vec<u8>> {
    let mut seed = Zeroizing::new(Vec::with_capacity(b"hex:".len() + encoded.len()));
    seed.extend_from_slice(b"hex:");
    seed.extend_from_slice(encoded.as_bytes());
    seed
}

fn decode_hex(source: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if !source.len().is_multiple_of(2) {
        return Err("hex fixture length was odd");
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(source.len() / 2));
    for pair in source.as_bytes().chunks_exact(2) {
        let high = hex_nibble(*pair.first().ok_or("hex fixture pair was empty")?)?;
        let low = hex_nibble(*pair.get(1).ok_or("hex fixture pair was short")?)?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("hex fixture contained a non-hex byte"),
    }
}
