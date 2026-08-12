use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::{CryptoBackend, RustCryptoBackend, SecretKeyBytes};

fn protected_segment_fixture() -> Result<
    (
        super::ObjectDataKey,
        super::FrameContext,
        super::FrameLimits,
        super::EncryptedFrame,
    ),
    &'static str,
> {
    let tenant = TenantId::from_bytes([0xd1; 16]).map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(2).map_err(|_| "shard fixture was invalid")?;
    let object = super::FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        super::FrameObjectId::new([0xd2; 16]).map_err(|_| "object fixture was invalid")?,
        super::KeyEpoch::new(1),
        super::FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?,
    );
    let context = object
        .frame(
            super::SegmentFramePurpose::StoreBlock,
            super::FrameSequence::new(5),
        )
        .map_err(|_| "frame context fixture was invalid")?;
    let key = super::ObjectDataKey::import(super::SecretKeyInput::new([0xd3; 32]), object);
    let limits = super::FrameLimits::new(256).map_err(|_| "frame limit fixture was invalid")?;
    let encrypted =
        super::DataProtection::protect_frame(&key, context, b"persistent-frame-fixture", limits)
            .map_err(|_| "frame fixture protection failed")?;
    Ok((key, context, limits, encrypted))
}

#[test]
fn rust_crypto_backend_matches_nist_aes_256_gcm_vector() -> Result<(), &'static str> {
    // NIST CAVP AES-GCM example with a 256-bit zero key, 96-bit zero IV,
    // one zero plaintext block, and no AAD. The expected ciphertext and
    // tag are independent published values, not derived by this test.
    // Source: NIST CAVP GCM test vectors, gcmEncryptExtIV256.rsp.
    let backend = RustCryptoBackend;
    let key = SecretKeyBytes::new([0_u8; 32]);
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
fn data_protection_emits_the_stable_frame_v1_vector() -> Result<(), &'static str> {
    use super::{
        DataProtection, FormatEpoch, FrameLimits, FrameObjectContext, FrameObjectId, FrameSequence,
        KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose,
    };

    // Independently derived with Node.js/OpenSSL 3.5.7 from the documented
    // frame-v1 byte contract. This literal fixes the durable artifact and
    // cannot change merely because the Rust implementation changes.
    let expected = [
        0x50, 0x46, 0x52, 0x4d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x21, 0x43, 0x40, 0x1e, 0x3f, 0xa1, 0x6d, 0xd6, 0xbe, 0x0a, 0x4c,
        0xf9, 0x03, 0x32, 0x4b, 0x74, 0x2f, 0xb3, 0x6a, 0x38, 0xde, 0xd6, 0x08, 0xd7, 0xe9, 0x2b,
        0xb0, 0x44, 0x84, 0x65, 0xf1, 0x25, 0x83, 0xeb, 0x40, 0xdd, 0x56, 0x33, 0x7f, 0xc3, 0x3a,
        0x42, 0xae, 0x55, 0xe3, 0xb2, 0xba, 0xe5, 0xf7, 0xbf, 0xc2, 0x2d, 0x79, 0x0a, 0xff, 0xe8,
        0x6e, 0x80, 0x39, 0x20, 0xcf, 0xe1, 0xab, 0x26, 0xde, 0xfd,
    ];
    let tenant = TenantId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        .map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(7).map_err(|_| "shard fixture was invalid")?;
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        FrameObjectId::new([
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ])
        .map_err(|_| "object fixture was invalid")?,
        KeyEpoch::new(3),
        FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?,
    );
    let key = ObjectDataKey::import(
        SecretKeyInput::new([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]),
        object,
    );
    let context = object
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(9))
        .map_err(|_| "frame fixture context was invalid")?;
    let limits = FrameLimits::new(1024).map_err(|_| "frame fixture limit was invalid")?;

    let frame = DataProtection::protect_frame(&key, context, b"positron-frame-v1", limits)
        .map_err(|_| "frame protection failed")?;

    if frame.as_bytes() == expected {
        Ok(())
    } else {
        Err("frame-v1 bytes differed from the independent vector")
    }
}

#[test]
fn wrong_key_returns_no_plaintext() -> Result<(), &'static str> {
    use super::{
        DataProtection, FormatEpoch, FrameFailureCode, FrameLimits, FrameObjectContext,
        FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose,
    };

    let tenant = TenantId::from_bytes([0x21; 16]).map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(1).map_err(|_| "shard fixture was invalid")?;
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        FrameObjectId::new([0x31; 16]).map_err(|_| "object fixture was invalid")?,
        KeyEpoch::new(1),
        FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?,
    );
    let correct_key = ObjectDataKey::import(SecretKeyInput::new([0x41; 32]), object);
    let wrong_key = ObjectDataKey::import(SecretKeyInput::new([0x42; 32]), object);
    let context = object
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1))
        .map_err(|_| "frame fixture context was invalid")?;
    let limits = FrameLimits::new(256).map_err(|_| "frame fixture limit was invalid")?;
    let encrypted =
        DataProtection::protect_frame(&correct_key, context, b"plaintext-secret-canary", limits)
            .map_err(|_| "frame protection failed")?;

    let failure = DataProtection::open_frame(&wrong_key, context, encrypted.as_bytes(), limits)
        .expect_err("a wrong key must never produce a verified frame");

    if failure.code() == FrameFailureCode::AuthenticationFailed {
        Ok(())
    } else {
        Err("wrong-key failure classification differed")
    }
}

#[test]
fn frames_are_rereadable_only_at_the_exact_authoritative_context() -> Result<(), &'static str> {
    use super::{
        DataProtection, FormatEpoch, FrameFailureCode, FrameLimits, FrameObjectContext,
        FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose,
    };

    let tenant = TenantId::from_bytes([0x51; 16]).map_err(|_| "tenant fixture was invalid")?;
    let other_tenant =
        TenantId::from_bytes([0x52; 16]).map_err(|_| "alternate tenant fixture was invalid")?;
    let shard = VirtualShardId::new(3).map_err(|_| "shard fixture was invalid")?;
    let other_shard = VirtualShardId::new(4).map_err(|_| "alternate shard fixture was invalid")?;
    let object_id = FrameObjectId::new([0x61; 16]).map_err(|_| "object fixture was invalid")?;
    let other_object_id =
        FrameObjectId::new([0x62; 16]).map_err(|_| "alternate object fixture was invalid")?;
    let format_epoch = FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?;
    let other_format_epoch =
        FormatEpoch::new(2).map_err(|_| "alternate format epoch fixture was invalid")?;
    let authentic_object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        object_id,
        KeyEpoch::new(7),
        format_epoch,
    );
    let authentic_context = authentic_object
        .frame(SegmentFramePurpose::Index, FrameSequence::new(11))
        .map_err(|_| "authentic frame context was invalid")?;
    let limits = FrameLimits::new(512).map_err(|_| "frame limit fixture was invalid")?;
    let authentic_key = ObjectDataKey::import(SecretKeyInput::new([0x71; 32]), authentic_object);
    let encrypted = DataProtection::protect_frame(
        &authentic_key,
        authentic_context,
        b"authenticated-frame",
        limits,
    )
    .map_err(|_| "frame protection failed")?;
    let verified = DataProtection::open_frame(
        &authentic_key,
        authentic_context,
        encrypted.as_bytes(),
        limits,
    )
    .map_err(|_| "authentic frame reread failed")?;
    if verified.as_plaintext() != b"authenticated-frame" {
        return Err("authentic frame plaintext differed");
    }

    let substitutions = [
        (
            FrameObjectContext::tenant_segment(
                other_tenant,
                SignalKind::Logs,
                shard,
                object_id,
                KeyEpoch::new(7),
                format_epoch,
            ),
            SegmentFramePurpose::Index,
            FrameSequence::new(11),
        ),
        (
            FrameObjectContext::tenant_segment(
                tenant,
                SignalKind::Traces,
                shard,
                object_id,
                KeyEpoch::new(7),
                format_epoch,
            ),
            SegmentFramePurpose::Index,
            FrameSequence::new(11),
        ),
        (
            FrameObjectContext::tenant_segment(
                tenant,
                SignalKind::Logs,
                other_shard,
                object_id,
                KeyEpoch::new(7),
                format_epoch,
            ),
            SegmentFramePurpose::Index,
            FrameSequence::new(11),
        ),
        (
            FrameObjectContext::tenant_segment(
                tenant,
                SignalKind::Logs,
                shard,
                other_object_id,
                KeyEpoch::new(7),
                format_epoch,
            ),
            SegmentFramePurpose::Index,
            FrameSequence::new(11),
        ),
        (
            FrameObjectContext::tenant_segment(
                tenant,
                SignalKind::Logs,
                shard,
                object_id,
                KeyEpoch::new(8),
                format_epoch,
            ),
            SegmentFramePurpose::Index,
            FrameSequence::new(11),
        ),
        (
            FrameObjectContext::tenant_segment(
                tenant,
                SignalKind::Logs,
                shard,
                object_id,
                KeyEpoch::new(7),
                other_format_epoch,
            ),
            SegmentFramePurpose::Index,
            FrameSequence::new(11),
        ),
        (
            authentic_object,
            SegmentFramePurpose::Statistics,
            FrameSequence::new(11),
        ),
        (
            authentic_object,
            SegmentFramePurpose::Index,
            FrameSequence::new(12),
        ),
    ];

    for (object, purpose, sequence) in substitutions {
        let substituted_key = ObjectDataKey::import(SecretKeyInput::new([0x71; 32]), object);
        let substituted_context = object
            .frame(purpose, sequence)
            .map_err(|_| "substituted frame context was invalid")?;
        let failure = DataProtection::open_frame(
            &substituted_key,
            substituted_context,
            encrypted.as_bytes(),
            limits,
        )
        .expect_err("context substitution must not expose plaintext");
        if failure.code() != FrameFailureCode::AuthenticationFailed {
            return Err("context substitution failure classification differed");
        }
    }
    Ok(())
}

#[test]
fn every_persistent_object_kind_round_trips() -> Result<(), &'static str> {
    use super::{
        DataProtection, FormatEpoch, FrameLimits, FrameObjectContext, FrameObjectId, FrameSequence,
        KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose, SystemObjectKind,
    };

    let tenant = TenantId::from_bytes([0x81; 16]).map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(9).map_err(|_| "shard fixture was invalid")?;
    let format_epoch = FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?;
    let limits = FrameLimits::new(512).map_err(|_| "frame limit fixture was invalid")?;

    for (offset, purpose) in [
        SegmentFramePurpose::StoreBlock,
        SegmentFramePurpose::Index,
        SegmentFramePurpose::Statistics,
        SegmentFramePurpose::SegmentMetadata,
    ]
    .into_iter()
    .enumerate()
    {
        let identity_byte =
            u8::try_from(offset + 1).map_err(|_| "segment object fixture exceeded one byte")?;
        let object = FrameObjectContext::tenant_segment(
            tenant,
            SignalKind::Logs,
            shard,
            FrameObjectId::new([identity_byte; 16])
                .map_err(|_| "segment object fixture was invalid")?,
            KeyEpoch::new(1),
            format_epoch,
        );
        let context = object
            .frame(purpose, FrameSequence::new(1))
            .map_err(|_| "segment frame context was invalid")?;
        let key = ObjectDataKey::import(SecretKeyInput::new([identity_byte; 32]), object);
        let encrypted = DataProtection::protect_frame(&key, context, b"segment", limits)
            .map_err(|_| "segment frame protection failed")?;
        let verified = DataProtection::open_frame(&key, context, encrypted.as_bytes(), limits)
            .map_err(|_| "segment frame open failed")?;
        if verified.as_plaintext() != b"segment" {
            return Err("segment frame plaintext differed");
        }
    }

    for (offset, kind) in [
        SystemObjectKind::Catalog,
        SystemObjectKind::Manifest,
        SystemObjectKind::GovernanceAudit,
        SystemObjectKind::BackupMetadata,
    ]
    .into_iter()
    .enumerate()
    {
        let identity_byte =
            u8::try_from(offset + 11).map_err(|_| "system object fixture exceeded one byte")?;
        let object = FrameObjectContext::system(
            kind,
            FrameObjectId::new([identity_byte; 16])
                .map_err(|_| "system object fixture was invalid")?,
            KeyEpoch::new(1),
            format_epoch,
        );
        let context = object
            .system_frame(FrameSequence::new(1))
            .map_err(|_| "system frame context was invalid")?;
        let key = ObjectDataKey::import(SecretKeyInput::new([identity_byte; 32]), object);
        let encrypted = DataProtection::protect_frame(&key, context, b"system", limits)
            .map_err(|_| "system frame protection failed")?;
        let verified = DataProtection::open_frame(&key, context, encrypted.as_bytes(), limits)
            .map_err(|_| "system frame open failed")?;
        if verified.as_plaintext() != b"system" {
            return Err("system frame plaintext differed");
        }
    }
    Ok(())
}

#[test]
fn declared_frame_length_above_policy_is_rejected_before_authentication() -> Result<(), &'static str>
{
    use super::{
        DataProtection, FormatEpoch, FrameFailureCode, FrameLimits, FrameObjectContext,
        FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose,
    };

    let tenant = TenantId::from_bytes([0xb1; 16]).map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(1).map_err(|_| "shard fixture was invalid")?;
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        FrameObjectId::new([0xb2; 16]).map_err(|_| "object fixture was invalid")?,
        KeyEpoch::new(1),
        FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?,
    );
    let context = object
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1))
        .map_err(|_| "frame context fixture was invalid")?;
    let key = ObjectDataKey::import(SecretKeyInput::new([0xb3; 32]), object);
    let limits = FrameLimits::new(128).map_err(|_| "frame limit fixture was invalid")?;
    let encrypted = DataProtection::protect_frame(&key, context, b"bounded", limits)
        .map_err(|_| "frame protection failed")?;
    let mut hostile = encrypted.as_bytes().to_vec();
    let declared_length = hostile
        .get_mut(16..20)
        .ok_or("frame fixture omitted its declared length")?;
    declared_length.copy_from_slice(&200_u32.to_be_bytes());

    let failure = DataProtection::open_frame(&key, context, &hostile, limits)
        .expect_err("an over-policy declaration must not reach authentication");
    if failure.code() == FrameFailureCode::LimitExceeded {
        Ok(())
    } else {
        Err("over-policy declaration failure classification differed")
    }
}

#[test]
fn truncated_frame_is_structurally_refused_without_plaintext() -> Result<(), &'static str> {
    use super::{
        DataProtection, FormatEpoch, FrameFailureCode, FrameLimits, FrameObjectContext,
        FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose,
    };

    let tenant = TenantId::from_bytes([0xc1; 16]).map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(1).map_err(|_| "shard fixture was invalid")?;
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        FrameObjectId::new([0xc2; 16]).map_err(|_| "object fixture was invalid")?,
        KeyEpoch::new(1),
        FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?,
    );
    let context = object
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1))
        .map_err(|_| "frame context fixture was invalid")?;
    let key = ObjectDataKey::import(SecretKeyInput::new([0xc3; 32]), object);
    let limits = FrameLimits::new(256).map_err(|_| "frame limit fixture was invalid")?;
    let encrypted = DataProtection::protect_frame(&key, context, b"truncate-me", limits)
        .map_err(|_| "frame protection failed")?;
    let mut truncated = encrypted.as_bytes().to_vec();
    truncated
        .pop()
        .ok_or("frame fixture was unexpectedly empty")?;

    let failure = DataProtection::open_frame(&key, context, &truncated, limits)
        .expect_err("a truncated frame must not produce plaintext");
    if failure.code() == FrameFailureCode::MalformedFrame {
        Ok(())
    } else {
        Err("truncated frame failure classification differed")
    }
}

#[test]
fn unsupported_frame_version_is_refused_before_authentication() -> Result<(), &'static str> {
    use super::{DataProtection, FrameFailureCode};

    let (key, context, limits, encrypted) = protected_segment_fixture()?;
    let mut hostile = encrypted.as_bytes().to_vec();
    let version = hostile
        .get_mut(4..6)
        .ok_or("frame fixture omitted its version")?;
    version.copy_from_slice(&2_u16.to_be_bytes());

    let failure = DataProtection::open_frame(&key, context, &hostile, limits)
        .expect_err("an unsupported version must not produce plaintext");
    if failure.code() == FrameFailureCode::UnsupportedVersion {
        Ok(())
    } else {
        Err("unsupported-version failure classification differed")
    }
}

#[test]
fn unsupported_frame_algorithm_is_refused_before_authentication() -> Result<(), &'static str> {
    use super::{DataProtection, FrameFailureCode};

    let (key, context, limits, encrypted) = protected_segment_fixture()?;
    let mut hostile = encrypted.as_bytes().to_vec();
    let algorithm = hostile
        .get_mut(6..8)
        .ok_or("frame fixture omitted its algorithm")?;
    algorithm.copy_from_slice(&2_u16.to_be_bytes());

    let failure = DataProtection::open_frame(&key, context, &hostile, limits)
        .expect_err("an unsupported algorithm must not produce plaintext");
    if failure.code() == FrameFailureCode::UnsupportedAlgorithm {
        Ok(())
    } else {
        Err("unsupported-algorithm failure classification differed")
    }
}

#[test]
fn ciphertext_checksum_detects_keyless_corruption() -> Result<(), &'static str> {
    use super::{DataProtection, FrameFailureCode};

    let (key, context, limits, encrypted) = protected_segment_fixture()?;
    let mut corrupt = encrypted.as_bytes().to_vec();
    let last = corrupt
        .last_mut()
        .ok_or("frame fixture was unexpectedly empty")?;
    *last ^= 0x01;

    let failure = DataProtection::open_frame(&key, context, &corrupt, limits)
        .expect_err("ciphertext corruption must not produce plaintext");
    if failure.code() == FrameFailureCode::ChecksumMismatch {
        Ok(())
    } else {
        Err("ciphertext corruption failure classification differed")
    }
}

#[test]
fn restart_sequence_reset_uses_a_fresh_object_key() -> Result<(), &'static str> {
    use super::{DataProtection, ObjectDataKey};

    let (_, context, limits, _) = protected_segment_fixture()?;
    let object = context.object;
    let first_restart_key =
        ObjectDataKey::generate(object).map_err(|_| "first key generation failed")?;
    let second_restart_key =
        ObjectDataKey::generate(object).map_err(|_| "second key generation failed")?;
    let first =
        DataProtection::protect_frame(&first_restart_key, context, b"restart-sequence", limits)
            .map_err(|_| "first restarted frame protection failed")?;
    let second =
        DataProtection::protect_frame(&second_restart_key, context, b"restart-sequence", limits)
            .map_err(|_| "second restarted frame protection failed")?;

    if first.as_bytes() != second.as_bytes() {
        Ok(())
    } else {
        Err("fresh object keys produced the same restarted frame")
    }
}

#[test]
fn aead_tag_remains_authoritative_when_the_checksum_is_recomputed() -> Result<(), &'static str> {
    use super::{DataProtection, FrameFailureCode};
    use sha2::{Digest, Sha256};

    let (key, context, limits, encrypted) = protected_segment_fixture()?;
    let mut hostile = encrypted.as_bytes().to_vec();
    let ciphertext = hostile
        .get_mut(52..)
        .ok_or("frame fixture omitted ciphertext")?;
    let first = ciphertext
        .first_mut()
        .ok_or("frame fixture ciphertext was unexpectedly empty")?;
    *first ^= 0x01;
    let recomputed_checksum: [u8; 32] = Sha256::digest(ciphertext).into();
    let stored_checksum = hostile
        .get_mut(20..52)
        .ok_or("frame fixture omitted its checksum")?;
    stored_checksum.copy_from_slice(&recomputed_checksum);

    let failure = DataProtection::open_frame(&key, context, &hostile, limits)
        .expect_err("a forged checksum must not replace AEAD authentication");
    if failure.code() == FrameFailureCode::AuthenticationFailed {
        Ok(())
    } else {
        Err("forged ciphertext failure classification differed")
    }
}

#[test]
fn tenant_frame_substituted_as_a_system_object_returns_no_plaintext() -> Result<(), &'static str> {
    use super::{
        DataProtection, FormatEpoch, FrameFailureCode, FrameObjectContext, FrameObjectId,
        FrameSequence, KeyEpoch, ObjectDataKey, SecretKeyInput, SystemObjectKind,
    };

    let (_, _, limits, encrypted) = protected_segment_fixture()?;
    let system_object = FrameObjectContext::system(
        SystemObjectKind::Catalog,
        FrameObjectId::new([0xd2; 16]).map_err(|_| "system object fixture was invalid")?,
        KeyEpoch::new(1),
        FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?,
    );
    let system_context = system_object
        .system_frame(FrameSequence::new(5))
        .map_err(|_| "system frame context was invalid")?;
    let system_key = ObjectDataKey::import(SecretKeyInput::new([0xd3; 32]), system_object);

    let failure =
        DataProtection::open_frame(&system_key, system_context, encrypted.as_bytes(), limits)
            .expect_err("tenant ciphertext must not authenticate as system state");
    if failure.code() == FrameFailureCode::AuthenticationFailed {
        Ok(())
    } else {
        Err("tenant/system substitution failure classification differed")
    }
}

#[test]
fn malformed_headers_are_refused_as_structural_failures() -> Result<(), &'static str> {
    use super::{DataProtection, FrameFailureCode};

    let (key, context, limits, encrypted) = protected_segment_fixture()?;
    let mut bad_magic = encrypted.as_bytes().to_vec();
    let magic = bad_magic
        .first_mut()
        .ok_or("frame fixture was unexpectedly empty")?;
    *magic ^= 0x01;
    let mut undersized_ciphertext = encrypted.as_bytes().to_vec();
    let declared_length = undersized_ciphertext
        .get_mut(16..20)
        .ok_or("frame fixture omitted its declared length")?;
    declared_length.copy_from_slice(&15_u32.to_be_bytes());
    let mut mismatched_length = encrypted.as_bytes().to_vec();
    let declared_length = mismatched_length
        .get_mut(16..20)
        .ok_or("frame fixture omitted its declared length")?;
    declared_length.copy_from_slice(&16_u32.to_be_bytes());

    for malformed in [
        Vec::new(),
        encrypted
            .as_bytes()
            .get(..19)
            .ok_or("frame fixture was shorter than its header")?
            .to_vec(),
        bad_magic,
        undersized_ciphertext,
        mismatched_length,
    ] {
        let failure = DataProtection::open_frame(&key, context, &malformed, limits)
            .expect_err("a malformed header must not produce plaintext");
        if failure.code() != FrameFailureCode::MalformedFrame {
            return Err("malformed header failure classification differed");
        }
    }
    Ok(())
}

#[test]
fn finite_policy_bounds_both_protection_and_opening() -> Result<(), &'static str> {
    use super::{DataProtection, FrameFailureCode, FrameLimits};

    let (key, context, _, encrypted) = protected_segment_fixture()?;
    let minimum = FrameLimits::new(68).map_err(|_| "minimum frame limit was invalid")?;
    let empty = DataProtection::protect_frame(&key, context, b"", minimum)
        .map_err(|_| "empty frame did not fit the exact minimum limit")?;
    if empty.as_bytes().len() != 68 {
        return Err("empty frame size differed from the fixed minimum");
    }
    let verified_empty = DataProtection::open_frame(&key, context, empty.as_bytes(), minimum)
        .map_err(|_| "minimum-size empty frame did not authenticate")?;
    if !verified_empty.as_plaintext().is_empty() {
        return Err("minimum-size empty frame exposed non-empty plaintext");
    }
    let protect_failure = DataProtection::protect_frame(&key, context, b"x", minimum)
        .expect_err("a one-byte plaintext cannot fit the minimum empty-frame limit");
    if protect_failure.code() != FrameFailureCode::LimitExceeded {
        return Err("protection limit failure classification differed");
    }
    let open_failure = DataProtection::open_frame(&key, context, encrypted.as_bytes(), minimum)
        .expect_err("an encoded frame above the caller policy must be refused");
    if open_failure.code() != FrameFailureCode::LimitExceeded {
        return Err("open limit failure classification differed");
    }
    Ok(())
}

#[test]
fn invalid_context_and_limit_construction_fails_closed() -> Result<(), &'static str> {
    use super::{
        DataProtection, FormatEpoch, FrameFailureCode, FrameLimits, FrameObjectContext,
        FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose,
        SystemObjectKind,
    };

    if FrameObjectId::new([0_u8; 16])
        .expect_err("the object sentinel must be rejected")
        .code()
        != FrameFailureCode::InvalidContext
    {
        return Err("object sentinel failure classification differed");
    }
    if FormatEpoch::new(0)
        .expect_err("the Format Epoch sentinel must be rejected")
        .code()
        != FrameFailureCode::InvalidContext
    {
        return Err("Format Epoch sentinel failure classification differed");
    }
    if FrameLimits::new(67)
        .expect_err("a policy below the fixed empty-frame size must be rejected")
        .code()
        != FrameFailureCode::InvalidLimit
    {
        return Err("minimum limit failure classification differed");
    }

    let tenant = TenantId::from_bytes([0xe1; 16]).map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(1).map_err(|_| "shard fixture was invalid")?;
    let object_id = FrameObjectId::new([0xe2; 16]).map_err(|_| "object fixture was invalid")?;
    let epoch = FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?;
    let segment = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        object_id,
        KeyEpoch::new(1),
        epoch,
    );
    if segment
        .system_frame(FrameSequence::new(1))
        .expect_err("a segment must not create a system frame")
        .code()
        != FrameFailureCode::InvalidContext
    {
        return Err("segment/system purpose failure classification differed");
    }
    let system = FrameObjectContext::system(
        SystemObjectKind::Catalog,
        object_id,
        KeyEpoch::new(1),
        epoch,
    );
    if system
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1))
        .expect_err("a system object must not create a segment frame")
        .code()
        != FrameFailureCode::InvalidContext
    {
        return Err("system/segment purpose failure classification differed");
    }
    let system_context = system
        .system_frame(FrameSequence::new(1))
        .map_err(|_| "system frame context was invalid")?;
    let segment_key = ObjectDataKey::import(SecretKeyInput::new([0xe3; 32]), segment);
    let limits = FrameLimits::new(128).map_err(|_| "frame limit fixture was invalid")?;
    if DataProtection::protect_frame(&segment_key, system_context, b"object mismatch", limits)
        .expect_err("a key bound to another object must be refused")
        .code()
        != FrameFailureCode::InvalidContext
    {
        return Err("key/object mismatch failure classification differed");
    }
    Ok(())
}

#[test]
fn keys_plaintext_and_failures_have_bounded_redacted_diagnostics() -> Result<(), &'static str> {
    use std::error::Error;

    use super::{DataProtection, ObjectDataKey, SecretKeyInput};

    let (_, context, limits, _) = protected_segment_fixture()?;
    let key_canary = [b'K'; 32];
    let key = ObjectDataKey::import(SecretKeyInput::new(key_canary), context.object);
    let plaintext = b"plaintext-secret-canary";
    let encrypted = DataProtection::protect_frame(&key, context, plaintext, limits)
        .map_err(|_| "frame protection failed")?;
    if encrypted
        .as_bytes()
        .windows(plaintext.len())
        .any(|window| window == plaintext)
    {
        return Err("encrypted frame exposed plaintext");
    }
    if encrypted
        .as_bytes()
        .windows(key_canary.len())
        .any(|window| window == key_canary)
    {
        return Err("encrypted frame exposed key material");
    }
    let verified = DataProtection::open_frame(&key, context, encrypted.as_bytes(), limits)
        .map_err(|_| "authentic frame open failed")?;
    let key_debug = format!("{key:?}");
    let encrypted_debug = format!("{encrypted:?}");
    let verified_debug = format!("{verified:?}");
    for diagnostic in [&key_debug, &encrypted_debug, &verified_debug] {
        if diagnostic.contains("plaintext-secret-canary") || diagnostic.contains("KKKKKKKK") {
            return Err("debug output exposed a secret canary");
        }
        if diagnostic.len() > 96 {
            return Err("debug output exceeded its bounded representation");
        }
    }

    let wrong_key = ObjectDataKey::import(SecretKeyInput::new([b'W'; 32]), context.object);
    let failure = DataProtection::open_frame(&wrong_key, context, encrypted.as_bytes(), limits)
        .expect_err("a wrong key must fail authentication");
    let failure_display = failure.to_string();
    let failure_debug = format!("{failure:?}");
    if failure_display.contains("plaintext-secret-canary")
        || failure_debug.contains("plaintext-secret-canary")
        || failure_display.contains("KKKKKKKK")
        || failure_debug.contains("KKKKKKKK")
        || failure.source().is_some()
        || failure_display.len() > 96
        || failure_debug.len() > 96
    {
        return Err("frame failure diagnostics exposed or retained secret context");
    }
    Ok(())
}

#[test]
fn immutable_frame_reread_and_nonce_sequence_semantics_are_explicit() -> Result<(), &'static str> {
    use super::{DataProtection, FrameSequence, SegmentFramePurpose};

    let (key, context, limits, _) = protected_segment_fixture()?;
    let same_address = DataProtection::protect_frame(&key, context, b"immutable", limits)
        .map_err(|_| "frame protection failed")?;
    for _ in 0..2 {
        let verified = DataProtection::open_frame(&key, context, same_address.as_bytes(), limits)
            .map_err(|_| "legitimate immutable-frame reread failed")?;
        if verified.as_plaintext() != b"immutable" {
            return Err("legitimate immutable-frame reread differed");
        }
    }

    let next_context = context
        .object
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(6))
        .map_err(|_| "next frame context was invalid")?;
    let next = DataProtection::protect_frame(&key, next_context, b"immutable", limits)
        .map_err(|_| "next sequence frame protection failed")?;
    if next.as_bytes() == same_address.as_bytes() {
        return Err("distinct sequences reused one encrypted frame");
    }
    Ok(())
}
