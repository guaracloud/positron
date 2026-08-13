use super::*;

#[test]
fn object_authenticator_verifies_only_the_exact_evidence() -> Result<(), &'static str> {
    use super::{
        DataProtection, FormatEpoch, FrameFailureCode, FrameObjectContext, FrameObjectId, KeyEpoch,
        ObjectDataKey, SecretKeyInput,
    };

    let object = FrameObjectContext::tenant_segment(
        TenantId::from_bytes([0x11; 16]).map_err(|_| "invalid tenant")?,
        SignalKind::Logs,
        VirtualShardId::new(1).map_err(|_| "invalid shard")?,
        FrameObjectId::new([0x12; 16]).map_err(|_| "invalid object")?,
        KeyEpoch::new(1),
        FormatEpoch::new(1).map_err(|_| "invalid format")?,
    );
    let key = ObjectDataKey::import(SecretKeyInput::from_test_bytes([0x13; 32]), object);
    let authenticator = DataProtection::authenticate_object_key(&key, b"receipt-evidence")
        .map_err(|_| "authentication failed")?;
    DataProtection::verify_object_authentication(&key, b"receipt-evidence", &authenticator)
        .map_err(|_| "exact evidence did not verify")?;
    let failure = DataProtection::verify_object_authentication(
        &key,
        b"different-receipt-evidence",
        &authenticator,
    )
    .expect_err("different evidence must not verify");
    if failure.code() == FrameFailureCode::AuthenticationFailed {
        Ok(())
    } else {
        Err("wrong authenticator failure classification")
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
    let correct_key = ObjectDataKey::import(SecretKeyInput::from_test_bytes([0x41; 32]), object);
    let wrong_key = ObjectDataKey::import(SecretKeyInput::from_test_bytes([0x42; 32]), object);
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
fn frame_open_rejects_a_key_bound_to_a_different_object_before_parsing() -> Result<(), &'static str>
{
    use super::{
        DataProtection, FormatEpoch, FrameFailureCode, FrameLimits, FrameObjectContext,
        FrameObjectId, FrameSequence, KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose,
    };

    let tenant = TenantId::from_bytes([0x25; 16]).map_err(|_| "invalid tenant")?;
    let shard = VirtualShardId::new(2).map_err(|_| "invalid shard")?;
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        FrameObjectId::new([0x35; 16]).map_err(|_| "invalid object")?,
        KeyEpoch::new(1),
        FormatEpoch::new(1).map_err(|_| "invalid format")?,
    );
    let other = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        FrameObjectId::new([0x36; 16]).map_err(|_| "invalid other object")?,
        KeyEpoch::new(1),
        FormatEpoch::new(1).map_err(|_| "invalid format")?,
    );
    let key = ObjectDataKey::import(SecretKeyInput::from_test_bytes([0x45; 32]), object);
    let expected = other
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(0))
        .map_err(|_| "invalid frame context")?;
    let failure = DataProtection::open_frame(
        &key,
        expected,
        b"not-even-a-frame",
        FrameLimits::new(256).map_err(|_| "invalid limits")?,
    )
    .expect_err("object mismatch must be rejected before parsing");
    if failure.code() == FrameFailureCode::AuthenticationFailed {
        Ok(())
    } else {
        Err("object mismatch was misclassified")
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
    let authentic_key = ObjectDataKey::import(
        SecretKeyInput::from_test_bytes([0x71; 32]),
        authentic_object,
    );
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
        let substituted_key =
            ObjectDataKey::import(SecretKeyInput::from_test_bytes([0x71; 32]), object);
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
        let key =
            ObjectDataKey::import(SecretKeyInput::from_test_bytes([identity_byte; 32]), object);
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
        let key =
            ObjectDataKey::import(SecretKeyInput::from_test_bytes([identity_byte; 32]), object);
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
