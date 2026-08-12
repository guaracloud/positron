use super::*;

#[test]
fn committed_empty_frame_fuzz_seed_authenticates() -> Result<(), &'static str> {
    const SEED: &[u8; 68] =
        include_bytes!("../../../../../fuzz/corpus/encrypted_frame_open/valid_empty_frame");

    let tenant = TenantId::from_bytes([0x11; 16]).map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(1).map_err(|_| "shard fixture was invalid")?;
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        FrameObjectId::new([0x22; 16]).map_err(|_| "object fixture was invalid")?,
        KeyEpoch::new(1),
        FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?,
    );
    let context = object
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1))
        .map_err(|_| "frame context fixture was invalid")?;
    let key = ObjectDataKey::import(SecretKeyInput::from_test_bytes([0x33; 32]), object);
    let limits = FrameLimits::new(2048).map_err(|_| "frame limit fixture was invalid")?;
    let verified = DataProtection::open_frame(&key, context, SEED, limits)
        .map_err(|_| "committed fuzz seed did not authenticate")?;
    if !verified.as_plaintext().is_empty() {
        return Err("committed fuzz seed was not an empty frame");
    }
    Ok(())
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
        SecretKeyInput::from_test_bytes([
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
fn every_persistent_kind_matches_its_canonical_frame_v1_vector() -> Result<(), &'static str> {
    use std::fmt::Write as _;

    use super::{
        DataProtection, FormatEpoch, FrameLimits, FrameObjectContext, FrameObjectId, FrameSequence,
        KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose, SystemObjectKind,
    };

    enum Kind {
        Segment(SegmentFramePurpose),
        System(SystemObjectKind),
    }

    struct Vector {
        name: &'static str,
        kind: Kind,
        key_start: u8,
        object_byte: u8,
        epoch: u64,
        sequence: u64,
        plaintext: &'static [u8],
        expected_hex: &'static str,
    }

    // Independently derived with Node.js v24.18.0/OpenSSL 3.5.7 from the
    // documented frame-v1 byte contract. Rust neither generates nor rewrites
    // these canonical literal artifact bytes.
    let vectors = [
        Vector {
            name: "Store Block",
            kind: Kind::Segment(SegmentFramePurpose::StoreBlock),
            key_start: 0x00,
            object_byte: 0x11,
            epoch: 1,
            sequence: 9,
            plaintext: b"vector-store-block",
            expected_hex: "5046524d00010001000000000000000900000022a403669d4597029d8087f82bc6493a25dc5620cfbba1d8cf65ca4ee01cf36447ed4acd4b287f81271ba755e7f2bda4eeed16cf5a2dcef4523401d0ec0f2154c5ce16",
        },
        Vector {
            name: "index",
            kind: Kind::Segment(SegmentFramePurpose::Index),
            key_start: 0x20,
            object_byte: 0x12,
            epoch: 2,
            sequence: 10,
            plaintext: b"vector-index",
            expected_hex: "5046524d00010001000000000000000a0000001c9bfd549a59cf0a1251a12c42918197e43c6d60ad90ee797fb2d7675dc60a04956b13f09792d8e204d43900479ce4fb81532c296d9ba17a2993faccf4",
        },
        Vector {
            name: "statistics",
            kind: Kind::Segment(SegmentFramePurpose::Statistics),
            key_start: 0x40,
            object_byte: 0x13,
            epoch: 3,
            sequence: 11,
            plaintext: b"vector-statistics",
            expected_hex: "5046524d00010001000000000000000b00000021d345b190646caa6825cb599b122de061c01ca4f2f81528232973f21b85b9b06e290c2e04458baf4a3fc3e8e40723073f08eac06daf811044421ccff9f1f19e3165",
        },
        Vector {
            name: "segment metadata",
            kind: Kind::Segment(SegmentFramePurpose::SegmentMetadata),
            key_start: 0x60,
            object_byte: 0x14,
            epoch: 4,
            sequence: 12,
            plaintext: b"vector-segment-metadata",
            expected_hex: "5046524d00010001000000000000000c00000027df32274d622e796fe8f1f41989cde24c9222eb5b75b9152acf03c83cbb6c1bb9858a80aae2ec03206962699f692d2eb39fc4b5ffb9e02f955e86bb6c62d50d60104f03abe8eeba",
        },
        Vector {
            name: "Catalog Object",
            kind: Kind::System(SystemObjectKind::Catalog),
            key_start: 0x80,
            object_byte: 0x15,
            epoch: 5,
            sequence: 13,
            plaintext: b"vector-catalog",
            expected_hex: "5046524d00010001000000000000000d0000001e272e819858de01eab4bdade940513883ed9343e9897fc49f091ec8ddaa987de5638808974c365ea999b6561aebbbf8ccff68d3777e153ccef79713546c34",
        },
        Vector {
            name: "manifest",
            kind: Kind::System(SystemObjectKind::Manifest),
            key_start: 0xa0,
            object_byte: 0x16,
            epoch: 6,
            sequence: 14,
            plaintext: b"vector-manifest",
            expected_hex: "5046524d00010001000000000000000e0000001f67d873748112363aededaf2034aa1ea6a6384717e57ce309e35bcd1a5db0f618d6bab9f9159b2b47ddc6393e334ee7eda1814e2947497e78ef9cc62e17ed2d",
        },
        Vector {
            name: "Governance Audit",
            kind: Kind::System(SystemObjectKind::GovernanceAudit),
            key_start: 0xc0,
            object_byte: 0x17,
            epoch: 7,
            sequence: 15,
            plaintext: b"vector-governance-audit",
            expected_hex: "5046524d00010001000000000000000f0000002798278309bb6b9d284a5b307fe603d0252ca7eabd70d25f702c496eec55260186a5059b52c2f5d9381725d1cdfcbce67f7f20ed62d019311eeb096be5ed504abc6d7877c0e2c00b",
        },
        Vector {
            name: "backup metadata",
            kind: Kind::System(SystemObjectKind::BackupMetadata),
            key_start: 0xe0,
            object_byte: 0x18,
            epoch: 8,
            sequence: 16,
            plaintext: b"vector-backup-metadata",
            expected_hex: "5046524d000100010000000000000010000000264649c1603c6091322f47e6b06b76958790ca4e4469d8eaf64a8f0c723dc9f4fe7d25d0afe5b735f000814cf755ed155c6040afe4c651acb39c6c47eea8437e6a92923c8a6f6d",
        },
    ];
    let tenant = TenantId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        .map_err(|_| "tenant fixture was invalid")?;
    let shard = VirtualShardId::new(7).map_err(|_| "shard fixture was invalid")?;
    let format_epoch = FormatEpoch::new(1).map_err(|_| "format epoch fixture was invalid")?;
    let limits = FrameLimits::new(1024).map_err(|_| "frame fixture limit was invalid")?;

    for vector in vectors {
        let mut key_bytes = [0_u8; 32];
        for (offset, destination) in key_bytes.iter_mut().enumerate() {
            let offset = u8::try_from(offset).map_err(|_| "key offset exceeded one byte")?;
            *destination = vector
                .key_start
                .checked_add(offset)
                .ok_or("vector key fixture overflowed")?;
        }
        let object_id = FrameObjectId::new([vector.object_byte; 16])
            .map_err(|_| "vector object fixture was invalid")?;
        let (object, context) = match vector.kind {
            Kind::Segment(purpose) => {
                let object = FrameObjectContext::tenant_segment(
                    tenant,
                    SignalKind::Logs,
                    shard,
                    object_id,
                    KeyEpoch::new(vector.epoch),
                    format_epoch,
                );
                let context = object
                    .frame(purpose, FrameSequence::new(vector.sequence))
                    .map_err(|_| "segment vector context was invalid")?;
                (object, context)
            },
            Kind::System(kind) => {
                let object = FrameObjectContext::system(
                    kind,
                    object_id,
                    KeyEpoch::new(vector.epoch),
                    format_epoch,
                );
                let context = object
                    .system_frame(FrameSequence::new(vector.sequence))
                    .map_err(|_| "system vector context was invalid")?;
                (object, context)
            },
        };
        let key = ObjectDataKey::import(SecretKeyInput::from_test_bytes(key_bytes), object);
        let frame = DataProtection::protect_frame(&key, context, vector.plaintext, limits)
            .map_err(|_| "canonical vector protection failed")?;
        let mut actual_hex = String::with_capacity(frame.as_bytes().len() * 2);
        for byte in frame.as_bytes() {
            write!(&mut actual_hex, "{byte:02x}").map_err(|_| "hex formatting failed")?;
        }
        if actual_hex != vector.expected_hex {
            return Err(vector.name);
        }
    }
    Ok(())
}
