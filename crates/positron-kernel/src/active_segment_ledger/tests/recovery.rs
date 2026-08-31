use std::error::Error;
use std::fs::{self, File};
use std::num::NonZeroU64;

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use super::support::TemporaryRoot;
use crate::active_segment_ledger::format::{SegmentMetadata, SegmentState};
use crate::active_segment_ledger::recovery::{
    BlockRecoveryFormat, RecoveryMode, publish_frontier, read_blocks, recover, recover_with_mode,
    segment_name,
};
use crate::active_segment_ledger::{
    LedgerFailureCode, MAX_ENCODED_FRAME_BYTES, SegmentId, SegmentRetention, SegmentScope,
    object_context,
};
use crate::data_protection::{DataProtection, FrameLimits, FrameSequence, SegmentFramePurpose};

#[test]
fn recovery_rejects_a_file_shorter_than_its_declared_header() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let directory = File::open(root.path())?;
    let metadata = metadata(CommitPosition::origin());
    fs::write(root.path().join(segment_name(metadata.id)), [])?;
    let key = key(metadata)?;
    let failure = recover(&directory, &directory, metadata, &key, 1, true)
        .err()
        .expect("the segment cannot be shorter than its header");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn observe_recovery_ignores_unfrontiered_bytes_without_repairing_storage()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let directory = File::open(root.path())?;
    let metadata = metadata(CommitPosition::origin());
    fs::write(root.path().join(segment_name(metadata.id)), [0_u8, 1])?;
    let state = recover_with_mode(
        &directory,
        &directory,
        metadata,
        &key(metadata)?,
        1,
        RecoveryMode::Observe,
        false,
    )?;
    assert_eq!(state.frontier, CommitPosition::origin());
    assert!(state.blocks.is_empty());
    assert_eq!(
        fs::read(root.path().join(segment_name(metadata.id)))?,
        [0, 1]
    );
    let repaired = recover(&directory, &directory, metadata, &key(metadata)?, 1, true)?;
    assert!(repaired.blocks.is_empty());
    assert_eq!(
        fs::metadata(root.path().join(segment_name(metadata.id)))?.len(),
        1
    );
    Ok(())
}

#[test]
fn authenticated_but_semantically_inconsistent_frontier_is_rejected() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let directory = File::open(root.path())?;
    let metadata = metadata(CommitPosition::origin());
    fs::write(root.path().join(segment_name(metadata.id)), [])?;
    let key = key(metadata)?;
    publish_frontier(
        &directory,
        metadata.id,
        &key,
        0,
        0,
        CommitPosition::origin().next()?,
        SegmentRetention::Empty,
    )?;
    let failure = recover(&directory, &directory, metadata, &key, 0, true)
        .err()
        .expect("position and sequence must agree");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn block_reader_rejects_oversized_lengths_overflow_and_record_overrun() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let metadata = metadata(CommitPosition::origin());
    let key = key(metadata)?;
    let path = root.path().join("frames");
    fs::write(&path, (MAX_ENCODED_FRAME_BYTES + 1).to_be_bytes())?;
    let failure = read_blocks(
        &mut File::open(&path)?,
        4,
        CommitPosition::origin(),
        metadata.id,
        0,
        &key,
        BlockRecoveryFormat {
            version: 2,
            segment_retention: SegmentRetention::Unavailable,
        },
    )
    .expect_err("oversized record");
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);

    let context = key
        .object
        .frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1))?;
    let frame = DataProtection::protect_frame(
        &key,
        context,
        &identity_payload(0, b"one"),
        FrameLimits::new(MAX_ENCODED_FRAME_BYTES)?,
    )?;
    let mut record = Vec::new();
    record.extend_from_slice(&u32::try_from(frame.as_bytes().len())?.to_be_bytes());
    record.extend_from_slice(frame.as_bytes());
    fs::write(&path, &record)?;
    let failure = read_blocks(
        &mut File::open(&path)?,
        u64::try_from(record.len() - 1)?,
        CommitPosition::origin(),
        metadata.id,
        0,
        &key,
        BlockRecoveryFormat {
            version: 2,
            segment_retention: SegmentRetention::Unavailable,
        },
    )
    .expect_err("record cannot overrun frontier bytes");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);

    let maximum =
        CommitPosition::origin().advance_by(NonZeroU64::new(u64::MAX).expect("nonzero"))?;
    let failure = read_blocks(
        &mut File::open(&path)?,
        u64::try_from(record.len())?,
        maximum,
        metadata.id,
        0,
        &key,
        BlockRecoveryFormat {
            version: 2,
            segment_retention: SegmentRetention::Unavailable,
        },
    )
    .expect_err("commit position cannot wrap");
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    Ok(())
}

#[test]
fn frontier_publication_rejects_an_unremovable_temporary_path() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let directory = File::open(root.path())?;
    let metadata = metadata(CommitPosition::origin());
    let temporary = format!(
        "{}.frontier.tmp",
        crate::active_segment_ledger::io::hex(metadata.id.to_bytes())
    );
    fs::create_dir(root.path().join(temporary))?;
    let failure = publish_frontier(
        &directory,
        metadata.id,
        &key(metadata)?,
        0,
        0,
        CommitPosition::origin(),
        SegmentRetention::Empty,
    )
    .expect_err("temporary directory cannot be unlinked as a file");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    Ok(())
}

#[test]
fn recovery_maps_missing_segments_and_unsafe_frontiers() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let directory = File::open(root.path())?;
    let metadata = metadata(CommitPosition::origin());
    let key = key(metadata)?;
    let failure = recover(&directory, &directory, metadata, &key, 0, true)
        .err()
        .expect("a catalog segment must have a physical artifact");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);

    fs::write(root.path().join(segment_name(metadata.id)), [])?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "missing-frontier-target",
        root.path()
            .join(crate::active_segment_ledger::recovery::frontier_name(
                metadata.id,
            )),
    )?;
    let failure = recover(&directory, &directory, metadata, &key, 0, true)
        .err()
        .expect("frontier aliases are unavailable storage paths");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    Ok(())
}

#[test]
fn block_reader_enforces_the_bounded_recovery_cardinality() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let metadata = metadata(CommitPosition::origin());
    let key = key(metadata)?;
    let mut encoded = Vec::new();
    for sequence in 0..1_024_u64 {
        let context = key.object.frame(
            SegmentFramePurpose::StoreBlock,
            FrameSequence::new(sequence + 1),
        )?;
        let frame = DataProtection::protect_frame(
            &key,
            context,
            &identity_payload(sequence, b"x"),
            FrameLimits::new(MAX_ENCODED_FRAME_BYTES)?,
        )?;
        encoded.extend_from_slice(&u32::try_from(frame.as_bytes().len())?.to_be_bytes());
        encoded.extend_from_slice(frame.as_bytes());
    }
    encoded.push(0);
    let path = root.path().join("bounded-frames");
    fs::write(&path, &encoded)?;
    let failure = read_blocks(
        &mut File::open(&path)?,
        u64::try_from(encoded.len())?,
        CommitPosition::origin(),
        metadata.id,
        0,
        &key,
        BlockRecoveryFormat {
            version: 2,
            segment_retention: SegmentRetention::Unavailable,
        },
    )
    .expect_err("recovery cannot retain an unbounded block set");
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    Ok(())
}

fn metadata(base_position: CommitPosition) -> SegmentMetadata {
    SegmentMetadata {
        scope: SegmentScope::new(
            TenantId::from_bytes([0x43; 16]).expect("fixed tenant"),
            SignalKind::Logs,
            VirtualShardId::new(1).expect("fixed shard"),
        ),
        id: SegmentId::new([0x84; 16]).expect("fixed segment"),
        state: SegmentState::Active,
        base_position,
    }
}

fn key(metadata: SegmentMetadata) -> Result<crate::data_protection::ObjectDataKey, Box<dyn Error>> {
    Ok(DataProtection::random_key(object_context(
        metadata.scope,
        metadata.id,
    )?)?)
}

fn identity_payload(sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes[8..16].copy_from_slice(&sequence.saturating_add(1).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
