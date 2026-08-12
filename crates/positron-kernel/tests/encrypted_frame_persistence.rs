use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    DataProtection, FormatEpoch, FrameLimits, FrameObjectContext, FrameObjectId, FrameSequence,
    KeyEpoch, ObjectDataKey, SecretKeyInput, SegmentFramePurpose,
};

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Result<Self, std::io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "positron-encrypted-frame-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn authenticated_frame_survives_persistent_file_reopen() -> Result<(), Box<dyn Error>> {
    let root = TemporaryDirectory::new()?;
    let path = root.path().join("frame.pfr");
    let tenant = TenantId::from_bytes([0x11; 16])?;
    let shard = VirtualShardId::new(12)?;
    let object = FrameObjectContext::tenant_segment(
        tenant,
        SignalKind::Logs,
        shard,
        FrameObjectId::new([0x22; 16])?,
        KeyEpoch::new(4),
        FormatEpoch::new(1)?,
    );
    let context = object.frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(14))?;
    let key = ObjectDataKey::import(SecretKeyInput::new([0x33; 32]), object);
    let limits = FrameLimits::new(1024)?;
    let plaintext = b"persisted authenticated frame";
    let encrypted = DataProtection::protect_frame(&key, context, plaintext, limits)?;

    let mut output = File::create(&path)?;
    output.write_all(encrypted.as_bytes())?;
    output.sync_all()?;
    drop(output);

    let mut persisted = Vec::new();
    File::open(&path)?.read_to_end(&mut persisted)?;
    assert!(
        !persisted
            .windows(plaintext.len())
            .any(|window| window == plaintext)
    );
    let verified = DataProtection::open_frame(&key, context, &persisted, limits)?;
    assert_eq!(verified.as_plaintext(), plaintext);
    Ok(())
}
