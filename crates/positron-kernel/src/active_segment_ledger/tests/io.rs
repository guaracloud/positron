use std::error::Error;
use std::fs::File;

use super::support::TemporaryRoot;
use crate::active_segment_ledger::LedgerFailureCode;
use crate::active_segment_ledger::io::{open_or_create_directory, open_regular};

#[test]
fn directory_creation_and_regular_open_map_filesystem_failures() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let directory = File::open(root.path())?;
    let overlong_name = "x".repeat(1_025);

    let failure = open_or_create_directory(&directory, &overlong_name)
        .expect_err("an overlong component cannot be created");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);

    let failure =
        open_regular(&directory, "missing", false).expect_err("a required file cannot be absent");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);

    let failure = open_regular(&directory, &overlong_name, false)
        .expect_err("an invalid component is an unavailable storage path");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    Ok(())
}
