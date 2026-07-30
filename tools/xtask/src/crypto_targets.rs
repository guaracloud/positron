//! Frozen profile-aware M0-10 cryptographic target selection.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;
use crate::quality::Profile;

const PATH: &str = "qualification/engineering/security-crypto-targets.tsv";
const MAXIMUM_REGISTRY_BYTES: usize = 4_096;
const EXPECTED: &str = "profile\ttarget_id\ttarget_kind\tstate\tcommand\toutcome\tqualification\nPR\txtask-crypto-runner-capability-v1\trunner-capability\tactive\tcargo test --locked --package xtask --bin xtask security_harness::tests::crypto_self_test_covers_the_registered_harness_obligations -- --exact\tExecutedRunnerCapability\tno-product-qualification\nEXT\t-\tproduct-target\tnot-applicable\t-\tNoActiveProductTarget\tno-product-qualification\nQUAL\t-\tproduct-target\tnot-applicable\t-\tNoActiveProductTarget\tno-product-qualification\n";

pub(crate) enum Selection {
    RunnerCapability(String),
    NoActiveProductTarget(String),
}

pub(crate) fn select(root: &Path, profile: Profile) -> Result<Selection, XtaskError> {
    let path = root.join(PATH);
    let bytes = crate::bounded_input::read(
        &path,
        MAXIMUM_REGISTRY_BYTES,
        "profile-aware crypto target registry",
    )?;
    if bytes != EXPECTED.as_bytes() {
        return Err(XtaskError::invalid_path(
            &path,
            "profile-aware crypto target registry is missing, stale, or tampered",
        ));
    }
    let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    if matches!(profile, Profile::Pr) {
        Ok(Selection::RunnerCapability(digest))
    } else {
        Ok(Selection::NoActiveProductTarget(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_and_qualification_profiles_never_reuse_pr_runner_capability() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(matches!(
            select(&root, Profile::Ext),
            Ok(Selection::NoActiveProductTarget(_))
        ));
        assert!(matches!(
            select(&root, Profile::Qual),
            Ok(Selection::NoActiveProductTarget(_))
        ));
    }
}
