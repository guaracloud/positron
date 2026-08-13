//! Held-directory entry points for bootstrap key custody.

use std::fs::File;

use super::{BootstrapKeyCustody, BootstrapKeyFailure, map_local};
use crate::data_protection::local_key::bootstrap::initialize_local_key;
use crate::data_protection::local_key::persistence::open_existing_local_key_in;
use crate::data_protection::local_key::security_directory::FreshInitializationRootProof;

impl BootstrapKeyCustody {
    pub(crate) fn initialize_in(directory: &File) -> Result<Self, BootstrapKeyFailure> {
        let proof =
            FreshInitializationRootProof::from_open_directory(directory).map_err(map_local)?;
        initialize_local_key(proof)
            .map(|key| Self { key })
            .map_err(map_local)
    }

    pub(crate) fn open_in(directory: &File) -> Result<Self, BootstrapKeyFailure> {
        open_existing_local_key_in(directory)
            .map(|key| Self { key })
            .map_err(map_local)
    }
}
