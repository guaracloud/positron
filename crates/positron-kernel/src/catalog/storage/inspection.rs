use std::fs::File;

use super::io::open_existing_directory;
use super::{CatalogFailure, CatalogStorage};

impl CatalogStorage {
    pub(crate) fn inspect(root: &File) -> Result<Self, CatalogFailure> {
        let catalog = open_existing_directory(root, "catalog")?;
        Ok(Self {
            objects: open_existing_directory(&catalog, "objects")?,
            audit: open_existing_directory(&catalog, "governance-audit")?,
            audit_checkpoints: open_existing_directory(&catalog, "governance-audit-checkpoints")?,
            commits: open_existing_directory(&catalog, "commits")?,
            generations: open_existing_directory(&catalog, "generations")?,
            staging: open_existing_directory(&catalog, "staging")?,
            _catalog: catalog,
        })
    }
}
