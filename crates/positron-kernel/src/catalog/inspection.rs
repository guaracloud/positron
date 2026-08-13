use std::fs::File;

use super::{
    CatalogFailure, CatalogObjectId, CatalogSecret, CatalogSnapshot, CatalogStorage, InstanceId,
    recover,
};

impl CatalogSnapshot {
    /// Returns the bounded identities reachable from this immutable generation.
    ///
    /// Semantic owners use these identities with [`Self::object`] to rebuild
    /// their generation-pinned read views. Mutation remains exclusive to the
    /// Catalog Writer.
    pub fn object_identities(&self) -> impl Iterator<Item = CatalogObjectId> + '_ {
        self.0.objects.keys().copied()
    }
}

pub(crate) fn inspect_read_only(
    root: &File,
    instance: InstanceId,
    secret: CatalogSecret,
) -> Result<u64, CatalogFailure> {
    let storage = CatalogStorage::inspect(root)?;
    Ok(recover(&storage, &secret, instance)?.current.number())
}
