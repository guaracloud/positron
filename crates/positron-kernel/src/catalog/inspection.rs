use std::fs::File;

use super::{CatalogFailure, CatalogSecret, CatalogStorage, InstanceId, recover};

pub(crate) fn inspect_read_only(
    root: &File,
    instance: InstanceId,
    secret: CatalogSecret,
) -> Result<u64, CatalogFailure> {
    let storage = CatalogStorage::inspect(root)?;
    Ok(recover(&storage, &secret, instance)?.current.number())
}
