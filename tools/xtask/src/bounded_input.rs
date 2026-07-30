//! Shared fail-closed reader for repository-controlled external inputs.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::XtaskError;

pub(crate) fn read(
    path: &Path,
    maximum_bytes: usize,
    subject: &str,
) -> Result<Vec<u8>, XtaskError> {
    let read_capacity = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| XtaskError::invalid_path(path, "bounded input limit overflows usize"))?;
    let read_limit = u64::try_from(read_capacity)
        .map_err(|_| XtaskError::invalid_path(path, "bounded input limit exceeds u64"))?;
    let mut file = File::open(path)
        .map_err(|source| XtaskError::io(format!("open {}", path.display()), source))?;
    let mut bytes = Vec::with_capacity(read_capacity);
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| XtaskError::io(format!("bounded read {}", path.display()), source))?;
    if bytes.len() > maximum_bytes {
        return Err(XtaskError::invalid_path(
            path,
            format!("{subject} exceeds {maximum_bytes} bytes"),
        ));
    }
    Ok(bytes)
}
