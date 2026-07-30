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
    let file = File::open(path)
        .map_err(|source| XtaskError::io(format!("open {}", path.display()), source))?;
    read_opened(file, path, maximum_bytes, subject)
}

pub(crate) fn read_optional(
    path: &Path,
    maximum_bytes: usize,
    subject: &str,
) -> Result<Option<Vec<u8>>, XtaskError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(XtaskError::io(
                format!("open optional {}", path.display()),
                source,
            ));
        },
    };
    read_opened(file, path, maximum_bytes, subject).map(Some)
}

fn read_opened(
    mut file: File,
    path: &Path,
    maximum_bytes: usize,
    subject: &str,
) -> Result<Vec<u8>, XtaskError> {
    let read_capacity = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| XtaskError::invalid_path(path, "bounded input limit overflows usize"))?;
    let read_limit = u64::try_from(read_capacity)
        .map_err(|_| XtaskError::invalid_path(path, "bounded input limit exceeds u64"))?;
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{read, read_optional};

    #[test]
    fn required_and_optional_reads_enforce_the_exact_source_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "positron-bounded-input-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir(&root)?;
        let required = root.join("required.tsv");
        let optional = root.join("optional.tsv");
        let result = (|| {
            fs::write(&required, [b'x'; 16])?;
            if read(&required, 16, "required registry")?.len() != 16 {
                return Err(std::io::Error::other(
                    "required exact-boundary read changed byte length",
                )
                .into());
            }
            fs::write(&required, [b'x'; 17])?;
            if !read(&required, 16, "required registry")
                .is_err_and(|error| error.to_string().contains("exceeds 16 bytes"))
            {
                return Err(std::io::Error::other(
                    "required max+1 registry did not fail at the source boundary",
                )
                .into());
            }
            if read_optional(&optional, 16, "optional registry")?.is_some() {
                return Err(
                    std::io::Error::other("missing optional registry was not absent").into(),
                );
            }
            fs::write(&optional, [b'x'; 16])?;
            if read_optional(&optional, 16, "optional registry")?
                .is_none_or(|bytes| bytes.len() != 16)
            {
                return Err(std::io::Error::other(
                    "optional exact-boundary read changed byte length",
                )
                .into());
            }
            fs::write(&optional, [b'x'; 17])?;
            if !read_optional(&optional, 16, "optional registry")
                .is_err_and(|error| error.to_string().contains("exceeds 16 bytes"))
            {
                return Err(std::io::Error::other(
                    "optional max+1 registry did not fail at the source boundary",
                )
                .into());
            }
            fs::remove_file(&optional)?;
            fs::create_dir(&optional)?;
            if read_optional(&optional, 16, "optional registry").is_ok() {
                return Err(std::io::Error::other(
                    "optional registry converted a non-NotFound I/O error into absence",
                )
                .into());
            }
            Ok(())
        })();
        fs::remove_dir_all(root)?;
        result
    }
}
