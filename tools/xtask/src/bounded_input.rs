//! Shared fail-closed reader for repository-controlled external inputs.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::XtaskError;

const MAXIMUM_EXTERNAL_INPUT_COUNT: usize = 64;
const MAXIMUM_EXTERNAL_INPUT_BYTES: usize = 262_144;

pub(crate) struct ExternalInputBudget {
    count: usize,
    bytes: usize,
    declared: Option<(usize, usize)>,
}

impl ExternalInputBudget {
    pub(crate) const fn new() -> Self {
        Self {
            count: 0,
            bytes: 0,
            declared: None,
        }
    }

    pub(crate) fn apply_declared_limits(
        &mut self,
        maximum_count: usize,
        maximum_bytes: usize,
    ) -> Result<(), XtaskError> {
        if maximum_count == 0
            || maximum_count > MAXIMUM_EXTERNAL_INPUT_COUNT
            || maximum_bytes == 0
            || maximum_bytes > MAXIMUM_EXTERNAL_INPUT_BYTES
        {
            return Err(XtaskError::invalid(
                "M0-10 external input budget",
                "declared external input limits are zero or exceed the hard safety ceiling",
            ));
        }
        if self
            .declared
            .is_some_and(|declared| declared != (maximum_count, maximum_bytes))
        {
            return Err(XtaskError::invalid(
                "M0-10 external input budget",
                "declared external input limits changed during one quality attempt",
            ));
        }
        self.declared = Some((maximum_count, maximum_bytes));
        self.enforce()
    }

    pub(crate) fn charge(&mut self, bytes: usize) -> Result<(), XtaskError> {
        self.count = self.count.checked_add(1).ok_or_else(|| {
            XtaskError::invalid("M0-10 external input budget", "input count overflowed")
        })?;
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(|| {
            XtaskError::invalid(
                "M0-10 external input budget",
                "aggregate input bytes overflowed",
            )
        })?;
        self.enforce()
    }

    pub(crate) fn summary(&self) -> Result<String, XtaskError> {
        let Some((maximum_count, maximum_bytes)) = self.declared else {
            return Err(XtaskError::invalid(
                "M0-10 external input budget",
                "PC-0015 did not declare attempt-wide external input limits",
            ));
        };
        Ok(format!(
            "external-input-count={}; external-input-aggregate-bytes={}; external-input-maximum-count={maximum_count}; external-input-maximum-aggregate-bytes={maximum_bytes}",
            self.count, self.bytes,
        ))
    }

    fn enforce(&self) -> Result<(), XtaskError> {
        let (maximum_count, maximum_bytes) = self
            .declared
            .unwrap_or((MAXIMUM_EXTERNAL_INPUT_COUNT, MAXIMUM_EXTERNAL_INPUT_BYTES));
        if self.count > maximum_count {
            return Err(XtaskError::invalid(
                "M0-10 external input budget",
                format!("external input count exceeds {maximum_count}"),
            ));
        }
        if self.bytes > maximum_bytes {
            return Err(XtaskError::invalid(
                "M0-10 external input budget",
                format!("external input aggregate exceeds {maximum_bytes} bytes"),
            ));
        }
        Ok(())
    }
}

pub(crate) fn read_external(
    path: &Path,
    maximum_bytes: usize,
    subject: &str,
    budget: &mut ExternalInputBudget,
) -> Result<Vec<u8>, XtaskError> {
    let bytes = read(path, maximum_bytes, subject)?;
    budget.charge(bytes.len())?;
    Ok(bytes)
}

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
