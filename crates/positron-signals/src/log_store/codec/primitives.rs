use crate::log_store::LogStoreFailure;

pub(super) fn put_count(output: &mut Vec<u8>, value: usize) -> Result<(), LogStoreFailure> {
    put_u16(
        output,
        u16::try_from(value).map_err(|_| LogStoreFailure::limit_exceeded())?,
    );
    Ok(())
}

pub(super) fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn put_i32(output: &mut Vec<u8>, value: i32) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), LogStoreFailure> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| LogStoreFailure::limit_exceeded())?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

pub(super) struct Input<'a> {
    remaining: &'a [u8],
    observer: Option<&'a dyn crate::log_store::ScanObserver>,
}

impl<'a> Input<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            observer: None,
        }
    }

    pub(super) const fn observed(
        bytes: &'a [u8],
        observer: &'a dyn crate::log_store::ScanObserver,
    ) -> Self {
        Self {
            remaining: bytes,
            observer: Some(observer),
        }
    }

    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8], LogStoreFailure> {
        if let Some(observer) = self.observer {
            let units = u64::try_from(count)
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or_else(LogStoreFailure::malformed_block)?;
            observer
                .observe_work(units)
                .map_err(LogStoreFailure::observation)?;
        }
        let (value, remaining) = self
            .remaining
            .split_at_checked(count)
            .ok_or_else(LogStoreFailure::malformed_block)?;
        self.remaining = remaining;
        Ok(value)
    }

    pub(super) fn u8(&mut self) -> Result<u8, LogStoreFailure> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(LogStoreFailure::malformed_block)
    }

    pub(super) fn u16(&mut self) -> Result<u16, LogStoreFailure> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32, LogStoreFailure> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn i32(&mut self) -> Result<i32, LogStoreFailure> {
        Ok(i32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, LogStoreFailure> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn i64(&mut self) -> Result<i64, LogStoreFailure> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], LogStoreFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| LogStoreFailure::malformed_block())
    }

    pub(super) fn count(&mut self, maximum: usize) -> Result<usize, LogStoreFailure> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(LogStoreFailure::malformed_block());
        }
        Ok(count)
    }

    pub(super) fn bytes_slice(&mut self, maximum: usize) -> Result<&'a [u8], LogStoreFailure> {
        let count = usize::try_from(self.u32()?).map_err(|_| LogStoreFailure::malformed_block())?;
        if count > maximum {
            return Err(LogStoreFailure::malformed_block());
        }
        self.take(count)
    }

    pub(super) fn string_slice(&mut self, maximum: usize) -> Result<&'a str, LogStoreFailure> {
        std::str::from_utf8(self.bytes_slice(maximum)?)
            .map_err(|_| LogStoreFailure::malformed_block())
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
