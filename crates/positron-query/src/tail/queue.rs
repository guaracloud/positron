use crate::{QueryFailure, QueryFailureCode};

pub(super) struct QueueAccounting(u64);

impl QueueAccounting {
    pub(super) const fn new() -> Self {
        Self(0)
    }

    pub(super) fn add(&mut self, amount: u64) -> Result<(), QueryFailure> {
        self.0 = self
            .0
            .checked_add(amount)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        Ok(())
    }

    pub(super) fn release(&mut self, amount: u64) -> Result<(), QueryFailure> {
        self.0 = self
            .0
            .checked_sub(amount)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        Ok(())
    }

    pub(super) fn take(&mut self) -> u64 {
        std::mem::take(&mut self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounting_adds_releases_and_takes_once() {
        let mut accounting = QueueAccounting::new();
        accounting.add(8).expect("queue bytes fit");
        accounting.release(3).expect("released bytes were reserved");
        assert_eq!(accounting.take(), 5);
        assert_eq!(accounting.take(), 0);
    }

    #[test]
    fn accounting_maps_overflow_and_underflow_to_typed_failures() {
        let mut accounting = QueueAccounting(u64::MAX);
        assert_eq!(
            accounting
                .add(1)
                .expect_err("overflow must be rejected")
                .code(),
            QueryFailureCode::ResourceExhausted
        );
        assert_eq!(
            accounting
                .release(u64::MAX)
                .expect("full accounting can be released"),
            ()
        );
        assert_eq!(
            accounting
                .release(1)
                .expect_err("release without reservation is internal")
                .code(),
            QueryFailureCode::Internal
        );
    }
}
