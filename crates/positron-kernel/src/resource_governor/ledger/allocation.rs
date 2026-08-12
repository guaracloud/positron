use std::sync::atomic::{AtomicU8, AtomicU64};

use super::{GrantRecord, SLOT_FREE};
use crate::resource_governor::bootstrap::{
    BootstrapAllocationStage, BootstrapInventoryLayout, allocate_exact, into_boxed_exact,
};
use crate::resource_governor::{GovernorFailure, ResourceAmounts};

pub(in crate::resource_governor) struct LedgerAllocation {
    pub(in crate::resource_governor) signals: Box<[AtomicU8]>,
    pub(in crate::resource_governor) pending_words: Box<[AtomicU64]>,
    pub(in crate::resource_governor) records: Box<[Option<GrantRecord>]>,
    pub(in crate::resource_governor) free_slots: Vec<u16>,
}

pub(in crate::resource_governor) fn allocate(
    layout: BootstrapInventoryLayout,
    required: ResourceAmounts,
    fail_at: Option<BootstrapAllocationStage>,
) -> Result<LedgerAllocation, GovernorFailure> {
    let count = layout.outstanding_count();
    let words = layout.pending_word_count();
    let mut signals = allocate_exact(
        count,
        required,
        BootstrapAllocationStage::LedgerSignals,
        fail_at,
    )?;
    signals.resize_with(count, || AtomicU8::new(SLOT_FREE));
    let mut pending_words = allocate_exact(
        words,
        required,
        BootstrapAllocationStage::LedgerPendingWords,
        fail_at,
    )?;
    pending_words.resize_with(words, || AtomicU64::new(0));
    let mut records = allocate_exact(
        count,
        required,
        BootstrapAllocationStage::LedgerRecords,
        fail_at,
    )?;
    records.resize(count, None);
    let mut free_slots = allocate_exact(
        count,
        required,
        BootstrapAllocationStage::LedgerFreeSlots,
        fail_at,
    )?;
    for index in (0..count).rev() {
        free_slots.push(u16::try_from(index).map_err(|_| GovernorFailure::InvalidConfiguration)?);
    }
    Ok(LedgerAllocation {
        signals: into_boxed_exact(signals, required)?,
        pending_words: into_boxed_exact(pending_words, required)?,
        records: into_boxed_exact(records, required)?,
        free_slots,
    })
}
