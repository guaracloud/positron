use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use super::{SLOT_ACTIVE, SLOT_RELEASE_PENDING};

pub(in crate::resource_governor) struct DropLedger {
    pub(in crate::resource_governor) slot_signals: Box<[AtomicU8]>,
    pub(in crate::resource_governor) pending_words: Box<[AtomicU64]>,
    pub(in crate::resource_governor) has_pending_releases: AtomicBool,
    pub(in crate::resource_governor) pending_fence: AtomicBool,
}

impl DropLedger {
    pub(in crate::resource_governor) fn new(
        slot_signals: Box<[AtomicU8]>,
        pending_words: Box<[AtomicU64]>,
    ) -> Self {
        Self {
            slot_signals,
            pending_words,
            has_pending_releases: AtomicBool::new(false),
            pending_fence: AtomicBool::new(false),
        }
    }

    pub(in crate::resource_governor) fn mark_drop_pending(&self, slot: u16) {
        let index = usize::from(slot);
        let Some(signal) = self.slot_signals.get(index) else {
            self.pending_fence.store(true, Ordering::Release);
            return;
        };
        if signal
            .compare_exchange(
                SLOT_ACTIVE,
                SLOT_RELEASE_PENDING,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            self.pending_fence.store(true, Ordering::Release);
            return;
        }
        let word_index = index / 64;
        let bit = 1_u64 << (index % 64);
        let Some(word) = self.pending_words.get(word_index) else {
            self.pending_fence.store(true, Ordering::Release);
            return;
        };
        word.fetch_or(bit, Ordering::Release);
        self.has_pending_releases.store(true, Ordering::Release);
    }

    pub(in crate::resource_governor) fn mark_foreign_release(&self) {
        self.pending_fence.store(true, Ordering::Release);
    }
}
