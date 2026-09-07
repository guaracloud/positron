use crate::{ScanCancellation, ScanObserver};
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

use super::TraceStoreFailure;

const MINIMUM_BUCKETS: usize = 8;

#[derive(Clone, Copy)]
struct Bucket {
    trace_id: [u8; 16],
    slot: usize,
}

pub(super) enum Lookup {
    Present(usize),
    Vacant(usize),
}

/// Stable-slot trace lookup with a bounded load factor and no tombstones.
pub(super) struct SummaryIndex {
    buckets: Vec<Option<Bucket>>,
    entries: usize,
    hasher: RandomState,
}

impl SummaryIndex {
    pub(super) fn new() -> Self {
        Self {
            buckets: Vec::new(),
            entries: 0,
            hasher: RandomState::new(),
        }
    }

    pub(super) fn retained_bytes(&self) -> Result<u64, TraceStoreFailure> {
        u64::try_from(self.buckets.capacity())
            .ok()
            .zip(u64::try_from(std::mem::size_of::<Option<Bucket>>()).ok())
            .and_then(|(count, bytes)| count.checked_mul(bytes))
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    }

    /// The additional retained bytes needed before an absent trace can be added.
    pub(super) fn growth_bytes_for_insert(&self) -> Result<Option<u64>, TraceStoreFailure> {
        if !self.needs_growth_for_insert()? {
            return Ok(None);
        }
        u64::try_from(self.next_capacity()?)
            .ok()
            .zip(u64::try_from(std::mem::size_of::<Option<Bucket>>()).ok())
            .and_then(|(count, bytes)| count.checked_mul(bytes))
            .map(Some)
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    }

    /// Looks up an already committed trace without consuming maintenance work.
    pub(super) fn slot(&self, trace_id: [u8; 16]) -> Option<usize> {
        let mask = self.buckets.len().checked_sub(1)?;
        let mut bucket = self.bucket_for(trace_id, mask);
        for _ in 0..self.buckets.len() {
            match self.buckets.get(bucket)? {
                Some(entry) if entry.trace_id == trace_id => return Some(entry.slot),
                Some(_) => bucket = bucket.checked_add(1)? & mask,
                None => return None,
            }
        }
        None
    }

    pub(super) fn lookup_observed(
        &self,
        trace_id: [u8; 16],
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<Lookup, TraceStoreFailure> {
        let Some(mask) = self.buckets.len().checked_sub(1) else {
            return Ok(Lookup::Vacant(0));
        };
        let mut bucket = self.bucket_for(trace_id, mask);
        for _ in 0..self.buckets.len() {
            observe(cancellation, observer)?;
            match self
                .buckets
                .get(bucket)
                .ok_or_else(TraceStoreFailure::invalid_input)?
            {
                Some(entry) if entry.trace_id == trace_id => {
                    return Ok(Lookup::Present(entry.slot));
                },
                Some(_) => {
                    bucket = bucket
                        .checked_add(1)
                        .map(|value| value & mask)
                        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
                },
                None => return Ok(Lookup::Vacant(bucket)),
            }
        }
        Err(TraceStoreFailure::limit_exceeded())
    }

    pub(super) fn needs_growth_for_insert(&self) -> Result<bool, TraceStoreFailure> {
        let next = self
            .entries
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        if self.buckets.is_empty() {
            return Ok(true);
        }
        next.checked_mul(2)
            .map(|doubled| doubled > self.buckets.len())
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    }

    pub(super) fn staged_with_insert(
        &self,
        trace_id: [u8; 16],
        slot: usize,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<Self, TraceStoreFailure> {
        let capacity = self.next_capacity()?;
        let mut buckets = Vec::new();
        buckets
            .try_reserve_exact(capacity)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        buckets.resize_with(capacity, || None);
        let mut staged = Self {
            buckets,
            entries: 0,
            hasher: self.hasher.clone(),
        };
        for entry in self.buckets.iter().flatten() {
            let Lookup::Vacant(bucket) =
                staged.lookup_observed(entry.trace_id, cancellation, observer)?
            else {
                return Err(TraceStoreFailure::invalid_input());
            };
            staged.insert_at(bucket, entry.trace_id, entry.slot)?;
        }
        let Lookup::Vacant(bucket) = staged.lookup_observed(trace_id, cancellation, observer)?
        else {
            return Err(TraceStoreFailure::invalid_input());
        };
        staged.insert_at(bucket, trace_id, slot)?;
        Ok(staged)
    }

    pub(super) fn insert_at(
        &mut self,
        bucket: usize,
        trace_id: [u8; 16],
        slot: usize,
    ) -> Result<(), TraceStoreFailure> {
        let entry = self
            .buckets
            .get_mut(bucket)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        if entry.is_some() {
            return Err(TraceStoreFailure::invalid_input());
        }
        *entry = Some(Bucket { trace_id, slot });
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        Ok(())
    }

    /// Removes the immediately preceding insertion into a bucket that was empty.
    pub(super) fn remove_inserted(
        &mut self,
        bucket: usize,
        trace_id: [u8; 16],
        slot: usize,
    ) -> Result<(), TraceStoreFailure> {
        let entry = self
            .buckets
            .get_mut(bucket)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        if !entry.is_some_and(|entry| entry.trace_id == trace_id && entry.slot == slot) {
            return Err(TraceStoreFailure::invalid_input());
        }
        *entry = None;
        self.entries = self
            .entries
            .checked_sub(1)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        Ok(())
    }

    fn next_capacity(&self) -> Result<usize, TraceStoreFailure> {
        if self.buckets.is_empty() {
            return Ok(MINIMUM_BUCKETS);
        }
        self.buckets
            .len()
            .checked_mul(2)
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    }

    fn bucket_for(&self, trace_id: [u8; 16], mask: usize) -> usize {
        let hash = match usize::try_from(self.hasher.hash_one(trace_id)) {
            Ok(hash) => hash,
            Err(_) => usize::MAX,
        };
        hash & mask
    }
}

fn observe(
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    super::super::scan::check_cancel(cancellation)?;
    observer
        .observe_work(1)
        .map_err(TraceStoreFailure::observation)
}
