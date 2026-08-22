use super::super::SchemaBudget;
use super::super::catalog::SchemaCatalog;
use super::super::failure::SchemaFailure;
use super::super::index::{
    BLOCK_INDEX_HEADER_BYTES, INDEX_HEADER_BYTES, ScalarIndexFraming, SchemaBlockIndex,
    TextIndexFraming,
};
use super::super::text_index::TextBlockSummary;
use super::SchemaDelta;
use super::accounting::{projected_cost, staged_memory_bytes};
use crate::log_store::{ScanObservationFailureCode, ScanObserver};

impl SchemaDelta {
    pub(crate) fn into_block_index(
        self,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
    ) -> (Self, Option<SchemaBlockIndex>) {
        if self.index_paths.is_empty() && self.text_summary.is_none() {
            return (self, None);
        }
        let mut delta = self;
        let paths = std::mem::take(&mut delta.index_paths);
        let text_summary = delta.text_summary.take();
        let text_framing = if text_summary.is_some() {
            TextIndexFraming::V1
        } else {
            TextIndexFraming::LegacyV2
        };
        (
            delta,
            Some(SchemaBlockIndex {
                identity,
                digest,
                paths,
                scalar_framing: ScalarIndexFraming::V2,
                text_framing,
                text_summary,
            }),
        )
    }

    pub(crate) fn attach_text_summary(
        &mut self,
        catalog: &SchemaCatalog,
        summary: TextBlockSummary,
    ) -> Result<(), SchemaFailure> {
        self.attach_text_summary_inner(catalog, summary, None)
            .map_err(|failure| match failure {
                TextSummaryAttachFailure::Schema(failure) => failure,
                TextSummaryAttachFailure::Observation(_) => SchemaFailure::AllocationUnavailable,
            })
    }

    pub(crate) fn attach_text_summary_observed(
        &mut self,
        catalog: &SchemaCatalog,
        summary: TextBlockSummary,
        observer: &dyn ScanObserver,
    ) -> Result<(), crate::log_store::LogStoreFailure> {
        self.attach_text_summary_inner(catalog, summary, Some(observer))
            .map_err(|failure| match failure {
                TextSummaryAttachFailure::Schema(failure) => {
                    crate::log_store::map_schema_failure(failure)
                },
                TextSummaryAttachFailure::Observation(failure) => {
                    crate::log_store::LogStoreFailure::observation(failure)
                },
            })
    }

    fn attach_text_summary_inner(
        &mut self,
        catalog: &SchemaCatalog,
        summary: TextBlockSummary,
        observer: Option<&dyn ScanObserver>,
    ) -> Result<(), TextSummaryAttachFailure> {
        if !self.build_physical_index || self.text_summary.is_some() {
            return Ok(());
        }
        let summary_memory = summary
            .memory_bytes()
            .map_err(TextSummaryAttachFailure::Schema)?;
        let summary_wire = summary
            .encoded_bytes()?
            .checked_add(1)
            .ok_or(SchemaFailure::LimitExceeded)
            .map_err(TextSummaryAttachFailure::Schema)?;
        if let Some(observer) = observer {
            let units = summary
                .trigrams()
                .len()
                .checked_add(super::super::text_builder::WORK_QUANTUM_OPERATIONS - 1)
                .ok_or(SchemaFailure::LimitExceeded)
                .map_err(TextSummaryAttachFailure::Schema)?
                / super::super::text_builder::WORK_QUANTUM_OPERATIONS;
            if units > 0 {
                observer
                    .observe_work(u64::try_from(units).map_err(|_| {
                        TextSummaryAttachFailure::Schema(SchemaFailure::LimitExceeded)
                    })?)
                    .map_err(TextSummaryAttachFailure::Observation)?;
            }
        }
        let old_memory = self.physical_memory_bytes;
        let old_wire = self.physical_index_bytes;
        self.physical_memory_bytes = self
            .physical_memory_bytes
            .checked_add(summary_memory)
            .and_then(|bytes| {
                if self.index_paths.is_empty() {
                    bytes.checked_add(SchemaBudget::block_index_memory_bytes())
                } else {
                    Some(bytes)
                }
            })
            .ok_or(SchemaFailure::LimitExceeded)?;
        self.physical_index_bytes = self
            .physical_index_bytes
            .checked_add(summary_wire)
            .and_then(|bytes| bytes.checked_add(TextIndexFraming::V1.encoded_bytes()))
            .and_then(|bytes| {
                if self.index_paths.is_empty() {
                    bytes
                        .checked_add(ScalarIndexFraming::V2.encoded_bytes())
                        .and_then(|value| value.checked_add(BLOCK_INDEX_HEADER_BYTES))
                } else {
                    Some(bytes)
                }
            })
            .and_then(|bytes| {
                if self.index_paths.is_empty() && catalog.block_indexes.is_empty() {
                    bytes.checked_add(INDEX_HEADER_BYTES)
                } else {
                    Some(bytes)
                }
            })
            .ok_or(SchemaFailure::LimitExceeded)?;
        let (memory, persistent, index, _) = projected_cost(catalog, self, None)?;
        let text_version_upgrade = catalog
            .block_indexes
            .iter()
            .filter(|block| block.text_framing == TextIndexFraming::LegacyV2)
            .count()
            .checked_mul(TextIndexFraming::V1.encoded_bytes())
            .ok_or(SchemaFailure::LimitExceeded)?;
        let fits = catalog
            .memory_bytes
            .checked_add(memory)
            .is_some_and(|value| value <= catalog.budget.max_memory_bytes())
            && catalog
                .persistent_bytes
                .checked_add(persistent)
                .and_then(|value| value.checked_add(text_version_upgrade))
                .is_some_and(|value| value <= catalog.budget.max_persistent_bytes())
            && catalog
                .index_bytes
                .checked_add(index)
                .and_then(|value| value.checked_add(text_version_upgrade))
                .is_some_and(|value| value <= catalog.budget.max_index_bytes());
        if !fits {
            self.physical_memory_bytes = old_memory;
            self.physical_index_bytes = old_wire;
            return Ok(());
        }
        self.text_summary = Some(summary);
        self.retained_memory_bytes = memory;
        self.persistent_bytes = persistent;
        self.index_bytes = index;
        self.staged_memory_bytes = staged_memory_bytes(self)?;
        Ok(())
    }
}

enum TextSummaryAttachFailure {
    Schema(SchemaFailure),
    Observation(ScanObservationFailureCode),
}

impl From<SchemaFailure> for TextSummaryAttachFailure {
    fn from(failure: SchemaFailure) -> Self {
        Self::Schema(failure)
    }
}
