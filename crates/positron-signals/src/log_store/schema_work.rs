use super::schema::{self, SchemaCatalog, SchemaDelta, SchemaRepresentation};
use super::types::AttributeRepresentation;
use super::{
    LogRecord, LogStoreFailure, LogStoreFailureCode, ScanCancellation, ScanObservationFailureCode,
    ScanObserver, codec, map_schema_failure,
};
use positron_kernel::{CommittedBlock, LedgerSnapshot};

impl super::LogStore {
    /// Stages one complete group's root-atomic schema decisions against an immutable view.
    pub(crate) fn stage_schema_group(
        &self,
        records: &mut [LogRecord],
        schema: &SchemaCatalog,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        self.stage_schema_group_inner(records, schema, None)
    }

    pub(crate) fn stage_schema_group_observed(
        &self,
        records: &mut [LogRecord],
        schema: &SchemaCatalog,
        observer: &dyn ScanObserver,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        self.stage_schema_group_inner(records, schema, Some(observer))
    }

    fn stage_schema_group_inner(
        &self,
        records: &mut [LogRecord],
        schema: &SchemaCatalog,
        observer: Option<&dyn ScanObserver>,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        let mut delta = SchemaDelta::empty(schema.tenant(), true);
        let mut meter = observer.map_or_else(
            schema::delta::DiscoveryMeter::new,
            schema::delta::DiscoveryMeter::observed,
        );
        for record in records.iter_mut() {
            let mut attributes = Vec::new();
            attributes
                .try_reserve_exact(record.attributes().len())
                .map_err(|_| LogStoreFailure::resource_exhausted())?;
            for attribute in record.attributes() {
                attributes.push(attribute.occurrences());
            }
            let representations = schema
                .stage_record_representations(&attributes, &mut delta, &mut meter)
                .map_err(map_schema_failure)?;
            for (attribute, representation) in record
                .attributes_mut()
                .iter_mut()
                .zip(representations.into_representations())
            {
                attribute.set_representation(match representation {
                    SchemaRepresentation::Cataloged => AttributeRepresentation::Generic,
                    SchemaRepresentation::Overflow => AttributeRepresentation::SchemaOverflow,
                });
            }
        }
        let has_schema_overflow = records.iter().any(|record| {
            record.attributes().iter().any(|attribute| {
                attribute.representation() == AttributeRepresentation::SchemaOverflow
            })
        });
        let has_text_body = records
            .iter()
            .any(|record| record.body().and_then(|body| body.as_str()).is_some());
        if has_text_body
            && !has_schema_overflow
            && !delta.has_index_paths()
            && may_add_text_summary(schema, observer)?
            && schema.budget().max_index_bytes() >= schema::MIN_TEXT_INDEX_BUDGET_BYTES
        {
            let bodies = records
                .iter()
                .map(|record| record.body().and_then(|body| body.as_str()));
            match observer {
                Some(observer) => {
                    match schema::TextBlockSummary::from_bodies_observed(bodies, observer) {
                        Ok(summary) => {
                            match delta.attach_text_summary_observed(schema, summary, observer) {
                                Ok(()) => {},
                                Err(failure)
                                    if failure.code() == LogStoreFailureCode::BudgetExhausted => {},
                                Err(failure) => return Err(failure),
                            }
                        },
                        Err(schema::TextSummaryFailure::Observation(
                            ScanObservationFailureCode::BudgetExhausted,
                        )) => {},
                        Err(failure) => return Err(map_text_summary_failure(failure)),
                    }
                },
                None => {
                    let summary = schema::TextBlockSummary::from_bodies(bodies)
                        .map_err(map_schema_failure)?;
                    delta
                        .attach_text_summary(schema, summary)
                        .map_err(map_schema_failure)?;
                },
            }
        }
        Ok(delta)
    }

    /// Reconstructs one committed v2 block's schema delta without changing Store Block grammar.
    pub(crate) fn replay_schema_block(
        &self,
        tenant: positron_domain::identity::TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        schema: &SchemaCatalog,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        self.replay_schema_block_inner(tenant, snapshot, block, schema, None, None, None)
    }

    #[allow(dead_code)]
    pub(crate) fn replay_schema_block_observed(
        &self,
        tenant: positron_domain::identity::TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        schema: &SchemaCatalog,
        observer: &dyn ScanObserver,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        self.replay_schema_block_observed_cancellable(
            tenant,
            snapshot,
            block,
            schema,
            &super::scan::NeverCancelled,
            observer,
        )
    }

    pub(crate) fn replay_schema_block_observed_cancellable(
        &self,
        tenant: positron_domain::identity::TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        schema: &SchemaCatalog,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        self.replay_schema_block_observed_cancellable_with_text_observer(
            tenant,
            snapshot,
            block,
            schema,
            cancellation,
            observer,
            Some(observer),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn replay_schema_block_observed_cancellable_with_text_observer(
        &self,
        tenant: positron_domain::identity::TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        schema: &SchemaCatalog,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
        text_observer: Option<&dyn ScanObserver>,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        self.replay_schema_block_inner(
            tenant,
            snapshot,
            block,
            schema,
            Some(cancellation),
            Some(observer),
            text_observer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_schema_block_inner(
        &self,
        tenant: positron_domain::identity::TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        schema: &SchemaCatalog,
        cancellation: Option<&dyn ScanCancellation>,
        observer: Option<&dyn ScanObserver>,
        text_observer: Option<&dyn ScanObserver>,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        let decoded = match (cancellation, observer) {
            (Some(cancellation), Some(observer)) => codec::BlockDecode::observed_quantized(
                tenant,
                block.payload(),
                cancellation,
                observer,
            )?
            .decode(snapshot, usize::MAX, cancellation)?,
            _ => codec::decode_block(tenant, snapshot, block.payload(), usize::MAX)?,
        };
        if schema.tenant() != tenant {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        // A reduced replay explicitly declined optional text work. Branch
        // before inspecting bodies so fallback does not traverse discarded
        // evidence outside the admitted text authority.
        let summary = if observer.is_some() && text_observer.is_none() {
            None
        } else {
            let has_schema_overflow = decoded.records.iter().any(|record| {
                record.attributes().iter().any(|attribute| {
                    attribute.representation() == AttributeRepresentation::SchemaOverflow
                })
            });
            let has_text_body = decoded
                .records
                .iter()
                .any(|record| record.body().and_then(|body| body.as_str()).is_some());
            if !has_text_body || has_schema_overflow {
                None
            } else {
                let bodies = decoded
                    .records
                    .iter()
                    .map(|record| record.body().and_then(|body| body.as_str()));
                match text_observer {
                    Some(observer) => {
                        match schema::TextBlockSummary::from_bodies_observed(bodies, observer) {
                            Ok(summary) => Some(summary),
                            Err(schema::TextSummaryFailure::Observation(
                                ScanObservationFailureCode::BudgetExhausted,
                            )) => None,
                            Err(failure) => return Err(map_text_summary_failure(failure)),
                        }
                    },
                    None if observer.is_none() => Some(
                        schema::TextBlockSummary::from_bodies(bodies)
                            .map_err(map_schema_failure)?,
                    ),
                    None => None,
                }
            }
        };
        let mut delta = SchemaDelta::empty(tenant, true);
        let mut meter = observer.map_or_else(
            schema::delta::DiscoveryMeter::new,
            schema::delta::DiscoveryMeter::observed,
        );
        for record in decoded.records {
            schema
                .stage_replayed_record(record.attributes(), &mut delta, &mut meter)
                .map_err(map_schema_failure)?;
        }
        if let Some(summary) = summary
            && !delta.has_index_paths()
            && may_add_text_summary(schema, text_observer)?
            && schema.budget().max_index_bytes() >= schema::MIN_TEXT_INDEX_BUDGET_BYTES
        {
            if let Some(observer) = text_observer {
                match delta.attach_text_summary_observed(schema, summary, observer) {
                    Ok(()) => {},
                    Err(failure) if failure.code() == LogStoreFailureCode::BudgetExhausted => {},
                    Err(failure) => return Err(failure),
                }
            } else if observer.is_none() {
                delta
                    .attach_text_summary(schema, summary)
                    .map_err(map_schema_failure)?;
            }
        }
        Ok(delta)
    }
}

fn may_add_text_summary(
    schema: &SchemaCatalog,
    observer: Option<&dyn ScanObserver>,
) -> Result<bool, LogStoreFailure> {
    match observer {
        Some(observer) => match schema.may_add_text_summary_observed(observer) {
            Ok(value) => Ok(value),
            Err(ScanObservationFailureCode::BudgetExhausted) => Ok(false),
            Err(failure) => Err(LogStoreFailure::observation(failure)),
        },
        None => Ok(schema.may_add_text_summary()),
    }
}

fn map_text_summary_failure(failure: schema::TextSummaryFailure) -> LogStoreFailure {
    match failure {
        schema::TextSummaryFailure::Schema(failure) => map_schema_failure(failure),
        schema::TextSummaryFailure::Observation(failure) => LogStoreFailure::observation(failure),
    }
}

#[cfg(test)]
mod tests {
    use super::map_text_summary_failure;
    use crate::log_store::{LogStoreFailureCode, schema};

    #[test]
    fn schema_summary_failures_keep_their_typed_public_code() {
        let failure = map_text_summary_failure(schema::TextSummaryFailure::Schema(
            schema::SchemaFailure::InvalidValue,
        ));
        assert_eq!(failure.code(), LogStoreFailureCode::InvalidInput);
    }
}
