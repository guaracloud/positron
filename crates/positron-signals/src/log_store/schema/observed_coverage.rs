use positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES;
use positron_kernel::StoreBlockIdentity;

use super::{SchemaCatalog, SchemaPath, SchemaQuery, SchemaValue};
use crate::log_store::{ScanObservationFailureCode, ScanObserver};

impl SchemaCatalog {
    pub(crate) fn verified_text_coverage_observed(
        &self,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
        candidate: &super::TextSearchCandidate,
        observer: &dyn ScanObserver,
    ) -> Result<Option<bool>, ScanObservationFailureCode> {
        for index in &self.block_indexes {
            observer.observe_work(1)?;
            if index.identity != identity {
                continue;
            }
            if index.digest != digest || !index.semantically_valid(&self.entries) {
                return Ok(None);
            }
            let Some(summary) = index.text_summary.as_ref() else {
                return Ok(None);
            };
            // The summary is a sorted, bounded set. Charge the physical
            // lookup once, then poll cancellation while doing its bounded
            // binary searches. Charging every stored trigram would make the
            // cost depend on the index representation rather than the
            // caller's one candidate lookup.
            observer.observe_work(1)?;
            return summary.might_contain_observed(candidate, observer);
        }
        Ok(None)
    }

    pub(crate) fn verified_query_coverage_observed(
        &self,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
        query: &SchemaQuery,
        observer: &dyn ScanObserver,
    ) -> Result<Option<bool>, ScanObservationFailureCode> {
        for index in &self.block_indexes {
            observer.observe_work(1)?;
            if index.identity != identity {
                continue;
            }
            if index.digest != digest {
                return Ok(None);
            }
            for known in &index.paths {
                observe_path(&known.path, observer)?;
                for value in &known.values {
                    observe_value(value, observer)?;
                }
            }
            for entry in &self.entries {
                observe_path(entry.path(), observer)?;
                for _ in entry.variants() {
                    observer.observe_work(1)?;
                }
            }
            if !index.semantically_valid(&self.entries) {
                return Ok(None);
            }
            return Ok(query.expected_scalar().map_or_else(
                || index.covers_kind(query.path(), query.expected_kind()),
                |expected| index.covers_value(query.path(), expected),
            ));
        }
        Ok(None)
    }
}

fn observe_path(
    path: &SchemaPath,
    observer: &dyn ScanObserver,
) -> Result<(), ScanObservationFailureCode> {
    observer.observe_work(1)?;
    for segment in path.segments() {
        observer.observe_work(1)?;
        poll_payload(segment.as_bytes(), observer)?;
    }
    Ok(())
}

fn observe_value(
    value: &SchemaValue,
    observer: &dyn ScanObserver,
) -> Result<(), ScanObservationFailureCode> {
    observer.observe_work(1)?;
    match value {
        SchemaValue::String(value) => poll_payload(value.as_bytes(), observer),
        SchemaValue::Bytes(value) => poll_payload(value, observer),
        SchemaValue::Null
        | SchemaValue::Boolean(_)
        | SchemaValue::SignedInteger(_)
        | SchemaValue::FloatingPointBits(_)
        | SchemaValue::Kind(_) => Ok(()),
    }
}

fn poll_payload(
    payload: &[u8],
    observer: &dyn ScanObserver,
) -> Result<(), ScanObservationFailureCode> {
    for _ in payload.chunks(NATIVE_VALUE_PAYLOAD_CHUNK_BYTES) {
        observer.observe_work(0)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use positron_domain::identity::TenantId;
    use positron_kernel::StoreBlockIdentity;

    use super::super::index::{ScalarIndexFraming, SchemaBlockIndex, TextIndexFraming};
    use super::super::text_index::TextBlockSummary;
    use super::super::{SchemaBudget, TextSearchCandidate};
    use super::SchemaCatalog;
    use crate::log_store::{ScanObservationFailureCode, ScanObserver};

    struct Unobserved;

    impl ScanObserver for Unobserved {
        fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
            Ok(())
        }
    }

    #[test]
    fn text_coverage_falls_back_for_missing_and_skips_other_block_indexes()
    -> Result<(), Box<dyn Error>> {
        let tenant = TenantId::from_bytes([0x41; 16])?;
        let mut catalog = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
        let first = StoreBlockIdentity::new([0x01; 16])?;
        let second = StoreBlockIdentity::new([0x02; 16])?;
        catalog.block_indexes = vec![
            SchemaBlockIndex {
                identity: first,
                digest: [0x11; 32],
                paths: Vec::new(),
                scalar_framing: ScalarIndexFraming::V2,
                text_framing: TextIndexFraming::V1,
                text_summary: Some(TextBlockSummary::from_bodies([Some("alpha")])?),
            },
            SchemaBlockIndex {
                identity: second,
                digest: [0x22; 32],
                paths: Vec::new(),
                scalar_framing: ScalarIndexFraming::V2,
                text_framing: TextIndexFraming::V1,
                text_summary: Some(TextBlockSummary::from_bodies([Some("beta")])?),
            },
        ];
        let candidate = TextSearchCandidate::literal("eta")?.ok_or("candidate was generic")?;
        let observer = Unobserved;

        assert_eq!(
            catalog.verified_text_coverage_observed(second, [0x22; 32], &candidate, &observer),
            Ok(Some(true))
        );
        let missing = StoreBlockIdentity::new([0x03; 16])?;
        assert_eq!(
            catalog.verified_text_coverage_observed(missing, [0x33; 32], &candidate, &observer),
            Ok(None)
        );
        let partial = StoreBlockIdentity::new([0x04; 16])?;
        catalog.block_indexes.push(SchemaBlockIndex {
            identity: partial,
            digest: [0x44; 32],
            paths: Vec::new(),
            scalar_framing: ScalarIndexFraming::V2,
            text_framing: TextIndexFraming::V1,
            text_summary: Some(TextBlockSummary::from_wire_parts(
                false,
                vec![[b'z', b'z', b'z']],
            )),
        });
        assert_eq!(
            catalog.verified_text_coverage_observed(partial, [0x44; 32], &candidate, &observer),
            Ok(None)
        );
        Ok(())
    }
}
