use positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES;
use positron_kernel::StoreBlockIdentity;

use super::{SchemaCatalog, SchemaPath, SchemaQuery, SchemaValue};
use crate::log_store::{ScanObservationFailureCode, ScanObserver};

impl SchemaCatalog {
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
