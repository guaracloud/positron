use positron_domain::value::{
    AttributeNamespace, NATIVE_VALUE_PAYLOAD_CHUNK_BYTES, NativeValueObserver,
    ObservedValueFailure, ValidatedAttributeValue,
};
use positron_kernel::ResourceReservation;

use crate::{ScanCancellation, ScanObserver};

use super::{
    LogicalSpan, LogicalTraceScanResult, SpanObservation, TraceIncompleteness, TraceScan,
    TraceStoreFailure,
};

/// A bounded request for one native Trace Store search operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceSearch {
    scan: TraceScan,
    attribute_equals: Option<TraceAttributeEquals>,
}

impl TraceSearch {
    /// Searches the complete authenticated snapshot subject to the finite scan limit.
    #[must_use]
    pub const fn all(limit: crate::ScanLimit) -> Self {
        Self {
            scan: TraceScan::all(limit),
            attribute_equals: None,
        }
    }

    /// Narrows the search to observations with one exact native attribute value.
    pub fn with_attribute_equals(
        mut self,
        namespace: AttributeNamespace,
        key: String,
        value: ValidatedAttributeValue,
    ) -> Result<Self, TraceStoreFailure> {
        let maximum = super::TraceStore::value_limit_profile()
            .effective_limits()
            .dynamic_value()
            .key_path_bytes()
            .value() as usize;
        if key.is_empty() || key.len() > maximum || matches!(namespace, AttributeNamespace::Stream)
        {
            return Err(TraceStoreFailure::invalid_input());
        }
        self.attribute_equals = Some(TraceAttributeEquals {
            namespace,
            key,
            value,
        });
        Ok(self)
    }

    /// Applies the caller's cumulative raw-payload ceiling before block decode.
    #[must_use]
    pub const fn with_scanned_bytes(mut self, limit: u64) -> Self {
        self.scan = self.scan.with_scanned_bytes(limit);
        self
    }

    pub(super) const fn scan(&self) -> TraceScan {
        self.scan
    }

    pub(super) fn matches(
        &self,
        observation: &SpanObservation,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<bool, TraceStoreFailure> {
        let Some(filter) = self.attribute_equals.as_ref() else {
            return Ok(true);
        };
        filter.matches(observation, cancellation, observer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TraceAttributeEquals {
    namespace: AttributeNamespace,
    key: String,
    value: ValidatedAttributeValue,
}

impl TraceAttributeEquals {
    fn matches(
        &self,
        observation: &SpanObservation,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<bool, TraceStoreFailure> {
        let mut traversal = AttributeFilterObserver {
            cancellation,
            observer,
        };
        for attribute in observation.attributes() {
            traversal.observe_structure()?;
            if attribute.namespace() != self.namespace || attribute.key() != self.key {
                continue;
            }
            for index in 0..attribute.len() {
                let Some(value) = attribute.occurrence(index) else {
                    return Err(TraceStoreFailure::invalid_input());
                };
                match value.equals_observed(&self.value, &mut traversal) {
                    Ok(true) => return Ok(true),
                    Ok(false) => {},
                    Err(ObservedValueFailure::Domain(failure)) => {
                        return Err(TraceStoreFailure::domain(failure));
                    },
                    Err(ObservedValueFailure::Observer(failure)) => return Err(failure),
                }
            }
        }
        Ok(false)
    }
}

struct AttributeFilterObserver<'a> {
    cancellation: &'a dyn ScanCancellation,
    observer: &'a dyn ScanObserver,
}

impl NativeValueObserver for AttributeFilterObserver<'_> {
    type Error = TraceStoreFailure;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        super::scan::check_cancel(self.cancellation)?;
        self.observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)
    }

    fn observe_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        if payload.len() > NATIVE_VALUE_PAYLOAD_CHUNK_BYTES {
            return Err(TraceStoreFailure::invalid_input());
        }
        self.observe_structure()
    }
}

/// One snapshot-stable trace-by-ID result.
///
/// An empty result proves absence only when [`Self::complete`] is true. When
/// false, [`Self::incompleteness`] discloses the finite scan boundary that
/// prevented a complete answer.
#[derive(Debug)]
pub struct TraceByIdResult<'kernel> {
    trace_id: [u8; 16],
    spans: Vec<LogicalSpan>,
    complete: bool,
    scanned_bytes: u64,
    incompleteness: TraceIncompleteness,
    _capacity: ResourceReservation<'kernel>,
}

impl<'kernel> TraceByIdResult<'kernel> {
    pub(super) fn from_logical(
        trace_id: [u8; 16],
        logical: LogicalTraceScanResult<'kernel>,
    ) -> Self {
        let LogicalTraceScanResult {
            spans,
            complete,
            scanned_bytes,
            scanned_bytes_limited,
            _capacity,
            ..
        } = logical;
        let incompleteness = if complete {
            TraceIncompleteness::None
        } else if scanned_bytes_limited {
            TraceIncompleteness::ScannedBytesLimit
        } else {
            TraceIncompleteness::ResultLimit
        };
        Self {
            trace_id,
            spans,
            complete,
            scanned_bytes,
            incompleteness,
            _capacity,
        }
    }

    #[must_use]
    pub const fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }

    /// Returns logical spans with identical retries consolidated and conflict variants retained.
    #[must_use]
    pub fn spans(&self) -> &[LogicalSpan] {
        &self.spans
    }

    /// Whether the entire authenticated snapshot was searched.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns the authenticated raw-payload volume admitted to this search.
    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }

    /// Returns the explicit reason an incomplete search cannot prove absence.
    #[must_use]
    pub const fn incompleteness(&self) -> TraceIncompleteness {
        self.incompleteness
    }
}
