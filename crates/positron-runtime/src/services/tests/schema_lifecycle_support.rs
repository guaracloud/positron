use std::sync::{Arc, Mutex, mpsc};

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{IngestRequestOutcome, NativeLogAdmissionGroups, NativeSpanAdmissionGroups};

use crate::services::{QueryExecutionTestHook, ReceiverTestBackend};

pub(super) struct BlockingFinalizationBackend {
    pub(super) entered: mpsc::Sender<()>,
    pub(super) release: Mutex<mpsc::Receiver<()>>,
    pub(super) lifecycle_before_finish:
        Option<(Arc<crate::InitializedInstance>, String, mpsc::Sender<bool>)>,
}

impl ReceiverTestBackend for BlockingFinalizationBackend {
    fn ingest(&self, _groups: NativeLogAdmissionGroups<'_>) -> IngestRequestOutcome {
        let _ = self.entered.send(());
        if let Ok(receiver) = self.release.lock() {
            let _ = receiver.recv();
        }
        IngestRequestOutcome::new(Vec::new())
    }

    fn handles_traces(&self) -> bool {
        true
    }

    fn ingest_traces(&self, _groups: NativeSpanAdmissionGroups<'_>) -> IngestRequestOutcome {
        let _ = self.entered.send(());
        if let Ok(receiver) = self.release.lock() {
            let _ = receiver.recv();
        }
        if let Some((instance, ingest_secret, observed)) = &self.lifecycle_before_finish {
            let admitted = instance
                .attribute(
                    PresentedCredential::parse(ingest_secret).expect("fixture credential"),
                    RequestedIntent::Ingest,
                    CompatibilityHints::none(),
                )
                .is_ok();
            let _ = observed.send(admitted);
        }
        IngestRequestOutcome::new(Vec::new())
    }
}

pub(super) struct BlockingQueryExecution {
    pub(super) progress: mpsc::Sender<&'static str>,
    pub(super) release: Mutex<mpsc::Receiver<()>>,
}

impl QueryExecutionTestHook for BlockingQueryExecution {
    fn after_admission(&self) {
        let _ = self.progress.send("admitted");
        if let Ok(receiver) = self.release.lock() {
            let _ = receiver.recv();
        }
    }
}

pub(super) fn trace_request() -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x70; 16],
                    span_id: vec![0x71; 8],
                    name: "lifecycle-drain".to_owned(),
                    start_time_unix_nano: 1,
                    end_time_unix_nano: 2,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}
