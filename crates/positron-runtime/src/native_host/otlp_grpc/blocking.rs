use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::{
    logs::v1::ExportLogsServiceRequest, trace::v1::ExportTraceServiceRequest,
};
use positron_governance::AuthorizedContext;
use positron_ingest::{IngestRequestOutcome, OtlpGrpcTransportEvidence};
use positron_kernel::TransferredResourceReservation;

use crate::{ServiceFailure, ServiceHandle, TaskCancellation};

use super::GrpcFailure;

const QUEUED_INGESTS: usize = 1;

pub(super) struct BlockingIngestExecutor {
    cancellation: TaskCancellation,
    sender: Option<SyncSender<BlockingIngestJob>>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Clone, Debug)]
pub(super) struct BlockingIngestHandle {
    sender: SyncSender<BlockingIngestJob>,
}

enum BlockingIngestJob {
    Ingest(Box<BlockingIngestOperation>),
    TraceIngest(Box<BlockingTraceIngestOperation>),
    #[cfg(test)]
    Stall {
        entered: std::sync::mpsc::SyncSender<()>,
    },
}

struct BlockingIngestOperation {
    services: ServiceHandle,
    context: AuthorizedContext,
    request: ExportLogsServiceRequest,
    reservation: TransferredResourceReservation,
    response: tokio::sync::oneshot::Sender<Result<IngestRequestOutcome, ServiceFailure>>,
}

struct BlockingTraceIngestOperation {
    services: ServiceHandle,
    context: AuthorizedContext,
    request: ExportTraceServiceRequest,
    evidence: OtlpGrpcTransportEvidence,
    reservation: TransferredResourceReservation,
    response: tokio::sync::oneshot::Sender<Result<IngestRequestOutcome, ServiceFailure>>,
}

impl BlockingIngestExecutor {
    pub(super) fn start() -> Result<Self, GrpcFailure> {
        let cancellation = TaskCancellation::new();
        let worker_cancellation = cancellation.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(QUEUED_INGESTS);
        let worker = std::thread::Builder::new()
            .name("positron-otlp-logs-blocking".to_owned())
            .spawn(move || run(receiver, worker_cancellation))
            .map_err(|_| GrpcFailure)?;
        Ok(Self {
            cancellation,
            sender: Some(sender),
            worker: Some(worker),
        })
    }

    pub(super) fn handle(&self) -> Result<BlockingIngestHandle, GrpcFailure> {
        self.sender
            .as_ref()
            .cloned()
            .map(|sender| BlockingIngestHandle { sender })
            .ok_or(GrpcFailure)
    }

    pub(super) fn shutdown(&mut self) -> Result<(), GrpcFailure> {
        self.cancellation.cancel();
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| GrpcFailure)?;
        }
        Ok(())
    }

    pub(super) fn shutdown_within(&mut self, limit: Duration) -> Result<bool, GrpcFailure> {
        self.cancellation.cancel();
        self.sender.take();
        let deadline = std::time::Instant::now() + limit;
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            if std::time::Instant::now() >= deadline {
                self.worker.take();
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| GrpcFailure)?;
        }
        Ok(true)
    }
}

impl Drop for BlockingIngestExecutor {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.sender.take();
        if let Some(worker) = self.worker.take().filter(JoinHandle::is_finished) {
            let _ = worker.join();
        }
    }
}

impl BlockingIngestHandle {
    pub(super) async fn ingest(
        &self,
        services: ServiceHandle,
        context: AuthorizedContext,
        request: ExportLogsServiceRequest,
        reservation: TransferredResourceReservation,
    ) -> Result<IngestRequestOutcome, ServiceFailure> {
        let (response, outcome) = tokio::sync::oneshot::channel();
        let job = BlockingIngestJob::Ingest(Box::new(BlockingIngestOperation {
            services,
            context,
            request,
            reservation,
            response,
        }));
        self.sender.try_send(job).map_err(|failure| match failure {
            TrySendError::Full(_) => ServiceFailure::CapacityUnavailable,
            TrySendError::Disconnected(_) => ServiceFailure::Internal,
        })?;
        outcome.await.map_err(|_| ServiceFailure::Internal)?
    }

    pub(super) async fn ingest_traces(
        &self,
        services: ServiceHandle,
        context: AuthorizedContext,
        request: ExportTraceServiceRequest,
        evidence: OtlpGrpcTransportEvidence,
        reservation: TransferredResourceReservation,
    ) -> Result<IngestRequestOutcome, ServiceFailure> {
        let (response, outcome) = tokio::sync::oneshot::channel();
        let job = BlockingIngestJob::TraceIngest(Box::new(BlockingTraceIngestOperation {
            services,
            context,
            request,
            evidence,
            reservation,
            response,
        }));
        self.sender.try_send(job).map_err(|failure| match failure {
            TrySendError::Full(_) => ServiceFailure::CapacityUnavailable,
            TrySendError::Disconnected(_) => ServiceFailure::Internal,
        })?;
        outcome.await.map_err(|_| ServiceFailure::Internal)?
    }

    #[cfg(test)]
    pub(super) fn stall_for_test(
        &self,
        entered: std::sync::mpsc::SyncSender<()>,
    ) -> Result<(), &'static str> {
        self.sender
            .try_send(BlockingIngestJob::Stall { entered })
            .map_err(|_| "blocking ingest test job could not be queued")
    }
}

fn run(receiver: Receiver<BlockingIngestJob>, cancellation: TaskCancellation) {
    while !cancellation.is_cancelled() {
        let job = match receiver.recv_timeout(Duration::from_millis(5)) {
            Ok(job) => job,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        match job {
            BlockingIngestJob::Ingest(operation) => {
                if cancellation.is_cancelled() {
                    continue;
                }
                let result = operation.services.ingest_decoded_otlp_logs(
                    operation.context,
                    operation.request,
                    operation.reservation,
                );
                let _ = operation.response.send(result);
            },
            BlockingIngestJob::TraceIngest(operation) => {
                if cancellation.is_cancelled() {
                    continue;
                }
                let result = operation.services.ingest_decoded_otlp_traces(
                    operation.context,
                    operation.request,
                    operation.evidence,
                    operation.reservation,
                );
                let _ = operation.response.send(result);
            },
            #[cfg(test)]
            BlockingIngestJob::Stall { entered } => {
                let _ = entered.send(());
                while !cancellation.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
            },
        }
    }
}
