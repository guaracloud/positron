use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTracePartialSuccess, ExportTraceServiceResponse,
};
use positron_domain::routing::VirtualShardId;
use positron_ingest::{AdmissionGroupOutcome, IngestOutcome, IngestRequestOutcome};
use prost::Message;

use super::{
    ResponseEncoding, RpcStatus, ingest_response, success, trace_service_response_with_encoding,
    trace_success,
};
use crate::native_host::native_http::Response;

mod live;
mod live_outcomes;
mod outcomes;

fn single(outcome: IngestOutcome) -> IngestRequestOutcome {
    IngestRequestOutcome::new(vec![AdmissionGroupOutcome::new(
        VirtualShardId::new(1).expect("fixed shard"),
        1,
        outcome,
    )])
}

fn decode_status(response: &Response, encoding: ResponseEncoding) -> RpcStatus {
    match encoding {
        ResponseEncoding::Protobuf => RpcStatus::decode(response.body()).expect("protobuf status"),
        ResponseEncoding::Json => {
            let status: serde_json::Value =
                serde_json::from_slice(response.body()).expect("JSON status");
            RpcStatus {
                code: status["code"].as_i64().expect("status code") as i32,
                message: status["message"]
                    .as_str()
                    .expect("status message")
                    .to_owned(),
            }
        },
    }
}

fn decode_success(response: &Response, encoding: ResponseEncoding) -> ExportLogsServiceResponse {
    match encoding {
        ResponseEncoding::Protobuf => {
            ExportLogsServiceResponse::decode(response.body()).expect("protobuf response")
        },
        ResponseEncoding::Json => {
            let value: serde_json::Value =
                serde_json::from_slice(response.body()).expect("JSON response");
            let partial_success =
                value
                    .get("partialSuccess")
                    .map(|partial| ExportLogsPartialSuccess {
                        rejected_log_records: partial["rejectedLogRecords"]
                            .as_str()
                            .expect("decimal string")
                            .parse()
                            .expect("i64 records"),
                        error_message: partial["errorMessage"]
                            .as_str()
                            .expect("error message")
                            .to_owned(),
                    });
            ExportLogsServiceResponse { partial_success }
        },
    }
}

fn decode_trace_success(
    response: &Response,
    encoding: ResponseEncoding,
) -> ExportTraceServiceResponse {
    match encoding {
        ResponseEncoding::Protobuf => {
            ExportTraceServiceResponse::decode(response.body()).expect("protobuf response")
        },
        ResponseEncoding::Json => {
            let value: serde_json::Value =
                serde_json::from_slice(response.body()).expect("JSON response");
            let partial_success =
                value
                    .get("partialSuccess")
                    .map(|partial| ExportTracePartialSuccess {
                        rejected_spans: partial["rejectedSpans"]
                            .as_str()
                            .expect("decimal string")
                            .parse()
                            .expect("i64 spans"),
                        error_message: partial["errorMessage"]
                            .as_str()
                            .expect("error message")
                            .to_owned(),
                    });
            ExportTraceServiceResponse { partial_success }
        },
    }
}
