use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceResponse;
use positron_domain::routing::VirtualShardId;
use positron_ingest::{AdmissionGroupOutcome, IngestOutcome, IngestRequestOutcome};
use prost::Message;

use super::{ResponseEncoding, RpcStatus, ingest_response, success};
use crate::native_host::native_http::Response;

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
        ResponseEncoding::Json => serde_json::from_slice(response.body()).expect("JSON response"),
    }
}
