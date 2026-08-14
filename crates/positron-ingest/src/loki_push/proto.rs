use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub(super) struct PushRequest {
    #[prost(message, repeated, tag = "1")]
    pub(super) streams: Vec<StreamAdapter>,
    #[prost(string, tag = "2")]
    pub(super) format: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct StreamAdapter {
    #[prost(string, tag = "1")]
    pub(super) labels: String,
    #[prost(message, repeated, tag = "2")]
    pub(super) entries: Vec<EntryAdapter>,
    #[prost(uint64, tag = "3")]
    pub(super) hash: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct EntryAdapter {
    #[prost(message, optional, tag = "1")]
    pub(super) timestamp: Option<Timestamp>,
    #[prost(string, tag = "2")]
    pub(super) line: String,
    #[prost(message, repeated, tag = "3")]
    pub(super) structured_metadata: Vec<LabelPair>,
    #[prost(message, repeated, tag = "4")]
    pub(super) parsed: Vec<LabelPair>,
}

#[derive(Clone, Copy, PartialEq, Message)]
pub(super) struct Timestamp {
    #[prost(int64, tag = "1")]
    pub(super) seconds: i64,
    #[prost(int32, tag = "2")]
    pub(super) nanos: i32,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct LabelPair {
    #[prost(string, tag = "1")]
    pub(super) name: String,
    #[prost(string, tag = "2")]
    pub(super) value: String,
}
