use std::error::Error;

use prost::Message;

pub(super) fn snappy_push(line: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let protobuf = PushRequest {
        streams: vec![StreamAdapter {
            labels: "{app=\"producer\"}".to_owned(),
            entries: vec![EntryAdapter {
                timestamp: Some(Timestamp {
                    seconds: 1,
                    nanos: 2,
                }),
                line: line.to_owned(),
            }],
        }],
    }
    .encode_to_vec();
    raw_snappy_literal(&protobuf)
}

fn raw_snappy_literal(input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoded = Vec::new();
    let mut remaining = u64::try_from(input.len())?;
    loop {
        let byte = u8::try_from(remaining & 0x7f)?;
        remaining >>= 7;
        encoded.push(if remaining == 0 { byte } else { byte | 0x80 });
        if remaining == 0 {
            break;
        }
    }
    let length_minus_one = input.len().checked_sub(1).ok_or("empty Snappy literal")?;
    if length_minus_one < 60 {
        encoded.push(u8::try_from(length_minus_one)? << 2);
    } else if u8::try_from(length_minus_one).is_ok() {
        encoded.push(60 << 2);
        encoded.push(u8::try_from(length_minus_one)?);
    } else {
        encoded.push(61 << 2);
        encoded.extend_from_slice(&u16::try_from(length_minus_one)?.to_le_bytes());
    }
    encoded.extend_from_slice(input);
    Ok(encoded)
}

#[derive(Clone, PartialEq, Message)]
struct PushRequest {
    #[prost(message, repeated, tag = "1")]
    streams: Vec<StreamAdapter>,
}

#[derive(Clone, PartialEq, Message)]
struct StreamAdapter {
    #[prost(string, tag = "1")]
    labels: String,
    #[prost(message, repeated, tag = "2")]
    entries: Vec<EntryAdapter>,
}

#[derive(Clone, PartialEq, Message)]
struct EntryAdapter {
    #[prost(message, optional, tag = "1")]
    timestamp: Option<Timestamp>,
    #[prost(string, tag = "2")]
    line: String,
}

#[derive(Clone, Copy, PartialEq, Message)]
struct Timestamp {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}
