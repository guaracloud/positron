use positron_ingest::OtlpRequestEncoding;

use super::{INVALID_ARGUMENT, Response};

#[derive(Clone, Copy)]
pub(crate) enum ResponseEncoding {
    Json,
    Protobuf,
}

#[cfg(test)]
impl ResponseEncoding {
    pub(crate) const fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Protobuf => "application/x-protobuf",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum OtlpHttpSignal {
    Logs,
    Traces,
}

impl OtlpHttpSignal {
    pub(crate) const fn unsupported_content_type_message(self) -> &'static str {
        match self {
            Self::Logs => "OTLP Logs Content-Type is unsupported",
            Self::Traces => "OTLP Traces Content-Type is unsupported",
        }
    }

    pub(crate) const fn unsupported_content_encoding_message(self) -> &'static str {
        match self {
            Self::Logs => "OTLP Logs Content-Encoding is unsupported",
            Self::Traces => "OTLP Traces Content-Encoding is unsupported",
        }
    }
}

pub(crate) fn request_encoding(
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    signal: OtlpHttpSignal,
) -> Result<(OtlpRequestEncoding, ResponseEncoding), Response> {
    let media_type = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    match media_type {
        Some(value) if value.eq_ignore_ascii_case("application/x-protobuf") => {
            let request = compression_variant(
                content_encoding,
                OtlpRequestEncoding::Protobuf,
                OtlpRequestEncoding::GzipProtobuf,
                ResponseEncoding::Protobuf,
                signal,
            )?;
            Ok((request, ResponseEncoding::Protobuf))
        },
        Some(value) if value.eq_ignore_ascii_case("application/json") => {
            let request = compression_variant(
                content_encoding,
                OtlpRequestEncoding::Json,
                OtlpRequestEncoding::GzipJson,
                ResponseEncoding::Json,
                signal,
            )?;
            Ok((request, ResponseEncoding::Json))
        },
        _ => Err(super::response::failure(
            415,
            INVALID_ARGUMENT,
            signal.unsupported_content_type_message(),
            ResponseEncoding::Json,
        )),
    }
}

fn compression_variant(
    content_encoding: Option<&str>,
    plain: OtlpRequestEncoding,
    gzip: OtlpRequestEncoding,
    response_encoding: ResponseEncoding,
    signal: OtlpHttpSignal,
) -> Result<OtlpRequestEncoding, Response> {
    match content_encoding.map(str::trim) {
        None | Some("") => Ok(plain),
        Some(value) if value.eq_ignore_ascii_case("gzip") => Ok(gzip),
        Some(value) if value.eq_ignore_ascii_case("identity") => Ok(plain),
        Some(_) => Err(super::response::failure(
            415,
            INVALID_ARGUMENT,
            signal.unsupported_content_encoding_message(),
            response_encoding,
        )),
    }
}
