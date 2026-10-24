//! Bounded, sequenced RPC and deterministic offline broker operations.
//! No host sockets, DNS, HTTP client or worker-supplied host paths.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub const MAX_PACKET: usize = 24 * 1024 * 1024;
pub const MAX_STREAM: usize = 128 * 1024 * 1024;
pub const MAX_CALLS: u32 = 4096;
/// The emulator can ask a qualified broker; it never opens host sockets or
/// guest-selected host paths. Implementations validate sequence and reply shape.
pub trait Client {
    fn call(&mut self, operation: Operation) -> Result<Reply, String>;
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Probe {
    InternetStreamA,
    InternetStreamW,
    InternetStreamZero,
    InternetStreamLinked,
    InternetStreamFull,
    InternetStreamEmpty,
    InternetStreamBadCount,
    InternetStreamExcess,
    InternetStreamBadStruct,
    InternetStreamIncomplete,
    InternetStreamClosed,

    InternetPostA,
    InternetPostW,
    InternetSendWideLength,
    InternetSendBeforeRead,
    InternetQueryA,
    InternetQueryW,
    InternetQuerySmallA,
    InternetQuerySmallW,
    InternetQueryCustomA,
    InternetQueryCustomW,
    InternetQueryNull,
    InternetQueryReadOnly,
    InternetQueryMissing,

    InternetAnsi,
    InternetWide,
    InternetSplit,
    InternetEmpty,
    InternetMiss,
    InternetClosed,
    InternetBadRead,
    InternetBadCount,
    InternetNullAvailable,
    InternetFlags,
    InternetAsync,

    Normal,
    Miss,
    Dns,
    Crash,
    Partial,
    Hang,
    BadId,
    BadFrame,
    WorkerCrash,
    NativeA,
    NativeW,
    NativeMiss,
    NativeCallback,
    NativeParent,
    NativePartial,
    NativeNull,
    ControllerCrash,
    ControllerPartial,
    HttpBinary,
    HttpPost,
    HttpHeaders,
    HttpBodyMiss,
    HttpChunkedMiss,
    NativeBinaryA,
    NativeBinaryW,
    NativeBinaryPartial,
    NativeBinaryEmpty,
    NativeBinaryMiss,
    WinHttp,
    WinHttpBeforeReceive,
    WinHttpBadRead,
    WinHttpBadAvailable,
    WinHttpCloseParent,
    WinHttpMiss,
    WinHttpAsync,
    WinHttpQueryStatus,
    WinHttpQuerySmall,
    WinHttpQueryCustom,
    WinHttpQueryRaw,
    WinHttpEmpty,
    WinHttpUpload,
    WinHttpUploadEarly,
    WinHttpUploadBadCount,
    WinHttpUploadOverrun,
    WinHttpUploadIncomplete,
    WinHttpUploadClosed,
    WinHttpChunked,
    WinHttpChunkedSplit,
    WinHttpChunkedIncomplete,
    WinHttpChunkedMalformed,
    WinHttpChunkedZero,
}
impl Probe {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "internet-ansi" => Self::InternetAnsi,
            "internet-wide" => Self::InternetWide,
            "internet-split" => Self::InternetSplit,
            "internet-empty" => Self::InternetEmpty,
            "internet-miss" => Self::InternetMiss,
            "internet-closed" => Self::InternetClosed,
            "internet-bad-read" => Self::InternetBadRead,
            "internet-bad-count" => Self::InternetBadCount,
            "internet-null-available" => Self::InternetNullAvailable,
            "internet-flags" => Self::InternetFlags,
            "internet-async" => Self::InternetAsync,
            "internet-post-a" => Self::InternetPostA,
            "internet-post-w" => Self::InternetPostW,
            "internet-send-wide-length" => Self::InternetSendWideLength,
            "internet-send-before-read" => Self::InternetSendBeforeRead,
            "internet-query-a" => Self::InternetQueryA,
            "internet-query-w" => Self::InternetQueryW,
            "internet-query-small-a" => Self::InternetQuerySmallA,
            "internet-query-small-w" => Self::InternetQuerySmallW,
            "internet-query-custom-a" => Self::InternetQueryCustomA,
            "internet-query-custom-w" => Self::InternetQueryCustomW,
            "internet-query-null" => Self::InternetQueryNull,
            "internet-query-read-only" => Self::InternetQueryReadOnly,
            "internet-query-missing" => Self::InternetQueryMissing,
            "internet-stream-a" => Self::InternetStreamA,
            "internet-stream-w" => Self::InternetStreamW,
            "internet-stream-zero" => Self::InternetStreamZero,
            "internet-stream-linked" => Self::InternetStreamLinked,
            "internet-stream-full" => Self::InternetStreamFull,
            "internet-stream-empty" => Self::InternetStreamEmpty,
            "internet-stream-bad-count" => Self::InternetStreamBadCount,
            "internet-stream-excess" => Self::InternetStreamExcess,
            "internet-stream-bad-struct" => Self::InternetStreamBadStruct,
            "internet-stream-incomplete" => Self::InternetStreamIncomplete,
            "internet-stream-closed" => Self::InternetStreamClosed,
            "normal" => Self::Normal,
            "miss" => Self::Miss,
            "dns" => Self::Dns,
            "crash" => Self::Crash,
            "partial" => Self::Partial,
            "hang" => Self::Hang,
            "bad-id" => Self::BadId,
            "bad-frame" => Self::BadFrame,
            "worker-crash" => Self::WorkerCrash,
            "native-a" => Self::NativeA,
            "native-w" => Self::NativeW,
            "native-miss" => Self::NativeMiss,
            "native-callback" => Self::NativeCallback,
            "native-parent" => Self::NativeParent,
            "native-partial" => Self::NativePartial,
            "native-null" => Self::NativeNull,
            "controller-crash" => Self::ControllerCrash,
            "controller-partial" => Self::ControllerPartial,
            "http-binary" => Self::HttpBinary,
            "http-post" => Self::HttpPost,
            "http-headers" => Self::HttpHeaders,
            "http-body-miss" => Self::HttpBodyMiss,
            "http-chunked-miss" => Self::HttpChunkedMiss,
            "native-binary-a" => Self::NativeBinaryA,
            "native-binary-w" => Self::NativeBinaryW,
            "native-binary-partial" => Self::NativeBinaryPartial,
            "native-binary-empty" => Self::NativeBinaryEmpty,
            "native-binary-miss" => Self::NativeBinaryMiss,
            "winhttp" => Self::WinHttp,
            "winhttp-before-receive" => Self::WinHttpBeforeReceive,
            "winhttp-bad-read" => Self::WinHttpBadRead,
            "winhttp-bad-available" => Self::WinHttpBadAvailable,
            "winhttp-close-parent" => Self::WinHttpCloseParent,
            "winhttp-miss" => Self::WinHttpMiss,
            "winhttp-async" => Self::WinHttpAsync,
            "winhttp-query-status" => Self::WinHttpQueryStatus,
            "winhttp-query-small" => Self::WinHttpQuerySmall,
            "winhttp-query-custom" => Self::WinHttpQueryCustom,
            "winhttp-query-raw" => Self::WinHttpQueryRaw,
            "winhttp-empty" => Self::WinHttpEmpty,
            "winhttp-upload" => Self::WinHttpUpload,
            "winhttp-upload-early" => Self::WinHttpUploadEarly,
            "winhttp-upload-bad-count" => Self::WinHttpUploadBadCount,
            "winhttp-upload-overrun" => Self::WinHttpUploadOverrun,
            "winhttp-upload-incomplete" => Self::WinHttpUploadIncomplete,
            "winhttp-upload-closed" => Self::WinHttpUploadClosed,
            "winhttp-chunked" => Self::WinHttpChunked,
            "winhttp-chunked-split" => Self::WinHttpChunkedSplit,
            "winhttp-chunked-incomplete" => Self::WinHttpChunkedIncomplete,
            "winhttp-chunked-malformed" => Self::WinHttpChunkedMalformed,
            "winhttp-chunked-zero" => Self::WinHttpChunkedZero,
            _ => return None,
        })
    }
}
impl Probe {
    pub fn internet(self) -> Option<crate::fixtures::InternetFixture> {
        use crate::fixtures::InternetFixture as F;
        Some(match self {
            Self::InternetPostA => F::PostA,
            Self::InternetPostW => F::PostW,
            Self::InternetSendWideLength => F::SendWideLength,
            Self::InternetSendBeforeRead => F::SendBeforeRead,
            Self::InternetQueryA => F::QueryA,
            Self::InternetQueryW => F::QueryW,
            Self::InternetQuerySmallA => F::QuerySmallA,
            Self::InternetQuerySmallW => F::QuerySmallW,
            Self::InternetQueryCustomA => F::QueryCustomA,
            Self::InternetQueryCustomW => F::QueryCustomW,
            Self::InternetQueryNull => F::QueryNull,
            Self::InternetQueryReadOnly => F::QueryReadOnly,
            Self::InternetQueryMissing => F::QueryMissing,
            Self::InternetStreamA => F::StreamA,
            Self::InternetStreamW => F::StreamW,
            Self::InternetStreamZero => F::StreamZero,
            Self::InternetStreamLinked => F::StreamLinked,
            Self::InternetStreamFull => F::StreamFull,
            Self::InternetStreamEmpty => F::StreamEmpty,
            Self::InternetStreamBadCount => F::StreamBadCount,
            Self::InternetStreamExcess => F::StreamExcess,
            Self::InternetStreamBadStruct => F::StreamBadStruct,
            Self::InternetStreamIncomplete => F::StreamIncomplete,
            Self::InternetStreamClosed => F::StreamClosed,
            Self::InternetAnsi => F::Ansi,
            Self::InternetWide => F::Wide,
            Self::InternetSplit => F::Split,
            Self::InternetEmpty => F::Empty,
            Self::InternetMiss => F::Miss,
            Self::InternetClosed => F::Closed,
            Self::InternetBadRead => F::BadRead,
            Self::InternetBadCount => F::BadCount,
            Self::InternetNullAvailable => F::NullAvailable,
            Self::InternetFlags => F::Flags,
            Self::InternetAsync => F::Async,
            _ => return None,
        })
    }
    pub fn winhttp(self) -> Option<crate::fixtures::WinHttpFixture> {
        use crate::fixtures::WinHttpFixture as F;
        Some(match self {
            Self::WinHttp => F::Normal,
            Self::WinHttpBeforeReceive => F::BeforeReceive,
            Self::WinHttpBadRead => F::BadReadBuffer,
            Self::WinHttpBadAvailable => F::BadAvailable,
            Self::WinHttpCloseParent => F::CloseParent,
            Self::WinHttpMiss => F::Miss,
            Self::WinHttpAsync => F::Async,
            Self::WinHttpQueryStatus => F::QueryStatus,
            Self::WinHttpQuerySmall => F::QuerySmall,
            Self::WinHttpQueryCustom => F::QueryCustom,
            Self::WinHttpQueryRaw => F::QueryRaw,
            Self::WinHttpEmpty => F::Empty,
            Self::WinHttpUpload => F::Upload,
            Self::WinHttpUploadEarly => F::UploadEarly,
            Self::WinHttpUploadBadCount => F::UploadBadCount,
            Self::WinHttpUploadOverrun => F::UploadOverrun,
            Self::WinHttpUploadIncomplete => F::UploadIncomplete,
            Self::WinHttpUploadClosed => F::UploadClosed,
            Self::WinHttpChunked => F::Chunked,
            Self::WinHttpChunkedSplit => F::ChunkedSplit,
            Self::WinHttpChunkedIncomplete => F::ChunkedIncomplete,
            Self::WinHttpChunkedMalformed => F::ChunkedMalformed,
            Self::WinHttpChunkedZero => F::ChunkedZero,
            _ => return None,
        })
    }
    pub fn binary(self) -> bool {
        matches!(
            self,
            Self::NativeBinaryA
                | Self::NativeBinaryW
                | Self::NativeBinaryPartial
                | Self::NativeBinaryEmpty
                | Self::NativeBinaryMiss
        )
    }
    pub fn http(self) -> bool {
        matches!(
            self,
            Self::HttpBinary
                | Self::HttpPost
                | Self::HttpHeaders
                | Self::HttpBodyMiss
                | Self::HttpChunkedMiss
        )
    }
    pub fn native(self) -> Option<crate::fixtures::DownloadFixture> {
        use crate::fixtures::DownloadFixture as F;
        Some(match self {
            Self::NativeA
            | Self::NativePartial
            | Self::NativeBinaryA
            | Self::NativeBinaryPartial
            | Self::NativeBinaryEmpty => F::Ansi,
            Self::NativeW | Self::NativeBinaryW => F::Wide,
            Self::NativeMiss | Self::NativeBinaryMiss => F::Miss,
            Self::NativeCallback => F::Callback,
            Self::NativeParent => F::MissingParent,
            Self::NativeNull => F::NullUrl,
            _ => return None,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub probe: Probe,
    pub fixture: OfflineHttp,
    pub architecture: String,
    pub cleanup_plan: String,
    pub fixture_document_sha256: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Ping,
    Resolve {
        host: String,
    },
    HttpGet {
        url: String,
    },
    Http {
        request: crate::networkfixtures::HttpRequest,
    },
    Close,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: u32,
    pub request: Operation,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Data {
    Pong,
    Http {
        status: u16,
        body: Vec<u8>,
    },
    HttpFull {
        response: crate::networkfixtures::HttpResponse,
    },
    Closed,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub id: u32,
    pub ok: bool,
    pub value: Option<Data>,
    pub error: Option<String>,
}
impl Reply {
    pub fn validate(&self, expected: u32) -> Result<(), String> {
        if self.id != expected || self.ok != self.value.is_some() || self.ok == self.error.is_some()
        {
            return Err("Malformed or out-of-order broker reply".into());
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct FrameReader {
    header: [u8; 4],
    header_used: usize,
    body: Vec<u8>,
    body_used: usize,
    total: usize,
}
impl FrameReader {
    fn read_some(&mut self, count: usize) -> Result<(), String> {
        self.total = self.total.checked_add(count).ok_or("RPC stream overflow")?;
        if self.total > MAX_STREAM {
            return Err("RPC stream exceeds bound".into());
        }
        Ok(())
    }
    /// EOF means no new bytes yet for an append-only, parent-pinned file.
    /// Partial headers/bodies remain buffered; nothing is parsed prematurely.
    pub fn poll(&mut self, input: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
        while self.header_used < 4 {
            let count = input
                .read(&mut self.header[self.header_used..])
                .map_err(|e| e.to_string())?;
            if count == 0 {
                return Ok(None);
            }
            self.header_used += count;
            self.read_some(count)?;
        }
        if self.body.is_empty() {
            let size = u32::from_le_bytes(self.header) as usize;
            if size == 0 || size > MAX_PACKET {
                return Err("RPC packet length exceeds bound".into());
            }
            self.body.resize(size, 0);
        }
        while self.body_used < self.body.len() {
            let count = input
                .read(&mut self.body[self.body_used..])
                .map_err(|e| e.to_string())?;
            if count == 0 {
                return Ok(None);
            }
            self.body_used += count;
            self.read_some(count)?;
        }
        self.header_used = 0;
        self.body_used = 0;
        Ok(Some(std::mem::take(&mut self.body)))
    }
}
pub fn write_packet(output: &mut impl Write, value: &impl Serialize) -> Result<(), String> {
    let data = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if data.is_empty() || data.len() > MAX_PACKET {
        return Err("RPC packet length exceeds bound".into());
    }
    output
        .write_all(&(data.len() as u32).to_le_bytes())
        .map_err(|e| e.to_string())?;
    output.write_all(&data).map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineHttp {
    pub url: String,
    pub status: u16,
    pub body: Vec<u8>,
}
impl OfflineHttp {
    pub fn validate(&self) -> Result<(), String> {
        // This exact-match-only initial model never interprets the URL as a
        // destination. Full legacy fixture/header/body matching is separate.
        if self.url.is_empty()
            || self.url.len() > 2048
            || !self.url.is_ascii()
            || self.url.bytes().any(|b| b.is_ascii_control())
            || !(self.url.starts_with("https://") || self.url.starts_with("http://"))
            || !(100..=999).contains(&self.status)
            || self.body.len() > 4096
        {
            return Err("Invalid initial offline HTTP fixture".into());
        }
        Ok(())
    }
}
pub struct Service {
    next: u32,
    closed: bool,
    fixture: Option<OfflineHttp>,
    fixtures: Option<crate::networkfixtures::Fixtures>,
}
impl Service {
    pub fn new(fixture: Option<OfflineHttp>) -> Result<Self, String> {
        if let Some(fixture) = &fixture {
            fixture.validate()?;
        }
        Ok(Self {
            next: 1,
            closed: false,
            fixture,
            fixtures: None,
        })
    }
    pub fn with_fixtures(fixtures: crate::networkfixtures::Fixtures) -> Self {
        Self {
            next: 1,
            closed: false,
            fixture: None,
            fixtures: Some(fixtures),
        }
    }
    pub fn closed(&self) -> bool {
        self.closed
    }
    pub fn handle(
        &mut self,
        request: Request,
        mut record: impl FnMut(Value) -> Result<(), String>,
    ) -> Result<Reply, String> {
        if self.closed || request.id != self.next || request.id > MAX_CALLS {
            return Err("Out-of-order or excessive broker request".into());
        }
        self.next += 1;
        let op = match &request.request {
            Operation::Ping => "ping",
            Operation::Resolve { .. } => "resolve",
            Operation::HttpGet { .. } => "http_get",
            Operation::Http { .. } => "http",
            Operation::Close => "close",
        };
        record(json!({"event":"request","id":request.id,"op":op}))?;
        let mut denied = None;
        let value = match request.request {
            Operation::Ping => Some(Data::Pong),
            Operation::Close => {
                record(json!({"event":"broker_closed"}))?;
                self.closed = true;
                Some(Data::Closed)
            }
            Operation::Resolve { host } => {
                if host.is_empty()
                    || host.len() > 253
                    || !host.is_ascii()
                    || host.bytes().any(|b| b.is_ascii_control())
                {
                    return Err("Invalid broker hostname".into());
                }
                record(json!({"event":"dns_attempt","host":host,"id":request.id}))?;
                denied = Some("DNS unavailable in offline replay".to_owned());
                None
            }
            Operation::HttpGet { url } => {
                if url.is_empty()
                    || url.len() > 2048
                    || !url.is_ascii()
                    || url.bytes().any(|b| b.is_ascii_control())
                {
                    return Err("Invalid broker URL".into());
                }
                record(
                    json!({"event":"http_request_attempt","url":url,"method":"GET","id":request.id}),
                )?;
                if let Some(fixture) = self.fixture.as_ref().filter(|fixture| fixture.url == url) {
                    record(
                        json!({"event":"network_fixture_match","id":"initial-exact-get","url":url}),
                    )?;
                    record(
                        json!({"event":"http_request","source":"fixture","url":url,"status":fixture.status,"size":fixture.body.len(),"sha256":format!("{:x}",Sha256::digest(&fixture.body))}),
                    )?;
                    Some(Data::Http {
                        status: fixture.status,
                        body: fixture.body.clone(),
                    })
                } else if let Some(rule) = self
                    .fixtures
                    .as_ref()
                    .map(|fixtures| {
                        fixtures.matching(&crate::networkfixtures::HttpRequest::get(url.clone()))
                    })
                    .transpose()?
                    .flatten()
                {
                    record(json!({"event":"network_fixture_match","id":rule.id,"url":url}))?;
                    record(
                        json!({"event":"http_request","source":"fixture","url":url,"status":rule.response.status,"size":rule.response.body.len(),"sha256":format!("{:x}",Sha256::digest(&rule.response.body))}),
                    )?;
                    Some(Data::HttpFull {
                        response: rule.response.clone(),
                    })
                } else {
                    denied = Some("No exact offline HTTP fixture".to_owned());
                    None
                }
            }
            Operation::Http { request: mut http } => {
                http.normalize()?;
                record(
                    json!({"event":"http_request_attempt","url":http.url,"method":http.method,"chunked":http.chunked,"header_count":http.headers.len(),"body_size":http.body.len(),"body_sha256":format!("{:x}",Sha256::digest(&http.body)),"id":request.id}),
                )?;
                if let Some(rule) = self
                    .fixtures
                    .as_ref()
                    .map(|fixtures| fixtures.matching(&http))
                    .transpose()?
                    .flatten()
                {
                    record(json!({"event":"network_fixture_match","id":rule.id,"url":http.url}))?;
                    record(
                        json!({"event":"http_request","source":"fixture","url":http.url,"status":rule.response.status,"size":rule.response.body.len(),"sha256":format!("{:x}",Sha256::digest(&rule.response.body))}),
                    )?;
                    Some(Data::HttpFull {
                        response: rule.response.clone(),
                    })
                } else {
                    denied = Some("No exact offline HTTP fixture".into());
                    None
                }
            }
        };
        if let Some(error) = &denied {
            record(json!({"event":"network_denied","id":request.id,"reason":error}))?;
        }
        Ok(Reply {
            id: request.id,
            ok: value.is_some(),
            value,
            error: denied,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_http_binary_round_trip_records_attempt_before_return_and_denies_body_mismatch() {
        let document = json!({"version":1,"rules":[{"id":"post","request":{"method":"POST","url":"https://fixture.invalid/a","chunked":true,"headers":{"X-Test":"one"},"body_base64":"AP8="},"response":{"status":206,"reason":"Partial","version":"HTTP/1.0","headers":[["Set-Cookie","a"],["Set-Cookie","b"]],"body_utf8":"binary\u{0}"}}]});
        let fixtures =
            crate::networkfixtures::Fixtures::parse(&serde_json::to_vec(&document).unwrap())
                .unwrap();
        let expected = fixtures.rules()[0].response.clone();
        let mut http = fixtures.rules()[0].request.clone();
        let mut service = Service::with_fixtures(fixtures);
        let mut events = Vec::new();
        let result = service
            .handle(
                Request {
                    id: 1,
                    request: Operation::Http {
                        request: http.clone(),
                    },
                },
                |e| {
                    events.push(e);
                    Ok(())
                },
            )
            .unwrap();
        assert!(matches!(result.value,Some(Data::HttpFull{response}) if response==expected));
        assert_eq!(events[1]["event"], "http_request_attempt");
        assert_eq!(events[1]["body_size"], 2);
        assert_eq!(events[2]["id"], "post");
        http.body.push(0);
        assert!(
            !service
                .handle(
                    Request {
                        id: 2,
                        request: Operation::Http { request: http }
                    },
                    |_| Ok(())
                )
                .unwrap()
                .ok
        );
        let mut service = Service::with_fixtures(
            crate::networkfixtures::Fixtures::parse(&serde_json::to_vec(&document).unwrap())
                .unwrap(),
        );
        let http = crate::networkfixtures::HttpRequest {
            body: vec![0, 255],
            method: "POST".into(),
            chunked: true,
            headers: std::collections::BTreeMap::from([("x-test".into(), "one".into())]),
            ..crate::networkfixtures::HttpRequest::get("https://fixture.invalid/a".into())
        };
        assert!(
            service
                .handle(
                    Request {
                        id: 1,
                        request: Operation::Http { request: http }
                    },
                    |e| if e["event"] == "http_request_attempt" {
                        Err("disk full".into())
                    } else {
                        Ok(())
                    }
                )
                .is_err()
        );
    }
    #[test]
    fn frames_preserve_every_partial_header_and_body_without_parsing_early() {
        let request = Request {
            id: 1,
            request: Operation::Ping,
        };
        let mut data = Vec::new();
        write_packet(&mut data, &request).unwrap();
        for cut in 0..data.len() {
            let mut reader = FrameReader::default();
            assert!(reader.poll(&mut &data[..cut]).unwrap().is_none());
            let complete = reader.poll(&mut &data[cut..]).unwrap().unwrap();
            assert_eq!(serde_json::from_slice::<Request>(&complete).unwrap().id, 1);
        }
        let mut reader = FrameReader::default();
        let doubled = [data.clone(), data].concat();
        let mut input = &doubled[..];
        assert!(reader.poll(&mut input).unwrap().is_some());
        assert!(reader.poll(&mut input).unwrap().is_some());
        assert!(reader.poll(&mut input).unwrap().is_none());
    }
    #[test]
    fn frames_reject_bounds_and_reply_id_or_success_shape_mismatches() {
        for size in [0, MAX_PACKET as u32 + 1, u32::MAX] {
            assert!(
                FrameReader::default()
                    .poll(&mut &size.to_le_bytes()[..])
                    .is_err()
            );
        }
        let mut reader = FrameReader {
            total: MAX_STREAM,
            ..FrameReader::default()
        };
        assert!(reader.poll(&mut &1u32.to_le_bytes()[..]).is_err());
        let reply = Reply {
            id: 2,
            ok: true,
            value: Some(Data::Pong),
            error: None,
        };
        assert!(reply.validate(1).is_err());
        reply.validate(2).unwrap();
        assert!(
            Reply {
                error: Some("contradictory".into()),
                ..reply
            }
            .validate(2)
            .is_err()
        );
    }
    #[test]
    fn offline_match_is_exact_and_attempts_are_recorded_before_result() {
        let fixture = OfflineHttp {
            url: "https://fixture.invalid/payload".into(),
            status: 200,
            body: b"RUST".to_vec(),
        };
        let mut service = Service::new(Some(fixture.clone())).unwrap();
        let mut events = Vec::new();
        let reply = service
            .handle(
                Request {
                    id: 1,
                    request: Operation::HttpGet { url: fixture.url },
                },
                |e| {
                    events.push(e);
                    Ok(())
                },
            )
            .unwrap();
        assert!(matches!(reply.value,Some(Data::Http{status:200,body}) if body==b"RUST"));
        assert_eq!(events[1]["event"], "http_request_attempt");
        assert_eq!(events[2]["event"], "network_fixture_match");
        let reply = service
            .handle(
                Request {
                    id: 2,
                    request: Operation::HttpGet {
                        url: "https://fixture.invalid/PAYLOAD".into(),
                    },
                },
                |_| Ok(()),
            )
            .unwrap();
        assert!(!reply.ok);
        let reply = service
            .handle(
                Request {
                    id: 3,
                    request: Operation::Resolve {
                        host: "example.invalid".into(),
                    },
                },
                |_| Ok(()),
            )
            .unwrap();
        assert!(!reply.ok);
        assert!(
            service
                .handle(
                    Request {
                        id: 5,
                        request: Operation::Ping
                    },
                    |_| Ok(())
                )
                .is_err()
        );
        service
            .handle(
                Request {
                    id: 4,
                    request: Operation::Close,
                },
                |_| Ok(()),
            )
            .unwrap();
        assert!(service.closed());
        assert!(
            service
                .handle(
                    Request {
                        id: 5,
                        request: Operation::Ping
                    },
                    |_| Ok(())
                )
                .is_err()
        );
    }
    #[test]
    fn failed_durable_record_aborts_before_fixture_success_and_bounds_are_explicit() {
        let fixture = OfflineHttp {
            url: "http://fixture.invalid/".into(),
            status: 200,
            body: vec![1],
        };
        let mut service = Service::new(Some(fixture.clone())).unwrap();
        let mut count = 0;
        assert!(
            service
                .handle(
                    Request {
                        id: 1,
                        request: Operation::HttpGet { url: fixture.url }
                    },
                    |_| {
                        count += 1;
                        if count == 2 {
                            Err("disk failure".into())
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        assert_eq!(count, 2);
        assert!(
            Service::new(Some(OfflineHttp {
                url: "https://fixture.invalid/".into(),
                status: 200,
                body: vec![0; 4097]
            }))
            .is_err()
        );
        let mut service = Service {
            next: MAX_CALLS + 1,
            closed: false,
            fixture: None,
            fixtures: None,
        };
        assert!(
            service
                .handle(
                    Request {
                        id: MAX_CALLS + 1,
                        request: Operation::Ping
                    },
                    |_| Ok(())
                )
                .is_err()
        );
    }
}
