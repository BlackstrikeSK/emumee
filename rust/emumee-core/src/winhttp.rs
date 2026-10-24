//! Guest-only synchronous WinHTTP handles. No host WinHTTP or socket calls.
//! Unsupported proxy/async/extended chunk semantics remain explicit model stops.
mod chunks;
use crate::networkfixtures::{HttpRequest, HttpResponse, MAX_BODY, validate_url};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
const MAX_HANDLES: usize = 4096;
const MAX_RESPONSES: usize = 32 * 1024 * 1024;
const MAX_PENDING: usize = 128;
const MAX_PENDING_BYTES: usize = 32 * 1024 * 1024;
#[derive(Debug, Error)]
pub enum HttpError {
    #[error("Guest WinHTTP: {reason} (Win32 {code})")]
    Windows { code: u32, reason: &'static str },
    #[error("Guest WinHTTP profile unsupported: {0}")]
    Unsupported(&'static str),
}
fn error(code: u32, reason: &'static str) -> HttpError {
    HttpError::Windows { code, reason }
}
type Result<T> = std::result::Result<T, HttpError>;
pub struct HeaderValue {
    pub value: String,
    pub next_index: Option<u32>,
}
pub enum SendAction {
    Transmit(HttpRequest),
    Staged {
        url: String,
        initial: usize,
        total: Option<usize>,
    },
}
impl SendAction {
    pub fn url(&self) -> &str {
        match self {
            Self::Transmit(request) => &request.url,
            Self::Staged { url, .. } => url,
        }
    }
}
enum Phase {
    Created,
    InFlight,
    Pending {
        request: HttpRequest,
        total: Option<usize>,
        chunks: u32,
        decoder: Option<chunks::Decoder>,
        wire_bytes: usize,
    },
    Sent(HttpResponse),
    Ready {
        response: HttpResponse,
        at: usize,
    },
}
struct Request {
    parent: u64,
    method: String,
    url: String,
    total: Option<u32>,
    phase: Phase,
}
enum Object {
    Session,
    Connection {
        parent: u64,
        host: String,
        port: u16,
    },
    Request(Box<Request>),
}
impl Object {
    fn parent(&self) -> Option<u64> {
        match self {
            Self::Session => None,
            Self::Connection { parent, .. } => Some(*parent),
            Self::Request(request) => Some(request.parent),
        }
    }
    fn response_bytes(&self) -> usize {
        match self {
            Self::Request(request) => match &request.phase {
                Phase::Sent(response) | Phase::Ready { response, .. } => response.body.len(),
                _ => 0,
            },
            _ => 0,
        }
    }
    fn pending(&self) -> Option<usize> {
        match self {
            Self::Request(request) => match &request.phase {
                Phase::Pending {
                    request, decoder, ..
                } => {
                    Some(request.body.len() + decoder.as_ref().map_or(0, chunks::Decoder::buffered))
                }
                _ => None,
            },
            _ => None,
        }
    }
}
pub struct WinHttp {
    next: u64,
    objects: BTreeMap<u64, Object>,
}
impl Default for WinHttp {
    fn default() -> Self {
        Self {
            next: 0x59000000,
            objects: BTreeMap::new(),
        }
    }
}
#[cfg(test)]
mod staged_tests {
    use super::*;
    #[test]
    fn full_and_empty_initial_streams_remain_pending_until_explicit_end() {
        for body in [Vec::new(), b"RUSTBODY".to_vec()] {
            let mut http = WinHttp::internet_profile();
            let session = http.open("", 1, 0).unwrap();
            let connection = http.connect(session, "fixture.invalid", 443).unwrap();
            let handle = http
                .open_request(connection, "POST", "/payload", true)
                .unwrap();
            let action = http
                .begin_staged(handle, BTreeMap::new(), body.clone(), body.len() as u32)
                .unwrap();
            assert!(matches!(action, SendAction::Staged { .. }));
            assert!(http.available(handle).is_err());
            assert!(http.receive(handle).is_err());
            let request = http.pending_for_receive(handle).unwrap().unwrap();
            assert_eq!(request.body, body);
            assert_eq!(request.url, "https://fixture.invalid:443/payload");
            assert!(http.receive(handle).is_err());
            http.complete(
                handle,
                HttpResponse {
                    status: 200,
                    reason: "OK".into(),
                    version: "HTTP/1.0".into(),
                    headers: vec![],
                    body: vec![],
                },
            )
            .unwrap();
            http.receive(handle).unwrap();
            assert_eq!(http.available(handle).unwrap(), 0);
        }
    }
}
impl WinHttp {
    /// Separate handle namespace for the synchronous WinINet URL stream adapter.
    pub fn internet_profile() -> Self {
        Self {
            next: 0x5c000000,
            objects: BTreeMap::new(),
        }
    }
    /// A literal HTTP GET stream parented directly by its WinINet session.
    /// URL parsing validates only: it never resolves or rewrites a destination.
    pub fn open_url(&mut self, session: u64, url: &str) -> Result<(u64, HttpRequest)> {
        if !matches!(self.object(session)?, Object::Session) {
            return Err(error(12018, "session handle required"));
        }
        if !url.is_ascii() || url.contains('#') {
            return Err(HttpError::Unsupported(
                "WinINet URL escaping, fragment or Unicode",
            ));
        }
        let mut message = HttpRequest::get(url.into());
        message
            .normalize()
            .map_err(|_| error(12005, "invalid HTTP URL"))?;
        let handle = self.insert(Object::Request(Box::new(Request {
            parent: session,
            method: "GET".into(),
            url: url.into(),
            total: Some(0),
            phase: Phase::InFlight,
        })))?;
        Ok((handle, message))
    }
    fn insert(&mut self, object: Object) -> Result<u64> {
        if self.objects.len() >= MAX_HANDLES || self.next > u32::MAX as u64 - 8 {
            return Err(error(8, "handle quota exceeded"));
        }
        let handle = self.next;
        self.next += 8;
        self.objects.insert(handle, object);
        Ok(handle)
    }
    fn object(&self, handle: u64) -> Result<&Object> {
        self.objects
            .get(&handle)
            .ok_or_else(|| error(6, "invalid or closed handle"))
    }
    fn request(&self, handle: u64) -> Result<&Request> {
        match self.object(handle)? {
            Object::Request(request) => Ok(request),
            _ => Err(error(12018, "request handle required")),
        }
    }
    fn request_mut(&mut self, handle: u64) -> Result<&mut Request> {
        match self
            .objects
            .get_mut(&handle)
            .ok_or_else(|| error(6, "invalid or closed handle"))?
        {
            Object::Request(request) => Ok(request),
            _ => Err(error(12018, "request handle required")),
        }
    }
    pub fn open(&mut self, agent: &str, access: u32, flags: u32) -> Result<u64> {
        if agent.chars().count() > 1024 || agent.contains(['\r', '\n', '\0']) {
            return Err(error(87, "invalid user agent"));
        }
        // Default/no-proxy sessions share this explicit offline logical model;
        // no machine or browser proxy setting is consulted.
        if !matches!(access, 0 | 1) || flags != 0 {
            return Err(HttpError::Unsupported(
                "proxy selection or asynchronous session",
            ));
        }
        self.insert(Object::Session)
    }
    pub fn connect(&mut self, session: u64, host: &str, port: u16) -> Result<u64> {
        if !matches!(self.object(session)?, Object::Session) {
            return Err(error(12018, "session handle required"));
        }
        if host.is_empty()
            || host.len() > 253
            || !host.is_ascii()
            || host.contains(['/', ':', '@', '?', '#', '\\'])
            || host.bytes().any(|b| b.is_ascii_control() || b == b' ')
        {
            return Err(HttpError::Unsupported(
                "server name outside initial ASCII DNS/IPv4 profile",
            ));
        }
        validate_url(&format!("http://{host}/")).map_err(|_| error(12005, "invalid server URL"))?;
        self.insert(Object::Connection {
            parent: session,
            host: host.into(),
            port,
        })
    }
    pub fn open_request(
        &mut self,
        connection: u64,
        method: &str,
        path: &str,
        secure: bool,
    ) -> Result<u64> {
        let Object::Connection { host, port, .. } = self.object(connection)? else {
            return Err(error(12018, "connection handle required"));
        };
        if !path.starts_with('/')
            || !path.is_ascii()
            || path.contains(['#', '\\'])
            || path.bytes().any(|b| b.is_ascii_control() || b == b' ')
        {
            return Err(HttpError::Unsupported(
                "object path escaping, fragment or Unicode",
            ));
        }
        let port = if *port == 0 {
            if secure { 443 } else { 80 }
        } else {
            *port
        };
        // Port443 alone does not request TLS. The SECURE flag determines the
        // scheme, per WinHttpConnect/WinHttpOpenRequest's documented contract.
        let url = format!(
            "{}://{host}:{port}{path}",
            if secure { "https" } else { "http" }
        );
        let mut request = HttpRequest::get(url.clone());
        request.method = method.into();
        request
            .normalize()
            .map_err(|_| HttpError::Unsupported("HTTP verb or URL profile"))?;
        self.insert(Object::Request(Box::new(Request {
            parent: connection,
            method: method.into(),
            url,
            total: None,
            phase: Phase::Created,
        })))
    }
    pub fn begin_send(
        &mut self,
        handle: u64,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
        total: u32,
    ) -> Result<SendAction> {
        self.begin_mode(handle, headers, body, total, false)
    }
    /// Fixed-length WinINet SendRequestEx waits for EndRequest even when the
    /// initial buffer already contains the complete (possibly empty) body.
    pub fn begin_staged(
        &mut self,
        handle: u64,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
        total: u32,
    ) -> Result<SendAction> {
        if total == u32::MAX {
            return Err(HttpError::Unsupported(
                "WinINet unknown-length streamed upload",
            ));
        }
        self.begin_mode(handle, headers, body, total, true)
    }
    fn begin_mode(
        &mut self,
        handle: u64,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
        total: u32,
        force_staged: bool,
    ) -> Result<SendAction> {
        let request = self.request(handle)?;
        if !matches!(request.phase, Phase::Created)
            && !matches!(&request.phase,Phase::Ready{response,at} if *at==response.body.len())
        {
            return Err(error(12019, "prior response has not been fully consumed"));
        }
        let chunked = total == u32::MAX;
        if (!chunked && (total as usize > MAX_BODY || (total as usize) < body.len()))
            || (chunked && !body.is_empty())
        {
            return Err(error(87, "invalid total/initial request length"));
        }
        if request.total.is_some_and(|previous| previous != total) {
            return Err(error(87, "total request length changed on reused handle"));
        }
        let mut message = HttpRequest {
            method: request.method.clone(),
            url: request.url.clone(),
            chunked,
            headers,
            body,
        };
        message
            .normalize()
            .map_err(|_| error(87, "invalid HTTP request fields"))?;
        if chunked {
            if message.headers.contains_key("content-length")
                || !message
                    .headers
                    .get("transfer-encoding")
                    .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
            {
                return Err(error(
                    87,
                    "chunked request requires Transfer-Encoding and no Content-Length",
                ));
            }
        } else {
            if message
                .headers
                .get("content-length")
                .is_some_and(|value| value.parse::<u64>().ok() != Some(total as u64))
            {
                return Err(error(
                    87,
                    "Content-Length differs from total request length",
                ));
            }
            if message.headers.contains_key("transfer-encoding") {
                return Err(error(87, "Transfer-Encoding requires unknown total length"));
            }
        }
        if force_staged || chunked || total as usize > message.body.len() {
            let pending: Vec<usize> = self.objects.values().filter_map(Object::pending).collect();
            if pending.len() >= MAX_PENDING
                || pending.iter().sum::<usize>() + message.body.len() > MAX_PENDING_BYTES
            {
                return Err(error(8, "pending upload quota exceeded"));
            }
            let length = (!chunked).then_some(total as usize);
            let action = SendAction::Staged {
                url: message.url.clone(),
                initial: message.body.len(),
                total: length,
            };
            let request = self.request_mut(handle)?;
            request.total = Some(total);
            request.phase = Phase::Pending {
                request: message,
                total: length,
                chunks: 0,
                decoder: chunked.then(chunks::Decoder::default),
                wire_bytes: 0,
            };
            Ok(action)
        } else {
            let request = self.request_mut(handle)?;
            request.total = Some(total);
            request.phase = Phase::InFlight;
            Ok(SendAction::Transmit(message))
        }
    }
    pub fn write(&mut self, handle: u64, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Err(error(87, "zero-byte WinHttpWriteData"));
        }
        let Phase::Pending {
            request,
            total,
            chunks,
            wire_bytes,
            ..
        } = &self.request(handle)?.phase
        else {
            return Err(error(12019, "no pending upload"));
        };
        if data.len() > MAX_BODY
            || total.is_some_and(|total| request.body.len() + data.len() > total)
        {
            return Err(error(87, "write exceeds declared upload length"));
        }
        let bytes = self
            .objects
            .values()
            .filter_map(Object::pending)
            .sum::<usize>();
        if *chunks >= 4096
            || bytes + data.len() > MAX_PENDING_BYTES
            || *wire_bytes + data.len() > MAX_PENDING_BYTES
        {
            return Err(error(8, "pending upload write quota exceeded"));
        }
        let Phase::Pending {
            request,
            chunks,
            decoder,
            wire_bytes,
            ..
        } = &mut self.request_mut(handle)?.phase
        else {
            unreachable!()
        };
        if let Some(decoder) = decoder {
            decoder.feed(data, &mut request.body);
        } else {
            request.body.extend_from_slice(data);
        }
        *chunks += 1;
        *wire_bytes += data.len();
        Ok(data.len())
    }
    pub fn pending_for_receive(&mut self, handle: u64) -> Result<Option<HttpRequest>> {
        if let Phase::Pending {
            request,
            total,
            decoder,
            ..
        } = &self.request(handle)?.phase
        {
            if let Some(decoder) = decoder {
                if let Some(error) = decoder.failure() {
                    return Err(HttpError::Unsupported(error));
                }
                if !decoder.complete() {
                    return Err(error(12019, "chunk wire body is incomplete"));
                }
            } else if request.body.len() != total.unwrap() {
                return Err(error(12019, "upload body is incomplete"));
            }
            let phase = std::mem::replace(&mut self.request_mut(handle)?.phase, Phase::InFlight);
            let Phase::Pending { request, .. } = phase else {
                unreachable!()
            };
            Ok(Some(request))
        } else {
            Ok(None)
        }
    }
    pub fn upload_status(&self, handle: u64) -> Result<(String, usize, Option<usize>)> {
        match &self.request(handle)?.phase {
            Phase::Pending { request, total, .. } => {
                Ok((request.url.clone(), request.body.len(), *total))
            }
            _ => Err(error(12019, "no pending upload")),
        }
    }
    pub fn complete(&mut self, handle: u64, response: HttpResponse) -> Result<()> {
        if !matches!(self.request(handle)?.phase, Phase::InFlight) {
            return Err(error(12019, "no request is in flight"));
        }
        response
            .validate()
            .map_err(|_| HttpError::Unsupported("malformed broker HTTP response"))?;
        let bytes = self
            .objects
            .values()
            .map(Object::response_bytes)
            .sum::<usize>();
        if bytes + response.body.len() > MAX_RESPONSES {
            return Err(error(8, "retained response quota exceeded"));
        }
        self.request_mut(handle)?.phase = Phase::Sent(response);
        Ok(())
    }
    pub fn fail(&mut self, handle: u64) -> Result<()> {
        if !matches!(self.request(handle)?.phase, Phase::InFlight) {
            return Err(error(12019, "no request is in flight"));
        }
        self.request_mut(handle)?.phase = Phase::Created;
        Ok(())
    }
    pub fn receive(&mut self, handle: u64) -> Result<()> {
        let request = self.request_mut(handle)?;
        if !matches!(request.phase, Phase::Sent(_)) {
            return Err(error(12019, "response not available for receive"));
        }
        let Phase::Sent(response) = std::mem::replace(&mut request.phase, Phase::Created) else {
            unreachable!()
        };
        request.phase = Phase::Ready { response, at: 0 };
        Ok(())
    }
    pub fn response(&self, handle: u64) -> Result<&HttpResponse> {
        match &self.request(handle)?.phase {
            Phase::Ready { response, .. } => Ok(response),
            _ => Err(error(12019, "response headers/body not ready")),
        }
    }
    pub fn query(
        &self,
        handle: u64,
        attribute: u16,
        name: Option<&str>,
        index: u32,
    ) -> Result<HeaderValue> {
        let response = self.response(handle)?;
        if index > 64 {
            return Err(error(87, "header index exceeds profile bound"));
        }
        let named = match attribute {
            1 => Some("content-type"),
            5 => Some("content-length"),
            33 => Some("location"),
            65535 => {
                let name = name.ok_or_else(|| error(87, "custom header name missing"))?;
                if name.is_empty()
                    || name.len() > 256
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                {
                    return Err(error(87, "invalid custom header name"));
                }
                Some(name)
            }
            18 | 19 | 20 | 22 => None,
            _ => return Err(HttpError::Unsupported("header query attribute")),
        };
        if let Some(name) = named {
            let value = response
                .headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .nth(index as usize)
                .map(|(_, value)| value.clone())
                .ok_or_else(|| error(12150, "response header not found"))?;
            return Ok(HeaderValue {
                value,
                next_index: Some(index + 1),
            });
        }
        let value = match attribute {
            18 => response.version.clone(),
            19 => response.status.to_string(),
            20 => response.reason.clone(),
            22 => {
                let mut text = format!(
                    "{} {} {}\r\n",
                    response.version, response.status, response.reason
                );
                for (name, value) in &response.headers {
                    text.push_str(name);
                    text.push_str(": ");
                    text.push_str(value);
                    text.push_str("\r\n");
                }
                text.push_str("\r\n");
                if text.chars().count() > 16 * 1024 {
                    return Err(HttpError::Unsupported("raw response header text bound"));
                }
                text
            }
            _ => unreachable!(),
        };
        Ok(HeaderValue {
            value,
            next_index: None,
        })
    }
    pub fn available(&self, handle: u64) -> Result<usize> {
        match &self.request(handle)?.phase {
            Phase::Ready { response, at } => Ok(response.body.len() - at),
            _ => Err(error(12019, "response body not ready")),
        }
    }
    /// Native adapters validate/write all guest outputs before committing this
    /// cursor. A bad output pointer must not silently consume response bytes.
    pub fn peek_read(&self, handle: u64, size: usize) -> Result<&[u8]> {
        if size > MAX_BODY {
            return Err(error(87, "read exceeds transfer bound"));
        }
        match &self.request(handle)?.phase {
            Phase::Ready { response, at } => {
                Ok(&response.body[*at..(*at + size).min(response.body.len())])
            }
            _ => Err(error(12019, "response body not ready")),
        }
    }
    pub fn consume(&mut self, handle: u64, count: usize) -> Result<()> {
        match &mut self.request_mut(handle)?.phase {
            Phase::Ready { response, at } if count <= response.body.len() - *at => {
                *at += count;
                Ok(())
            }
            Phase::Ready { .. } => Err(error(87, "read cursor exceeds response")),
            _ => Err(error(12019, "response body not ready")),
        }
    }
    pub fn close(&mut self, handle: u64) -> Result<usize> {
        self.object(handle)?;
        let mut affected = BTreeSet::from([handle]);
        for _ in 0..2 {
            for (id, object) in &self.objects {
                if object
                    .parent()
                    .is_some_and(|parent| affected.contains(&parent))
                {
                    affected.insert(*id);
                }
            }
        }
        let count = affected.len();
        for id in affected {
            self.objects.remove(&id);
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunk_wire_is_decoded_before_publication_and_zero_writes_do_not_terminate_it() {
        let mut state = WinHttp::default();
        let (_, _, handle) = request(&mut state);
        let headers = BTreeMap::from([("Transfer-Encoding".into(), "chunked".into())]);
        assert!(matches!(
            state
                .begin_send(handle, headers, Vec::new(), u32::MAX)
                .unwrap(),
            SendAction::Staged { total: None, .. }
        ));
        state.write(handle, b"4\r\nRU").unwrap();
        code(state.pending_for_receive(handle), 12019);
        code(state.write(handle, b""), 87);
        state
            .write(handle, b"ST\r\n4\r\nBODY\r\n0\r\n\r\n")
            .unwrap();
        let message = state.pending_for_receive(handle).unwrap().unwrap();
        assert!(message.chunked);
        assert_eq!(message.body, b"RUSTBODY");
        assert_eq!(message.headers["transfer-encoding"], "chunked");
    }
    #[test]
    fn staged_fixed_upload_retains_partial_body_until_complete_receive_and_rejects_excess() {
        let mut state = WinHttp::default();
        let (_, _, handle) = request(&mut state);
        code(
            state.begin_send(
                handle,
                BTreeMap::from([("Content-Length".into(), "9".into())]),
                b"RUST".to_vec(),
                8,
            ),
            87,
        );
        assert!(matches!(
            state
                .begin_send(handle, BTreeMap::new(), b"RUST".to_vec(), 8)
                .unwrap(),
            SendAction::Staged {
                initial: 4,
                total: Some(8),
                ..
            }
        ));
        code(state.pending_for_receive(handle), 12019);
        assert_eq!(state.upload_status(handle).unwrap().1, 4);
        assert_eq!(state.write(handle, b"BOD").unwrap(), 3);
        code(state.pending_for_receive(handle), 12019);
        code(state.write(handle, b"YY"), 87);
        assert_eq!(state.write(handle, b"Y").unwrap(), 1);
        let complete = state.pending_for_receive(handle).unwrap().unwrap();
        assert_eq!(complete.body, b"RUSTBODY");
        assert!(!complete.chunked);
        code(state.write(handle, b"X"), 12019);
        state.complete(handle, response()).unwrap();
        state.receive(handle).unwrap();
        assert_eq!(state.peek_read(handle, 4).unwrap(), [0, 255, 128, 1]);
    }
    #[test]
    fn pending_upload_quotas_are_released_by_parent_close_and_never_truncate_bodies() {
        let mut state = WinHttp::default();
        let (session, connection, first) = request(&mut state);
        state
            .begin_send(first, BTreeMap::new(), Vec::new(), 1)
            .unwrap();
        for _ in 1..MAX_PENDING {
            let h = state.open_request(connection, "POST", "/", true).unwrap();
            state.begin_send(h, BTreeMap::new(), Vec::new(), 1).unwrap();
        }
        let extra = state.open_request(connection, "POST", "/", true).unwrap();
        code(state.begin_send(extra, BTreeMap::new(), Vec::new(), 1), 8);
        state.close(session).unwrap();
        let (_, _, handle) = request(&mut state);
        state
            .begin_send(handle, BTreeMap::new(), b"R".to_vec(), 4)
            .unwrap();
        assert_eq!(state.write(handle, b"UST").unwrap(), 3);
        assert_eq!(
            state.pending_for_receive(handle).unwrap().unwrap().body,
            b"RUST"
        );
    }
    fn request(state: &mut WinHttp) -> (u64, u64, u64) {
        let session = state.open("Owned fixture", 1, 0).unwrap();
        let connection = state.connect(session, "fixture.invalid", 443).unwrap();
        let request = state
            .open_request(connection, "GET", "/payload?q=One", true)
            .unwrap();
        (session, connection, request)
    }
    fn response() -> HttpResponse {
        HttpResponse {
            status: 206,
            reason: "Partial".into(),
            version: "HTTP/1.0".into(),
            headers: vec![
                ("Set-Cookie".into(), "a".into()),
                ("Set-Cookie".into(), "b".into()),
            ],
            body: vec![0, 255, 128, 1],
        }
    }
    fn code<T>(result: Result<T>, expected: u32) {
        assert!(matches!(result,Err(HttpError::Windows{code,..}) if code==expected));
    }
    #[test]
    fn synchronous_state_preserves_literal_request_binary_cursor_and_resend_contract() {
        let mut state = WinHttp::default();
        let (_, _, handle) = request(&mut state);
        code(state.available(handle), 12019);
        let sent = state
            .begin_send(handle, BTreeMap::new(), Vec::new(), 0)
            .unwrap();
        assert_eq!(sent.url(), "https://fixture.invalid:443/payload?q=One");
        code(
            state.begin_send(handle, BTreeMap::new(), Vec::new(), 0),
            12019,
        );
        state.complete(handle, response()).unwrap();
        code(state.peek_read(handle, 4), 12019);
        state.receive(handle).unwrap();
        assert_eq!(state.response(handle).unwrap().headers.len(), 2);
        assert_eq!(state.available(handle).unwrap(), 4);
        assert_eq!(state.peek_read(handle, 2).unwrap(), [0, 255]);
        assert_eq!(state.peek_read(handle, 2).unwrap(), [0, 255]);
        state.consume(handle, 2).unwrap();
        code(
            state.begin_send(handle, BTreeMap::new(), Vec::new(), 0),
            12019,
        );
        assert_eq!(state.peek_read(handle, 100).unwrap(), [128, 1]);
        state.consume(handle, 2).unwrap();
        assert!(state.peek_read(handle, 100).unwrap().is_empty());
        code(state.begin_send(handle, BTreeMap::new(), vec![1], 1), 87);
        state
            .begin_send(handle, BTreeMap::new(), Vec::new(), 0)
            .unwrap();
        state.fail(handle).unwrap();
        state
            .begin_send(handle, BTreeMap::new(), Vec::new(), 0)
            .unwrap();
    }
    #[test]
    fn header_queries_require_ready_response_preserve_duplicates_and_do_not_invent_content_length()
    {
        let mut state = WinHttp::default();
        let (_, _, handle) = request(&mut state);
        state
            .begin_send(handle, BTreeMap::new(), Vec::new(), 0)
            .unwrap();
        state.complete(handle, response()).unwrap();
        code(state.query(handle, 19, None, 0), 12019);
        state.receive(handle).unwrap();
        assert_eq!(state.query(handle, 19, None, 0).unwrap().value, "206");
        assert_eq!(state.query(handle, 18, None, 0).unwrap().value, "HTTP/1.0");
        for (index, value) in [(0, "a"), (1, "b")] {
            let found = state
                .query(handle, 65535, Some("SET-cookie"), index)
                .unwrap();
            assert_eq!(found.value, value);
            assert_eq!(found.next_index, Some(index + 1));
        }
        code(state.query(handle, 65535, Some("Set-Cookie"), 2), 12150);
        code(state.query(handle, 5, None, 0), 12150);
        code(state.query(handle, 65535, Some("bad name"), 0), 87);
        assert_eq!(
            state.query(handle, 22, None, 0).unwrap().value,
            "HTTP/1.0 206 Partial\r\nSet-Cookie: a\r\nSet-Cookie: b\r\n\r\n"
        );
        assert_eq!(state.available(handle).unwrap(), 4);
    }
    #[test]
    fn handles_are_typed_parent_close_invalidates_descendants_and_ports_do_not_imply_tls() {
        let mut state = WinHttp::default();
        let (session, connection, handle) = request(&mut state);
        code(state.connect(handle, "fixture.invalid", 80), 12018);
        code(state.receive(session), 12018);
        code(state.available(42), 6);
        let plain = state.open_request(connection, "GET", "/", false).unwrap();
        assert_eq!(
            state
                .begin_send(plain, BTreeMap::new(), Vec::new(), 0)
                .unwrap()
                .url(),
            "http://fixture.invalid:443/"
        );
        assert_eq!(state.close(session).unwrap(), 4);
        code(state.receive(handle), 6);
        code(state.close(connection), 6);
        let session = state.open("", 0, 0).unwrap();
        let connection = state.connect(session, "fixture.invalid", 0).unwrap();
        let secure = state.open_request(connection, "HEAD", "/", true).unwrap();
        assert_eq!(
            state
                .begin_send(secure, BTreeMap::new(), Vec::new(), 0)
                .unwrap()
                .url(),
            "https://fixture.invalid:443/"
        );
    }
    #[test]
    fn unmodeled_options_invalid_fields_and_resource_limits_never_invent_success() {
        let mut state = WinHttp::default();
        assert!(matches!(
            state.open("", 1, 0x10000000),
            Err(HttpError::Unsupported(_))
        ));
        let (session, _, handle) = request(&mut state);
        assert!(state.connect(session, "a/path", 80).is_err());
        assert!(matches!(
            state.begin_send(handle, BTreeMap::new(), vec![], u32::MAX),
            Err(HttpError::Windows { code: 87, .. })
        ));
        code(
            state.begin_send(
                handle,
                BTreeMap::from([("X-Test".into(), "\r\n".into())]),
                vec![],
                0,
            ),
            87,
        );
        state
            .begin_send(handle, BTreeMap::new(), vec![], 0)
            .unwrap();
        let mut bad = response();
        bad.version = "HTTP/2".into();
        assert!(matches!(
            state.complete(handle, bad),
            Err(HttpError::Unsupported(_))
        ));
        state.fail(handle).unwrap();
        state
            .begin_send(handle, BTreeMap::new(), vec![], 0)
            .unwrap();
        state.complete(handle, response()).unwrap();
        state.receive(handle).unwrap();
        code(state.consume(handle, 5), 87);
        assert_eq!(state.available(handle).unwrap(), 4);
        code(state.peek_read(handle, MAX_BODY + 1), 87);
        let mut quota = WinHttp::default();
        for _ in 0..MAX_HANDLES {
            quota.open("", 1, 0).unwrap();
        }
        code(quota.open("", 1, 0), 8);
    }
}
