//! Synchronous, guest-only WinHTTP adapter over the explicit offline broker.
use super::*;
use emumee_core::{
    artifacts::ArtifactKind,
    broker::{Data, Operation},
    winhttp::{HttpError, SendAction},
};
#[derive(Clone, Copy)]
pub(super) enum Call {
    Open,
    Connect,
    Request,
    Send,
    Receive,
    Read,
    Available,
    Close,
    Query,
    Write,
    AddHeaders,
    CrackUrl,
    IeProxyConfig,
    ProxyForUrl,
    SetOption,
}

// WINHTTP_ADDREQ_FLAG_* modifiers.
const ADDREQ_ADD_IF_NEW: u32 = 0x1000_0000;
const ADDREQ_ADD: u32 = 0x2000_0000;
const ADDREQ_COALESCE_WITH_COMMA: u32 = 0x4000_0000;
const ADDREQ_COALESCE_WITH_SEMICOLON: u32 = 0x0100_0000;
const ADDREQ_REPLACE: u32 = 0x8000_0000;
/// ERROR_WINHTTP_HEADER_ALREADY_EXISTS.
const HEADER_ALREADY_EXISTS: u32 = 12_155;
/// ERROR_WINHTTP_HEADER_NOT_FOUND.
const HEADER_NOT_FOUND: u32 = 12_150;
/// ERROR_WINHTTP_INVALID_OPTION.
const INVALID_OPTION: u32 = 12_009;
/// ERROR_WINHTTP_AUTODETECTION_FAILED: there is no WPAD here to detect.
const AUTODETECTION_FAILED: u32 = 12_180;
/// ERROR_WINHTTP_UNRECOGNIZED_SCHEME and ERROR_WINHTTP_INVALID_URL.
const UNRECOGNIZED_SCHEME: u32 = 12_006;
const INVALID_URL: u32 = 12_005;
/// ICU_REJECT_USERPWD: refuse a URL that carries credentials.
const ICU_REJECT_USERPWD: u32 = 0x0000_4000;
/// WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL.
const AUTOPROXY_FLAGS: u32 = 0x1 | 0x2;
/// WINHTTP_ACCESS_TYPE_NO_PROXY.
const ACCESS_TYPE_NO_PROXY: u32 = 1;

/// What a settable WinHTTP option's buffer holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Dword,
    /// A `DWORD_PTR` context value.
    Pointer,
    /// A `WINHTTP_PROXY_INFO`.
    ProxyInfo,
    /// A wide string.
    Text,
}

/// The options this model accepts and the shape each one carries. Anything
/// else is refused with `ERROR_WINHTTP_INVALID_OPTION` rather than silently
/// accepted.
fn settable_option(option: u32) -> Option<Shape> {
    Some(match option {
        // Resolve/connect/send/receive/response timeouts, connect retries,
        // security flags, request priority, HTTP version, the feature,
        // connection-limit, autologon, protocol, redirect and decompression
        // switches: all plain DWORDs.
        2 | 3 | 4 | 5 | 6 | 7 | 31 | 58 | 59 | 63 | 73 | 77 | 79 | 84 | 88 | 118 => Shape::Dword,
        45 => Shape::Pointer,
        38 => Shape::ProxyInfo,
        41 => Shape::Text,
        _ => return None,
    })
}
fn outcome(
    engine: &mut Unicorn<Trace>,
    result: std::result::Result<u64, HttpError>,
) -> Result<u64> {
    match result {
        Ok(value) => Ok(value),
        Err(HttpError::Windows { code, .. }) => {
            engine.get_data_mut().apis.last_error = code;
            Ok(0)
        }
        Err(error) => Err(error.into()),
    }
}
fn fail(engine: &mut Unicorn<Trace>, code: u32) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(0)
}
fn output(engine: &mut Unicorn<Trace>, address: u64, size: u64) -> bool {
    if size == 0
        || (address != 0
            && engine
                .get_data()
                .apis
                .memory
                .allows(address, size, P::WRITE))
    {
        true
    } else {
        engine.get_data_mut().apis.last_error = if address == 0 { 87 } else { 998 };
        false
    }
}
fn text(engine: &Unicorn<Trace>, address: u64, default: &str) -> Result<String> {
    if address == 0 {
        Ok(default.into())
    } else {
        files::path(engine, address, true)
    }
}
fn headers(engine: &Unicorn<Trace>, address: u64, count: u32) -> Result<BTreeMap<String, String>> {
    if address == 0 {
        ensure!(count == 0, "WinHTTP header length without a buffer");
        return Ok(BTreeMap::new());
    }
    let text = if count == u32::MAX {
        text(engine, address, "")?
    } else {
        ensure!(
            count <= 16 * 1024,
            "WinHTTP header character bound exceeded"
        );
        let data = read(engine, address, count as u64 * 2)?;
        String::from_utf16(
            &data
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )?
    };
    ensure!(
        text.chars().count() <= 16 * 1024 && !text.contains('\0'),
        "WinHTTP header bound/NUL"
    );
    let mut headers = BTreeMap::new();
    for line in text.split("\r\n").filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("WinHTTP malformed header"))?;
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
            "WinHTTP invalid header name"
        );
        ensure!(
            !value.contains(['\r', '\n']),
            "WinHTTP invalid header value"
        );
        ensure!(
            headers
                .insert(
                    name.to_ascii_lowercase(),
                    value.trim_matches([' ', '\t']).into()
                )
                .is_none(),
            "WinHTTP repeated request header merging is not modeled"
        );
    }
    ensure!(headers.len() <= 64, "WinHTTP header count bound exceeded");
    Ok(headers)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::Open => {
            ensure!(
                args[2] == 0 && args[3] == 0,
                "WinHTTP explicit proxies/bypass are not modeled"
            );
            let agent = text(engine, args[0], "")?;
            let result =
                engine
                    .get_data_mut()
                    .apis
                    .http
                    .open(&agent, args[1] as u32, args[4] as u32);
            outcome(engine, result)
        }
        Call::Connect => {
            if args[3] != 0 {
                return fail(engine, 87);
            }
            let host = text(engine, args[1], "")?;
            let result = engine
                .get_data_mut()
                .apis
                .http
                .connect(args[0], &host, args[2] as u16);
            outcome(engine, result)
        }
        Call::Request => {
            ensure!(
                args[3] == 0 && args[4] == 0 && args[5] == 0,
                "WinHTTP explicit version/referrer/accept lists are not modeled"
            );
            ensure!(
                matches!(args[6] as u32, 0 | 0x00800000),
                "WinHTTP request flags outside synchronous initial profile"
            );
            let method = text(engine, args[1], "GET")?;
            let path = text(engine, args[2], "/")?;
            let result = engine.get_data_mut().apis.http.open_request(
                args[0],
                &method,
                &path,
                args[6] as u32 == 0x00800000,
            );
            outcome(engine, result)
        }
        Call::Send => send(engine, args),
        Call::Receive => {
            if args[1] != 0 {
                return fail(engine, 87);
            }
            let request = match engine.get_data_mut().apis.http.pending_for_receive(args[0]) {
                Ok(request) => request,
                Err(error) => return outcome(engine, Err(error)),
            };
            if let Some(request) = request {
                if transmit(engine, args[0], request, "WinHttpReceiveResponse")? == 0 {
                    return Ok(0);
                }
            }
            let result = engine.get_data_mut().apis.http.receive(args[0]).map(|_| 1);
            outcome(engine, result)
        }
        Call::Write => {
            if args[2] as u32 == 0 {
                return fail(engine, 87);
            }
            if !output(engine, args[3], 4) {
                return Ok(0);
            }
            crate::cpu::write(engine, args[3], &0u32.to_le_bytes())?;
            let count = args[2] as u32 as u64;
            if count > MAX_TRANSFER || (count > 0 && args[1] == 0) {
                return fail(engine, 87);
            }
            let data = read(engine, args[1], count)?;
            let written = match engine.get_data_mut().apis.http.write(args[0], &data) {
                Ok(written) => written,
                Err(error) => return outcome(engine, Err(error)),
            };
            crate::cpu::write(engine, args[3], &(written as u32).to_le_bytes())?;
            let (url, bytes, total) = engine.get_data().apis.http.upload_status(args[0])?;
            upload(engine, "write", args[0], url, bytes, total);
            Ok(1)
        }
        Call::Available => {
            if !output(engine, args[1], 4) {
                return Ok(0);
            }
            crate::cpu::write(engine, args[1], &0u32.to_le_bytes())?;
            let result = engine
                .get_data()
                .apis
                .http
                .available(args[0])
                .map(|size| size as u64);
            let size = match result {
                Ok(size) => size,
                Err(error) => return outcome(engine, Err(error)),
            };
            crate::cpu::write(engine, args[1], &(size as u32).to_le_bytes())?;
            Ok(1)
        }
        Call::Read => {
            if !output(engine, args[3], 4) {
                return Ok(0);
            }
            crate::cpu::write(engine, args[3], &0u32.to_le_bytes())?;
            let size = args[2] as u32 as u64;
            if size > MAX_TRANSFER {
                return fail(engine, 87);
            }
            if !output(engine, args[1], size) {
                return Ok(0);
            }
            let result = engine
                .get_data()
                .apis
                .http
                .peek_read(args[0], size as usize)
                .map(<[u8]>::to_vec);
            let data = match result {
                Ok(data) => data,
                Err(error) => return outcome(engine, Err(error)),
            };
            if !data.is_empty() {
                crate::cpu::write(engine, args[1], &data)?;
            }
            crate::cpu::write(engine, args[3], &(data.len() as u32).to_le_bytes())?;
            let result = engine
                .get_data_mut()
                .apis
                .http
                .consume(args[0], data.len())
                .map(|_| 1);
            outcome(engine, result)
        }
        Call::Query => query(engine, args),
        Call::Close => {
            let result = engine.get_data_mut().apis.http.close(args[0]).map(|_| 1);
            engine.get_data_mut().apis.http_config.forget(args[0]);
            outcome(engine, result)
        }
        Call::AddHeaders => add_headers(engine, args),
        Call::CrackUrl => crack_url(engine, args),
        Call::IeProxyConfig => {
            // WINHTTP_CURRENT_USER_IE_PROXY_CONFIG: automatic detection off
            // and no proxy, autoconfiguration URL or bypass list. That is a
            // direct connection, which is this profile's configuration — and
            // because every string pointer stays null, the caller has nothing
            // to free, as the documented contract allows.
            if args[0] == 0 {
                return fail(engine, 87);
            }
            let width = engine.get_data().architecture.width();
            let size = if width == 8 { 32 } else { 16 };
            require(engine, args[0], size as u64, P::WRITE)?;
            crate::cpu::write(engine, args[0], &vec![0u8; size])?;
            engine
                .get_data_mut()
                .apis
                .http_config
                .record("WinHttpGetIEProxyConfigForCurrentUser", "direct".into());
            Ok(1)
        }
        Call::ProxyForUrl => proxy_for_url(engine, args),
        Call::SetOption => set_option(engine, args),
    }
}

/// `WinHttpAddRequestHeaders`: parse the header block and apply the documented
/// modifiers to the request's own header set, which `WinHttpSendRequest` then
/// transmits.
fn add_headers(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    use emumee_core::winhttp::HandleKind;
    let modifiers = args[3] as u32;
    let facts = match engine.get_data().apis.http.facts(args[0]) {
        Ok(facts) => facts,
        Err(error) => return outcome(engine, Err(error)),
    };
    if facts.kind != HandleKind::Request {
        return fail(engine, 12_018); // ERROR_WINHTTP_INCORRECT_HANDLE_TYPE
    }
    if args[1] == 0 {
        return fail(engine, 87);
    }
    // At least one of add, add-if-new, replace or a coalesce has to be asked
    // for; anything else is not a documented modifier set.
    let known = ADDREQ_ADD
        | ADDREQ_ADD_IF_NEW
        | ADDREQ_REPLACE
        | ADDREQ_COALESCE_WITH_COMMA
        | ADDREQ_COALESCE_WITH_SEMICOLON;
    if modifiers & !known != 0 || modifiers == 0 {
        return fail(engine, 87);
    }
    let added = headers(engine, args[1], args[2] as u32)?;
    if added.is_empty() {
        return fail(engine, 87);
    }
    let mut detail = Vec::new();
    for (name, value) in added {
        let held = engine.get_data().apis.http_config.has_header(args[0], &name);
        if modifiers & ADDREQ_REPLACE != 0 {
            // A replace with an empty value removes the header; with a value
            // it replaces one, or adds it when ADD is also asked for.
            if value.is_empty() {
                if !engine
                    .get_data_mut()
                    .apis
                    .http_config
                    .remove_header(args[0], &name)
                {
                    return fail(engine, HEADER_NOT_FOUND);
                }
                detail.push(format!("-{name}"));
                continue;
            }
            if !held && modifiers & ADDREQ_ADD == 0 {
                return fail(engine, HEADER_NOT_FOUND);
            }
            engine
                .get_data_mut()
                .apis
                .http_config
                .add_header(args[0], name.clone(), value.clone());
            detail.push(format!("{name}: {value}"));
            continue;
        }
        if held && modifiers & ADDREQ_ADD_IF_NEW != 0 {
            return fail(engine, HEADER_ALREADY_EXISTS);
        }
        let separator = if modifiers & ADDREQ_COALESCE_WITH_SEMICOLON != 0 {
            "; "
        } else {
            ", "
        };
        let combined = match engine.get_data().apis.http_config.added_headers(args[0]).get(&name) {
            Some(existing)
                if modifiers & (ADDREQ_COALESCE_WITH_COMMA | ADDREQ_COALESCE_WITH_SEMICOLON)
                    != 0 =>
            {
                format!("{existing}{separator}{value}")
            }
            _ => value.clone(),
        };
        engine
            .get_data_mut()
            .apis
            .http_config
            .add_header(args[0], name.clone(), combined.clone());
        detail.push(format!("{name}: {combined}"));
    }
    engine
        .get_data_mut()
        .apis
        .http_config
        .record("WinHttpAddRequestHeaders", detail.join(", "));
    engine.get_data_mut().apis.last_error = 0;
    Ok(1)
}

/// `WinHttpCrackUrl`: the wide-only URL splitter, carried out for real.
fn crack_url(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let flags = args[2] as u32;
    ensure!(
        flags & !ICU_REJECT_USERPWD == 0,
        "WinHTTP URL escaping and decoding flags are not modeled"
    );
    if args[0] == 0 || args[3] == 0 {
        return fail(engine, 87);
    }
    let length = args[1] as u32 as usize;
    if length > http_config::MAX_URL {
        return fail(engine, INVALID_URL);
    }
    let url = if length == 0 {
        text(engine, args[0], "")?
    } else {
        let raw = read(engine, args[0], length as u64 * 2)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units)?
    };
    if !url.is_ascii() || url.is_empty() || url.chars().any(|c| c < ' ') {
        return fail(engine, INVALID_URL);
    }
    let Some(parts) = http_config::parse(&url) else {
        engine
            .get_data_mut()
            .apis
            .http_config
            .record("WinHttpCrackUrl", format!("{url}: not a URL"));
        return fail(engine, UNRECOGNIZED_SCHEME);
    };
    if parts.number == http_config::SCHEME_UNKNOWN {
        engine
            .get_data_mut()
            .apis
            .http_config
            .record("WinHttpCrackUrl", format!("{url}: unknown scheme"));
        return fail(engine, UNRECOGNIZED_SCHEME);
    }
    if flags & ICU_REJECT_USERPWD != 0 && !(parts.user.is_empty() && parts.password.is_empty()) {
        engine
            .get_data_mut()
            .apis
            .http_config
            .record("WinHttpCrackUrl", format!("{url}: credentials refused"));
        return fail(engine, INVALID_URL);
    }
    if let Some(code) = http_config::fill(engine, args[3], args[0], &url, &parts, true)? {
        return fail(engine, code);
    }
    engine
        .get_data_mut()
        .apis
        .http_config
        .record("WinHttpCrackUrl", url);
    Ok(1)
}

/// `WinHttpGetProxyForUrl`: there is no WPAD server, no DHCP option and no
/// configuration script to fetch here, so autodetection genuinely fails. The
/// URL the sample wanted a route for is recorded.
fn proxy_for_url(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    use emumee_core::winhttp::HandleKind;
    let facts = match engine.get_data().apis.http.facts(args[0]) {
        Ok(facts) => facts,
        Err(error) => return outcome(engine, Err(error)),
    };
    if facts.kind != HandleKind::Session {
        return fail(engine, 12_018);
    }
    if args[1] == 0 || args[2] == 0 || args[3] == 0 {
        return fail(engine, 87);
    }
    let url = text(engine, args[1], "")?;
    let width = engine.get_data().architecture.width() as u64;
    // WINHTTP_AUTOPROXY_OPTIONS begins with its flags and auto-detect types.
    let flags = u32::from_le_bytes(read(engine, args[2], 4)?.try_into().unwrap());
    if flags & !AUTOPROXY_FLAGS != 0 || flags == 0 {
        return fail(engine, 87);
    }
    let detected = u32::from_le_bytes(read(engine, args[2] + 4, 4)?.try_into().unwrap());
    let script = if flags & 0x2 != 0 {
        let pointer = {
            let raw = read(engine, args[2] + 8, width)?;
            let mut value = [0u8; 8];
            value[..width as usize].copy_from_slice(&raw);
            u64::from_le_bytes(value)
        };
        text(engine, pointer, "")?
    } else {
        String::new()
    };
    engine.get_data_mut().apis.http_config.record(
        "WinHttpGetProxyForUrl",
        format!(
            "{url}: flags {flags:#x}, detect {detected:#x}{}",
            if script.is_empty() {
                String::new()
            } else {
                format!(", script {script}")
            }
        ),
    );
    fail(engine, AUTODETECTION_FAILED)
}

/// `WinHttpSetOption`: the documented options are accepted and recorded; the
/// rest are refused rather than silently swallowed.
fn set_option(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let (option, buffer) = (args[1] as u32, args[2]);
    let length = args[3] as u32 as usize;
    if args[0] != 0 && engine.get_data().apis.http.facts(args[0]).is_err() {
        return fail(engine, 6);
    }
    let width = engine.get_data().architecture.width();
    let Some(shape) = settable_option(option) else {
        engine
            .get_data_mut()
            .apis
            .http_config
            .record("WinHttpSetOption", format!("option {option} refused"));
        return fail(engine, INVALID_OPTION);
    };
    if buffer == 0 {
        return fail(engine, 87);
    }
    let detail = match shape {
        Shape::Dword | Shape::Pointer => {
            let size = if shape == Shape::Dword { 4 } else { width };
            if length != size {
                return fail(engine, 87);
            }
            let raw = read(engine, buffer, size as u64)?;
            let mut value = [0u8; 8];
            value[..size].copy_from_slice(&raw);
            let value = u64::from_le_bytes(value);
            engine
                .get_data_mut()
                .apis
                .http_config
                .set_option(args[0], option, raw);
            format!("option {option} = {value}")
        }
        Shape::ProxyInfo => {
            let size = if width == 8 { 24 } else { 12 };
            if length != size {
                return fail(engine, 87);
            }
            let raw = read(engine, buffer, size as u64)?;
            let access = u32::from_le_bytes(raw[..4].try_into().unwrap());
            let pointer = |offset: usize| -> u64 {
                let mut value = [0u8; 8];
                value[..width].copy_from_slice(&raw[offset..offset + width]);
                u64::from_le_bytes(value)
            };
            let (proxy, bypass) = if width == 8 {
                (pointer(8), pointer(16))
            } else {
                (pointer(4), pointer(8))
            };
            let proxy = text(engine, proxy, "")?;
            let bypass = text(engine, bypass, "")?;
            if access == ACCESS_TYPE_NO_PROXY && !proxy.is_empty() {
                return fail(engine, 87);
            }
            engine
                .get_data_mut()
                .apis
                .http_config
                .set_option(args[0], option, raw);
            format!("proxy access {access}, proxy {proxy:?}, bypass {bypass:?}")
        }
        Shape::Text => {
            let agent = text(engine, buffer, "")?;
            let mut bytes: Vec<u8> = agent.encode_utf16().flat_map(u16::to_le_bytes).collect();
            bytes.extend([0, 0]);
            engine
                .get_data_mut()
                .apis
                .http_config
                .set_option(args[0], option, bytes);
            format!("user agent {agent:?}")
        }
    };
    engine
        .get_data_mut()
        .apis
        .http_config
        .record("WinHttpSetOption", detail);
    engine.get_data_mut().apis.last_error = 0;
    Ok(1)
}
fn query(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let attribute = (args[1] as u32 & 0xffff) as u16;
    let flags = args[1] as u32 & !0xffff;
    ensure!(
        matches!(flags, 0 | 0x20000000),
        "WinHTTP header query flags are not modeled"
    );
    if !output(engine, args[4], 4) || (args[5] != 0 && !output(engine, args[5], 4)) {
        return Ok(0);
    }
    let capacity = u32::from_le_bytes(read(engine, args[4], 4)?.try_into().unwrap());
    let index = if args[5] == 0 {
        0
    } else {
        u32::from_le_bytes(read(engine, args[5], 4)?.try_into().unwrap())
    };
    let name = if attribute == 65535 {
        Some(text(engine, args[2], "")?)
    } else {
        None
    };
    let header = match engine
        .get_data()
        .apis
        .http
        .query(args[0], attribute, name.as_deref(), index)
    {
        Ok(value) => value,
        Err(error) => return outcome(engine, Err(error)),
    };
    let (data, length) = if flags == 0x20000000 {
        ensure!(
            matches!(attribute, 5 | 19)
                && !header.value.is_empty()
                && header.value.bytes().all(|b| b.is_ascii_digit()),
            "WinHTTP numeric header query profile"
        );
        let number: u32 = header.value.parse()?;
        (number.to_le_bytes().to_vec(), 4usize)
    } else {
        let mut data: Vec<u8> = header
            .value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let length = data.len();
        data.extend([0, 0]);
        (data, length)
    };
    if args[3] == 0 || (capacity as usize) < data.len() {
        crate::cpu::write(engine, args[4], &(data.len() as u32).to_le_bytes())?;
        return fail(engine, 122);
    }
    if !output(engine, args[3], data.len() as u64) {
        return Ok(0);
    }
    crate::cpu::write(engine, args[3], &data)?;
    crate::cpu::write(engine, args[4], &(length as u32).to_le_bytes())?;
    if args[5] != 0 {
        if let Some(next) = header.next_index {
            crate::cpu::write(engine, args[5], &next.to_le_bytes())?;
        }
    }
    engine.get_data_mut().apis.last_error = 0;
    Ok(1)
}
fn send(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        args[6] == 0,
        "WinHTTP request callback context is not modeled"
    );
    let count = args[4] as u32 as u64;
    if count > MAX_TRANSFER || (count > 0 && args[3] == 0) {
        return fail(engine, 87);
    }
    if args[5] as u32 == u32::MAX && (args[3] != 0 || count != 0) {
        return fail(engine, 87);
    }
    // Headers added earlier with WinHttpAddRequestHeaders belong to the
    // request; the ones passed here are applied on top of them, as the send
    // call's own documentation describes.
    let mut headers = engine.get_data().apis.http_config.added_headers(args[0]);
    headers.extend(self::headers(engine, args[1], args[2] as u32)?);
    let body = read(engine, args[3], count)?;
    ensure!(
        engine.get_data().apis.broker.is_some(),
        "Network broker unavailable; host fallback is disabled"
    );
    let action =
        match engine
            .get_data_mut()
            .apis
            .http
            .begin_send(args[0], headers, body, args[5] as u32)
        {
            Ok(action) => action,
            Err(error) => return outcome(engine, Err(error)),
        };
    match action {
        SendAction::Transmit(request) => transmit(engine, args[0], request, "WinHttpSendRequest"),
        SendAction::Staged {
            url,
            initial,
            total,
        } => {
            upload(engine, "staged", args[0], url, initial, total);
            Ok(1)
        }
    }
}
fn upload(
    engine: &mut Unicorn<Trace>,
    phase: &'static str,
    handle: u64,
    url: String,
    bytes: usize,
    total: Option<usize>,
) {
    let report = &mut engine.get_data_mut().apis.network;
    if report.uploads.len() < 64 {
        report.uploads.push(network::Upload {
            phase,
            handle,
            url,
            bytes,
            total,
        });
    } else {
        report.omitted_uploads += 1;
    }
}
fn transmit(
    engine: &mut Unicorn<Trace>,
    handle: u64,
    request: emumee_core::networkfixtures::HttpRequest,
    api: &'static str,
) -> Result<u64> {
    if !request.body.is_empty() {
        engine.get_data_mut().apis.captures.add(
            request.body.clone(),
            ArtifactKind::MemorySnapshot,
            "winhttp_request_body",
            &request.url,
        );
    }
    let mut event = network::Event {
        api,
        url: request.url.clone(),
        guest_path: String::new(),
        status: None,
        bytes: 0,
        result: None,
        error: None,
        destination_created: false,
    };
    let result = (|| -> Result<u64> {
        let client = engine.get_data_mut().apis.broker.as_mut().ok_or_else(|| {
            anyhow::anyhow!("Network broker unavailable; host fallback is disabled")
        })?;
        let reply = client
            .call(Operation::Http { request })
            .map_err(anyhow::Error::msg)?;
        reply.validate(reply.id).map_err(anyhow::Error::msg)?;
        if !reply.ok {
            engine.get_data_mut().apis.http.fail(handle)?;
            event.error = reply.error;
            event.result = Some(0);
            return fail(engine, 12029);
        }
        let Some(Data::HttpFull { response }) = reply.value else {
            bail!("WinHTTP broker returned a non-full HTTP response");
        };
        response.validate().map_err(anyhow::Error::msg)?;
        event.status = Some(response.status);
        event.bytes = response.body.len();
        let captured = response.body.clone();
        let result = engine
            .get_data_mut()
            .apis
            .http
            .complete(handle, response)
            .map(|_| 1);
        if result.is_ok() {
            engine.get_data_mut().apis.captures.add(
                captured,
                ArtifactKind::MemorySnapshot,
                "winhttp_response",
                &event.url,
            );
        }
        if matches!(&result, Err(HttpError::Windows { .. })) {
            engine.get_data_mut().apis.http.fail(handle)?;
        }
        let result = outcome(engine, result)?;
        event.result = Some(result as u32);
        Ok(result)
    })();
    if let Err(error) = &result {
        event.error = Some(format!("{error:#}"));
    }
    let report = &mut engine.get_data_mut().apis.network;
    report.calls += 1;
    if report.events.len() < 64 {
        report.events.push(event);
    } else {
        report.omitted_events += 1;
    }
    result
}
