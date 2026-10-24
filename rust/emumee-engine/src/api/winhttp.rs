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
            outcome(engine, result)
        }
    }
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
    let headers = headers(engine, args[1], args[2] as u32)?;
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
