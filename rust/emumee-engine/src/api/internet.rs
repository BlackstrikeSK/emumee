//! Synchronous WinINet HTTP streams over explicit offline broker RPC.
//! No WinINet DLL, browser cache, credential store, socket or host proxy is used.
use super::*;
use emumee_core::{
    artifacts::ArtifactKind,
    broker::{Data, Operation},
    winhttp::HttpError,
};
#[derive(Clone, Copy)]
pub(super) enum Call {
    Open(bool),
    Url(bool),
    Connect(bool),
    Request(bool),
    Send(bool),
    Query(bool),
    Begin(bool),
    Write,
    End,
    Read,
    Available,
    Close,
}
fn outcome(engine: &mut Unicorn<Trace>, value: std::result::Result<u64, HttpError>) -> Result<u64> {
    match value {
        Ok(value) => Ok(value),
        Err(HttpError::Windows { code, .. }) => fail(engine, code),
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
fn text(engine: &Unicorn<Trace>, address: u64, wide: bool) -> Result<String> {
    if address == 0 {
        Ok(String::new())
    } else {
        files::path(engine, address, wide)
    }
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "WinINet is outside the kernel target profile"
    );
    match call {
        Call::Open(wide) => {
            ensure!(
                args[2] == 0 && args[3] == 0,
                "WinINet explicit proxy/bypass is not modeled"
            );
            let agent = text(engine, args[0], wide)?;
            let result =
                engine
                    .get_data_mut()
                    .apis
                    .internet
                    .open(&agent, args[1] as u32, args[4] as u32);
            outcome(engine, result)
        }
        Call::Url(wide) => {
            ensure!(
                args[2] == 0 && args[3] == 0,
                "WinINet additional request headers are not modeled"
            );
            ensure!(
                args[4] == 0 && args[5] == 0,
                "WinINet URL flags/context/cache/callback behavior is not modeled"
            );
            let url = text(engine, args[1], wide)?;
            let (handle, request) =
                match engine.get_data_mut().apis.internet.open_url(args[0], &url) {
                    Ok(value) => value,
                    Err(error) => return outcome(engine, Err(error)),
                };
            let result = fetch(engine, handle, request, "InternetOpenUrl");
            if !matches!(result,Ok(value) if value!=0) {
                engine.get_data_mut().apis.internet.close(handle)?;
            }
            result
        }
        Call::Connect(wide) => {
            ensure!(
                args[3] == 0 && args[4] == 0 && args[5] == 3 && args[6] == 0 && args[7] == 0,
                "WinINet credentials, non-HTTP service, flags or context are not modeled"
            );
            let host = text(engine, args[1], wide)?;
            let result =
                engine
                    .get_data_mut()
                    .apis
                    .internet
                    .connect(args[0], &host, args[2] as u16);
            outcome(engine, result)
        }
        Call::Request(wide) => {
            ensure!(
                args[3] == 0 && args[4] == 0 && args[5] == 0 && args[7] == 0,
                "WinINet explicit version/referrer/accept lists/context are not modeled"
            );
            ensure!(
                matches!(args[6] as u32, 0 | 0x00800000),
                "WinINet request flags outside initial synchronous profile"
            );
            let method = if args[1] == 0 {
                "GET".into()
            } else {
                text(engine, args[1], wide)?
            };
            let path = if args[2] == 0 {
                "/".into()
            } else {
                text(engine, args[2], wide)?
            };
            let result = engine.get_data_mut().apis.internet.open_request(
                args[0],
                &method,
                &path,
                args[6] as u32 == 0x00800000,
            );
            outcome(engine, result)
        }
        Call::Send(wide) => send(engine, args, wide),
        Call::Query(wide) => query(engine, args, wide),
        Call::Begin(wide) => begin(engine, args, wide),
        Call::Write => {
            // Owned Windows reference: zero-length writes fail87 without
            // touching the caller's count, before ordinary buffer validation.
            if args[2] as u32 == 0 {
                return fail(engine, 87);
            }
            if !output(engine, args[3], 4) {
                return Ok(0);
            }
            crate::cpu::write(engine, args[3], &0u32.to_le_bytes())?;
            let count = args[2] as u32 as u64;
            if count > MAX_TRANSFER || args[1] == 0 {
                return fail(engine, 87);
            }
            let bytes = read(engine, args[1], count)?;
            let written = match engine.get_data_mut().apis.internet.write(args[0], &bytes) {
                Ok(value) => value,
                Err(error) => return outcome(engine, Err(error)),
            };
            crate::cpu::write(engine, args[3], &(written as u32).to_le_bytes())?;
            upload(engine, args[0], "write")?;
            Ok(1)
        }
        Call::End => {
            ensure!(
                args[1] == 0 && args[2] == 0 && args[3] == 0,
                "WinINet end output/flags/context are not modeled"
            );
            let (_, bytes, total) = match engine.get_data().apis.internet.upload_status(args[0]) {
                Ok(value) => value,
                Err(error) => return outcome(engine, Err(error)),
            };
            ensure!(
                total == Some(bytes),
                "WinINet incomplete end is outside the exact-length upload profile"
            );
            let request = match engine
                .get_data_mut()
                .apis
                .internet
                .pending_for_receive(args[0])
            {
                Ok(Some(value)) => value,
                Ok(None) => bail!("WinINet end has no staged request"),
                Err(error) => return outcome(engine, Err(error)),
            };
            fetch(engine, args[0], request, "HttpEndRequest").map(|value| u64::from(value != 0))
        }
        Call::Read => {
            if !output(engine, args[3], 4) {
                return Ok(0);
            }
            crate::cpu::write(engine, args[3], &0u32.to_le_bytes())?;
            let count = args[2] as u32 as u64;
            if count > MAX_TRANSFER {
                return fail(engine, 87);
            }
            if !output(engine, args[1], count) {
                return Ok(0);
            }
            let bytes = match engine
                .get_data()
                .apis
                .internet
                .peek_read(args[0], count as usize)
            {
                Ok(bytes) => bytes.to_vec(),
                Err(error) => return outcome(engine, Err(error)),
            };
            if !bytes.is_empty() {
                crate::cpu::write(engine, args[1], &bytes)?;
            }
            crate::cpu::write(engine, args[3], &(bytes.len() as u32).to_le_bytes())?;
            let result = engine
                .get_data_mut()
                .apis
                .internet
                .consume(args[0], bytes.len())
                .map(|_| 1);
            outcome(engine, result)
        }
        Call::Available => {
            if args[2] != 0 || args[3] != 0 {
                return fail(engine, 87);
            }
            // WinINet permits a null output pointer for this API.
            if args[1] != 0 && !output(engine, args[1], 4) {
                return Ok(0);
            }
            let count = match engine.get_data().apis.internet.available(args[0]) {
                Ok(value) => value,
                Err(error) => return outcome(engine, Err(error)),
            };
            if args[1] != 0 {
                crate::cpu::write(engine, args[1], &(count as u32).to_le_bytes())?;
            }
            Ok(1)
        }
        Call::Close => {
            let result = engine
                .get_data_mut()
                .apis
                .internet
                .close(args[0])
                .map(|_| 1);
            outcome(engine, result)
        }
    }
}
fn fetch(
    engine: &mut Unicorn<Trace>,
    handle: u64,
    request: emumee_core::networkfixtures::HttpRequest,
    api: &'static str,
) -> Result<u64> {
    if !request.body.is_empty() {
        engine.get_data_mut().apis.captures.add(
            request.body.clone(),
            ArtifactKind::MemorySnapshot,
            "wininet_request_body",
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
            engine.get_data_mut().apis.internet.fail(handle)?;
            event.error = reply.error;
            event.result = Some(0);
            return fail(engine, 12029);
        }
        let Some(Data::HttpFull { response }) = reply.value else {
            bail!("WinINet broker returned a non-full HTTP response");
        };
        response.validate().map_err(anyhow::Error::msg)?;
        event.status = Some(response.status);
        event.bytes = response.body.len();
        let captured = response.body.clone();
        if let Err(error) = engine
            .get_data_mut()
            .apis
            .internet
            .complete(handle, response)
        {
            if matches!(error, HttpError::Windows { .. }) {
                engine.get_data_mut().apis.internet.fail(handle)?;
            }
            return outcome(engine, Err(error));
        }
        engine.get_data_mut().apis.internet.receive(handle)?;
        engine.get_data_mut().apis.captures.add(
            captured,
            ArtifactKind::MemorySnapshot,
            "wininet_response",
            &event.url,
        );
        event.result = Some(1);
        Ok(handle)
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
fn send(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    let count = args[2] as u32;
    // W explicitly rejects -1 with a non-null header buffer (A permits ASCIIZ).
    if wide && args[1] != 0 && count == u32::MAX {
        return fail(engine, 87);
    }
    if args[1] == 0 && count != 0 {
        return fail(engine, 87);
    }
    let headers = request_headers(engine, args[1], count, wide)?;
    let length = args[4] as u32 as u64;
    if length > MAX_TRANSFER || (length != 0 && args[3] == 0) {
        return fail(engine, 87);
    }
    let body = if length == 0 {
        vec![]
    } else {
        read(engine, args[3], length)?
    };
    let action =
        match engine
            .get_data_mut()
            .apis
            .internet
            .begin_send(args[0], headers, body, length as u32)
        {
            Ok(value) => value,
            Err(error) => return outcome(engine, Err(error)),
        };
    let emumee_core::winhttp::SendAction::Transmit(request) = action else {
        bail!("WinINet direct send unexpectedly staged a body");
    };
    fetch(engine, args[0], request, "HttpSendRequest").map(|value| u64::from(value != 0))
}
fn begin(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    ensure!(
        args[2] == 0 && args[3] == 0 && args[4] == 0,
        "WinINet begin reserved output/flags/context are not modeled"
    );
    let pointer = engine.get_data().architecture.width();
    let size = if pointer == 8 { 56 } else { 40 };
    let (next, header, header_count, body, length, total) = if args[1] == 0 {
        (0, 0, 0, 0, 0, 0)
    } else {
        if u32::from_le_bytes(read(engine, args[1], 4)?.try_into().unwrap()) != size as u32 {
            return fail(engine, 87);
        }
        let raw = read(engine, args[1], size as u64)?;
        let d = |offset: usize| u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap());
        let p = |offset: usize| {
            if pointer == 8 {
                u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
            } else {
                d(offset) as u64
            }
        };
        let h = if pointer == 8 { 16 } else { 8 };
        let b = if pointer == 8 { 32 } else { 20 };
        ensure!(
            d(h + pointer + 4) == 0,
            "WinINet streamed header total field is not modeled"
        );
        if d(b + pointer + 8) != 0 || d(b + pointer + 12) != 0 {
            return fail(engine, 87);
        }
        (
            p(pointer),
            p(h),
            d(h + pointer),
            p(b),
            d(b + pointer),
            d(b + pointer + 4),
        )
    };
    if total as u64 > MAX_TRANSFER
        || length > total
        || (length > 0 && body == 0)
        || (header == 0 && header_count != 0)
        || (wide && header != 0 && header_count == u32::MAX)
    {
        return fail(engine, 87);
    }
    let headers = request_headers(engine, header, header_count, wide)?;
    ensure!(
        !headers.contains_key("transfer-encoding"),
        "WinINet chunked SendRequestEx upload is outside the fixed-length profile"
    );
    let bytes = if length == 0 {
        vec![]
    } else {
        read(engine, body, length as u64)?
    };
    let result = engine
        .get_data_mut()
        .apis
        .internet
        .begin_staged(args[0], headers, bytes, total);
    match result {
        Ok(emumee_core::winhttp::SendAction::Staged { .. }) => {}
        Ok(_) => bail!("WinINet begin published a staged request"),
        Err(error) => return outcome(engine, Err(error)),
    }
    // Native reference on this Windows build ignores Next and uses only the
    // head's header/body. Never dereference that guest value as a host pointer.
    upload(
        engine,
        args[0],
        if next == 0 {
            "staged"
        } else {
            "staged_head_only"
        },
    )?;
    Ok(1)
}
fn upload(engine: &mut Unicorn<Trace>, handle: u64, phase: &'static str) -> Result<()> {
    let (url, bytes, total) = engine.get_data().apis.internet.upload_status(handle)?;
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
    Ok(())
}
fn query(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    let attribute = (args[1] as u32 & 0xffff) as u16;
    let flags = args[1] as u32 & !0xffff;
    ensure!(
        matches!(flags, 0 | 0x20000000),
        "WinINet header query flags are not modeled"
    );
    if !output(engine, args[3], 4) || (args[4] != 0 && !output(engine, args[4], 4)) {
        return Ok(0);
    }
    let capacity = u32::from_le_bytes(read(engine, args[3], 4)?.try_into().unwrap());
    let index = if args[4] == 0 {
        0
    } else {
        u32::from_le_bytes(read(engine, args[4], 4)?.try_into().unwrap())
    };
    let name = if attribute == 65535 {
        if args[2] == 0 {
            return fail(engine, 87);
        }
        ensure!(
            capacity <= 16384,
            "WinINet custom header name capacity bound"
        );
        let bytes = read(engine, args[2], capacity as u64)?;
        let value = if wide {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .collect();
            let end = units.iter().position(|v| *v == 0).ok_or_else(|| {
                anyhow::anyhow!("WinINet custom header lacks terminator within buffer")
            })?;
            String::from_utf16(&units[..end])?
        } else {
            let end = bytes.iter().position(|v| *v == 0).ok_or_else(|| {
                anyhow::anyhow!("WinINet custom header lacks terminator within buffer")
            })?;
            String::from_utf8(bytes[..end].to_vec())?
        };
        Some(value)
    } else {
        None
    };
    let header =
        match engine
            .get_data()
            .apis
            .internet
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
            "WinINet numeric query profile"
        );
        (header.value.parse::<u32>()?.to_le_bytes().to_vec(), 4)
    } else {
        ensure!(
            header.value.chars().all(|c| u32::from(c) <= 255),
            "WinINet response header outside ISO-8859-1 profile"
        );
        let mut data: Vec<u8> = if wide {
            header
                .value
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect()
        } else {
            header.value.chars().map(|c| c as u8).collect()
        };
        let length = data.len();
        data.extend(if wide { vec![0, 0] } else { vec![0] });
        (data, length)
    };
    if args[2] == 0 || (capacity as usize) < data.len() {
        crate::cpu::write(engine, args[3], &(data.len() as u32).to_le_bytes())?;
        return fail(engine, 122);
    }
    if !output(engine, args[2], data.len() as u64) {
        return Ok(0);
    }
    crate::cpu::write(engine, args[2], &data)?;
    crate::cpu::write(engine, args[3], &(length as u32).to_le_bytes())?;
    if args[4] != 0 {
        if let Some(next) = header.next_index {
            crate::cpu::write(engine, args[4], &next.to_le_bytes())?;
        }
    }
    Ok(1)
}

fn request_headers(
    engine: &Unicorn<Trace>,
    address: u64,
    count: u32,
    wide: bool,
) -> Result<BTreeMap<String, String>> {
    let headers = if address == 0 {
        if count != 0 {
            anyhow::bail!("WinINet header length without buffer");
        }
        BTreeMap::new()
    } else {
        let value = if count == u32::MAX {
            text(engine, address, wide)?
        } else {
            ensure!(count <= 16384, "WinINet request header bound");
            let bytes = read(engine, address, count as u64 * if wide { 2 } else { 1 })?;
            if wide {
                String::from_utf16(
                    &bytes
                        .chunks_exact(2)
                        .map(|v| u16::from_le_bytes([v[0], v[1]]))
                        .collect::<Vec<_>>(),
                )?
            } else {
                String::from_utf8(bytes)?
            }
        };
        ensure!(
            value.is_ascii() && value.len() <= 16384 && !value.contains('\0'),
            "WinINet request header ASCII/bound/NUL profile"
        );
        let mut headers = BTreeMap::new();
        for line in value.split("\r\n").filter(|line| !line.is_empty()) {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("WinINet malformed request header"))?;
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                    && !value.contains(['\r', '\n']),
                "WinINet invalid request header"
            );
            ensure!(
                headers
                    .insert(
                        name.to_ascii_lowercase(),
                        value.trim_matches([' ', '\t']).to_string()
                    )
                    .is_none(),
                "WinINet repeated header merging is not modeled"
            );
        }
        ensure!(headers.len() <= 64, "WinINet request header count");
        headers
    };
    Ok(headers)
}
