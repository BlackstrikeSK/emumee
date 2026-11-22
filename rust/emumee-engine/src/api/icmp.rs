//! ICMP echo (`iphlpapi` and the legacy `icmp` export set).
//!
//! No packet can leave this profile, so the model captures the *intent* of a
//! ping and then reports what an unreachable network genuinely produces: the
//! destination, the request payload and the requested TTL are all recorded —
//! and a non-empty payload is captured as a network artifact, because an echo
//! request is a documented covert channel — then the call reports
//! `IP_REQ_TIMED_OUT` with no reply invented.
//!
//! The two destinations that need no network answer for real: the loopback
//! address and the adapter's own address, which a real stack replies to
//! locally. Their replies are built in the caller's `ICMP_ECHO_REPLY` with the
//! real layout for each pointer width, round-trip time zero, so a control can
//! assert them exactly without touching the clock.
use super::adapters::{adapter, dotted, ptr_width, put};
use super::*;
use emumee_core::artifacts::ArtifactKind;
use std::collections::BTreeSet;

const INVALID_HANDLE_VALUE: u64 = u64::MAX;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NOT_SUPPORTED: u32 = 50;
/// IP_REQ_TIMED_OUT: the request went out (as far as this profile goes) and
/// nothing came back.
const IP_REQ_TIMED_OUT: u32 = 11_010;
/// The TTL a reply from this machine carries.
const REPLY_TTL: u8 = 128;
/// Bound on a single echo payload.
const MAX_REQUEST: u64 = 4096;
const MAX_HANDLES: usize = 128;

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    /// The destination the guest asked for, as dotted-quad text.
    pub host: String,
    pub request_bytes: usize,
    pub request_ttl: u8,
    pub timeout_ms: u32,
    pub status: u32,
    pub replied: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub handles_opened: u64,
    pub echo_attempts: u64,
    pub replies: u64,
    pub bytes_offered: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that pinged nothing serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.handles_opened == 0
            && self.echo_attempts == 0
            && self.replies == 0
            && self.bytes_offered == 0
            && self.events.is_empty()
            && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    counter: u64,
    handles: BTreeSet<u64>,
    pub report: Report,
}

impl State {
    fn open(&mut self) -> Option<u64> {
        if self.handles.len() >= MAX_HANDLES {
            return None;
        }
        self.counter += 1;
        let handle = 0xE610_0000 + self.counter * 4;
        self.handles.insert(handle);
        self.report.handles_opened += 1;
        Some(handle)
    }
    fn close(&mut self, handle: u64) -> bool {
        self.handles.remove(&handle)
    }
    fn holds(&self, handle: u64) -> bool {
        self.handles.contains(&handle)
    }
    fn record(&mut self, event: Event) {
        self.report.echo_attempts += 1;
        self.report.bytes_offered += event.request_bytes as u64;
        if event.replied {
            self.report.replies += 1;
        }
        if self.report.events.len() < 64 {
            self.report.events.push(event);
        } else {
            self.report.omitted_events += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    CreateFile,
    SendEcho,
    CloseHandle,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    // The three are exported from both the modern IP Helper DLL and the legacy
    // icmp.dll a sample may still bind.
    if module != "iphlpapi" && module != "icmp" {
        return None;
    }
    let row = match name {
        "IcmpCreateFile" => (CreateFile, 0, T::Pointer),
        "IcmpSendEcho" => (SendEcho, 8, T::U32),
        "IcmpCloseHandle" => (CloseHandle, 1, T::U32),
        _ => return None,
    };
    Some(row)
}

fn fail(engine: &mut Unicorn<Trace>, code: u32, result: u64) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(result)
}

/// `ICMP_ECHO_REPLY` is 28 bytes on x86 and 40 on x64: the fixed head, the
/// reply data pointer and the inline `IP_OPTION_INFORMATION`.
fn reply_size(width: u64) -> u64 {
    if width == 8 { 40 } else { 28 }
}

fn send_echo(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let width = ptr_width(engine);
    let header = reply_size(width);
    let (handle, destination) = (args[0], args[1] as u32);
    let (request, size) = (args[2], args[3] as u16 as u64);
    let (options, output) = (args[4], args[5]);
    let (capacity, timeout) = (args[6] as u32 as u64, args[7] as u32);
    let config = adapter(engine);
    let address = destination.to_le_bytes();
    let mut event = Event {
        api: "IcmpSendEcho",
        host: dotted(address),
        request_bytes: size as usize,
        request_ttl: REPLY_TTL,
        timeout_ms: timeout,
        status: 0,
        replied: false,
    };
    if !engine.get_data().apis.icmp.holds(handle) {
        return fail(engine, ERROR_INVALID_HANDLE, 0);
    }
    if size > MAX_REQUEST || output == 0 || capacity < header {
        return fail(engine, ERROR_INVALID_PARAMETER, 0);
    }
    if capacity < header + size {
        return fail(engine, ERROR_INSUFFICIENT_BUFFER, 0);
    }
    // Only a plain IPv4 TTL option is modeled; anything else would have to be
    // interpreted without a network to interpret it against.
    if options != 0 {
        let raw = read(engine, options, 4)?;
        if raw[0] == 0 || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
            event.status = ERROR_NOT_SUPPORTED;
            engine.get_data_mut().apis.icmp.record(event);
            return fail(engine, ERROR_NOT_SUPPORTED, 0);
        }
        event.request_ttl = raw[0];
    }
    // Broadcast, multicast and the unspecified address have no single peer, so
    // they are refused rather than answered for.
    if address == [0, 0, 0, 0]
        || address[0] >= 224
        || address == config.broadcast()
        || address == [255, 255, 255, 255]
    {
        event.status = ERROR_NOT_SUPPORTED;
        engine.get_data_mut().apis.icmp.record(event);
        return fail(engine, ERROR_NOT_SUPPORTED, 0);
    }
    let payload = if size == 0 {
        Vec::new()
    } else {
        read(engine, request, size)?
    };
    // An echo payload is a documented covert channel, so it is captured as
    // evidence whether or not anything replies.
    if !payload.is_empty() {
        engine.get_data_mut().apis.captures.add(
            payload.clone(),
            ArtifactKind::Network,
            "icmp_echo_request",
            &event.host,
        );
    }
    let local = address == [127, 0, 0, 1] || address == config.address();
    if !local {
        event.status = IP_REQ_TIMED_OUT;
        engine.get_data_mut().apis.icmp.record(event);
        return fail(engine, IP_REQ_TIMED_OUT, 0);
    }
    let mut reply = vec![0u8; (header + payload.len() as u64) as usize];
    reply[0..4].copy_from_slice(&address);
    // IP_SUCCESS, a zero round trip, and the payload echoed back.
    reply[8..12].copy_from_slice(&0u32.to_le_bytes());
    reply[12..14].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    let data = if payload.is_empty() { 0 } else { output + header };
    reply[16..16 + width as usize].copy_from_slice(&data.to_le_bytes()[..width as usize]);
    let option_at = if width == 8 { 24 } else { 20 };
    reply[option_at] = REPLY_TTL;
    reply[header as usize..].copy_from_slice(&payload);
    put(engine, output, &reply)?;
    event.replied = true;
    engine.get_data_mut().apis.icmp.record(event);
    engine.get_data_mut().apis.last_error = 0;
    Ok(1)
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "ICMP echo is outside the kernel target profile"
    );
    match call {
        Call::CreateFile => match engine.get_data_mut().apis.icmp.open() {
            Some(handle) => {
                engine.get_data_mut().apis.last_error = 0;
                Ok(handle)
            }
            None => fail(engine, ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE_VALUE),
        },
        Call::CloseHandle => {
            if engine.get_data_mut().apis.icmp.close(args[0]) {
                engine.get_data_mut().apis.last_error = 0;
                Ok(1)
            } else {
                fail(engine, ERROR_INVALID_HANDLE, 0)
            }
        }
        Call::SendEcho => send_echo(engine, args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_layout_matches_the_documented_structure() {
        assert_eq!(reply_size(4), 28);
        assert_eq!(reply_size(8), 40);
    }

    #[test]
    fn handles_are_issued_closed_once_and_bounded() {
        let mut state = State::default();
        let handle = state.open().expect("first handle");
        assert!(state.holds(handle));
        assert!(state.close(handle));
        assert!(!state.close(handle));
        for _ in 0..MAX_HANDLES {
            state.open();
        }
        assert!(state.open().is_none());
    }
}
