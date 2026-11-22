//! Winsock model (`ws2_32`), reachable by name and by ordinal.
//!
//! The profile is offline by construction, and the model is built so that the
//! *intent* of every socket operation is captured even though no packet can
//! leave: `connect` records the exact host and port asked for, `send` captures
//! the payload it was handed as a network artifact, and a DNS lookup records the
//! name queried. Each then reports the Winsock error an unreachable network
//! genuinely produces, rather than inventing a peer.
//!
//! Inbound networking stays refused, matching the frozen reference: `listen`
//! and `accept` report `WSAEOPNOTSUPP` and are recorded as denials, so a sample
//! cannot be handed a server socket that could never receive anything.
//!
//! Everything that is pure or local is answered for real: byte-order
//! conversion, address parsing and formatting, `WSAStartup` bookkeeping,
//! `select` timing out with no ready sockets, socket options, and the loopback
//! and own-host names.
use super::*;
use emumee_core::artifacts::ArtifactKind;
use std::collections::BTreeMap;

const INVALID_SOCKET: u64 = 0xffff_ffff;
const SOCKET_ERROR: u64 = 0xffff_ffff;

// Winsock errors.
const WSAEINVAL: u32 = 10022;
/// WSAEFAULT: a buffer argument is unusable or too small.
const WSAEFAULT_OR_INVALID: u32 = 10014;
const WSAENOPROTOOPT: u32 = 10042;
const WSAENOTSOCK: u32 = 10038;
const WSAEOPNOTSUPP: u32 = 10045;
const WSAEAFNOSUPPORT: u32 = 10047;
const WSAENETUNREACH: u32 = 10051;
const WSAENOTCONN: u32 = 10057;
const WSANOTINITIALISED: u32 = 10093;
const WSAHOST_NOT_FOUND: u32 = 11001;

const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

/// The synthetic adapter's address, in host order. A classic NAT layout,
/// deterministic and clearly not a real network.
pub(super) const HOST_IP: [u8; 4] = [10, 0, 2, 15];
pub(super) const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

#[derive(Clone, Debug)]
struct Socket {
    family: u32,
    kind: u32,
    bound: Option<(u32, u16)>,
    non_blocking: bool,
}

/// One observed socket or resolver operation.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub detail: String,
    pub bytes: usize,
    pub denied: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub sockets_opened: u64,
    pub connect_attempts: u64,
    pub resolve_attempts: u64,
    pub bytes_offered: u64,
    pub denied: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that opened no socket serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.sockets_opened == 0
            && self.connect_attempts == 0
            && self.resolve_attempts == 0
            && self.bytes_offered == 0
            && self.denied == 0
            && self.events.is_empty()
            && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    started: u32,
    counter: u64,
    sockets: BTreeMap<u64, Socket>,
    /// Winsock keeps one static buffer for `inet_ntoa`; so does this model.
    ntoa: Option<u64>,
    pub report: Report,
}

impl State {
    fn handle(&mut self) -> u64 {
        self.counter += 1;
        0x200 + self.counter * 4
    }
    fn record(&mut self, api: &'static str, detail: String, bytes: usize, denied: bool) {
        match api {
            // Only a socket that actually opened counts as opened.
            "socket" if !denied => self.report.sockets_opened += 1,
            "connect" => self.report.connect_attempts += 1,
            "gethostbyname" | "getaddrinfo" => self.report.resolve_attempts += 1,
            "send" => self.report.bytes_offered += bytes as u64,
            _ => {}
        }
        if denied {
            self.report.denied += 1;
        }
        if self.report.events.len() < 64 {
            self.report.events.push(Event { api, detail, bytes, denied });
        } else {
            self.report.omitted_events += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    Startup,
    Cleanup,
    SetLastError,
    GetLastError,
    Socket,
    CloseSocket,
    Connect,
    Bind,
    Listen,
    Accept,
    Send,
    Recv,
    Shutdown,
    Select,
    FdIsSet,
    IoctlSocket,
    WsaIoctl,
    SetSockOpt,
    GetSockOpt,
    GetHostName { wide: bool },
    GetHostByName,
    GetAddrInfo,
    FreeAddrInfo,
    InetAddr,
    InetNtoa,
    InetPton,
    InetNtop { wide: bool },
    Htonl,
    Htons,
    Ntohl,
    Ntohs,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    if module != "ws2_32" && module != "wsock32" {
        return None;
    }
    // Ordinal-only imports are routine for Winsock; the table is the documented
    // export ordinal for each function.
    let resolved: &str = match name {
        "#1" => "accept",
        "#2" => "bind",
        "#3" => "closesocket",
        "#4" => "connect",
        "#7" => "getsockopt",
        "#8" => "htonl",
        "#9" => "htons",
        "#10" => "ioctlsocket",
        "#11" => "inet_addr",
        "#12" => "inet_ntoa",
        "#13" => "listen",
        "#14" => "ntohl",
        "#15" => "ntohs",
        "#16" => "recv",
        "#18" => "select",
        "#19" => "send",
        "#21" => "setsockopt",
        "#22" => "shutdown",
        "#23" => "socket",
        "#52" => "gethostbyname",
        "#57" => "gethostname",
        "#112" => "WSASetLastError",
        "#115" => "WSAStartup",
        "#116" => "WSACleanup",
        "#151" => "__WSAFDIsSet",
        "#177" => "freeaddrinfo",
        "#178" => "getaddrinfo",
        "#180" => "inet_ntop",
        "#181" => "inet_pton",
        other => other,
    };
    let row = match resolved {
        "WSAStartup" => (Startup, 2, T::U32),
        "WSACleanup" => (Cleanup, 0, T::U32),
        "WSASetLastError" => (SetLastError, 1, T::Void),
        "WSAGetLastError" => (GetLastError, 0, T::U32),
        "socket" => (Socket, 3, T::Pointer),
        // The WSASocket spellings carry protocol info and flags the model reads
        // the same way; the extra arguments are observed, not required.
        "WSASocket" | "WSASocketA" | "WSASocketW" => (Socket, 6, T::Pointer),
        "closesocket" => (CloseSocket, 1, T::U32),
        "connect" => (Connect, 3, T::U32),
        "WSAConnect" => (Connect, 7, T::U32),
        "bind" => (Bind, 3, T::U32),
        "listen" => (Listen, 2, T::U32),
        "accept" => (Accept, 3, T::Pointer),
        "send" => (Send, 4, T::U32),
        "recv" => (Recv, 4, T::U32),
        "shutdown" => (Shutdown, 2, T::U32),
        "select" => (Select, 5, T::U32),
        "__WSAFDIsSet" => (FdIsSet, 2, T::U32),
        "ioctlsocket" => (IoctlSocket, 3, T::U32),
        "WSAIoctl" => (WsaIoctl, 9, T::U32),
        "setsockopt" => (SetSockOpt, 5, T::U32),
        "getsockopt" => (GetSockOpt, 5, T::U32),
        "gethostname" => (GetHostName { wide: false }, 2, T::U32),
        "GetHostNameW" => (GetHostName { wide: true }, 2, T::U32),
        "gethostbyname" => (GetHostByName, 1, T::Pointer),
        "getaddrinfo" => (GetAddrInfo, 4, T::U32),
        "freeaddrinfo" => (FreeAddrInfo, 1, T::Void),
        "inet_addr" => (InetAddr, 1, T::U32),
        "inet_ntoa" => (InetNtoa, 1, T::Pointer),
        "inet_pton" => (InetPton, 3, T::U32),
        "inet_ntop" => (InetNtop { wide: false }, 4, T::Pointer),
        "InetNtopW" => (InetNtop { wide: true }, 4, T::Pointer),
        "htonl" => (Htonl, 1, T::U32),
        "htons" => (Htons, 1, T::U32),
        "ntohl" => (Ntohl, 1, T::U32),
        "ntohs" => (Ntohs, 1, T::U32),
        _ => return None,
    };
    Some(row)
}

fn ptr_width(engine: &Unicorn<Trace>) -> u64 {
    if engine.get_data().architecture == Architecture::X64 {
        8
    } else {
        4
    }
}

fn put(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    require(engine, address, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, address, bytes)
}

fn write_dword(engine: &mut Unicorn<Trace>, address: u64, value: u32) -> Result<()> {
    put(engine, address, &value.to_le_bytes())
}

fn read_dword(engine: &Unicorn<Trace>, address: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(read(engine, address, 4)?.try_into().unwrap()))
}

fn write_pointer(engine: &mut Unicorn<Trace>, address: u64, value: u64) -> Result<()> {
    let width = ptr_width(engine) as usize;
    put(engine, address, &value.to_le_bytes()[..width])
}

fn read_pointer(engine: &Unicorn<Trace>, address: u64) -> Result<u64> {
    let width = ptr_width(engine);
    let bytes = read(engine, address, width)?;
    let mut value = [0u8; 8];
    value[..width as usize].copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(value))
}

fn fail(engine: &mut Unicorn<Trace>, code: u32, result: u64) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(result)
}

fn ok(engine: &mut Unicorn<Trace>, value: u64) -> Result<u64> {
    engine.get_data_mut().apis.last_error = 0;
    Ok(value)
}

/// Winsock requires a successful WSAStartup before anything else.
fn started(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().apis.sockets.started > 0
}

fn encode(text: &str, wide: bool) -> Vec<u8> {
    if wide {
        let mut bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        bytes.extend([0, 0]);
        bytes
    } else {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }
}

/// Parse a dotted-quad address.
fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = text.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out[index] = part.parse::<u16>().ok().filter(|v| *v <= 255)? as u8;
    }
    Some(out)
}

fn format_ipv4(address: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", address[0], address[1], address[2], address[3])
}

/// Resolve a host name offline. Loopback and the persona's own host answer for
/// real; a literal address parses; anything else is not found, because this
/// profile has no resolver and will not invent one.
fn resolve(engine: &Unicorn<Trace>, name: &str) -> Option<[u8; 4]> {
    if name.eq_ignore_ascii_case("localhost") {
        return Some(LOOPBACK);
    }
    if let Some(address) = parse_ipv4(name) {
        return Some(address);
    }
    let host = engine.get_data().apis.persona.model.computer_name_text();
    if name.eq_ignore_ascii_case(host) {
        return Some(HOST_IP);
    }
    None
}

/// Read a `sockaddr_in`, answering its address and port in host order.
fn read_sockaddr(engine: &Unicorn<Trace>, address: u64) -> Result<Option<([u8; 4], u16)>> {
    let bytes = read(engine, address, 16)?;
    let family = u16::from_le_bytes([bytes[0], bytes[1]]) as u32;
    if family != AF_INET {
        return Ok(None);
    }
    // sin_port is network order.
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    Ok(Some(([bytes[4], bytes[5], bytes[6], bytes[7]], port)))
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    // Byte-order helpers and the error setters work before initialization.
    match call {
        Call::Htonl | Call::Ntohl => return Ok((args[0] as u32).swap_bytes() as u64),
        Call::Htons | Call::Ntohs => return Ok((args[0] as u16).swap_bytes() as u64),
        Call::SetLastError => {
            engine.get_data_mut().apis.last_error = args[0] as u32;
            return Ok(0);
        }
        Call::GetLastError => return Ok(engine.get_data().apis.last_error as u64),
        Call::Startup => {
            // WSAStartup(wVersionRequested, lpWSAData)
            if args[1] == 0 {
                return Ok(WSAEINVAL as u64);
            }
            let requested = args[0] as u16;
            // Anything below 1.1 is not supported by a Winsock 2 stack.
            if requested < 0x0101 {
                return Ok(10092); // WSAVERNOTSUPPORTED
            }
            let description = "WinSock 2.0";
            let status = "Running";
            let width = ptr_width(engine);
            let mut bytes = vec![0u8; if width == 8 { 408 } else { 398 }];
            // The negotiated version is the lower of requested and 2.2.
            let negotiated = requested.min(0x0202);
            bytes[0..2].copy_from_slice(&negotiated.to_le_bytes());
            bytes[2..4].copy_from_slice(&0x0202u16.to_le_bytes());
            let (max_sockets_at, max_udp_at, description_at, status_at) =
                if width == 8 { (4, 6, 16, 273) } else { (390, 392, 4, 261) };
            bytes[max_sockets_at..max_sockets_at + 2].copy_from_slice(&0u16.to_le_bytes());
            bytes[max_udp_at..max_udp_at + 2].copy_from_slice(&0u16.to_le_bytes());
            bytes[description_at..description_at + description.len()]
                .copy_from_slice(description.as_bytes());
            bytes[status_at..status_at + status.len()].copy_from_slice(status.as_bytes());
            put(engine, args[1], &bytes)?;
            engine.get_data_mut().apis.sockets.started += 1;
            return ok(engine, 0);
        }
        Call::Cleanup => {
            let state = &mut engine.get_data_mut().apis.sockets;
            if state.started == 0 {
                return Ok(WSANOTINITIALISED as u64);
            }
            state.started -= 1;
            return ok(engine, 0);
        }
        _ => {}
    }
    if !started(engine) {
        // Every remaining entry point needs an initialized stack.
        let result = match call {
            Call::Socket | Call::Accept | Call::GetHostByName | Call::InetNtoa => 0,
            _ => SOCKET_ERROR,
        };
        return fail(engine, WSANOTINITIALISED, result);
    }
    match call {
        Call::Socket => {
            // socket(af, type, protocol) and the WSASocket spellings.
            let (family, kind) = (args[0] as u32, args[1] as u32);
            if family != AF_INET {
                engine.get_data_mut().apis.sockets.record(
                    "socket",
                    format!("family {family} refused"),
                    0,
                    true,
                );
                return fail(engine, WSAEAFNOSUPPORT, INVALID_SOCKET);
            }
            if kind != SOCK_STREAM && kind != SOCK_DGRAM {
                engine.get_data_mut().apis.sockets.record(
                    "socket",
                    format!("type {kind} refused"),
                    0,
                    true,
                );
                return fail(engine, WSAEOPNOTSUPP, INVALID_SOCKET);
            }
            let handle = engine.get_data_mut().apis.sockets.handle();
            let state = &mut engine.get_data_mut().apis.sockets;
            state.sockets.insert(
                handle,
                Socket { family, kind, bound: None, non_blocking: false },
            );
            state.record(
                "socket",
                if kind == SOCK_STREAM { "tcp".into() } else { "udp".into() },
                0,
                false,
            );
            ok(engine, handle)
        }
        Call::CloseSocket => {
            if engine
                .get_data_mut()
                .apis
                .sockets
                .sockets
                .remove(&args[0])
                .is_none()
            {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            }
            ok(engine, 0)
        }
        Call::Connect => {
            // connect(s, name, namelen) / WSAConnect(s, name, namelen, ...).
            let Some(socket) = engine.get_data().apis.sockets.sockets.get(&args[0]).cloned() else {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            };
            let Some((address, port)) = read_sockaddr(engine, args[1])? else {
                return fail(engine, WSAEAFNOSUPPORT, SOCKET_ERROR);
            };
            // The socket and the address it is pointed at must agree.
            if socket.family != AF_INET {
                return fail(engine, WSAEAFNOSUPPORT, SOCKET_ERROR);
            }
            // The destination is exactly what a sample intended to reach, so it
            // is recorded in full before the unreachable network is reported.
            engine.get_data_mut().apis.sockets.record(
                "connect",
                format!("{}:{port}", format_ipv4(address)),
                0,
                true,
            );
            fail(engine, WSAENETUNREACH, SOCKET_ERROR)
        }
        Call::Bind => {
            // Binding a local address needs no network and is accepted.
            if !engine.get_data().apis.sockets.sockets.contains_key(&args[0]) {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            }
            let Some((address, port)) = read_sockaddr(engine, args[1])? else {
                return fail(engine, WSAEAFNOSUPPORT, SOCKET_ERROR);
            };
            let packed = u32::from_be_bytes(address);
            if let Some(socket) = engine.get_data_mut().apis.sockets.sockets.get_mut(&args[0]) {
                socket.bound = Some((packed, port));
            }
            engine.get_data_mut().apis.sockets.record(
                "bind",
                format!("{}:{port}", format_ipv4(address)),
                0,
                false,
            );
            ok(engine, 0)
        }
        Call::Listen => {
            // Inbound networking stays disabled, as in the frozen reference.
            if !engine.get_data().apis.sockets.sockets.contains_key(&args[0]) {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            }
            engine
                .get_data_mut()
                .apis
                .sockets
                .record("listen", "inbound disabled".into(), 0, true);
            fail(engine, WSAEOPNOTSUPP, SOCKET_ERROR)
        }
        Call::Accept => {
            if !engine.get_data().apis.sockets.sockets.contains_key(&args[0]) {
                return fail(engine, WSAENOTSOCK, INVALID_SOCKET);
            }
            engine
                .get_data_mut()
                .apis
                .sockets
                .record("accept", "inbound disabled".into(), 0, true);
            fail(engine, WSAEOPNOTSUPP, INVALID_SOCKET)
        }
        Call::Send => {
            // send(s, buf, len, flags): the payload is captured as an artifact
            // even though it cannot leave, then the unconnected socket is
            // reported.
            if !engine.get_data().apis.sockets.sockets.contains_key(&args[0]) {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            }
            let length = args[2] as u32 as i32;
            if !(0..=1 << 20).contains(&length) {
                return fail(engine, WSAEINVAL, SOCKET_ERROR);
            }
            let payload = if args[1] != 0 && length > 0 {
                read(engine, args[1], length as u64)?
            } else {
                Vec::new()
            };
            let bytes = payload.len();
            if !payload.is_empty() {
                engine.get_data_mut().apis.captures.add(
                    payload,
                    ArtifactKind::Network,
                    "socket_outbound",
                    "send",
                );
            }
            engine
                .get_data_mut()
                .apis
                .sockets
                .record("send", format!("{bytes} bytes offered"), bytes, true);
            fail(engine, WSAENOTCONN, SOCKET_ERROR)
        }
        Call::Recv => {
            if !engine.get_data().apis.sockets.sockets.contains_key(&args[0]) {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            }
            engine
                .get_data_mut()
                .apis
                .sockets
                .record("recv", "no connection".into(), 0, true);
            fail(engine, WSAENOTCONN, SOCKET_ERROR)
        }
        Call::Shutdown => {
            if !engine.get_data().apis.sockets.sockets.contains_key(&args[0]) {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            }
            ok(engine, 0)
        }
        Call::Select => {
            // No socket is ever ready, so select reports its timeout with every
            // descriptor set emptied, which is what a caller must then read.
            for set in [args[1], args[2], args[3]] {
                if set != 0 {
                    let count = read_dword(engine, set)?;
                    ensure!(count <= 1024, "fd_set count exceeds its modeled bound");
                    write_dword(engine, set, 0)?;
                }
            }
            ok(engine, 0)
        }
        Call::FdIsSet => {
            // __WSAFDIsSet(s, set): scan the array the caller still holds.
            if args[1] == 0 {
                return Ok(0);
            }
            let width = ptr_width(engine);
            let count = read_dword(engine, args[1])?;
            ensure!(count <= 1024, "fd_set count exceeds its modeled bound");
            for index in 0..count as u64 {
                if read_pointer(engine, args[1] + width + index * width)? == args[0] {
                    return Ok(1);
                }
            }
            Ok(0)
        }
        Call::IoctlSocket => {
            // FIONBIO sets non-blocking; FIONREAD reports nothing readable.
            if !engine.get_data().apis.sockets.sockets.contains_key(&args[0]) {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            }
            match args[1] as u32 {
                0x8004_667e => {
                    let enable = args[2] != 0 && read_dword(engine, args[2])? != 0;
                    if let Some(socket) =
                        engine.get_data_mut().apis.sockets.sockets.get_mut(&args[0])
                    {
                        socket.non_blocking = enable;
                    }
                    ok(engine, 0)
                }
                0x4004_667f => {
                    if args[2] != 0 {
                        write_dword(engine, args[2], 0)?;
                    }
                    ok(engine, 0)
                }
                _ => fail(engine, WSAEINVAL, SOCKET_ERROR),
            }
        }
        Call::WsaIoctl => {
            // WSAIoctl(s, code, inBuf, inLen, outBuf, outLen, returned, ...)
            if !engine.get_data().apis.sockets.sockets.contains_key(&args[0]) {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            }
            // No control code is modeled to produce data; the output stays
            // empty and the byte count says so rather than returning garbage.
            if args[6] != 0 {
                write_dword(engine, args[6], 0)?;
            }
            fail(engine, WSAEOPNOTSUPP, SOCKET_ERROR)
        }
        Call::SetSockOpt => {
            if !engine.get_data().apis.sockets.sockets.contains_key(&args[0]) {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            }
            // Options are accepted; none of them can change an offline profile.
            ok(engine, 0)
        }
        Call::GetSockOpt => {
            // getsockopt(s, level, optname, optval, optlen)
            let Some(socket) = engine.get_data().apis.sockets.sockets.get(&args[0]).cloned() else {
                return fail(engine, WSAENOTSOCK, SOCKET_ERROR);
            };
            if args[3] == 0 || args[4] == 0 {
                return fail(engine, WSAEFAULT_OR_INVALID, SOCKET_ERROR);
            }
            let capacity = read_dword(engine, args[4])?;
            // SOL_SOCKET options this profile can answer honestly.
            let value: u32 = match args[2] as u32 {
                0x1008 => socket.kind,  // SO_TYPE
                0x1007 => 0,            // SO_ERROR: no pending error
                0x1002 => 65536,        // SO_SNDBUF
                0x1001 => 65536,        // SO_RCVBUF
                _ => return fail(engine, WSAENOPROTOOPT, SOCKET_ERROR),
            };
            if capacity < 4 {
                return fail(engine, WSAEINVAL, SOCKET_ERROR);
            }
            write_dword(engine, args[3], value)?;
            write_dword(engine, args[4], 4)?;
            ok(engine, 0)
        }
        Call::GetHostName { wide } => {
            // gethostname(name, namelen) / GetHostNameW
            let host = engine
                .get_data()
                .apis
                .persona
                .model
                .computer_name_text()
                .to_string();
            let bytes = encode(&host, wide);
            let units = if wide { bytes.len() / 2 } else { bytes.len() };
            if args[0] == 0 || (args[1] as u32 as usize) < units {
                return fail(engine, WSAEFAULT_OR_INVALID, SOCKET_ERROR);
            }
            put(engine, args[0], &bytes)?;
            ok(engine, 0)
        }
        Call::GetHostByName => host_by_name(engine, args),
        Call::GetAddrInfo => addr_info(engine, args),
        Call::FreeAddrInfo => {
            // The whole list was allocated as one block.
            heap::release(engine, args[0])?;
            Ok(0)
        }
        Call::InetAddr => {
            let text = files::path(engine, args[0], false)?;
            match parse_ipv4(&text) {
                // inet_addr answers network byte order.
                Some(address) => Ok(u32::from_le_bytes(address) as u64),
                None => Ok(INVALID_SOCKET), // INADDR_NONE
            }
        }
        Call::InetNtoa => {
            // inet_ntoa(in): one static buffer, reused by every call, as
            // Winsock documents.
            let packed = args[0] as u32;
            let text = format_ipv4(packed.to_le_bytes());
            let buffer = match engine.get_data().apis.sockets.ntoa {
                Some(address) => address,
                None => {
                    let address = heap::alloc(engine, 16)?;
                    engine.get_data_mut().apis.sockets.ntoa = Some(address);
                    address
                }
            };
            put(engine, buffer, &encode(&text, false))?;
            ok(engine, buffer)
        }
        Call::InetPton => {
            // inet_pton(family, src, dst)
            if args[0] as u32 != AF_INET {
                return fail(engine, WSAEAFNOSUPPORT, SOCKET_ERROR);
            }
            let text = files::path(engine, args[1], false)?;
            match parse_ipv4(&text) {
                Some(address) => {
                    put(engine, args[2], &address)?;
                    ok(engine, 1)
                }
                // A malformed address reports zero, not an error.
                None => ok(engine, 0),
            }
        }
        Call::InetNtop { wide } => {
            // inet_ntop(family, src, dst, size)
            if args[0] as u32 != AF_INET {
                return fail(engine, WSAEAFNOSUPPORT, 0);
            }
            let raw = read(engine, args[1], 4)?;
            let text = format_ipv4([raw[0], raw[1], raw[2], raw[3]]);
            let bytes = encode(&text, wide);
            let units = if wide { bytes.len() / 2 } else { bytes.len() };
            if (args[3] as u32 as usize) < units {
                return fail(engine, WSAEINVAL, 0);
            }
            put(engine, args[2], &bytes)?;
            ok(engine, args[2])
        }
        // Handled before initialization is checked.
        Call::Startup
        | Call::Cleanup
        | Call::SetLastError
        | Call::GetLastError
        | Call::Htonl
        | Call::Htons
        | Call::Ntohl
        | Call::Ntohs => unreachable!("handled above"),
    }
}

/// `gethostbyname(name)`: build a HOSTENT for a name this profile can answer.
fn host_by_name(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    if args[0] == 0 {
        return fail(engine, WSAEFAULT_OR_INVALID, 0);
    }
    let name = files::path(engine, args[0], false)?;
    if name.len() > 255 {
        return fail(engine, WSAHOST_NOT_FOUND, 0);
    }
    let resolved = resolve(engine, &name);
    engine.get_data_mut().apis.sockets.record(
        "gethostbyname",
        format!(
            "{name} -> {}",
            resolved.map(format_ipv4).unwrap_or_else(|| "not found".into())
        ),
        0,
        resolved.is_none(),
    );
    let Some(address) = resolved else {
        return fail(engine, WSAHOST_NOT_FOUND, 0);
    };
    let width = ptr_width(engine);
    // HOSTENT then the alias list, address list, address and name.
    let header = if width == 8 { 32u64 } else { 16 };
    let name_bytes = encode(&name, false);
    // Layout: [HOSTENT][aliases NULL][addr_list ptr, NULL][addr(4)][name]
    let aliases_at = header;
    let addr_list_at = aliases_at + width;
    let addr_at = addr_list_at + width * 2;
    let name_at = addr_at + 4;
    let total = name_at + name_bytes.len() as u64;
    let block = heap::alloc(engine, total)?;

    let (addrtype_at, length_at, addr_list_field) =
        if width == 8 { (16u64, 18u64, 24u64) } else { (8, 10, 12) };
    write_pointer(engine, block, block + name_at)?;
    write_pointer(engine, block + width, block + aliases_at)?;
    put(engine, block + addrtype_at, &(AF_INET as u16).to_le_bytes())?;
    put(engine, block + length_at, &4u16.to_le_bytes())?;
    write_pointer(engine, block + addr_list_field, block + addr_list_at)?;
    // An empty alias list and a one-entry, NULL-terminated address list.
    write_pointer(engine, block + aliases_at, 0)?;
    write_pointer(engine, block + addr_list_at, block + addr_at)?;
    write_pointer(engine, block + addr_list_at + width, 0)?;
    put(engine, block + addr_at, &address)?;
    put(engine, block + name_at, &name_bytes)?;
    ok(engine, block)
}

/// `getaddrinfo(node, service, hints, res)`: one ADDRINFOA plus its sockaddr.
fn addr_info(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    if args[3] == 0 {
        return Ok(WSAEINVAL as u64);
    }
    let node = if args[0] != 0 {
        files::path(engine, args[0], false)?
    } else {
        String::new()
    };
    let service = if args[1] != 0 {
        files::path(engine, args[1], false)?
    } else {
        String::new()
    };
    let port: u16 = service.parse().unwrap_or(0);
    // An empty node means the loopback address for a client lookup.
    let resolved = if node.is_empty() {
        Some(LOOPBACK)
    } else {
        resolve(engine, &node)
    };
    engine.get_data_mut().apis.sockets.record(
        "getaddrinfo",
        format!(
            "{node}:{service} -> {}",
            resolved.map(format_ipv4).unwrap_or_else(|| "not found".into())
        ),
        0,
        resolved.is_none(),
    );
    let Some(address) = resolved else {
        return Ok(WSAHOST_NOT_FOUND as u64);
    };
    // Honor the hints' socket type when given, defaulting to a stream socket.
    let (kind, protocol) = if args[2] != 0 {
        let socktype = read_dword(engine, args[2] + 8)?;
        let protocol = read_dword(engine, args[2] + 12)?;
        (if socktype == 0 { SOCK_STREAM } else { socktype }, protocol)
    } else {
        (SOCK_STREAM, 0)
    };
    let width = ptr_width(engine);
    let header = if width == 8 { 48u64 } else { 32 };
    let sockaddr_at = header;
    let total = sockaddr_at + 16;
    let block = heap::alloc(engine, total)?;
    write_dword(engine, block, 0)?;
    write_dword(engine, block + 4, AF_INET)?;
    write_dword(engine, block + 8, kind)?;
    write_dword(engine, block + 12, protocol)?;
    let (addrlen_at, canon_at, addr_at, next_at) =
        if width == 8 { (16u64, 24, 32, 40) } else { (16, 20, 24, 28) };
    if width == 8 {
        put(engine, block + addrlen_at, &16u64.to_le_bytes())?;
    } else {
        write_dword(engine, block + addrlen_at, 16)?;
    }
    write_pointer(engine, block + canon_at, 0)?;
    write_pointer(engine, block + addr_at, block + sockaddr_at)?;
    write_pointer(engine, block + next_at, 0)?;
    // sockaddr_in: family, network-order port, address, zero padding.
    let mut sockaddr = vec![0u8; 16];
    sockaddr[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    sockaddr[2..4].copy_from_slice(&port.to_be_bytes());
    sockaddr[4..8].copy_from_slice(&address);
    put(engine, block + sockaddr_at, &sockaddr)?;
    write_pointer(engine, args[3], block)?;
    ok(engine, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinal_imports_resolve_to_their_documented_functions() {
        // A representative spread of the Winsock export ordinals.
        for (ordinal, expected_argc) in [
            ("#1", 3),   // accept
            ("#2", 3),   // bind
            ("#3", 1),   // closesocket
            ("#4", 3),   // connect
            ("#8", 1),   // htonl
            ("#13", 2),  // listen
            ("#16", 4),  // recv
            ("#19", 4),  // send
            ("#23", 3),  // socket
            ("#52", 1),  // gethostbyname
            ("#115", 2), // WSAStartup
            ("#116", 0), // WSACleanup
            ("#151", 2), // __WSAFDIsSet
            ("#178", 4), // getaddrinfo
            ("#181", 3), // inet_pton
        ] {
            let (_, argc, _) = definition("ws2_32", ordinal)
                .unwrap_or_else(|| panic!("ordinal {ordinal} is not modeled"));
            assert_eq!(argc, expected_argc, "ordinal {ordinal}");
        }
        // An ordinal outside the table stays unmodeled rather than aliasing
        // something arbitrary.
        assert!(definition("ws2_32", "#9999").is_none());
    }

    #[test]
    fn address_text_round_trips() {
        assert_eq!(parse_ipv4("10.0.2.15"), Some([10, 0, 2, 15]));
        assert_eq!(parse_ipv4("127.0.0.1"), Some(LOOPBACK));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(parse_ipv4("10.0.2"), None);
        assert_eq!(parse_ipv4("10.0.2.256"), None);
        assert_eq!(parse_ipv4("10.0.2.x"), None);
        assert_eq!(parse_ipv4(""), None);
        assert_eq!(format_ipv4([10, 0, 2, 15]), "10.0.2.15");
    }
}
