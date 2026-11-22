//! IP Helper enumeration (`iphlpapi`): adapters, addresses, routes and the
//! ARP/TCP tables.
//!
//! Every answer is derived from the persona's single configured adapter, so a
//! run and its replay describe the same machine and no host interface is ever
//! read. The layout is the real one for each pointer width — the structures
//! are built byte by byte at the offsets a compiler would use, with the
//! interior `Next`, string and `sockaddr` pointers fixed up into the caller's
//! own buffer — so a sample that walks `IP_ADAPTER_ADDRESSES` by hand finds
//! what Windows would hand it.
//!
//! Network enumeration is a fingerprinting surface a sample uses to decide
//! where it is, so it is observed and answered rather than refused: the
//! address, mask, gateway, DNS servers, MAC and routing table all agree with
//! the Winsock model's own host address.
use super::*;
use emumee_core::persona::AdapterConfig;

// Win32 results these tables report.
pub(super) const NO_ERROR: u64 = 0;
pub(super) const ERROR_INVALID_PARAMETER: u64 = 87;
pub(super) const ERROR_BUFFER_OVERFLOW: u64 = 111;
pub(super) const ERROR_INSUFFICIENT_BUFFER: u64 = 122;
pub(super) const ERROR_NOT_SUPPORTED: u64 = 50;
pub(super) const ERROR_NO_DATA: u64 = 232;

const AF_UNSPEC: u32 = 0;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

/// MIB_IF_TYPE_ETHERNET, the one interface type this profile presents.
const IF_TYPE_ETHERNET: u32 = 6;
/// A gigabit link, as the description implies.
const LINK_SPEED: u64 = 1_000_000_000;

// GetAdaptersAddresses flags.
const SKIP_UNICAST: u32 = 0x0001;
const SKIP_ANYCAST: u32 = 0x0002;
const SKIP_MULTICAST: u32 = 0x0004;
const SKIP_DNS_SERVER: u32 = 0x0008;
const INCLUDE_PREFIX: u32 = 0x0010;
const SKIP_FRIENDLY_NAME: u32 = 0x0020;
const INCLUDE_WINS_INFO: u32 = 0x0040;
const INCLUDE_GATEWAYS: u32 = 0x0080;
const SUPPORTED_FLAGS: u32 = SKIP_UNICAST
    | SKIP_ANYCAST
    | SKIP_MULTICAST
    | SKIP_DNS_SERVER
    | INCLUDE_PREFIX
    | SKIP_FRIENDLY_NAME
    | INCLUDE_WINS_INFO
    | INCLUDE_GATEWAYS;

/// Bound on a table this model will build for a caller.
const MAX_TABLE: usize = 64 * 1024;

/// One observed IP Helper query.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub detail: String,
    /// Bytes the table needed, as the caller was told.
    pub required: u64,
    pub status: u32,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub queries: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that asked for no table serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.queries == 0 && self.events.is_empty() && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    pub report: Report,
}

impl State {
    fn record(&mut self, api: &'static str, detail: String, required: u64, status: u32) {
        self.report.queries += 1;
        if self.report.events.len() < 64 {
            self.report.events.push(Event {
                api,
                detail,
                required,
                status,
            });
        } else {
            self.report.omitted_events += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    AdaptersInfo,
    AdaptersAddresses,
    NetworkParams,
    IfTable,
    IpAddrTable,
    IpForwardTable,
    IpNetTable,
    ExtendedTcpTable,
    LengthToMask,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    if module != "iphlpapi" {
        return None;
    }
    let row = match name {
        "GetAdaptersInfo" => (AdaptersInfo, 2, T::U32),
        "GetAdaptersAddresses" => (AdaptersAddresses, 5, T::U32),
        "GetNetworkParams" => (NetworkParams, 2, T::U32),
        "GetIfTable" => (IfTable, 3, T::U32),
        "GetIpAddrTable" => (IpAddrTable, 3, T::U32),
        "GetIpForwardTable" => (IpForwardTable, 3, T::U32),
        "GetIpNetTable" => (IpNetTable, 3, T::U32),
        "GetExtendedTcpTable" => (ExtendedTcpTable, 6, T::U32),
        "ConvertLengthToIpv4Mask" => (LengthToMask, 2, T::U32),
        _ => return None,
    };
    Some(row)
}

pub(super) fn ptr_width(engine: &Unicorn<Trace>) -> u64 {
    if engine.get_data().architecture == Architecture::X64 {
        8
    } else {
        4
    }
}

pub(super) fn put(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    require(engine, address, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, address, bytes)
}

pub(super) fn write_dword(engine: &mut Unicorn<Trace>, address: u64, value: u32) -> Result<()> {
    put(engine, address, &value.to_le_bytes())
}

pub(super) fn read_dword(engine: &Unicorn<Trace>, address: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(
        read(engine, address, 4)?.try_into().unwrap(),
    ))
}

pub(super) fn write_pointer(engine: &mut Unicorn<Trace>, address: u64, value: u64) -> Result<()> {
    let width = ptr_width(engine) as usize;
    put(engine, address, &value.to_le_bytes()[..width])
}

pub(super) fn read_pointer(engine: &Unicorn<Trace>, address: u64) -> Result<u64> {
    let width = ptr_width(engine);
    let bytes = read(engine, address, width)?;
    let mut value = [0u8; 8];
    value[..width as usize].copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(value))
}

pub(super) fn encode(text: &str, wide: bool) -> Vec<u8> {
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

/// The persona's one adapter.
pub(super) fn adapter(engine: &Unicorn<Trace>) -> AdapterConfig {
    engine.get_data().apis.persona.model.adapter().clone()
}

/// A `sockaddr_in` for an IPv4 address, in the 16 bytes Windows uses.
pub(super) fn sockaddr_in(address: [u8; 4], port: u16) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend(AF_INET.to_le_bytes()[..2].to_vec());
    bytes.extend(port.to_be_bytes());
    bytes.extend(address);
    bytes.extend([0u8; 8]);
    bytes
}

/// Dotted-quad text for an address, as the fixed-width IP_ADDR_STRING fields
/// carry it.
pub(super) fn dotted(address: [u8; 4]) -> String {
    format!(
        "{}.{}.{}.{}",
        address[0], address[1], address[2], address[3]
    )
}

/// An IPv4 address as the `IPAddr` DWORD Windows stores it in: the four octets
/// in network order, read back as a little-endian word.
pub(super) fn ip_word(address: [u8; 4]) -> u32 {
    u32::from_le_bytes(address)
}

/// A buffer being built for a caller, with the caller's own base address so
/// interior pointers can be fixed up as the real tables' are.
pub(super) struct Writer {
    pub base: u64,
    pub width: usize,
    pub bytes: Vec<u8>,
}

impl Writer {
    pub(super) fn new(base: u64, width: usize) -> Self {
        Self {
            base,
            width,
            bytes: Vec::new(),
        }
    }
    /// Reserve `size` zeroed bytes at `align` and answer their offset.
    pub(super) fn reserve(&mut self, size: usize, align: usize) -> usize {
        let pad = (align - self.bytes.len() % align) % align;
        self.bytes.extend(std::iter::repeat_n(0u8, pad));
        let offset = self.bytes.len();
        self.bytes.extend(std::iter::repeat_n(0u8, size));
        offset
    }
    /// Place bytes and answer the guest address they will have.
    pub(super) fn add(&mut self, raw: &[u8], align: usize) -> u64 {
        let offset = self.reserve(raw.len(), align);
        self.bytes[offset..offset + raw.len()].copy_from_slice(raw);
        self.base + offset as u64
    }
    pub(super) fn address(&self, offset: usize) -> u64 {
        self.base + offset as u64
    }
    pub(super) fn blob(&mut self, offset: usize, raw: &[u8]) {
        self.bytes[offset..offset + raw.len()].copy_from_slice(raw);
    }
    pub(super) fn byte(&mut self, offset: usize, value: u8) {
        self.bytes[offset] = value;
    }
    pub(super) fn dword(&mut self, offset: usize, value: u32) {
        self.blob(offset, &value.to_le_bytes());
    }
    pub(super) fn qword(&mut self, offset: usize, value: u64) {
        self.blob(offset, &value.to_le_bytes());
    }
    pub(super) fn pointer(&mut self, offset: usize, address: u64) {
        let width = self.width;
        self.blob(offset, &address.to_le_bytes()[..width]);
    }
}

/// `IP_ADDR_STRING`: `Next`, a 16-byte address text, a 16-byte mask text and a
/// context word.
struct AddrString {
    size: usize,
    address: usize,
    mask: usize,
    context: usize,
}

impl AddrString {
    fn new(width: usize) -> Self {
        Self {
            size: if width == 8 { 48 } else { 40 },
            address: width,
            mask: width + 16,
            context: width + 32,
        }
    }
    /// Fill one node: the texts, the context and the `Next` link.
    fn fill(
        &self,
        writer: &mut Writer,
        offset: usize,
        address: [u8; 4],
        mask: [u8; 4],
        context: u32,
        next: u64,
    ) {
        writer.pointer(offset, next);
        let text = encode(&dotted(address), false);
        writer.blob(offset + self.address, &text);
        let text = encode(&dotted(mask), false);
        writer.blob(offset + self.mask, &text);
        writer.dword(offset + self.context, context);
    }
}

fn align_to(value: usize, align: usize) -> usize {
    value + (align - value % align) % align
}

/// `IP_ADAPTER_INFO` field offsets for a pointer width.
struct AdapterInfo {
    size: usize,
    combo_index: usize,
    adapter_name: usize,
    description: usize,
    address_length: usize,
    address: usize,
    index: usize,
    kind: usize,
    dhcp_enabled: usize,
    current_address: usize,
    address_list: usize,
    gateway_list: usize,
    dhcp_server: usize,
    have_wins: usize,
    primary_wins: usize,
    secondary_wins: usize,
    lease_obtained: usize,
    lease_expires: usize,
}

impl AdapterInfo {
    fn new(width: usize) -> Self {
        let strings = AddrString::new(width).size;
        let current_address = align_to(width + 420, width);
        let address_list = current_address + width;
        let have_wins = address_list + 3 * strings;
        let primary_wins = align_to(have_wins + 4, width);
        let secondary_wins = primary_wins + strings;
        let lease_obtained = align_to(secondary_wins + strings, 8);
        Self {
            size: lease_obtained + 16,
            combo_index: width,
            adapter_name: width + 4,
            description: width + 264,
            address_length: width + 396,
            address: width + 400,
            index: width + 408,
            kind: width + 412,
            dhcp_enabled: width + 416,
            current_address,
            address_list,
            gateway_list: address_list + strings,
            dhcp_server: address_list + 2 * strings,
            have_wins,
            primary_wins,
            secondary_wins,
            lease_obtained,
            lease_expires: lease_obtained + 8,
        }
    }
}

/// `FIXED_INFO` field offsets for a pointer width.
struct FixedInfo {
    size: usize,
    current_dns: usize,
    dns_list: usize,
    node_type: usize,
    scope_id: usize,
    enable_routing: usize,
    enable_proxy: usize,
    enable_dns: usize,
}

impl FixedInfo {
    fn new(width: usize) -> Self {
        let strings = AddrString::new(width).size;
        let dns_list = 264 + width;
        let node_type = dns_list + strings;
        let scope_id = node_type + 4;
        let enable_routing = scope_id + 260;
        Self {
            size: align_to(enable_routing + 12, width),
            current_dns: 264,
            dns_list,
            node_type,
            scope_id,
            enable_routing,
            enable_proxy: enable_routing + 4,
            enable_dns: enable_routing + 8,
        }
    }
}

/// `IP_ADAPTER_ADDRESSES` field offsets for a pointer width. The layout is
/// irregular enough that the real offsets are named outright.
struct AdapterAddresses {
    size: usize,
    adapter_name: usize,
    first_unicast: usize,
    first_anycast: usize,
    first_multicast: usize,
    first_dns: usize,
    dns_suffix: usize,
    description: usize,
    friendly_name: usize,
    physical_address: usize,
    physical_length: usize,
    flags: usize,
    mtu: usize,
    if_type: usize,
    oper_status: usize,
    first_prefix: usize,
    transmit_speed: usize,
    receive_speed: usize,
    first_wins: usize,
    first_gateway: usize,
    ipv4_metric: usize,
    luid: usize,
    dhcpv4_server: usize,
    compartment: usize,
    connection_type: usize,
    duid_length: usize,
}

impl AdapterAddresses {
    fn new(width: usize) -> Self {
        if width == 8 {
            Self {
                size: 448,
                adapter_name: 16,
                first_unicast: 24,
                first_anycast: 32,
                first_multicast: 40,
                first_dns: 48,
                dns_suffix: 56,
                description: 64,
                friendly_name: 72,
                physical_address: 80,
                physical_length: 88,
                flags: 92,
                mtu: 96,
                if_type: 100,
                oper_status: 104,
                first_prefix: 176,
                transmit_speed: 184,
                receive_speed: 192,
                first_wins: 200,
                first_gateway: 208,
                ipv4_metric: 216,
                luid: 224,
                dhcpv4_server: 232,
                compartment: 248,
                connection_type: 268,
                duid_length: 428,
            }
        } else {
            Self {
                size: 376,
                adapter_name: 12,
                first_unicast: 16,
                first_anycast: 20,
                first_multicast: 24,
                first_dns: 28,
                dns_suffix: 32,
                description: 36,
                friendly_name: 40,
                physical_address: 44,
                physical_length: 52,
                flags: 56,
                mtu: 60,
                if_type: 64,
                oper_status: 68,
                first_prefix: 140,
                transmit_speed: 144,
                receive_speed: 152,
                first_wins: 160,
                first_gateway: 164,
                ipv4_metric: 168,
                luid: 176,
                dhcpv4_server: 184,
                compartment: 192,
                connection_type: 212,
                duid_length: 360,
            }
        }
    }
}

/// Offsets shared by the address-list nodes hung off an adapter. Each begins
/// with a union of a `ULONGLONG` alignment member and the length/flags pair,
/// so every one of these nodes is eight-byte aligned in both architectures.
struct AddressNode {
    size: usize,
    address: usize,
}

impl AddressNode {
    fn new(width: usize) -> Self {
        let address = align_to(8 + width, width);
        Self {
            size: align_to(address + 2 * width, 8),
            address,
        }
    }
}

/// The documented MIB table protocol: a caller passes a capacity, learns the
/// required size, and gets the table only when it fits.
fn table_out(
    engine: &mut Unicorn<Trace>,
    api: &'static str,
    detail: String,
    buffer: u64,
    size_ptr: u64,
    image: &[u8],
    short: u64,
) -> Result<u64> {
    if size_ptr == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let required = image.len() as u64;
    if image.len() > MAX_TABLE {
        engine
            .get_data_mut()
            .apis
            .adapters
            .record(api, detail, required, ERROR_NOT_SUPPORTED as u32);
        return Ok(ERROR_NOT_SUPPORTED);
    }
    let capacity = u64::from(read_dword(engine, size_ptr)?);
    if buffer == 0 || capacity < required {
        write_dword(engine, size_ptr, required as u32)?;
        engine
            .get_data_mut()
            .apis
            .adapters
            .record(api, detail, required, short as u32);
        return Ok(short);
    }
    put(engine, buffer, image)?;
    write_dword(engine, size_ptr, required as u32)?;
    engine
        .get_data_mut()
        .apis
        .adapters
        .record(api, detail, required, 0);
    Ok(NO_ERROR)
}

/// `GetAdaptersInfo`: one adapter, with its address, mask, gateway and DHCP
/// server as fixed-width dotted-quad text, exactly where the structure puts
/// them. The lease times stay zero: this profile has no clock-independent
/// lease to report and will not invent one.
fn adapters_info(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let width = ptr_width(engine) as usize;
    let layout = AdapterInfo::new(width);
    let strings = AddrString::new(width);
    let config = adapter(engine);
    let mut writer = Writer::new(args[0], width);
    let head = writer.reserve(layout.size, 8);
    writer.dword(head + layout.combo_index, 0);
    writer.blob(head + layout.adapter_name, &encode(&config.guid, false));
    writer.blob(head + layout.description, &encode(&config.description, false));
    writer.dword(head + layout.address_length, 6);
    writer.blob(head + layout.address, &config.physical());
    writer.dword(head + layout.index, config.if_index);
    writer.dword(head + layout.kind, IF_TYPE_ETHERNET);
    writer.dword(head + layout.dhcp_enabled, u32::from(config.dhcp_enabled));
    writer.pointer(head + layout.current_address, 0);
    strings.fill(
        &mut writer,
        head + layout.address_list,
        config.address(),
        config.mask(),
        config.if_index,
        0,
    );
    strings.fill(
        &mut writer,
        head + layout.gateway_list,
        config.gateway_address(),
        [0, 0, 0, 0],
        0,
        0,
    );
    // A DHCP-configured adapter reports the server that leased it; the lease
    // comes from the gateway in this layout.
    let (server, server_mask) = if config.dhcp_enabled {
        (config.gateway_address(), [255, 255, 255, 255])
    } else {
        ([0, 0, 0, 0], [0, 0, 0, 0])
    };
    strings.fill(
        &mut writer,
        head + layout.dhcp_server,
        server,
        server_mask,
        0,
        0,
    );
    writer.dword(head + layout.have_wins, 0);
    for offset in [layout.primary_wins, layout.secondary_wins] {
        strings.fill(
            &mut writer,
            head + offset,
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            0,
            0,
        );
    }
    writer.qword(head + layout.lease_obtained, 0);
    writer.qword(head + layout.lease_expires, 0);
    let image = writer.bytes;
    table_out(
        engine,
        "GetAdaptersInfo",
        config.ipv4.clone(),
        args[0],
        args[1],
        &image,
        ERROR_BUFFER_OVERFLOW,
    )
}

/// `GetAdaptersAddresses`: the modern linked graph, built in the caller's
/// buffer with every interior pointer fixed up to address that buffer.
fn adapters_addresses(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let (family, flags) = (args[0] as u32, args[1] as u32);
    // The reserved argument is a DWORD, so only its low half is the value.
    if args[2] as u32 != 0 || args[4] == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    if !matches!(family, AF_UNSPEC | AF_INET | AF_INET6) {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    if flags & !SUPPORTED_FLAGS != 0 {
        engine.get_data_mut().apis.adapters.record(
            "GetAdaptersAddresses",
            format!("flags {flags:#x} are not modeled"),
            0,
            ERROR_NOT_SUPPORTED as u32,
        );
        return Ok(ERROR_NOT_SUPPORTED);
    }
    // This profile presents one IPv4 adapter, so an IPv6-only enumeration
    // genuinely has nothing to report.
    if family == AF_INET6 {
        engine.get_data_mut().apis.adapters.record(
            "GetAdaptersAddresses",
            "IPv6 is not configured".into(),
            0,
            ERROR_NO_DATA as u32,
        );
        return Ok(ERROR_NO_DATA);
    }
    let width = ptr_width(engine) as usize;
    let layout = AdapterAddresses::new(width);
    let node = AddressNode::new(width);
    let config = adapter(engine);
    // Both also open with the eight-byte-aligned union, so both are padded
    // to eight bytes however wide a pointer is.
    let unicast_size = align_to(align_to(8 + width, width) + 2 * width + 24 + 1, 8);
    let prefix_size = align_to(align_to(8 + width, width) + 2 * width + 4, 8);
    let dns = config.dns_addresses();
    let mut writer = Writer::new(args[3], width);

    let head = writer.reserve(layout.size, 8);
    let unicast = (flags & SKIP_UNICAST == 0).then(|| writer.reserve(unicast_size, 8));
    let servers: Vec<usize> = if flags & SKIP_DNS_SERVER == 0 {
        dns.iter().map(|_| writer.reserve(node.size, 8)).collect()
    } else {
        Vec::new()
    };
    let gateway = (flags & INCLUDE_GATEWAYS != 0).then(|| writer.reserve(node.size, 8));
    let prefix = (flags & INCLUDE_PREFIX != 0).then(|| writer.reserve(prefix_size, 8));

    // Strings and sockaddrs follow the nodes that point at them.
    let name = writer.add(&encode(&config.guid, false), 1);
    let suffix_text = if engine.get_data().apis.persona.model.domain_joined() {
        engine.get_data().apis.persona.model.domain_text().to_owned()
    } else {
        String::new()
    };
    let suffix = writer.add(&encode(&suffix_text, true), 2);
    let description = writer.add(&encode(&config.description, true), 2);
    let friendly = if flags & SKIP_FRIENDLY_NAME == 0 {
        writer.add(&encode(&config.name, true), 2)
    } else {
        0
    };
    let unicast_sockaddr = unicast.map(|_| writer.add(&sockaddr_in(config.address(), 0), 8));
    let server_sockaddrs: Vec<u64> = servers
        .iter()
        .zip(&dns)
        .map(|(_, address)| writer.add(&sockaddr_in(*address, 0), 8))
        .collect();
    let gateway_sockaddr = gateway.map(|_| writer.add(&sockaddr_in(config.gateway_address(), 0), 8));
    let prefix_sockaddr = prefix.map(|_| writer.add(&sockaddr_in(config.network(), 0), 8));
    let dhcp_sockaddr = config
        .dhcp_enabled
        .then(|| writer.add(&sockaddr_in(config.gateway_address(), 0), 8));

    writer.dword(head, layout.size as u32);
    writer.dword(head + 4, config.if_index);
    writer.pointer(head + 8, 0);
    writer.pointer(head + layout.adapter_name, name);
    writer.pointer(
        head + layout.first_unicast,
        unicast.map_or(0, |offset| writer.address(offset)),
    );
    // No anycast or multicast membership is modeled, so both lists are empty
    // rather than carrying an invented group.
    writer.pointer(head + layout.first_anycast, 0);
    writer.pointer(head + layout.first_multicast, 0);
    writer.pointer(
        head + layout.first_dns,
        servers.first().map_or(0, |offset| writer.address(*offset)),
    );
    writer.pointer(head + layout.dns_suffix, suffix);
    writer.pointer(head + layout.description, description);
    writer.pointer(head + layout.friendly_name, friendly);
    writer.blob(head + layout.physical_address, &config.physical());
    writer.dword(head + layout.physical_length, 6);
    // IP_ADAPTER_IPV4_ENABLED | NETBIOS_OVER_TCPIP_ENABLED (| DHCP_ENABLED).
    writer.dword(
        head + layout.flags,
        0x80 | 0x40 | if config.dhcp_enabled { 0x04 } else { 0 },
    );
    writer.dword(head + layout.mtu, config.mtu);
    writer.dword(head + layout.if_type, IF_TYPE_ETHERNET);
    // IfOperStatusUp.
    writer.dword(head + layout.oper_status, 1);
    writer.pointer(
        head + layout.first_prefix,
        prefix.map_or(0, |offset| writer.address(offset)),
    );
    writer.qword(head + layout.transmit_speed, LINK_SPEED);
    writer.qword(head + layout.receive_speed, LINK_SPEED);
    // INCLUDE_WINS_INFO was asked for, but this profile configures no WINS
    // server, so the list stays empty instead of naming one.
    writer.pointer(head + layout.first_wins, 0);
    writer.pointer(
        head + layout.first_gateway,
        gateway.map_or(0, |offset| writer.address(offset)),
    );
    writer.dword(head + layout.ipv4_metric, 25);
    // NET_LUID: the interface type in the high bits, the index below it.
    writer.qword(
        head + layout.luid,
        (u64::from(IF_TYPE_ETHERNET) << 48) | (u64::from(config.if_index) << 24),
    );
    if let Some(address) = dhcp_sockaddr {
        writer.pointer(head + layout.dhcpv4_server, address);
        writer.dword(head + layout.dhcpv4_server + width, 16);
    }
    // NET_IF_COMPARTMENT_ID_PRIMARY and NET_IF_CONNECTION_DEDICATED.
    writer.dword(head + layout.compartment, 1);
    writer.dword(head + layout.connection_type, 1);
    writer.dword(head + layout.duid_length, 0);

    if let (Some(offset), Some(address)) = (unicast, unicast_sockaddr) {
        writer.dword(offset, unicast_size as u32);
        // IP_ADAPTER_ADDRESS_DNS_ELIGIBLE.
        writer.dword(offset + 4, 1);
        writer.pointer(offset + 8, 0);
        let address_at = align_to(8 + width, width);
        writer.pointer(offset + address_at, address);
        writer.dword(offset + address_at + width, 16);
        let rest = address_at + 2 * width;
        // Prefix and suffix origin: DHCP when leased, manual otherwise.
        let origin = if config.dhcp_enabled { 3 } else { 1 };
        writer.dword(offset + rest, origin);
        writer.dword(offset + rest + 4, origin);
        // IpDadStatePreferred and a day of lifetime left.
        writer.dword(offset + rest + 8, 4);
        for index in 3..6 {
            writer.dword(offset + rest + index * 4, 86_400);
        }
        writer.byte(offset + rest + 24, config.prefix_length as u8);
    }
    for (index, offset) in servers.iter().enumerate() {
        writer.dword(*offset, node.size as u32);
        let next = servers
            .get(index + 1)
            .map_or(0, |next| writer.address(*next));
        writer.pointer(offset + 8, next);
        writer.pointer(offset + node.address, server_sockaddrs[index]);
        writer.dword(offset + node.address + width, 16);
    }
    if let (Some(offset), Some(address)) = (gateway, gateway_sockaddr) {
        writer.dword(offset, node.size as u32);
        writer.pointer(offset + 8, 0);
        writer.pointer(offset + node.address, address);
        writer.dword(offset + node.address + width, 16);
    }
    if let (Some(offset), Some(address)) = (prefix, prefix_sockaddr) {
        writer.dword(offset, prefix_size as u32);
        writer.pointer(offset + 8, 0);
        let address_at = align_to(8 + width, width);
        writer.pointer(offset + address_at, address);
        writer.dword(offset + address_at + width, 16);
        writer.dword(offset + address_at + 2 * width, config.prefix_length);
    }
    let image = writer.bytes;
    table_out(
        engine,
        "GetAdaptersAddresses",
        format!("family {family}, flags {flags:#x}"),
        args[3],
        args[4],
        &image,
        ERROR_BUFFER_OVERFLOW,
    )
}

/// `GetNetworkParams`: the host and domain names and the DNS server chain.
fn network_params(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let width = ptr_width(engine) as usize;
    let layout = FixedInfo::new(width);
    let strings = AddrString::new(width);
    let config = adapter(engine);
    let host = engine
        .get_data()
        .apis
        .persona
        .model
        .computer_name_text()
        .to_owned();
    let domain = if engine.get_data().apis.persona.model.domain_joined() {
        engine.get_data().apis.persona.model.domain_text().to_owned()
    } else {
        String::new()
    };
    // The fields are fixed-width ANSI, so a name that cannot be spelled there
    // is refused rather than truncated into something the guest would mistake
    // for the whole name.
    if !host.is_ascii() || !domain.is_ascii() || host.len() >= 132 || domain.len() >= 132 {
        engine.get_data_mut().apis.adapters.record(
            "GetNetworkParams",
            "host or domain name is outside the FIXED_INFO profile".into(),
            0,
            ERROR_NOT_SUPPORTED as u32,
        );
        return Ok(ERROR_NOT_SUPPORTED);
    }
    let servers = config.dns_addresses();
    let mut writer = Writer::new(args[0], width);
    let head = writer.reserve(layout.size + (servers.len() - 1) * strings.size, 8);
    writer.blob(head, &encode(&host, false));
    writer.blob(head + 132, &encode(&domain, false));
    writer.pointer(head + layout.current_dns, 0);
    for (index, server) in servers.iter().enumerate() {
        let offset = if index == 0 {
            head + layout.dns_list
        } else {
            head + layout.size + (index - 1) * strings.size
        };
        let next = if index + 1 < servers.len() {
            writer.address(head + layout.size + index * strings.size)
        } else {
            0
        };
        strings.fill(&mut writer, offset, *server, [0, 0, 0, 0], 0, next);
    }
    // A hybrid NetBIOS node with no DHCP scope, routing and proxying off and
    // DNS on: the ordinary configuration of a DHCP-configured workstation.
    writer.dword(head + layout.node_type, 8);
    writer.blob(head + layout.scope_id, &[0u8]);
    writer.dword(head + layout.enable_routing, 0);
    writer.dword(head + layout.enable_proxy, 0);
    writer.dword(head + layout.enable_dns, 1);
    let image = writer.bytes;
    table_out(
        engine,
        "GetNetworkParams",
        format!("{} DNS servers", servers.len()),
        args[0],
        args[1],
        &image,
        ERROR_BUFFER_OVERFLOW,
    )
}

/// `GetIfTable`: one operational Ethernet interface. Every counter is zero and
/// `dwLastChange` stays zero, because a contained run has no traffic history
/// and the clock must not leak into a table a control compares.
fn if_table(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let config = adapter(engine);
    let width = ptr_width(engine) as usize;
    let mut writer = Writer::new(args[0], width);
    let head = writer.reserve(4 + 860, 4);
    writer.dword(head, 1);
    let row = head + 4;
    let device = format!("\\DEVICE\\TCPIP_{}", config.guid);
    let name: Vec<u8> = device
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .take(510)
        .collect();
    writer.blob(row, &name);
    writer.dword(row + 512, config.if_index);
    writer.dword(row + 516, IF_TYPE_ETHERNET);
    writer.dword(row + 520, config.mtu);
    writer.dword(row + 524, LINK_SPEED as u32);
    writer.dword(row + 528, 6);
    writer.blob(row + 532, &config.physical());
    // Administratively up, and operationally connected.
    writer.dword(row + 540, 1);
    writer.dword(row + 544, 5);
    let description = config.description.as_bytes();
    writer.dword(row + 600, description.len() as u32);
    writer.blob(row + 604, description);
    let image = writer.bytes;
    table_out(
        engine,
        "GetIfTable",
        config.name.clone(),
        args[0],
        args[1],
        &image,
        ERROR_INSUFFICIENT_BUFFER,
    )
}

/// `GetIpAddrTable`: the adapter's one address and its mask.
fn ip_addr_table(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let config = adapter(engine);
    let width = ptr_width(engine) as usize;
    let mut writer = Writer::new(args[0], width);
    let head = writer.reserve(4 + 24, 4);
    writer.dword(head, 1);
    let row = head + 4;
    writer.dword(row, ip_word(config.address()));
    writer.dword(row + 4, config.if_index);
    writer.dword(row + 8, ip_word(config.mask()));
    // dwBCastAddr is the all-ones host convention, as a real stack reports.
    writer.dword(row + 12, 1);
    writer.dword(row + 16, 65_535);
    writer.blob(row + 20, &0u16.to_le_bytes());
    // MIB_IPADDR_PRIMARY.
    writer.blob(row + 22, &1u16.to_le_bytes());
    let image = writer.bytes;
    table_out(
        engine,
        "GetIpAddrTable",
        config.ipv4.clone(),
        args[0],
        args[1],
        &image,
        ERROR_INSUFFICIENT_BUFFER,
    )
}

/// `GetIpForwardTable`: the three routes a single-homed DHCP workstation has —
/// the default route through its gateway, the on-link subnet, and the host
/// route for its own address.
fn ip_forward_table(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let config = adapter(engine);
    let width = ptr_width(engine) as usize;
    // destination, mask, next hop, type (4 indirect / 3 direct), protocol
    // (3 NETMGMT / 2 LOCAL), metric.
    let mut routes = [
        ([0, 0, 0, 0], [0, 0, 0, 0], config.gateway_address(), 4, 3, 25),
        (config.network(), config.mask(), [0, 0, 0, 0], 3, 2, 25),
        (config.address(), [255, 255, 255, 255], [0, 0, 0, 0], 3, 2, 25),
    ];
    if args[2] as u32 != 0 {
        routes.sort_by_key(|route| (route.0, route.1));
    }
    let mut writer = Writer::new(args[0], width);
    let head = writer.reserve(4 + routes.len() * 56, 4);
    writer.dword(head, routes.len() as u32);
    for (index, (destination, mask, next_hop, kind, protocol, metric)) in
        routes.iter().enumerate()
    {
        let row = head + 4 + index * 56;
        writer.dword(row, ip_word(*destination));
        writer.dword(row + 4, ip_word(*mask));
        writer.dword(row + 8, 0);
        writer.dword(row + 12, ip_word(*next_hop));
        writer.dword(row + 16, config.if_index);
        writer.dword(row + 20, *kind);
        writer.dword(row + 24, *protocol);
        writer.dword(row + 28, 0);
        writer.dword(row + 32, 0);
        writer.dword(row + 36, *metric);
        // Metrics 2..5 are unused, which the documented tables spell as -1.
        for unused in 1..5 {
            writer.dword(row + 36 + unused * 4, u32::MAX);
        }
    }
    let image = writer.bytes;
    table_out(
        engine,
        "GetIpForwardTable",
        format!("{} routes", routes.len()),
        args[0],
        args[1],
        &image,
        ERROR_INSUFFICIENT_BUFFER,
    )
}

/// `GetIpNetTable`: the ARP cache. A contained run has resolved no peer, so
/// the only entry is the subnet broadcast's all-ones hardware address — the
/// one mapping that needs no invented neighbour.
fn ip_net_table(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let config = adapter(engine);
    let width = ptr_width(engine) as usize;
    if args[1] == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let mut writer = Writer::new(args[0], width);
    let head = writer.reserve(4 + 24, 4);
    writer.dword(head, 1);
    let row = head + 4;
    writer.dword(row, config.if_index);
    writer.dword(row + 4, 6);
    writer.blob(row + 8, &[0xff; 6]);
    writer.dword(row + 16, ip_word(config.broadcast()));
    // MIB_IPNET_TYPE_STATIC.
    writer.dword(row + 20, 4);
    let image = writer.bytes;
    table_out(
        engine,
        "GetIpNetTable",
        dotted(config.broadcast()),
        args[0],
        args[1],
        &image,
        ERROR_INSUFFICIENT_BUFFER,
    )
}

/// `GetExtendedTcpTable`: the TCP connection table. The profile is offline by
/// construction — the Winsock model never completes a connection — so the
/// table is genuinely empty rather than carrying a fabricated peer.
fn extended_tcp_table(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let (family, class) = (args[3] as u32, args[4] as u32);
    if args[5] as u32 != 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    // TCP_TABLE_OWNER_PID_ALL over IPv4 is the shape samples enumerate with.
    if family != AF_INET || class != 5 {
        engine.get_data_mut().apis.adapters.record(
            "GetExtendedTcpTable",
            format!("family {family}, class {class} are not modeled"),
            0,
            ERROR_NOT_SUPPORTED as u32,
        );
        return Ok(ERROR_NOT_SUPPORTED);
    }
    let width = ptr_width(engine) as usize;
    let mut writer = Writer::new(args[0], width);
    let head = writer.reserve(4, 4);
    writer.dword(head, 0);
    let image = writer.bytes;
    table_out(
        engine,
        "GetExtendedTcpTable",
        "no established connection".into(),
        args[0],
        args[1],
        &image,
        ERROR_INSUFFICIENT_BUFFER,
    )
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "IP Helper is outside the kernel target profile"
    );
    match call {
        Call::LengthToMask => {
            // ConvertLengthToIpv4Mask(MaskLength, Mask): the mask is reported
            // in network order, and a length past 32 reports INADDR_NONE.
            if args[1] == 0 {
                return Ok(ERROR_INVALID_PARAMETER);
            }
            let length = args[0] as u32;
            if length > 32 {
                write_dword(engine, args[1], u32::MAX)?;
                return Ok(ERROR_INVALID_PARAMETER);
            }
            let mask: u32 = if length == 0 {
                0
            } else {
                u32::MAX << (32 - length)
            };
            write_dword(engine, args[1], mask.swap_bytes())?;
            Ok(NO_ERROR)
        }
        Call::AdaptersInfo => adapters_info(engine, args),
        Call::AdaptersAddresses => adapters_addresses(engine, args),
        Call::NetworkParams => network_params(engine, args),
        Call::IfTable => if_table(engine, args),
        Call::IpAddrTable => ip_addr_table(engine, args),
        Call::IpForwardTable => ip_forward_table(engine, args),
        Call::IpNetTable => ip_net_table(engine, args),
        Call::ExtendedTcpTable => extended_tcp_table(engine, args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The structure sizes are the ones MSVC lays out for each pointer width.
    #[test]
    fn modeled_layouts_match_the_documented_structure_sizes() {
        assert_eq!(AddrString::new(4).size, 40);
        assert_eq!(AddrString::new(8).size, 48);
        assert_eq!(AdapterInfo::new(4).size, 648);
        assert_eq!(AdapterInfo::new(8).size, 704);
        assert_eq!(AdapterInfo::new(4).address_list, 428);
        assert_eq!(AdapterInfo::new(8).address_list, 440);
        assert_eq!(AdapterInfo::new(8).lease_obtained, 688);
        assert_eq!(FixedInfo::new(4).size, 584);
        assert_eq!(FixedInfo::new(8).size, 600);
        assert_eq!(FixedInfo::new(8).node_type, 320);
        assert_eq!(AddressNode::new(4).size, 24);
        assert_eq!(AddressNode::new(8).size, 32);
        assert_eq!(AddressNode::new(8).address, 16);
    }

    /// The default adapter is the NAT layout the Winsock model shares.
    #[test]
    fn default_adapter_geometry_is_consistent() {
        let config = AdapterConfig::default();
        assert_eq!(config.address(), [10, 0, 2, 15]);
        assert_eq!(config.mask(), [255, 255, 255, 0]);
        assert_eq!(config.network(), [10, 0, 2, 0]);
        assert_eq!(config.broadcast(), [10, 0, 2, 255]);
        assert_eq!(config.physical(), [0x00, 0x15, 0x5d, 0x2e, 0x4a, 0x71]);
        assert_eq!(config.dns_addresses(), vec![[10, 0, 2, 3]]);
        assert_eq!(super::super::sockets::HOST_IP, config.address());
    }

    #[test]
    fn dotted_text_and_address_words_round_trip() {
        assert_eq!(dotted([10, 0, 2, 15]), "10.0.2.15");
        assert_eq!(ip_word([10, 0, 2, 15]), 0x0f02_000a);
        assert_eq!(sockaddr_in([10, 0, 2, 15], 80).len(), 16);
        assert_eq!(&sockaddr_in([10, 0, 2, 15], 80)[..8], &[2, 0, 0, 80, 10, 0, 2, 15]);
    }
}
