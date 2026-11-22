//! The LAN Manager surfaces: workstation and join information
//! (`netapi32`/`wkscli`/`netutils`) and the multiple-provider network
//! redirector (`mpr`).
//!
//! Join and workstation information are pure fingerprinting — a sample asks
//! them to decide whether it landed on a domain-joined machine — so they are
//! answered from the persona in the real `WKSTA_INFO_*` layout for each
//! pointer width, with the strings published on the guest heap and released by
//! `NetApiBufferFree` exactly as the real allocator's are.
//!
//! The redirector is the lateral-movement surface, so what the sample *asked
//! for* is what matters: `WNetAddConnection2` records the share, the local
//! device and the user name it tried to authenticate as (never the password
//! itself, only that one was supplied), and then reports `ERROR_NO_NETWORK` —
//! which is the literal truth of this profile. `NetUserAdd` records the
//! account a sample tried to create, with its privilege level and flags; no
//! account database exists, so nothing is created.
use super::adapters::{
    ERROR_INVALID_PARAMETER, encode, ptr_width, put, read_dword, read_pointer, write_dword,
    write_pointer,
};
use super::*;
use std::collections::BTreeSet;

const NERR_SUCCESS: u64 = 0;
const ERROR_INVALID_LEVEL: u64 = 124;
const ERROR_INVALID_HANDLE: u64 = 6;
/// ERROR_NO_NETWORK: there is no network, which is this profile's truth.
const ERROR_NO_NETWORK: u64 = 1222;
const ERROR_BAD_DEVICE: u64 = 1200;
const ERROR_BAD_NET_NAME: u64 = 67;
const ERROR_NOT_CONNECTED: u64 = 2250;
/// NERR_InvalidComputer: the named server is not this machine.
const NERR_INVALID_COMPUTER: u64 = 2351;

/// PLATFORM_ID_NT.
const PLATFORM_ID_NT: u32 = 500;
/// NETSETUP_JOIN_STATUS values.
const NET_SETUP_WORKGROUP_NAME: u32 = 2;
const NET_SETUP_DOMAIN_NAME: u32 = 3;

const RESOURCE_SCOPES: [u32; 5] = [1, 2, 3, 4, 5];
const RESOURCE_TYPES: [u32; 3] = [0, 1, 2];
const RESOURCE_USAGE_BITS: u32 = 0x1 | 0x2 | 0x10;

const MAX_BLOCKS: usize = 64;

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub detail: String,
    pub status: u32,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub queries: u64,
    /// Attempts to map or browse a remote share.
    pub share_attempts: u64,
    /// Accounts a sample tried to create.
    pub accounts_added: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that asked for none of this serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.queries == 0
            && self.share_attempts == 0
            && self.accounts_added == 0
            && self.events.is_empty()
            && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    blocks: BTreeSet<u64>,
    pub report: Report,
}

impl State {
    fn record(&mut self, api: &'static str, detail: String, status: u64) {
        self.report.queries += 1;
        match api {
            "WNetAddConnection2" | "WNetOpenEnum" => self.report.share_attempts += 1,
            "NetUserAdd" => self.report.accounts_added += 1,
            _ => {}
        }
        if self.report.events.len() < 64 {
            self.report.events.push(Event {
                api,
                detail,
                status: status as u32,
            });
        } else {
            self.report.omitted_events += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    JoinInformation,
    WkstaGetInfo,
    UserAdd,
    BufferFree,
    OpenEnum,
    EnumResource,
    AddConnection,
    GetConnection { wide: bool },
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    let row = match (module, name) {
        ("netapi32" | "wkscli", "NetGetJoinInformation") => (JoinInformation, 3, T::U32),
        ("netapi32" | "wkscli", "NetWkstaGetInfo") => (WkstaGetInfo, 3, T::U32),
        ("netapi32", "NetUserAdd") => (UserAdd, 4, T::U32),
        ("netapi32" | "netutils", "NetApiBufferFree") => (BufferFree, 1, T::U32),
        ("mpr", "WNetOpenEnum" | "WNetOpenEnumA" | "WNetOpenEnumW") => (OpenEnum, 5, T::U32),
        ("mpr", "WNetEnumResource" | "WNetEnumResourceA" | "WNetEnumResourceW") => {
            (EnumResource, 4, T::U32)
        }
        ("mpr", "WNetAddConnection2" | "WNetAddConnection2A" | "WNetAddConnection2W") => {
            (AddConnection, 4, T::U32)
        }
        ("mpr", "WNetGetConnectionA") => (GetConnection { wide: false }, 3, T::U32),
        ("mpr", "WNetGetConnectionW") => (GetConnection { wide: true }, 3, T::U32),
        _ => return None,
    };
    Some(row)
}

/// Publish a block on the guest heap, remember it so `NetApiBufferFree` can
/// release it, and answer its address.
fn publish(engine: &mut Unicorn<Trace>, bytes: &[u8]) -> Result<u64> {
    if engine.get_data().apis.lanman.blocks.len() >= MAX_BLOCKS {
        return Ok(0);
    }
    let address = heap::alloc(engine, bytes.len().max(1) as u64)?;
    if address == 0 {
        return Ok(0);
    }
    put(engine, address, bytes)?;
    engine.get_data_mut().apis.lanman.blocks.insert(address);
    Ok(address)
}

/// Is `server` this machine? A null pointer, an empty string and the
/// machine's own name (with or without the UNC prefix) all mean the local
/// computer; anything else names a machine this profile cannot reach.
fn local_server(engine: &Unicorn<Trace>, pointer: u64, wide: bool) -> Result<Option<String>> {
    if pointer == 0 {
        return Ok(Some(String::new()));
    }
    let text = files::path(engine, pointer, wide)?;
    let bare = text.trim_start_matches('\\');
    let host = engine.get_data().apis.persona.model.computer_name_text();
    let fqdn = engine.get_data().apis.persona.model.fully_qualified_name();
    let local = bare.is_empty()
        || bare.eq_ignore_ascii_case(host)
        || bare.eq_ignore_ascii_case(&fqdn)
        || bare.eq_ignore_ascii_case("localhost");
    Ok(if local { Some(text) } else { None })
}

/// `WKSTA_INFO_100/101/102` offsets for a pointer width. The three levels are
/// one growing structure, so one layout serves them all.
struct WkstaInfo {
    computer_name: usize,
    group: usize,
    major: usize,
    minor: usize,
    lan_root: usize,
    users: usize,
}

fn align_to(value: usize, align: usize) -> usize {
    value + (align - value % align) % align
}

impl WkstaInfo {
    fn new(width: usize) -> Self {
        let lan_root = align_to(3 * width + 8, width);
        Self {
            computer_name: width,
            group: 2 * width,
            major: 3 * width,
            minor: 3 * width + 4,
            lan_root,
            users: lan_root + width,
        }
    }
    fn size(&self, level: u32, width: usize) -> usize {
        match level {
            100 => self.lan_root,
            101 => self.lan_root + width,
            _ => align_to(self.users + 4, width),
        }
    }
}

/// `USER_INFO_1` offsets for a pointer width.
struct UserInfo {
    password: usize,
    privilege: usize,
    home: usize,
    comment: usize,
    flags: usize,
    script: usize,
}

impl UserInfo {
    fn new(width: usize) -> Self {
        let home = align_to(2 * width + 8, width);
        let comment = home + width;
        let flags = comment + width;
        Self {
            password: width,
            privilege: 2 * width + 4,
            home,
            comment,
            flags,
            script: align_to(flags + 4, width),
        }
    }
}

/// `NETRESOURCE` offsets for a pointer width.
struct NetResource {
    local_name: usize,
    remote_name: usize,
    provider: usize,
}

impl NetResource {
    fn new(width: usize) -> Self {
        let local_name = 16;
        let remote_name = align_to(local_name + width, width);
        Self {
            local_name,
            remote_name,
            provider: remote_name + 2 * width,
        }
    }
}

fn join_information(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    if args[1] == 0 || args[2] == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    if local_server(engine, args[0], true)?.is_none() {
        let detail = files::path(engine, args[0], true)?;
        engine
            .get_data_mut()
            .apis
            .lanman
            .record("NetGetJoinInformation", detail, NERR_INVALID_COMPUTER);
        return Ok(NERR_INVALID_COMPUTER);
    }
    let joined = engine.get_data().apis.persona.model.domain_joined();
    let name = engine.get_data().apis.persona.model.domain_text().to_owned();
    let status = if joined {
        NET_SETUP_DOMAIN_NAME
    } else {
        NET_SETUP_WORKGROUP_NAME
    };
    let block = publish(engine, &encode(&name, true))?;
    if block == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    write_pointer(engine, args[1], block)?;
    write_dword(engine, args[2], status)?;
    engine.get_data_mut().apis.lanman.record(
        "NetGetJoinInformation",
        format!("{name} ({})", if joined { "domain" } else { "workgroup" }),
        NERR_SUCCESS,
    );
    Ok(NERR_SUCCESS)
}

fn wksta_get_info(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let level = args[1] as u32;
    if args[2] == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    if !matches!(level, 100..=102) {
        engine.get_data_mut().apis.lanman.record(
            "NetWkstaGetInfo",
            format!("level {level}"),
            ERROR_INVALID_LEVEL,
        );
        return Ok(ERROR_INVALID_LEVEL);
    }
    if local_server(engine, args[0], true)?.is_none() {
        let detail = files::path(engine, args[0], true)?;
        engine
            .get_data_mut()
            .apis
            .lanman
            .record("NetWkstaGetInfo", detail, NERR_INVALID_COMPUTER);
        return Ok(NERR_INVALID_COMPUTER);
    }
    let width = ptr_width(engine) as usize;
    let layout = WkstaInfo::new(width);
    let size = layout.size(level, width);
    let host = engine
        .get_data()
        .apis
        .persona
        .model
        .computer_name_text()
        .to_owned();
    let group = engine.get_data().apis.persona.model.domain_text().to_owned();
    let build = engine.get_data().machine.windows_build();
    // The structure and the strings it points at are one allocation, which is
    // what NetApiBufferFree releases.
    let mut image = vec![0u8; size];
    let mut strings: Vec<u8> = Vec::new();
    let mut place = |text: &str| -> usize {
        let at = size + strings.len();
        strings.extend(encode(text, true));
        while (size + strings.len()) % 8 != 0 {
            strings.push(0);
        }
        at
    };
    let host_at = place(&host);
    let group_at = place(&group);
    let root_at = place("");
    let total = size + strings.len();
    let block = heap::alloc(engine, total as u64)?;
    if block == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let pointer = |value: u64| value.to_le_bytes()[..width].to_vec();
    image[..4].copy_from_slice(&PLATFORM_ID_NT.to_le_bytes());
    image[layout.computer_name..layout.computer_name + width]
        .copy_from_slice(&pointer(block + host_at as u64));
    image[layout.group..layout.group + width].copy_from_slice(&pointer(block + group_at as u64));
    image[layout.major..layout.major + 4].copy_from_slice(&10u32.to_le_bytes());
    image[layout.minor..layout.minor + 4].copy_from_slice(&0u32.to_le_bytes());
    if level >= 101 {
        image[layout.lan_root..layout.lan_root + width]
            .copy_from_slice(&pointer(block + root_at as u64));
    }
    if level == 102 {
        // One interactive session, which is what the persona describes.
        image[layout.users..layout.users + 4].copy_from_slice(&1u32.to_le_bytes());
    }
    image.extend(strings);
    put(engine, block, &image)?;
    engine.get_data_mut().apis.lanman.blocks.insert(block);
    write_pointer(engine, args[2], block)?;
    engine.get_data_mut().apis.lanman.record(
        "NetWkstaGetInfo",
        format!("level {level}, {host} in {group}, build {build}"),
        NERR_SUCCESS,
    );
    Ok(NERR_SUCCESS)
}

fn user_add(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let level = args[1] as u32;
    if args[2] == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    // Levels 1 through 4 all begin with USER_INFO_1, which carries everything
    // this model reports.
    if !matches!(level, 1..=4) {
        engine.get_data_mut().apis.lanman.record(
            "NetUserAdd",
            format!("level {level}"),
            ERROR_INVALID_LEVEL,
        );
        return Ok(ERROR_INVALID_LEVEL);
    }
    if local_server(engine, args[0], true)?.is_none() {
        let detail = files::path(engine, args[0], true)?;
        engine
            .get_data_mut()
            .apis
            .lanman
            .record("NetUserAdd", detail, NERR_INVALID_COMPUTER);
        return Ok(NERR_INVALID_COMPUTER);
    }
    let width = ptr_width(engine) as usize;
    let layout = UserInfo::new(width);
    let name_pointer = read_pointer(engine, args[2])?;
    if name_pointer == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let name = files::path(engine, name_pointer, true)?;
    let password = read_pointer(engine, args[2] + layout.password as u64)?;
    let privilege = read_dword(engine, args[2] + layout.privilege as u64)?;
    let flags = read_dword(engine, args[2] + layout.flags as u64)?;
    let script = read_pointer(engine, args[2] + layout.script as u64)?;
    let home = read_pointer(engine, args[2] + layout.home as u64)?;
    let comment = read_pointer(engine, args[2] + layout.comment as u64)?;
    let text = |pointer: u64| -> Result<String> {
        if pointer == 0 {
            Ok(String::new())
        } else {
            files::path(engine, pointer, true)
        }
    };
    let script = text(script)?;
    let home = text(home)?;
    let comment = text(comment)?;
    // The account creation is recorded in full — privilege level, flags and
    // whether a password was supplied — and nothing is created, because this
    // profile keeps no account database. The password text itself is never
    // copied into evidence.
    let detail = format!(
        "{name}: privilege {privilege}, flags {flags:#x}, password {}{}{}{}",
        if password == 0 { "absent" } else { "supplied" },
        if home.is_empty() {
            String::new()
        } else {
            format!(", home {home}")
        },
        if script.is_empty() {
            String::new()
        } else {
            format!(", script {script}")
        },
        if comment.is_empty() {
            String::new()
        } else {
            format!(", comment {comment}")
        },
    );
    engine
        .get_data_mut()
        .apis
        .lanman
        .record("NetUserAdd", detail, NERR_SUCCESS);
    if args[3] != 0 {
        // No parameter was at fault; PARM_ERROR_NONE is -1.
        write_dword(engine, args[3], u32::MAX)?;
    }
    Ok(NERR_SUCCESS)
}

fn open_enum(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let (scope, kind, usage) = (args[0] as u32, args[1] as u32, args[2] as u32);
    if args[4] == 0
        || !RESOURCE_SCOPES.contains(&scope)
        || kind & !0x3 != 0
        || usage & !RESOURCE_USAGE_BITS != 0
    {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let width = ptr_width(engine) as usize;
    let layout = NetResource::new(width);
    let container = if args[3] == 0 {
        "the whole network".to_owned()
    } else {
        let remote = read_pointer(engine, args[3] + layout.remote_name as u64)?;
        if remote == 0 {
            "an unnamed container".to_owned()
        } else {
            files::path(engine, remote, true)?
        }
    };
    // No handle is issued: there is no network to enumerate, so the caller
    // never receives an enumeration it could walk.
    engine.get_data_mut().apis.lanman.record(
        "WNetOpenEnum",
        format!("scope {scope}, type {kind}: {container}"),
        ERROR_NO_NETWORK,
    );
    Ok(ERROR_NO_NETWORK)
}

fn add_connection(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    if args[0] == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let width = ptr_width(engine) as usize;
    let layout = NetResource::new(width);
    let kind = read_dword(engine, args[0] + 4)?;
    if !RESOURCE_TYPES.contains(&kind) {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let remote = read_pointer(engine, args[0] + layout.remote_name as u64)?;
    if remote == 0 {
        return Ok(ERROR_BAD_NET_NAME);
    }
    let share = files::path(engine, remote, true)?;
    if !share.starts_with("\\\\") {
        engine
            .get_data_mut()
            .apis
            .lanman
            .record("WNetAddConnection2", share, ERROR_BAD_NET_NAME);
        return Ok(ERROR_BAD_NET_NAME);
    }
    let local = read_pointer(engine, args[0] + layout.local_name as u64)?;
    let local = if local == 0 {
        String::new()
    } else {
        files::path(engine, local, true)?
    };
    let provider = read_pointer(engine, args[0] + layout.provider as u64)?;
    let provider = if provider == 0 {
        String::new()
    } else {
        files::path(engine, provider, true)?
    };
    let user = if args[2] == 0 {
        String::new()
    } else {
        files::path(engine, args[2], true)?
    };
    // The attempted mapping is the evidence: the share, the device it would
    // appear as, the account it authenticated as, and that a password was
    // supplied. The password itself is never copied.
    let detail = format!(
        "{share}{}{} as {}{}, password {}",
        if local.is_empty() { "" } else { " on " },
        local,
        if user.is_empty() { "the caller" } else { &user },
        if provider.is_empty() {
            String::new()
        } else {
            format!(" through {provider}")
        },
        if args[1] == 0 { "absent" } else { "supplied" },
    );
    engine
        .get_data_mut()
        .apis
        .lanman
        .record("WNetAddConnection2", detail, ERROR_NO_NETWORK);
    Ok(ERROR_NO_NETWORK)
}

fn get_connection(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    if args[0] == 0 || args[2] == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let device = files::path(engine, args[0], wide)?;
    let bytes = device.as_bytes();
    let drive = bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if !drive && !device.starts_with("\\\\") {
        engine
            .get_data_mut()
            .apis
            .lanman
            .record("WNetGetConnection", device, ERROR_BAD_DEVICE);
        return Ok(ERROR_BAD_DEVICE);
    }
    // The guest's only volume is local, so no device is redirected.
    engine
        .get_data_mut()
        .apis
        .lanman
        .record("WNetGetConnection", device, ERROR_NOT_CONNECTED);
    Ok(ERROR_NOT_CONNECTED)
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "The LAN Manager surface is outside the kernel target profile"
    );
    match call {
        Call::JoinInformation => join_information(engine, args),
        Call::WkstaGetInfo => wksta_get_info(engine, args),
        Call::UserAdd => user_add(engine, args),
        Call::BufferFree => {
            // A null buffer is a documented no-op; anything this model did not
            // hand out is refused rather than freed.
            if args[0] == 0 {
                return Ok(NERR_SUCCESS);
            }
            if engine.get_data_mut().apis.lanman.blocks.remove(&args[0]) {
                heap::release(engine, args[0])?;
                Ok(NERR_SUCCESS)
            } else {
                Ok(ERROR_INVALID_PARAMETER)
            }
        }
        Call::OpenEnum => open_enum(engine, args),
        Call::EnumResource => {
            // WNetOpenEnum never issues a handle in this profile, so every
            // handle a caller can present here is invalid.
            engine.get_data_mut().apis.lanman.record(
                "WNetEnumResource",
                format!("handle {:#x}", args[0]),
                ERROR_INVALID_HANDLE,
            );
            Ok(ERROR_INVALID_HANDLE)
        }
        Call::AddConnection => add_connection(engine, args),
        Call::GetConnection { wide } => get_connection(engine, args, wide),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workstation_layouts_match_the_documented_structures() {
        for (width, sizes) in [(4usize, [20, 24, 28]), (8, [32, 40, 48])] {
            let layout = WkstaInfo::new(width);
            assert_eq!(layout.size(100, width), sizes[0]);
            assert_eq!(layout.size(101, width), sizes[1]);
            assert_eq!(layout.size(102, width), sizes[2]);
        }
        let layout = WkstaInfo::new(8);
        assert_eq!(
            (layout.computer_name, layout.group, layout.major, layout.minor),
            (8, 16, 24, 28)
        );
        assert_eq!((layout.lan_root, layout.users), (32, 40));
    }

    #[test]
    fn user_and_resource_layouts_match_the_documented_structures() {
        let user = UserInfo::new(4);
        assert_eq!(
            (user.password, user.privilege, user.home, user.comment, user.flags, user.script),
            (4, 12, 16, 20, 24, 28)
        );
        let user = UserInfo::new(8);
        assert_eq!(
            (user.password, user.privilege, user.home, user.comment, user.flags, user.script),
            (8, 20, 24, 32, 40, 48)
        );
        let resource = NetResource::new(4);
        assert_eq!(
            (resource.local_name, resource.remote_name, resource.provider),
            (16, 20, 28)
        );
        let resource = NetResource::new(8);
        assert_eq!(
            (resource.local_name, resource.remote_name, resource.provider),
            (16, 24, 40)
        );
    }
}
