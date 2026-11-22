//! Security model: SIDs, access tokens, privileges, the hardware profile and
//! the `secur32` user-name surface.
//!
//! The persona owns one deterministic machine SID and one ordinary,
//! non-elevated interactive user, so every identity answer is the same on every
//! run. SIDs live entirely in guest memory in their real binary layout, so a
//! sample that walks a SID by hand — revision byte, authority, sub-authority
//! array — sees exactly what Windows would hand it.
//!
//! Privilege adjustment is observed rather than granted: a privilege the
//! persona's token does not hold (notably `SeDebugPrivilege`) reports the
//! documented partial success — `TRUE` with `ERROR_NOT_ALL_ASSIGNED` — which is
//! precisely the signal an elevation check looks for, so the attempt is visible
//! without the run quietly gaining rights it should not have.
use super::*;
use std::collections::BTreeMap;

const ERROR_SUCCESS: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NONE_MAPPED: u32 = 1332;
const ERROR_NO_TOKEN: u32 = 1008;
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
const ERROR_INVALID_HANDLE: u32 = 6;

/// SID_IDENTIFIER_AUTHORITY values, big-endian in memory.
const AUTHORITY_WORLD: u8 = 1;
const AUTHORITY_NT: u8 = 5;
const AUTHORITY_LABEL: u8 = 16;

/// The persona's machine SID sub-authorities: S-1-5-21-a-b-c. Fixed so the
/// identity is stable across runs and assertable by a control.
const MACHINE: [u32; 4] = [21, 2_147_483_649, 3_876_543_210, 1_234_567_890];
/// The persona user's relative id.
const USER_RID: u32 = 1001;

/// Well-known privileges and their real LUID low parts.
const PRIVILEGES: &[(&str, u32)] = &[
    ("SeCreateTokenPrivilege", 2),
    ("SeAssignPrimaryTokenPrivilege", 3),
    ("SeLockMemoryPrivilege", 4),
    ("SeIncreaseQuotaPrivilege", 5),
    ("SeMachineAccountPrivilege", 6),
    ("SeTcbPrivilege", 7),
    ("SeSecurityPrivilege", 8),
    ("SeTakeOwnershipPrivilege", 9),
    ("SeLoadDriverPrivilege", 10),
    ("SeSystemProfilePrivilege", 11),
    ("SeSystemtimePrivilege", 12),
    ("SeProfileSingleProcessPrivilege", 13),
    ("SeIncreaseBasePriorityPrivilege", 14),
    ("SeCreatePagefilePrivilege", 15),
    ("SeCreatePermanentPrivilege", 16),
    ("SeBackupPrivilege", 17),
    ("SeRestorePrivilege", 18),
    ("SeShutdownPrivilege", 19),
    ("SeDebugPrivilege", 20),
    ("SeAuditPrivilege", 21),
    ("SeSystemEnvironmentPrivilege", 22),
    ("SeChangeNotifyPrivilege", 23),
    ("SeRemoteShutdownPrivilege", 24),
    ("SeUndockPrivilege", 25),
    ("SeSyncAgentPrivilege", 26),
    ("SeEnableDelegationPrivilege", 27),
    ("SeManageVolumePrivilege", 28),
    ("SeImpersonatePrivilege", 29),
    ("SeCreateGlobalPrivilege", 30),
    ("SeTrustedCredManAccessPrivilege", 31),
    ("SeRelabelPrivilege", 32),
    ("SeIncreaseWorkingSetPrivilege", 33),
    ("SeTimeZonePrivilege", 34),
    ("SeCreateSymbolicLinkPrivilege", 35),
    ("SeDelegateSessionUserImpersonatePrivilege", 36),
];

/// The privileges an ordinary interactive user's token carries, and whether
/// each is enabled by default.
const HELD: &[(u32, bool)] = &[
    (23, true),  // SeChangeNotifyPrivilege
    (19, false), // SeShutdownPrivilege
    (25, false), // SeUndockPrivilege
    (33, true),  // SeIncreaseWorkingSetPrivilege
    (34, false), // SeTimeZonePrivilege
];

fn privilege_luid(name: &str) -> Option<u32> {
    PRIVILEGES
        .iter()
        .find(|(privilege, _)| privilege.eq_ignore_ascii_case(name))
        .map(|(_, luid)| *luid)
}

fn privilege_name(luid: u32) -> Option<&'static str> {
    PRIVILEGES
        .iter()
        .find(|(_, value)| *value == luid)
        .map(|(name, _)| *name)
}

#[derive(Clone, Debug)]
struct Token {
    /// Privilege LUID low part to attributes (bit 0 = enabled by default,
    /// bit 1 = enabled).
    privileges: BTreeMap<u32, u32>,
    impersonation: bool,
}

impl Token {
    fn user() -> Self {
        Token {
            privileges: HELD
                .iter()
                .map(|(luid, enabled)| (*luid, if *enabled { 3 } else { 0 }))
                .collect(),
            impersonation: false,
        }
    }
}

/// One observed privilege or impersonation attempt.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub detail: String,
    pub granted: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub privilege_requests: u64,
    pub impersonations: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that touched none of this serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.privilege_requests == 0
            && self.impersonations == 0
            && self.events.is_empty()
            && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    counter: u64,
    tokens: BTreeMap<u64, Token>,
    impersonating: bool,
    pub report: Report,
}

impl State {
    fn handle(&mut self) -> u64 {
        self.counter += 1;
        0x5A10_0000 + self.counter * 0x40
    }
    fn record(&mut self, api: &'static str, detail: String, granted: bool) {
        if api == "ImpersonateLoggedOnUser" {
            self.report.impersonations += 1;
        } else {
            self.report.privilege_requests += 1;
        }
        if self.report.events.len() < 64 {
            self.report.events.push(Event { api, detail, granted });
        } else {
            self.report.omitted_events += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    AllocateAndInitializeSid,
    InitializeSid,
    FreeSid,
    GetLengthSid,
    CopySid,
    EqualSid,
    IsValidSid,
    GetSidIdentifierAuthority,
    GetSidSubAuthority,
    GetSidSubAuthorityCount,
    LookupAccountName { wide: bool },
    LookupAccountSid { wide: bool },
    LookupPrivilegeValue { wide: bool },
    LookupPrivilegeName { wide: bool },
    LookupPrivilegeDisplayName { wide: bool },
    OpenProcessToken,
    OpenThreadToken,
    GetTokenInformation,
    SetTokenInformation,
    AdjustTokenPrivileges,
    CheckTokenMembership,
    DuplicateTokenEx,
    ImpersonateLoggedOnUser,
    RevertToSelf,
    GetCurrentHwProfile { wide: bool },
    GetUserNameEx { wide: bool },
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    let wide = name.ends_with('W');
    let row = match (module, name) {
        ("advapi32", "AllocateAndInitializeSid") => (AllocateAndInitializeSid, 11, T::U32),
        ("advapi32", "InitializeSid") => (InitializeSid, 3, T::U32),
        ("advapi32", "FreeSid") => (FreeSid, 1, T::Pointer),
        ("advapi32", "GetLengthSid") => (GetLengthSid, 1, T::U32),
        ("advapi32", "CopySid") => (CopySid, 3, T::U32),
        ("advapi32", "EqualSid") => (EqualSid, 2, T::U32),
        ("advapi32", "IsValidSid") => (IsValidSid, 1, T::U32),
        ("advapi32", "GetSidIdentifierAuthority") => (GetSidIdentifierAuthority, 1, T::Pointer),
        ("advapi32", "GetSidSubAuthority") => (GetSidSubAuthority, 2, T::Pointer),
        ("advapi32", "GetSidSubAuthorityCount") => (GetSidSubAuthorityCount, 1, T::Pointer),
        ("advapi32", "LookupAccountNameA" | "LookupAccountNameW") => {
            (LookupAccountName { wide }, 7, T::U32)
        }
        ("advapi32", "LookupAccountSidA" | "LookupAccountSidW") => {
            (LookupAccountSid { wide }, 7, T::U32)
        }
        ("advapi32", "LookupPrivilegeValueA" | "LookupPrivilegeValueW") => {
            (LookupPrivilegeValue { wide }, 3, T::U32)
        }
        ("advapi32", "LookupPrivilegeNameA" | "LookupPrivilegeNameW") => {
            (LookupPrivilegeName { wide }, 4, T::U32)
        }
        ("advapi32", "LookupPrivilegeDisplayNameA" | "LookupPrivilegeDisplayNameW") => {
            (LookupPrivilegeDisplayName { wide }, 5, T::U32)
        }
        // Outside the M7 partition, but the token surface is unreachable
        // without a way to obtain a token handle.
        ("advapi32" | "kernel32" | "kernelbase", "OpenProcessToken") => (OpenProcessToken, 3, T::U32),
        ("advapi32" | "kernel32" | "kernelbase", "OpenThreadToken") => (OpenThreadToken, 4, T::U32),
        ("advapi32", "GetTokenInformation") => (GetTokenInformation, 5, T::U32),
        ("advapi32", "SetTokenInformation") => (SetTokenInformation, 4, T::U32),
        ("advapi32", "AdjustTokenPrivileges") => (AdjustTokenPrivileges, 6, T::U32),
        ("advapi32", "CheckTokenMembership") => (CheckTokenMembership, 3, T::U32),
        ("advapi32", "DuplicateTokenEx") => (DuplicateTokenEx, 6, T::U32),
        ("advapi32", "ImpersonateLoggedOnUser") => (ImpersonateLoggedOnUser, 1, T::U32),
        ("advapi32", "RevertToSelf") => (RevertToSelf, 0, T::U32),
        ("advapi32", "GetCurrentHwProfileA" | "GetCurrentHwProfileW") => {
            (GetCurrentHwProfile { wide }, 1, T::U32)
        }
        ("secur32" | "sspicli", "GetUserNameExA" | "GetUserNameExW") => {
            (GetUserNameEx { wide }, 3, T::U32)
        }
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

fn write_pointer(engine: &mut Unicorn<Trace>, address: u64, value: u64) -> Result<()> {
    let width = ptr_width(engine) as usize;
    put(engine, address, &value.to_le_bytes()[..width])
}

fn read_dword(engine: &Unicorn<Trace>, address: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(read(engine, address, 4)?.try_into().unwrap()))
}

fn fail(engine: &mut Unicorn<Trace>, code: u32) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(0)
}

fn succeed(engine: &mut Unicorn<Trace>) -> Result<u64> {
    engine.get_data_mut().apis.last_error = ERROR_SUCCESS;
    Ok(1)
}

/// Build a SID's binary form: revision, count, 6-byte big-endian authority,
/// then little-endian sub-authorities.
fn sid_bytes(authority: u8, sub: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + sub.len() * 4);
    bytes.push(1);
    bytes.push(sub.len() as u8);
    bytes.extend([0, 0, 0, 0, 0, authority]);
    for value in sub {
        bytes.extend(value.to_le_bytes());
    }
    bytes
}

/// The persona user's SID: the machine SID plus the user's relative id.
fn user_sid() -> Vec<u8> {
    let mut sub = MACHINE.to_vec();
    sub.push(USER_RID);
    sid_bytes(AUTHORITY_NT, &sub)
}

fn everyone_sid() -> Vec<u8> {
    sid_bytes(AUTHORITY_WORLD, &[0])
}

fn administrators_sid() -> Vec<u8> {
    sid_bytes(AUTHORITY_NT, &[32, 544])
}

/// The groups the persona's token belongs to. The user is deliberately not an
/// administrator, so an elevation check sees the truth.
fn group_sids() -> Vec<Vec<u8>> {
    vec![
        everyone_sid(),
        sid_bytes(AUTHORITY_NT, &[32, 545]), // BUILTIN\Users
        sid_bytes(AUTHORITY_NT, &[4]),       // INTERACTIVE
        sid_bytes(AUTHORITY_NT, &[11]),      // Authenticated Users
    ]
}

/// Medium mandatory level: S-1-16-8192.
fn integrity_sid() -> Vec<u8> {
    sid_bytes(AUTHORITY_LABEL, &[8192])
}

/// Read a SID from guest memory using its own sub-authority count.
fn read_sid(engine: &Unicorn<Trace>, address: u64) -> Result<Vec<u8>> {
    if address == 0 {
        bail!("Null SID pointer");
    }
    let header = read(engine, address, 2)?;
    let count = header[1] as u64;
    ensure!(count <= 15, "SID sub-authority count exceeds its limit");
    read(engine, address, 8 + count * 4)
}

fn sid_is_valid(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[0] == 1 && bytes[1] <= 15 && bytes.len() == 8 + bytes[1] as usize * 4
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

/// Write `text` into a caller buffer whose capacity is a character count at
/// `count_at`, following the Win32 in/out convention.
fn write_counted(
    engine: &mut Unicorn<Trace>,
    buffer: u64,
    count_at: u64,
    text: &str,
    wide: bool,
) -> Result<std::result::Result<(), u32>> {
    let bytes = encode(text, wide);
    let units = if wide { bytes.len() / 2 } else { bytes.len() };
    let capacity = if count_at != 0 {
        read_dword(engine, count_at)?
    } else {
        0
    };
    if buffer == 0 || (capacity as usize) < units {
        if count_at != 0 {
            write_dword(engine, count_at, units as u32)?;
        }
        return Ok(Err(ERROR_INSUFFICIENT_BUFFER));
    }
    put(engine, buffer, &bytes)?;
    if count_at != 0 {
        // The written count excludes the terminator.
        write_dword(engine, count_at, units as u32 - 1)?;
    }
    Ok(Ok(()))
}

/// The persona's user and machine names.
fn identity(engine: &Unicorn<Trace>) -> (String, String) {
    let model = &engine.get_data().apis.persona.model;
    (
        model.user_name_text().to_string(),
        model.computer_name_text().to_string(),
    )
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::AllocateAndInitializeSid => {
            // (authority, count, sub0..sub7, pSid)
            let count = args[1] as u8;
            if args[0] == 0 || args[10] == 0 || count > 8 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let authority = read(engine, args[0], 6)?;
            let mut bytes = Vec::new();
            bytes.push(1);
            bytes.push(count);
            bytes.extend(authority);
            for index in 0..count as usize {
                bytes.extend((args[2 + index] as u32).to_le_bytes());
            }
            let address = heap::alloc(engine, bytes.len() as u64)?;
            put(engine, address, &bytes)?;
            write_pointer(engine, args[10], address)?;
            succeed(engine)
        }
        Call::InitializeSid => {
            // (pSid, pIdentifierAuthority, nSubAuthorityCount)
            let count = args[2] as u8;
            if args[0] == 0 || args[1] == 0 || count > 15 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let authority = read(engine, args[1], 6)?;
            let mut bytes = vec![1u8, count];
            bytes.extend(authority);
            // Only the header is initialized; sub-authorities stay the
            // caller's to fill, as the real function leaves them.
            put(engine, args[0], &bytes)?;
            succeed(engine)
        }
        Call::FreeSid => {
            heap::release(engine, args[0])?;
            // FreeSid returns NULL on success.
            Ok(0)
        }
        Call::GetLengthSid => {
            let sid = read_sid(engine, args[0])?;
            Ok(sid.len() as u64)
        }
        Call::CopySid => {
            // (nDestinationSidLength, pDestinationSid, pSourceSid)
            let source = read_sid(engine, args[2])?;
            if args[1] == 0 || (args[0] as usize) < source.len() {
                return fail(engine, ERROR_INSUFFICIENT_BUFFER);
            }
            put(engine, args[1], &source)?;
            succeed(engine)
        }
        Call::EqualSid => {
            let left = read_sid(engine, args[0])?;
            let right = read_sid(engine, args[1])?;
            engine.get_data_mut().apis.last_error = ERROR_SUCCESS;
            Ok((left == right) as u64)
        }
        Call::IsValidSid => {
            let Ok(sid) = read_sid(engine, args[0]) else {
                return Ok(0);
            };
            Ok(sid_is_valid(&sid) as u64)
        }
        // These three answer pointers into the caller's own SID, exactly as
        // Windows does, so a caller can read and even edit in place.
        Call::GetSidIdentifierAuthority => {
            read_sid(engine, args[0])?;
            Ok(args[0] + 2)
        }
        Call::GetSidSubAuthorityCount => {
            read_sid(engine, args[0])?;
            Ok(args[0] + 1)
        }
        Call::GetSidSubAuthority => {
            let sid = read_sid(engine, args[0])?;
            let index = args[1] as u32;
            ensure!(
                index < sid[1] as u32,
                "Sub-authority index is outside the SID"
            );
            Ok(args[0] + 8 + index as u64 * 4)
        }
        Call::LookupAccountName { wide } => lookup_account_name(engine, args, wide),
        Call::LookupAccountSid { wide } => lookup_account_sid(engine, args, wide),
        Call::LookupPrivilegeValue { wide } => {
            // (lpSystemName, lpName, lpLuid)
            if args[1] == 0 || args[2] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let name = files::path(engine, args[1], wide)?;
            let Some(luid) = privilege_luid(&name) else {
                return fail(engine, ERROR_NONE_MAPPED);
            };
            // LUID is a 64-bit value: low part then high part.
            write_dword(engine, args[2], luid)?;
            write_dword(engine, args[2] + 4, 0)?;
            succeed(engine)
        }
        Call::LookupPrivilegeName { wide } => {
            // (lpSystemName, lpLuid, lpName, cchName)
            if args[1] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let luid = read_dword(engine, args[1])?;
            let high = read_dword(engine, args[1] + 4)?;
            let Some(name) = privilege_name(luid).filter(|_| high == 0) else {
                return fail(engine, ERROR_NONE_MAPPED);
            };
            match write_counted(engine, args[2], args[3], name, wide)? {
                Ok(()) => succeed(engine),
                Err(code) => fail(engine, code),
            }
        }
        Call::LookupPrivilegeDisplayName { wide } => {
            // (lpSystemName, lpName, lpDisplayName, cchDisplayName, lpLanguageId)
            if args[1] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let name = files::path(engine, args[1], wide)?;
            if privilege_luid(&name).is_none() {
                return fail(engine, ERROR_NONE_MAPPED);
            }
            // The display text is the privilege's own name in this profile: no
            // localized resource table exists to render a description from.
            match write_counted(engine, args[2], args[3], &name, wide)? {
                Ok(()) => {
                    if args[4] != 0 {
                        // Neutral language.
                        write_dword(engine, args[4], 0)?;
                    }
                    succeed(engine)
                }
                Err(code) => fail(engine, code),
            }
        }
        Call::OpenProcessToken => {
            // (ProcessHandle, DesiredAccess, TokenHandle)
            if args[2] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let handle = engine.get_data_mut().apis.security.handle();
            engine
                .get_data_mut()
                .apis
                .security
                .tokens
                .insert(handle, Token::user());
            write_pointer(engine, args[2], handle)?;
            succeed(engine)
        }
        Call::OpenThreadToken => {
            // No thread carries an impersonation token unless one was set.
            if !engine.get_data().apis.security.impersonating {
                return fail(engine, ERROR_NO_TOKEN);
            }
            if args[3] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let mut token = Token::user();
            token.impersonation = true;
            let handle = engine.get_data_mut().apis.security.handle();
            engine
                .get_data_mut()
                .apis
                .security
                .tokens
                .insert(handle, token);
            write_pointer(engine, args[3], handle)?;
            succeed(engine)
        }
        Call::GetTokenInformation => token_information(engine, args),
        Call::SetTokenInformation => {
            if !engine.get_data().apis.security.tokens.contains_key(&args[0]) {
                return fail(engine, ERROR_INVALID_HANDLE);
            }
            // The change is accepted and recorded; no identity actually moves.
            engine.get_data_mut().apis.security.record(
                "SetTokenInformation",
                format!("class {}", args[1] as u32),
                true,
            );
            succeed(engine)
        }
        Call::AdjustTokenPrivileges => adjust_token_privileges(engine, args),
        Call::CheckTokenMembership => {
            // (TokenHandle, SidToCheck, IsMember)
            if args[2] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let sid = read_sid(engine, args[1])?;
            let member = group_sids().contains(&sid) || sid == user_sid();
            write_dword(engine, args[2], member as u32)?;
            if sid == administrators_sid() {
                // The check an elevation test makes; the answer is recorded.
                engine.get_data_mut().apis.security.record(
                    "CheckTokenMembership",
                    "BUILTIN\\Administrators".into(),
                    false,
                );
            }
            succeed(engine)
        }
        Call::DuplicateTokenEx => {
            // (hExistingToken, dwDesiredAccess, lpTokenAttributes,
            // ImpersonationLevel, TokenType, phNewToken)
            let Some(existing) = engine
                .get_data()
                .apis
                .security
                .tokens
                .get(&args[0])
                .cloned()
            else {
                return fail(engine, ERROR_INVALID_HANDLE);
            };
            if args[5] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let mut token = existing;
            // TokenType 2 is TokenImpersonation.
            token.impersonation = args[4] == 2;
            let handle = engine.get_data_mut().apis.security.handle();
            engine
                .get_data_mut()
                .apis
                .security
                .tokens
                .insert(handle, token);
            write_pointer(engine, args[5], handle)?;
            succeed(engine)
        }
        Call::ImpersonateLoggedOnUser => {
            if !engine.get_data().apis.security.tokens.contains_key(&args[0]) {
                return fail(engine, ERROR_INVALID_HANDLE);
            }
            // Impersonation is recorded; the persona identity does not change,
            // because there is only one user in this profile.
            let state = &mut engine.get_data_mut().apis.security;
            state.impersonating = true;
            state.record("ImpersonateLoggedOnUser", String::new(), true);
            succeed(engine)
        }
        Call::RevertToSelf => {
            engine.get_data_mut().apis.security.impersonating = false;
            succeed(engine)
        }
        Call::GetCurrentHwProfile { wide } => {
            // HW_PROFILE_INFO: dwDockInfo, szHwProfileGuid[39], szHwProfileName[80].
            if args[0] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            // DOCKINFO_DOCKED | DOCKINFO_USER_SUPPLIED is not claimed; the
            // profile is undocked and set by the system.
            write_dword(engine, args[0], 0x2)?;
            let guid = "{6f2a9e4d-0000-0000-0000-000000000001}";
            let name = "Profile 1";
            let unit = if wide { 2u64 } else { 1 };
            put(engine, args[0] + 4, &encode(guid, wide))?;
            put(engine, args[0] + 4 + 39 * unit, &encode(name, wide))?;
            succeed(engine)
        }
        Call::GetUserNameEx { wide } => {
            // (NameFormat, lpNameBuffer, nSize)
            let (user, machine) = identity(engine);
            let text = match args[0] as u32 {
                1 => format!("CN={user}"),              // NameFullyQualifiedDN
                2 => format!("{machine}\\{user}"),      // NameSamCompatible
                3 => user.clone(),                      // NameDisplay
                8 => format!("{user}@{machine}"),       // NameUserPrincipal
                _ => return fail(engine, ERROR_INVALID_PARAMETER),
            };
            // nSize is in characters and is updated the same way.
            match write_counted(engine, args[1], args[2], &text, wide)? {
                Ok(()) => succeed(engine),
                Err(code) => fail(engine, code),
            }
        }
    }
}

fn lookup_account_name(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    // (lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName,
    // cchReferencedDomainName, peUse)
    let (user, machine) = identity(engine);
    let requested = if args[1] == 0 {
        user.clone()
    } else {
        files::path(engine, args[1], wide)?
    };
    // Accept the bare user name or DOMAIN\user, plus the well-known groups.
    let bare = requested
        .rsplit_once('\\')
        .map(|(_, name)| name.to_string())
        .unwrap_or_else(|| requested.clone());
    // The referenced domain follows the account: the machine for a local user,
    // nothing for a world group, BUILTIN for an alias.
    let (sid, use_kind, domain) = if bare.eq_ignore_ascii_case(&user) {
        (user_sid(), 1u32, machine) // SidTypeUser
    } else if bare.eq_ignore_ascii_case("Everyone") {
        (everyone_sid(), 4, String::new()) // SidTypeWellKnownGroup
    } else if bare.eq_ignore_ascii_case("Administrators") {
        (administrators_sid(), 4, "BUILTIN".to_string())
    } else {
        return fail(engine, ERROR_NONE_MAPPED);
    };
    let capacity = if args[3] != 0 {
        read_dword(engine, args[3])?
    } else {
        0
    };
    let domain_fits = write_counted(engine, args[4], args[5], &domain, wide)?;
    if args[2] == 0 || (capacity as usize) < sid.len() || domain_fits.is_err() {
        if args[3] != 0 {
            write_dword(engine, args[3], sid.len() as u32)?;
        }
        return fail(engine, ERROR_INSUFFICIENT_BUFFER);
    }
    put(engine, args[2], &sid)?;
    write_dword(engine, args[3], sid.len() as u32)?;
    if args[6] != 0 {
        write_dword(engine, args[6], use_kind)?;
    }
    succeed(engine)
}

fn lookup_account_sid(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    // (lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchDomain, peUse)
    let sid = read_sid(engine, args[1])?;
    let (user, machine) = identity(engine);
    let (name, domain, use_kind) = if sid == user_sid() {
        (user, machine.clone(), 1u32)
    } else if sid == everyone_sid() {
        ("Everyone".to_string(), String::new(), 4)
    } else if sid == administrators_sid() {
        ("Administrators".to_string(), "BUILTIN".to_string(), 4)
    } else {
        return fail(engine, ERROR_NONE_MAPPED);
    };
    let name_fits = write_counted(engine, args[2], args[3], &name, wide)?;
    let domain_fits = write_counted(engine, args[4], args[5], &domain, wide)?;
    if name_fits.is_err() || domain_fits.is_err() {
        return fail(engine, ERROR_INSUFFICIENT_BUFFER);
    }
    if args[6] != 0 {
        write_dword(engine, args[6], use_kind)?;
    }
    succeed(engine)
}

/// `GetTokenInformation(TokenHandle, class, buffer, length, ReturnLength)`.
fn token_information(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let Some(token) = engine.get_data().apis.security.tokens.get(&args[0]).cloned() else {
        return fail(engine, ERROR_INVALID_HANDLE);
    };
    let width = ptr_width(engine);
    // Each answer is built as a flat blob; pointers inside it are fixed up
    // against the caller's buffer address once the length is known to fit.
    enum Blob {
        Flat(Vec<u8>),
        /// Bytes plus (offset-of-pointer, offset-of-target) fix-ups.
        Linked(Vec<u8>, Vec<(usize, usize)>),
    }
    let blob = match args[1] as u32 {
        // TokenUser: SID_AND_ATTRIBUTES { PSID; DWORD } then the SID.
        1 => {
            let sid = user_sid();
            let header = (width + 4).next_multiple_of(width) as usize;
            let mut bytes = vec![0u8; header];
            bytes.extend(&sid);
            Blob::Linked(bytes, vec![(0, header)])
        }
        // TokenGroups: DWORD count, then SID_AND_ATTRIBUTES[], then the SIDs.
        2 => {
            let groups = group_sids();
            let entry = (width + 4).next_multiple_of(width) as usize;
            let header = (4usize).next_multiple_of(width as usize) + groups.len() * entry;
            let mut bytes = vec![0u8; header];
            bytes[..4].copy_from_slice(&(groups.len() as u32).to_le_bytes());
            let mut links = Vec::new();
            let table = (4usize).next_multiple_of(width as usize);
            for (index, sid) in groups.iter().enumerate() {
                let at = table + index * entry;
                links.push((at, bytes.len()));
                // SE_GROUP_ENABLED | SE_GROUP_MANDATORY
                bytes[at + width as usize..at + width as usize + 4]
                    .copy_from_slice(&0x5u32.to_le_bytes());
                bytes.extend(sid);
            }
            Blob::Linked(bytes, links)
        }
        // TokenPrivileges: DWORD count, then LUID_AND_ATTRIBUTES[].
        3 => {
            let mut bytes = (token.privileges.len() as u32).to_le_bytes().to_vec();
            for (luid, attributes) in &token.privileges {
                bytes.extend(luid.to_le_bytes());
                bytes.extend(0u32.to_le_bytes());
                bytes.extend(attributes.to_le_bytes());
            }
            Blob::Flat(bytes)
        }
        // TokenOwner / TokenPrimaryGroup: a PSID into the same buffer.
        4 | 5 => {
            let sid = user_sid();
            let header = width as usize;
            let mut bytes = vec![0u8; header];
            bytes.extend(&sid);
            Blob::Linked(bytes, vec![(0, header)])
        }
        // TokenStatistics is not modeled; its LUIDs and quotas would be invented.
        10 => return fail(engine, ERROR_INVALID_PARAMETER),
        // TokenSessionId: the persona's interactive session.
        12 => Blob::Flat(1u32.to_le_bytes().to_vec()),
        // TokenElevationType: 1 = TokenElevationTypeDefault (UAC not split).
        18 => Blob::Flat(1u32.to_le_bytes().to_vec()),
        // TokenElevation: the persona is not elevated.
        20 => Blob::Flat(0u32.to_le_bytes().to_vec()),
        // TokenIntegrityLevel: medium.
        25 => {
            let sid = integrity_sid();
            let header = (width + 4).next_multiple_of(width) as usize;
            let mut bytes = vec![0u8; header];
            bytes.extend(&sid);
            Blob::Linked(bytes, vec![(0, header)])
        }
        _ => return fail(engine, ERROR_INVALID_PARAMETER),
    };
    let (mut bytes, links) = match blob {
        Blob::Flat(bytes) => (bytes, Vec::new()),
        Blob::Linked(bytes, links) => (bytes, links),
    };
    if args[4] != 0 {
        write_dword(engine, args[4], bytes.len() as u32)?;
    }
    if args[2] == 0 || (args[3] as usize) < bytes.len() {
        return fail(engine, ERROR_INSUFFICIENT_BUFFER);
    }
    // Interior pointers address the caller's buffer, as Windows returns them.
    for (pointer_at, target_at) in links {
        let target = args[2] + target_at as u64;
        let encoded = target.to_le_bytes();
        bytes[pointer_at..pointer_at + width as usize]
            .copy_from_slice(&encoded[..width as usize]);
    }
    put(engine, args[2], &bytes)?;
    succeed(engine)
}

/// `AdjustTokenPrivileges(TokenHandle, DisableAll, NewState, BufferLength,
/// PreviousState, ReturnLength)`.
///
/// A privilege the token does not hold cannot be enabled: the call still
/// reports `TRUE`, with `ERROR_NOT_ALL_ASSIGNED`, which is the documented
/// behavior and the signal an elevation attempt reads.
fn adjust_token_privileges(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let Some(mut token) = engine.get_data().apis.security.tokens.get(&args[0]).cloned() else {
        return fail(engine, ERROR_INVALID_HANDLE);
    };
    let previous = token.clone();
    let mut all_assigned = true;
    let mut requested: Vec<String> = Vec::new();
    if args[1] != 0 {
        // DisableAllPrivileges wins over the new state entirely.
        for attributes in token.privileges.values_mut() {
            *attributes &= !2;
        }
    } else {
        if args[2] == 0 {
            return fail(engine, ERROR_INVALID_PARAMETER);
        }
        let count = read_dword(engine, args[2])?;
        ensure!(count <= 256, "Privilege array exceeds its modeled bound");
        for index in 0..count as u64 {
            let entry = args[2] + 4 + index * 12;
            let luid = read_dword(engine, entry)?;
            let high = read_dword(engine, entry + 4)?;
            let attributes = read_dword(engine, entry + 8)?;
            requested.push(
                privilege_name(luid)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("LUID {luid}")),
            );
            // SE_PRIVILEGE_ENABLED is bit 1.
            let enable = attributes & 2 != 0;
            match token.privileges.get_mut(&luid) {
                Some(held) if high == 0 => {
                    if enable {
                        *held |= 2;
                    } else {
                        *held &= !2;
                    }
                }
                // Not held: nothing is granted, and the caller is told.
                _ => all_assigned = false,
            }
        }
    }
    // PreviousState is filled only when it fits.
    if args[4] != 0 {
        let mut bytes = (previous.privileges.len() as u32).to_le_bytes().to_vec();
        for (luid, attributes) in &previous.privileges {
            bytes.extend(luid.to_le_bytes());
            bytes.extend(0u32.to_le_bytes());
            bytes.extend(attributes.to_le_bytes());
        }
        if args[5] != 0 {
            write_dword(engine, args[5], bytes.len() as u32)?;
        }
        if (args[3] as usize) < bytes.len() {
            return fail(engine, ERROR_INSUFFICIENT_BUFFER);
        }
        put(engine, args[4], &bytes)?;
    }
    engine
        .get_data_mut()
        .apis
        .security
        .tokens
        .insert(args[0], token);
    let detail = if args[1] != 0 {
        "DisableAllPrivileges".to_string()
    } else {
        requested.join(",")
    };
    engine
        .get_data_mut()
        .apis
        .security
        .record("AdjustTokenPrivileges", detail, all_assigned);
    engine.get_data_mut().apis.last_error = if all_assigned {
        ERROR_SUCCESS
    } else {
        ERROR_NOT_ALL_ASSIGNED
    };
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_binary_layout_matches_the_documented_shape() {
        let sid = user_sid();
        // Revision 1, five sub-authorities, NT authority in the sixth byte.
        assert_eq!(sid[0], 1);
        assert_eq!(sid[1], 5);
        assert_eq!(&sid[2..8], &[0, 0, 0, 0, 0, AUTHORITY_NT]);
        assert_eq!(sid.len(), 8 + 5 * 4);
        assert_eq!(u32::from_le_bytes(sid[8..12].try_into().unwrap()), 21);
        // The user's relative id is last.
        assert_eq!(
            u32::from_le_bytes(sid[24..28].try_into().unwrap()),
            USER_RID
        );
        assert!(sid_is_valid(&sid));
        assert!(sid_is_valid(&everyone_sid()));
        // A truncated SID is not valid.
        assert!(!sid_is_valid(&sid[..7]));
    }

    #[test]
    fn well_known_privilege_luids_round_trip() {
        assert_eq!(privilege_luid("SeDebugPrivilege"), Some(20));
        assert_eq!(privilege_luid("sedebugprivilege"), Some(20));
        assert_eq!(privilege_luid("SeShutdownPrivilege"), Some(19));
        assert_eq!(privilege_name(20), Some("SeDebugPrivilege"));
        assert_eq!(privilege_luid("SeNotARealPrivilege"), None);
        assert_eq!(privilege_name(9999), None);
    }

    #[test]
    fn the_persona_user_is_not_an_administrator() {
        // An elevation check must see the truth.
        assert!(!group_sids().contains(&administrators_sid()));
        // SeDebugPrivilege is not held, so it cannot be enabled.
        assert!(!HELD.iter().any(|(luid, _)| *luid == 20));
    }
}
